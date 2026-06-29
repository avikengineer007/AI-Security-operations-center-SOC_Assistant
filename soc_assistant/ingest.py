"""
soc_assistant/ingest.py

Handles all raw input → normalized Alert schema conversions.
Two entry points:
  - from_file(path)  : read a .json / .log / .txt file
  - from_paste()     : read multiline text from stdin

Both funnel into normalize(), which does best-effort field extraction.
If parsing is incomplete, the raw text passes through unchanged so Claude
can do the heavy lifting.
"""

from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from soc_assistant.models import Alert


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------

def from_file(path: str | Path) -> Alert:
    """
    Load an alert from a local file.
    Supports .json, .log, .txt (and anything else treated as plain text).
    """
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Alert file not found: {file_path}")

    raw_text = file_path.read_text(encoding="utf-8", errors="replace")
    source_hint = _guess_source(raw_text)
    return normalize(raw_text, source_hint=source_hint, filename=file_path.name)


def from_paste() -> Alert:
    """
    Read a multiline alert from stdin.
    Prints a prompt, then reads until EOF (Ctrl+D on Unix / Ctrl+Z on Windows).
    """
    if sys.stdin.isatty():
        print("Paste your alert below, then press Ctrl+D (Unix) or Ctrl+Z + Enter (Windows) when done:")
        print("─" * 60)
    lines: list[str] = []
    try:
        for line in sys.stdin:
            lines.append(line)
    except EOFError:
        pass
    raw_text = "".join(lines).strip()
    if not raw_text:
        raise ValueError("No alert text was provided.")
    return normalize(raw_text, source_hint="manual")


# ---------------------------------------------------------------------------
# Core normalization
# ---------------------------------------------------------------------------

def normalize(
    raw_text: str,
    source_hint: str = "unknown",
    filename: str | None = None,
) -> Alert:
    """
    Convert raw text (JSON or freeform) into a normalized Alert.

    Strategy:
      1. Try to parse as JSON.
      2. If it's valid JSON, extract known fields from the top-level dict.
      3. If it's freeform text, run regex heuristics to pull common fields.
      4. Anything not extracted goes into fields={} — that's fine.
      5. Always preserve the original text in raw_alert.
    """
    parsed_json: dict[str, Any] | None = None

    # -- Try JSON parse -------------------------------------------------------
    try:
        candidate = json.loads(raw_text)
        if isinstance(candidate, dict):
            parsed_json = candidate
    except (json.JSONDecodeError, ValueError):
        pass

    if parsed_json is not None:
        return _from_json(parsed_json, raw_text)
    else:
        return _from_freetext(raw_text, source_hint)


# ---------------------------------------------------------------------------
# JSON path
# ---------------------------------------------------------------------------

_TIMESTAMP_KEYS = [
    "timestamp", "@timestamp", "time", "event_time", "datetime",
    "start_time", "occurred", "created_at",
]
_SOURCE_KEYS = ["source", "agent", "sensor", "product", "vendor", "manager"]
_SEVERITY_KEYS = [
    "severity", "level", "priority", "risk_level", "alert_severity",
    "rule_level", "syslog_severity",
]
_KNOWN_FIELD_KEYS = {
    "src_ip", "source_ip", "src", "sourceip", "source.ip",
    "dst_ip", "dest_ip", "dst", "destination_ip", "dest.ip",
    "user", "username", "user_name", "account", "subject_user",
    "process", "process_name", "image", "cmdline", "command_line",
    "rule_id", "rule", "signature_id", "alert_id", "event_id", "id",
    "host", "hostname", "computer_name", "agent_name",
    "action", "event_action", "type", "event_type",
    "port", "src_port", "dst_port", "dest_port",
    "protocol", "proto",
    "file", "file_path", "file_name",
    "url", "uri", "domain",
    "hash", "sha256", "md5",
}

# Canonical names for display consistency
_FIELD_ALIASES: dict[str, str] = {
    "source_ip": "src_ip", "sourceip": "src_ip", "src": "src_ip",
    "source.ip": "src_ip",
    "dest_ip": "dst_ip", "destination_ip": "dst_ip", "dest.ip": "dst_ip",
    "dest_port": "dst_port",
    "username": "user", "user_name": "user", "account": "user",
    "subject_user": "user",
    "process_name": "process", "image": "process",
    "command_line": "cmdline",
    "signature_id": "rule_id", "alert_id": "rule_id",
    "event_id": "rule_id",
    "hostname": "host", "computer_name": "host", "agent_name": "host",
}


def _from_json(data: dict[str, Any], raw_text: str) -> Alert:
    """Build an Alert from a parsed JSON dict."""
    # Flatten nested structures first so finding keys works on nested data
    flat = _flatten(data)

    timestamp = _find_value(flat, _TIMESTAMP_KEYS) or _now_iso()
    source = str(_find_value(flat, _SOURCE_KEYS) or "unknown")
    severity = str(_find_value(flat, _SEVERITY_KEYS) or "unknown")

    fields = _extract_known_fields(flat)

    return Alert(
        timestamp=timestamp,
        source=source,
        severity=severity,
        raw_alert=raw_text,
        fields=fields,
    )


def _from_freetext(raw_text: str, source_hint: str) -> Alert:
    """Build an Alert from freeform / log text using regex heuristics."""
    fields: dict[str, Any] = {}

    # Timestamps
    ts_match = re.search(
        r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.\d]*)?(?:Z|[+-]\d{2}:?\d{2})?",
        raw_text,
    )
    timestamp = ts_match.group(0) if ts_match else _now_iso()

    # Severity keywords (exclude 'alert' to prevent false matches with "Wazuh alert:")
    sev_match = re.search(
        r"\b(critical|high|medium|low|info(?:rmational)?|warning|error)\b",
        raw_text,
        re.IGNORECASE,
    )
    severity = sev_match.group(1).lower() if sev_match else "unknown"

    # IP addresses
    ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", raw_text)
    if ips:
        seen = set()
        unique_ips = []
        for ip in ips:
            if ip not in seen:
                seen.add(ip)
                unique_ips.append(ip)
        fields["src_ip"] = unique_ips[0]
        if len(unique_ips) > 1:
            fields["dst_ip"] = unique_ips[1]

    # Port numbers (e.g. "port 80", "port:8080", or "192.168.1.1:443")
    port_match = re.search(
        r"\bport\s*[:=]?\s*(\d{2,5})\b|\b(?:\d{1,3}\.){3}\d{1,3}:(\d{2,5})\b",
        raw_text,
        re.IGNORECASE,
    )
    if port_match:
        port = port_match.group(1) or port_match.group(2)
        fields["port"] = port.strip(".,;:\"'")

    # User / username
    user_match = re.search(
        r"(?:user(?:name)?|account)[=:\s]+([^\s,;\"']+)", raw_text, re.IGNORECASE
    )
    if user_match:
        fields["user"] = user_match.group(1).strip(".,;:\"'")

    # Process / image
    proc_match = re.search(
        r"(?:process|image|cmd(?:line)?)[=:\s]+([^\s,;\"']+)", raw_text, re.IGNORECASE
    )
    if proc_match:
        fields["process"] = proc_match.group(1).strip(".,;:\"'")

    # Rule / signature ID
    rule_match = re.search(
        r"(?:rule[_\s]?id|signature[_\s]?id|sid|gid|alert[_\s]?id)[=:\s]+([^\s,;\"']+)",
        raw_text,
        re.IGNORECASE,
    )
    if rule_match:
        fields["rule_id"] = rule_match.group(1).strip(".,;:\"'")

    # Hostname
    host_match = re.search(
        r"(?:host(?:name)?|agent|sensor)[=:\s]+([^\s,;\"']+)", raw_text, re.IGNORECASE
    )
    if host_match:
        fields["host"] = host_match.group(1).strip(".,;:\"'")

    return Alert(
        timestamp=timestamp,
        source=source_hint,
        severity=severity,
        raw_alert=raw_text,
        fields=fields,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _find_value(flat_data: dict[str, Any], keys: list[str]) -> Any:
    """Return the first value found for any of the given keys (case-insensitive) in flattened data."""
    lower_data = {k.lower(): v for k, v in flat_data.items()}
    
    # 1. Try exact match
    for key in keys:
        key_lower = key.lower()
        if key_lower in lower_data:
            val = lower_data[key_lower]
            if val is not None and val != "":
                return val

    # 2. Try nested match (e.g. key="agent", flat_data has "agent.name")
    for key in keys:
        key_lower = key.lower()
        for suffix in ["name", "id", "hostname", "username", "value"]:
            full_key = f"{key_lower}.{suffix}"
            if full_key in lower_data:
                val = lower_data[full_key]
                if val is not None and val != "":
                    return val

        # Fallback: starts with key_lower + "." or ends with "." + key_lower
        for k, v in flat_data.items():
            k_lower = k.lower()
            if k_lower.startswith(key_lower + ".") or k_lower.endswith("." + key_lower):
                if v is not None and v != "":
                    return v
    return None


def _flatten(data: dict[str, Any], prefix: str = "", sep: str = ".") -> dict[str, Any]:
    """Recursively flatten a nested dict to a single level."""
    result: dict[str, Any] = {}
    for k, v in data.items():
        full_key = f"{prefix}{sep}{k}" if prefix else k
        if isinstance(v, dict):
            result.update(_flatten(v, full_key, sep))
        else:
            result[full_key] = v
    return result


def _extract_known_fields(flat: dict[str, Any]) -> dict[str, Any]:
    """From a flat dict, keep only security-relevant fields with canonical names."""
    fields: dict[str, Any] = {}
    for raw_key, value in flat.items():
        key = raw_key.lower()
        segments = key.split(".")

        # Try to find a matching suffix in the aliases
        canonical = None
        for i in range(1, len(segments) + 1):
            suffix = ".".join(segments[-i:])
            canonical = _FIELD_ALIASES.get(suffix)
            if canonical:
                break
        
        if canonical:
            fields[canonical] = value
        else:
            # Check if suffix in known keys
            matched_key = None
            for i in range(1, len(segments) + 1):
                suffix = ".".join(segments[-i:])
                if suffix in _KNOWN_FIELD_KEYS:
                    matched_key = suffix
                    break
            if matched_key:
                fields[_FIELD_ALIASES.get(matched_key, matched_key)] = value
    return fields


def _guess_source(raw_text: str) -> str:
    """Heuristically identify the data source from keywords in the raw text."""
    lower = raw_text.lower()
    if "wazuh" in lower:
        return "Wazuh"
    if "suricata" in lower:
        return "Suricata"
    if "snort" in lower:
        return "Snort"
    if "zeek" in lower or "bro" in lower:
        return "Zeek"
    if "windows" in lower and ("eventid" in lower or "event_id" in lower or "evtx" in lower):
        return "Windows Event Log"
    if "syslog" in lower:
        return "Syslog"
    if "crowdstrike" in lower:
        return "CrowdStrike"
    if "sentinel" in lower:
        return "Microsoft Sentinel"
    return "unknown"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
