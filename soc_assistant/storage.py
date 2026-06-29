"""
soc_assistant/storage.py

Append-only JSONL audit log written to ./reports/audit.jsonl.
Each line is a self-contained JSON record — no DB, easily grep-able.
"""

from __future__ import annotations

import json
from pathlib import Path

from soc_assistant.models import Alert, Analysis, AuditEntry

REPORTS_DIR = Path("reports")
AUDIT_FILE = REPORTS_DIR / "audit.jsonl"


def append_log(
    alert: Alert,
    analysis: Analysis,
    model: str,
    duration_ms: int,
) -> Path:
    """
    Append one audit entry to ./reports/audit.jsonl.
    Creates the reports/ directory if it doesn't exist.
    Returns the path to the audit file.
    """
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    entry = AuditEntry(
        model=model,
        duration_ms=duration_ms,
        alert=alert,
        analysis=analysis,
    )

    with AUDIT_FILE.open("a", encoding="utf-8") as fh:
        fh.write(entry.model_dump_json() + "\n")

    return AUDIT_FILE


def read_log(n: int | None = None) -> list[AuditEntry]:
    """
    Read audit entries from the JSONL file.
    If n is given, return the last n entries. Otherwise return all.
    Useful for future tooling that browses the audit trail.
    """
    if not AUDIT_FILE.exists():
        return []

    lines = AUDIT_FILE.read_text(encoding="utf-8").splitlines()
    if n is not None:
        lines = lines[-n:]

    entries: list[AuditEntry] = []
    for line in lines:
        line = line.strip()
        if line:
            try:
                entries.append(AuditEntry.model_validate_json(line))
            except Exception:
                pass  # Skip malformed lines silently
    return entries
