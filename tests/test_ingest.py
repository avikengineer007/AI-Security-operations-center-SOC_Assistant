"""
tests/test_ingest.py

Unit tests for ingestion and normalization in ingest.py.
"""

import json
from soc_assistant.ingest import normalize


def test_normalize_json_standard():
    raw = json.dumps({
        "timestamp": "2026-06-29T12:00:00Z",
        "source": "Wazuh",
        "severity": "high",
        "src_ip": "192.168.1.50",
        "dst_ip": "8.8.8.8",
        "username": "admin",
        "process_name": "powershell.exe",
        "rule_id": "100200"
    })
    alert = normalize(raw, source_hint="Wazuh")
    assert alert.timestamp == "2026-06-29T12:00:00Z"
    assert alert.source == "Wazuh"
    assert alert.severity == "high"
    assert alert.fields["src_ip"] == "192.168.1.50"
    assert alert.fields["dst_ip"] == "8.8.8.8"
    assert alert.fields["user"] == "admin"
    assert alert.fields["process"] == "powershell.exe"
    assert alert.fields["rule_id"] == "100200"


def test_normalize_json_nested():
    raw = json.dumps({
        "time": "2026-06-29T12:00:00Z",
        "agent": {
            "name": "sensor-01"
        },
        "level": 3,
        "data": {
            "src": "10.0.0.5",
            "dest.ip": "10.0.0.10",
            "account": "system",
            "image": "cmd.exe"
        }
    })
    alert = normalize(raw, source_hint="Syslog")
    assert alert.timestamp == "2026-06-29T12:00:00Z"
    assert alert.source == "sensor-01"
    assert alert.severity == "3"
    assert alert.fields["src_ip"] == "10.0.0.5"
    assert alert.fields["dst_ip"] == "10.0.0.10"
    assert alert.fields["user"] == "system"
    assert alert.fields["process"] == "cmd.exe"


def test_normalize_freeform_text():
    raw = "2026-06-29 12:15:30 Wazuh alert: CRITICAL rule_id 99999. Src IP 192.168.1.100, Dest IP 10.0.0.1. User=john process: mal.exe on host: workstation1"
    alert = normalize(raw, source_hint="Wazuh")
    assert "2026-06-29" in alert.timestamp
    assert alert.severity == "critical"
    assert alert.fields["src_ip"] == "192.168.1.100"
    assert alert.fields["dst_ip"] == "10.0.0.1"
    assert alert.fields["user"] == "john"
    assert alert.fields["process"] == "mal.exe"
    assert alert.fields["rule_id"] == "99999"
    assert alert.fields["host"] == "workstation1"


def test_normalize_ssh_bruteforce_log():
    raw_log = (
        "Jun 29 21:05:42 host-prod-ssh-01 sshd[28491]: Failed password for invalid user admin from 198.51.100.42 port 49218 ssh2\n"
        "Jun 29 21:05:44 host-prod-ssh-01 sshd[28491]: Failed password for invalid user admin from 198.51.100.42 port 49222 ssh2\n"
    )
    alert = normalize(raw_log, source_hint="Syslog")
    # Verify that the parsed fields do not contain duplicate IPs
    assert alert.fields["src_ip"] == "198.51.100.42"
    # There is only one unique IP, so dst_ip should not be set (or should not equal src_ip)
    assert "dst_ip" not in alert.fields

    # Verify that the port is extracted correctly from the first port declaration,
    # rather than from the timestamp's colons (e.g. 21:05:42 -> "05")
    assert alert.fields["port"] == "49218"
