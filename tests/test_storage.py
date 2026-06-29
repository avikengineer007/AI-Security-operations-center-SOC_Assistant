"""
tests/test_storage.py

Unit tests for storage.py audit logging.
"""

import pytest
from pathlib import Path
from soc_assistant.models import Alert, Analysis, SeverityLevel, Confidence, Priority
from soc_assistant import storage


def test_storage_append_and_read(tmp_path, monkeypatch):
    # Set up temp files for testing to prevent polluting real reports/audit.jsonl
    temp_reports_dir = tmp_path / "reports"
    temp_audit_file = temp_reports_dir / "audit.jsonl"
    
    monkeypatch.setattr(storage, "REPORTS_DIR", temp_reports_dir)
    monkeypatch.setattr(storage, "AUDIT_FILE", temp_audit_file)

    # 1. Test empty log
    assert storage.read_log() == []

    # Create dummy data
    alert = Alert(
        timestamp="2026-06-29T12:00:00Z",
        source="Wazuh",
        severity="high",
        raw_alert="Raw text",
        fields={"src_ip": "1.1.1.1"},
    )
    
    analysis = Analysis(
        summary="This is a summary of the suspicious event.",
        severity_assessment=SeverityLevel.HIGH,
        severity_reasoning="Reasoning details.",
        mitre_mapping=[],
        is_likely_false_positive=False,
        false_positive_reasoning="Not a FP.",
        recommended_actions=[],
        questions_for_analyst=[],
    )

    # 2. Append a log entry
    log_path = storage.append_log(alert, analysis, model="test-model", duration_ms=123)
    assert log_path == temp_audit_file
    assert temp_audit_file.exists()

    # 3. Read it back
    entries = storage.read_log()
    assert len(entries) == 1
    assert entries[0].model == "test-model"
    assert entries[0].duration_ms == 123
    assert entries[0].alert.source == "Wazuh"
    assert entries[0].analysis.severity_assessment == SeverityLevel.HIGH

    # 4. Append another entry
    storage.append_log(alert, analysis, model="test-model-2", duration_ms=456)
    
    # Read last 1 entry
    entries_last = storage.read_log(n=1)
    assert len(entries_last) == 1
    assert entries_last[0].model == "test-model-2"

    # Read all entries
    all_entries = storage.read_log()
    assert len(all_entries) == 2
    assert all_entries[0].model == "test-model"
    assert all_entries[1].model == "test-model-2"
