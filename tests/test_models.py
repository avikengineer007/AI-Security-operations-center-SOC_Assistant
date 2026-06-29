"""
tests/test_models.py

Unit tests for Pydantic schemas in models.py.
"""

import json
from soc_assistant.models import Alert, Analysis, SeverityLevel, Confidence, Priority


def test_alert_validation_defaults():
    # Test that minimum fields are supplied and validation works, generating a default timestamp
    alert = Alert(
        raw_alert="Some alert text",
    )
    assert alert.timestamp is not None
    assert alert.source == "unknown"
    assert alert.severity == "unknown"
    assert alert.fields == {}
    assert alert.raw_alert == "Some alert text"


def test_alert_to_prompt_str():
    alert = Alert(
        timestamp="2026-06-29T12:00:00Z",
        source="Wazuh",
        severity="high",
        raw_alert="Raw text",
        fields={"src_ip": "1.1.1.1"},
    )
    prompt_str = alert.to_prompt_str()
    data = json.loads(prompt_str)
    assert data["source"] == "Wazuh"
    assert data["fields"]["src_ip"] == "1.1.1.1"


def test_analysis_schema():
    # Ensure correct schema instantiation
    analysis_data = {
        "summary": "This is a summary of the suspicious event.",
        "severity_assessment": "High",
        "severity_reasoning": "Reasoning details.",
        "mitre_mapping": [
            {
                "technique_id": "T1059",
                "technique_name": "Command and Scripting Interpreter",
                "confidence": "Confirmed",
                "justification": "Justification details."
            }
        ],
        "is_likely_false_positive": False,
        "false_positive_reasoning": "Not a false positive because X.",
        "recommended_actions": [
            {
                "action": "Isolate the host.",
                "priority": "Immediate",
                "rationale": "Rationale details."
            }
        ],
        "questions_for_analyst": ["What was the user doing?"]
    }
    analysis = Analysis.model_validate(analysis_data)
    assert analysis.severity_assessment == SeverityLevel.HIGH
    assert analysis.mitre_mapping[0].confidence == Confidence.CONFIRMED
    assert analysis.recommended_actions[0].priority == Priority.IMMEDIATE


def test_case_insensitive_enums():
    analysis_data = {
        "summary": "Suspicious event.",
        "severity_assessment": "critical",  # lowercase
        "severity_reasoning": "Reason.",
        "mitre_mapping": [
            {
                "technique_id": "T1059",
                "technique_name": "Execution",
                "confidence": "possible",  # lowercase
                "justification": "Reason."
            }
        ],
        "is_likely_false_positive": False,
        "false_positive_reasoning": "Reason.",
        "recommended_actions": [
            {
                "action": "Investigate.",
                "priority": "short_term",  # alternative string form
                "rationale": "Reason."
            }
        ],
        "questions_for_analyst": []
    }
    analysis = Analysis.model_validate(analysis_data)
    assert analysis.severity_assessment == SeverityLevel.CRITICAL
    assert analysis.mitre_mapping[0].confidence == Confidence.POSSIBLE
    assert analysis.recommended_actions[0].priority == Priority.SHORT_TERM
