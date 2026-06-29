"""
tests/test_analyzer.py

Unit tests for analyzer.py, including prompt parsing heuristics and the API retry loop.
"""

import pytest
from soc_assistant.models import Alert, Analysis, SeverityLevel
from soc_assistant.analyzer import analyze, _parse_response


def test_parse_response_clean_json():
    # Test valid json directly
    raw = '{"summary": "Suspicious activity.", "severity_assessment": "High", "severity_reasoning": "Reason.", "is_likely_false_positive": false, "false_positive_reasoning": "Reason."}'
    analysis, error = _parse_response(raw)
    assert analysis is not None
    assert error == ""
    assert analysis.severity_assessment == SeverityLevel.HIGH
    assert analysis.summary == "Suspicious activity."


def test_parse_response_wrapped_in_markdown():
    # Test JSON wrapped in markdown formatting and extra leading/trailing text
    raw = """
Here is the analysis:
```json
{
  "summary": "Suspicious login from new location.",
  "severity_assessment": "Medium",
  "severity_reasoning": "Reason.",
  "is_likely_false_positive": false,
  "false_positive_reasoning": "Reason."
}
```
Hope this helps!
"""
    analysis, error = _parse_response(raw)
    assert analysis is not None
    assert error == ""
    assert analysis.severity_assessment == SeverityLevel.MEDIUM
    assert analysis.summary == "Suspicious login from new location."


def test_parse_response_invalid_schema():
    # Test invalid keys that fail Pydantic validation
    raw = '{"summary": "Missing other fields."}'
    analysis, error = _parse_response(raw)
    assert analysis is None
    assert "Schema validation error" in error


def test_parse_response_invalid_json():
    # Test malformed JSON
    raw = '{"summary": "incomplete json'
    analysis, error = _parse_response(raw)
    assert analysis is None
    assert "JSON decode error" in error


def test_analyze_success_on_first_try(mocker):
    # Mock _get_client to avoid reading real API key or env
    mocker.patch("soc_assistant.analyzer._get_client")
    
    # Mock first API call to return valid JSON
    valid_json = '{"summary": "Alert is a test.", "severity_assessment": "Low", "severity_reasoning": "Reason.", "is_likely_false_positive": false, "false_positive_reasoning": "Reason."}'
    mock_call = mocker.patch("soc_assistant.analyzer._call_claude", return_value=valid_json)
    mock_retry = mocker.patch("soc_assistant.analyzer._call_claude_retry")

    alert = Alert(raw_alert="Test raw alert")
    analysis, duration = analyze(alert)

    assert analysis.severity_assessment == SeverityLevel.LOW
    assert mock_call.call_count == 1
    assert mock_retry.call_count == 0


def test_analyze_success_on_retry(mocker):
    mocker.patch("soc_assistant.analyzer._get_client")
    
    # First call returns malformed JSON, second call returns valid JSON
    malformed_json = '{"summary": "incomplete json'
    valid_json = '{"summary": "Alert is a test.", "severity_assessment": "Low", "severity_reasoning": "Reason.", "is_likely_false_positive": false, "false_positive_reasoning": "Reason."}'
    
    mock_call = mocker.patch("soc_assistant.analyzer._call_claude", return_value=malformed_json)
    mock_retry = mocker.patch("soc_assistant.analyzer._call_claude_retry", return_value=valid_json)

    alert = Alert(raw_alert="Test raw alert")
    analysis, duration = analyze(alert)

    assert analysis.severity_assessment == SeverityLevel.LOW
    assert mock_call.call_count == 1
    assert mock_retry.call_count == 1


def test_analyze_failure_after_retry(mocker):
    mocker.patch("soc_assistant.analyzer._get_client")
    
    # Both calls return malformed JSON
    malformed_json = '{"summary": "incomplete json'
    
    mock_call = mocker.patch("soc_assistant.analyzer._call_claude", return_value=malformed_json)
    mock_retry = mocker.patch("soc_assistant.analyzer._call_claude_retry", return_value=malformed_json)

    alert = Alert(raw_alert="Test raw alert")
    
    with pytest.raises(ValueError, match="Claude returned invalid JSON even after retry"):
        analyze(alert)

    assert mock_call.call_count == 1
    assert mock_retry.call_count == 1
