"""
soc_assistant/analyzer.py

Builds the Claude prompt, calls the API, validates the JSON response
against the Analysis pydantic schema, and retries once if parsing fails.
"""

from __future__ import annotations

import json
import time
from typing import Any

# pyrefly: ignore [missing-import]
import anthropic
# pyrefly: ignore [missing-import]
from pydantic import ValidationError

from soc_assistant.models import Alert, Analysis

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_MODEL = "claude-sonnet-4-5"
MAX_TOKENS = 4096

SYSTEM_PROMPT = """\
You are a senior SOC (Security Operations Center) analyst with deep expertise \
in threat detection, the MITRE ATT&CK framework, and incident response. \
You are analyzing a single security alert for a junior analyst.

Guidelines:
- Be precise; avoid speculation beyond what the alert supports.
- Flag uncertainty explicitly rather than guessing.
- When mapping to MITRE ATT&CK, only cite techniques you are confident apply. \
  If unsure, use confidence "Possible" and say so in the justification rather \
  than asserting it as confirmed.
- Always return your analysis in the exact JSON schema provided below, \
  with NO extra commentary, markdown fences, or text outside the JSON object.

Required output schema (return exactly this JSON, no wrapper, no markdown):
{
  "summary": "<2-3 sentence plain-language explanation of the alert>",
  "severity_assessment": "<Critical | High | Medium | Low | Informational>",
  "severity_reasoning": "<justification for the severity level>",
  "mitre_mapping": [
    {
      "technique_id": "<e.g. T1059>",
      "technique_name": "<human-readable name>",
      "confidence": "<Confirmed | Likely | Possible>",
      "justification": "<why this technique applies>"
    }
  ],
  "is_likely_false_positive": <true | false>,
  "false_positive_reasoning": "<explanation>",
  "recommended_actions": [
    {
      "action": "<concrete action>",
      "priority": "<Immediate | Short-term | Monitor>",
      "rationale": "<why this action is recommended>"
    }
  ],
  "questions_for_analyst": ["<question 1>", "<question 2>"]
}

If mitre_mapping, recommended_actions, or questions_for_analyst have no \
entries, return an empty array [] for that field.\
"""

USER_MESSAGE_TEMPLATE = """\
Analyze the following normalized security alert and return your analysis \
in the JSON schema specified in the system prompt. Do not include any text \
outside the JSON.

ALERT:
{alert_json}
"""

RETRY_MESSAGE_TEMPLATE = """\
Your previous response could not be parsed as valid JSON matching the required \
schema. Here is what went wrong:

{error_detail}

Your previous (malformed) response was:
{previous_response}

Please respond again with ONLY a valid JSON object matching the schema in the \
system prompt. No markdown, no explanation, just the JSON.\
"""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze(alert: Alert, model: str = DEFAULT_MODEL) -> tuple[Analysis, int]:
    """
    Send the alert to Claude and return (Analysis, duration_ms).

    Raises:
        anthropic.APIError: on API-level failures
        ValueError: if parsing fails even after the retry
    """
    client = _get_client()
    start = time.monotonic()

    # First attempt
    first_response = _call_claude(client, model, alert)
    analysis, error = _parse_response(first_response)

    if analysis is not None:
        duration_ms = int((time.monotonic() - start) * 1000)
        return analysis, duration_ms

    # Retry with error context
    retry_response = _call_claude_retry(client, model, alert, first_response, error)
    analysis, error2 = _parse_response(retry_response)

    duration_ms = int((time.monotonic() - start) * 1000)

    if analysis is not None:
        return analysis, duration_ms

    raise ValueError(
        f"Claude returned invalid JSON even after retry.\n"
        f"Last error: {error2}\n"
        f"Last response:\n{retry_response}"
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_client() -> anthropic.Anthropic:
    """
    Create an Anthropic client.
    The SDK automatically reads ANTHROPIC_API_KEY from the environment.
    python-dotenv (loaded in cli.py) ensures .env is sourced before this runs.
    """
    return anthropic.Anthropic()


def _call_claude(
    client: anthropic.Anthropic,
    model: str,
    alert: Alert,
) -> str:
    """Send the first analysis request. Returns the raw text content."""
    user_message = USER_MESSAGE_TEMPLATE.format(alert_json=alert.to_prompt_str())

    response = client.messages.create(
        model=model,
        max_tokens=MAX_TOKENS,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_message}],
    )
    return _extract_text(response)


def _call_claude_retry(
    client: anthropic.Anthropic,
    model: str,
    alert: Alert,
    previous_response: str,
    error: str,
) -> str:
    """Send a retry request showing Claude what was malformed."""
    user_message = USER_MESSAGE_TEMPLATE.format(alert_json=alert.to_prompt_str())
    retry_message = RETRY_MESSAGE_TEMPLATE.format(
        error_detail=error,
        previous_response=previous_response,
    )

    response = client.messages.create(
        model=model,
        max_tokens=MAX_TOKENS,
        system=SYSTEM_PROMPT,
        messages=[
            {"role": "user", "content": user_message},
            {"role": "assistant", "content": previous_response},
            {"role": "user", "content": retry_message},
        ],
    )
    return _extract_text(response)


def _parse_response(raw_text: str) -> tuple[Analysis | None, str]:
    """
    Attempt to parse raw_text as an Analysis.
    Returns (Analysis, "") on success, or (None, error_str) on failure.
    """
    text = raw_text.strip()
    
    # Try to find the bounds of the JSON object first to ignore surrounding text/markdown
    start_idx = text.find("{")
    end_idx = text.rfind("}")
    if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
        text = text[start_idx:end_idx + 1]
    else:
        # Fallback to standard stripping if no curly braces found
        if text.startswith("```"):
            lines = text.splitlines()
            inner = [l for l in lines if not l.startswith("```")]
            text = "\n".join(inner).strip()

    try:
        data: dict[str, Any] = json.loads(text)
    except json.JSONDecodeError as exc:
        return None, f"JSON decode error: {exc}"

    try:
        analysis = Analysis.model_validate(data)
        return analysis, ""
    except ValidationError as exc:
        return None, f"Schema validation error:\n{exc}"


def _extract_text(response: anthropic.types.Message) -> str:
    """Pull the text content out of an Anthropic Message object."""
    parts = [block.text for block in response.content if hasattr(block, "text")]
    return "\n".join(parts).strip()
