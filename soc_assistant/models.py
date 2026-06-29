"""
soc_assistant/models.py

Pydantic schemas for every data contract in SOC Assistant.
All other modules import from here — change field names here first.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from enum import Enum

# pyrefly: ignore [missing-import]
from pydantic import BaseModel, Field
# pyrefly: ignore [missing-import]
from pydantic.functional_validators import field_validator


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class Confidence(str, Enum):
    CONFIRMED = "Confirmed"
    LIKELY = "Likely"
    POSSIBLE = "Possible"


class Priority(str, Enum):
    IMMEDIATE = "Immediate"
    SHORT_TERM = "Short-term"
    MONITOR = "Monitor"


class SeverityLevel(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"


# ---------------------------------------------------------------------------
# Input schema — normalized from any raw source before sending to Claude
# ---------------------------------------------------------------------------

class Alert(BaseModel):
    """Normalized alert object passed to the analyzer."""

    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO-8601 timestamp; defaults to ingest time if not found in raw input"
    )
    source: str = Field(
        default="unknown",
        description="Data source identifier, e.g. 'Wazuh', 'Suricata', 'manual'",
    )
    severity: str = Field(
        default="unknown",
        description="Raw severity string from the source system, if present",
    )
    raw_alert: str = Field(
        description="Original, unmodified alert text or JSON string"
    )
    fields: dict[str, Any] = Field(
        default_factory=dict,
        description="Best-effort extracted key-value pairs (src_ip, dst_ip, user, process, rule_id, …)",
    )

    @field_validator("timestamp", mode="before")
    def default_timestamp(cls, v: Any) -> str:
        if not v:
            return datetime.now(timezone.utc).isoformat()
        return str(v)

    def to_prompt_str(self) -> str:
        """Render the alert as a compact JSON string for the Claude user message."""
        import json
        return json.dumps(self.model_dump(), indent=2)


# ---------------------------------------------------------------------------
# Output schema — Claude must return exactly this structure
# ---------------------------------------------------------------------------

class MitreMapping(BaseModel):
    """A single MITRE ATT&CK technique mapping."""

    technique_id: str = Field(description="e.g. 'T1059'")
    technique_name: str = Field(description="Human-readable technique name")
    confidence: Confidence = Field(description="Analyst confidence in this mapping")
    justification: str = Field(description="Why this technique was mapped")

    @field_validator("confidence", mode="before")
    def normalize_confidence(cls, v: Any) -> Any:
        if isinstance(v, str):
            mapping = {
                "confirmed": Confidence.CONFIRMED,
                "likely": Confidence.LIKELY,
                "possible": Confidence.POSSIBLE,
            }
            val_lower = v.lower().strip()
            if val_lower in mapping:
                return mapping[val_lower]
        return v


class RecommendedAction(BaseModel):
    """A single recommended investigative or remediation action."""

    action: str = Field(description="Concrete action for the analyst to take")
    priority: Priority = Field(description="Urgency level")
    rationale: str = Field(description="Why this action is recommended")

    @field_validator("priority", mode="before")
    def normalize_priority(cls, v: Any) -> Any:
        if isinstance(v, str):
            mapping = {
                "immediate": Priority.IMMEDIATE,
                "short-term": Priority.SHORT_TERM,
                "short_term": Priority.SHORT_TERM,
                "shortterm": Priority.SHORT_TERM,
                "monitor": Priority.MONITOR,
            }
            val_lower = v.lower().strip()
            if val_lower in mapping:
                return mapping[val_lower]
        return v


class Analysis(BaseModel):
    """
    Full structured analysis returned by Claude.
    Validated against this schema; retry is triggered if parsing fails.
    """

    summary: str = Field(description="2-3 sentence plain-language explanation of the alert")
    severity_assessment: SeverityLevel = Field(
        description="Assessed severity: Critical | High | Medium | Low | Informational"
    )
    severity_reasoning: str = Field(description="Justification for the severity level")
    mitre_mapping: list[MitreMapping] = Field(
        default_factory=list,
        description="MITRE ATT&CK technique mappings; may be empty if none apply",
    )
    is_likely_false_positive: bool = Field(
        description="True if Claude believes this is probably a false positive"
    )
    false_positive_reasoning: str = Field(
        description="Explanation of the false-positive assessment"
    )
    recommended_actions: list[RecommendedAction] = Field(
        default_factory=list,
        description="Ordered list of recommended actions for the analyst",
    )
    questions_for_analyst: list[str] = Field(
        default_factory=list,
        description="Questions Claude cannot answer without additional context",
    )

    @field_validator("severity_assessment", mode="before")
    def normalize_severity(cls, v: Any) -> Any:
        if isinstance(v, str):
            mapping = {
                "critical": SeverityLevel.CRITICAL,
                "high": SeverityLevel.HIGH,
                "medium": SeverityLevel.MEDIUM,
                "low": SeverityLevel.LOW,
                "informational": SeverityLevel.INFORMATIONAL,
                "info": SeverityLevel.INFORMATIONAL,
            }
            val_lower = v.lower().strip()
            if val_lower in mapping:
                return mapping[val_lower]
        return v


# ---------------------------------------------------------------------------
# Audit log entry — stored in ./reports/audit.jsonl
# ---------------------------------------------------------------------------

class AuditEntry(BaseModel):
    """One record written to the audit log after each analysis run."""

    run_timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    model: str
    duration_ms: int
    alert: Alert
    analysis: Analysis
