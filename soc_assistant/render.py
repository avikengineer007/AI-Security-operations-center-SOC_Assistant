"""
soc_assistant/render.py

Two rendering modes:
  1. Terminal output via `rich` (colored panels, tables, badges)
  2. Markdown export (clean incident report for tickets / copy-paste)
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

# pyrefly: ignore [missing-import]
from rich import box
# pyrefly: ignore [missing-import]
from rich.columns import Columns
# pyrefly: ignore [missing-import]
from rich.console import Console
# pyrefly: ignore [missing-import]
from rich.panel import Panel
# pyrefly: ignore [missing-import]
from rich.table import Table
# pyrefly: ignore [missing-import]
from rich.text import Text
# pyrefly: ignore [missing-import]
from rich import print as rprint

from soc_assistant.models import Alert, Analysis, SeverityLevel, Confidence, Priority

console = Console()

# ---------------------------------------------------------------------------
# Severity color mapping
# ---------------------------------------------------------------------------

_SEVERITY_STYLES: dict[SeverityLevel, tuple[str, str]] = {
    SeverityLevel.CRITICAL:      ("bold white on red",        "🔴"),
    SeverityLevel.HIGH:          ("bold white on dark_orange", "🟠"),
    SeverityLevel.MEDIUM:        ("bold black on yellow",      "🟡"),
    SeverityLevel.LOW:           ("bold white on blue",        "🔵"),
    SeverityLevel.INFORMATIONAL: ("bold white on green",       "🟢"),
}

_CONFIDENCE_COLORS: dict[Confidence, str] = {
    Confidence.CONFIRMED: "green",
    Confidence.LIKELY:    "yellow",
    Confidence.POSSIBLE:  "dim yellow",
}

_PRIORITY_COLORS: dict[Priority, str] = {
    Priority.IMMEDIATE:  "bold red",
    Priority.SHORT_TERM: "yellow",
    Priority.MONITOR:    "dim cyan",
}

_PRIORITY_ICONS: dict[Priority, str] = {
    Priority.IMMEDIATE:  "🚨",
    Priority.SHORT_TERM: "⚠️ ",
    Priority.MONITOR:    "👁 ",
}


# ---------------------------------------------------------------------------
# Terminal rendering
# ---------------------------------------------------------------------------

def render_terminal(alert: Alert, analysis: Analysis, duration_ms: int = 0) -> None:
    """Render the full analysis to the terminal using rich."""
    console.print()
    _render_header(alert, analysis, duration_ms)
    _render_summary(analysis)
    _render_severity(analysis)
    _render_false_positive(analysis)
    _render_mitre(analysis)
    _render_actions(analysis)
    _render_questions(analysis)
    console.print()


def _render_header(alert: Alert, analysis: Analysis, duration_ms: int) -> None:
    style, icon = _SEVERITY_STYLES[analysis.severity_assessment]

    title = Text()
    title.append("  SOC ASSISTANT — ALERT ANALYSIS  ", style="bold white on #1a1a2e")

    badge = Text()
    badge.append(f"  {icon}  {analysis.severity_assessment.value.upper()}  ", style=style)

    meta = Text()
    meta.append(f"Source: ", style="dim")
    meta.append(alert.source, style="cyan")
    meta.append("  │  ", style="dim")
    meta.append(f"Time: ", style="dim")
    meta.append(alert.timestamp[:19].replace("T", " "), style="cyan")
    if duration_ms:
        meta.append("  │  ", style="dim")
        meta.append(f"Analyzed in {duration_ms}ms", style="dim green")

    console.rule(style="#4a4a8a")
    console.print(Columns([title, badge], equal=False, expand=True))
    console.print(meta)
    console.rule(style="#4a4a8a")


def _render_summary(analysis: Analysis) -> None:
    console.print(
        Panel(
            f"[white]{analysis.summary}[/white]",
            title="[bold cyan]📋 Summary[/bold cyan]",
            border_style="cyan",
            padding=(1, 2),
        )
    )


def _render_severity(analysis: Analysis) -> None:
    style, icon = _SEVERITY_STYLES[analysis.severity_assessment]
    badge = Text(f" {icon}  {analysis.severity_assessment.value} ", style=style)
    body = Text()
    body.append(analysis.severity_reasoning)

    grid = Table.grid(padding=(0, 1))
    grid.add_row(badge, body)

    console.print(
        Panel(
            grid,
            title="[bold]⚡ Severity Assessment[/bold]",
            border_style="#4a4a8a",
            padding=(1, 2),
        )
    )


def _render_false_positive(analysis: Analysis) -> None:
    if analysis.is_likely_false_positive:
        fp_text = Text("⚠️  LIKELY FALSE POSITIVE", style="bold yellow")
    else:
        fp_text = Text("✅  NOT A FALSE POSITIVE", style="bold green")

    body = Text("\n")
    body.append(analysis.false_positive_reasoning, style="white")

    grid = Table.grid(padding=(0, 1))
    grid.add_row(fp_text)
    grid.add_row(body)

    border = "yellow" if analysis.is_likely_false_positive else "green"
    console.print(
        Panel(
            grid,
            title="[bold]🔍 False Positive Assessment[/bold]",
            border_style=border,
            padding=(1, 2),
        )
    )


def _render_mitre(analysis: Analysis) -> None:
    if not analysis.mitre_mapping:
        console.print(
            Panel(
                "[dim]No MITRE ATT&CK techniques mapped.[/dim]",
                title="[bold]🗺  MITRE ATT&CK Mapping[/bold]",
                border_style="dim",
                padding=(0, 2),
            )
        )
        return

    table = Table(
        box=box.ROUNDED,
        show_header=True,
        header_style="bold #a0a0ff",
        border_style="#4a4a8a",
        expand=True,
        padding=(0, 1),
    )
    table.add_column("ID", style="bold cyan", no_wrap=True, min_width=8)
    table.add_column("Technique", style="white", min_width=22)
    table.add_column("Confidence", no_wrap=True, min_width=12)
    table.add_column("Justification", style="dim white")

    for m in analysis.mitre_mapping:
        conf_color = _CONFIDENCE_COLORS[m.confidence]
        conf_text = Text(m.confidence.value, style=conf_color)
        table.add_row(m.technique_id, m.technique_name, conf_text, m.justification)

    console.print(
        Panel(
            table,
            title="[bold]🗺  MITRE ATT&CK Mapping[/bold]",
            border_style="#4a4a8a",
            padding=(0, 1),
        )
    )


def _render_actions(analysis: Analysis) -> None:
    if not analysis.recommended_actions:
        console.print(
            Panel(
                "[dim]No recommended actions.[/dim]",
                title="[bold]🛡  Recommended Actions[/bold]",
                border_style="dim",
            )
        )
        return

    grid = Table.grid(padding=(0, 1), expand=True)
    grid.add_column(no_wrap=True, min_width=16)
    grid.add_column()
    grid.add_column(style="dim white")

    for i, action in enumerate(analysis.recommended_actions, 1):
        prio_color = _PRIORITY_COLORS[action.priority]
        prio_icon = _PRIORITY_ICONS[action.priority]
        prio_badge = Text(f"{prio_icon} {action.priority.value}", style=prio_color)
        num = Text(f"{i}. ", style="bold white")
        action_text = Text(action.action, style="white")
        rationale = Text(f"↳ {action.rationale}", style="dim white")

        action_col = Text()
        action_col.append_text(num)
        action_col.append_text(action_text)

        grid.add_row(prio_badge, action_col, "")
        grid.add_row("", rationale, "")
        if i < len(analysis.recommended_actions):
            grid.add_row("", Text(""), "")

    console.print(
        Panel(
            grid,
            title="[bold]🛡  Recommended Actions[/bold]",
            border_style="blue",
            padding=(1, 2),
        )
    )


def _render_questions(analysis: Analysis) -> None:
    if not analysis.questions_for_analyst:
        return

    items = "\n".join(
        f"  [bold cyan]?[/bold cyan]  {q}" for q in analysis.questions_for_analyst
    )
    console.print(
        Panel(
            items,
            title="[bold]❓ Questions for Analyst[/bold]",
            border_style="yellow",
            padding=(1, 2),
        )
    )


# ---------------------------------------------------------------------------
# Markdown export
# ---------------------------------------------------------------------------

def render_markdown(alert: Alert, analysis: Analysis) -> str:
    """Render a clean Markdown incident report string."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines: list[str] = []

    lines += [
        "# Security Incident Analysis Report",
        "",
        f"**Generated:** {now}  ",
        f"**Alert Source:** {alert.source}  ",
        f"**Alert Timestamp:** {alert.timestamp}  ",
        f"**Raw Severity:** {alert.severity}  ",
        "",
        "---",
        "",
    ]

    # Summary
    lines += [
        "## Summary",
        "",
        analysis.summary,
        "",
    ]

    # Severity
    sev = analysis.severity_assessment.value
    lines += [
        "## Severity Assessment",
        "",
        f"**Severity:** {sev}  ",
        f"**Reasoning:** {analysis.severity_reasoning}",
        "",
    ]

    # False positive
    fp_str = "Yes — likely false positive" if analysis.is_likely_false_positive else "No"
    lines += [
        "## False Positive Assessment",
        "",
        f"**Likely False Positive:** {fp_str}  ",
        f"**Reasoning:** {analysis.false_positive_reasoning}",
        "",
    ]

    # MITRE mappings
    lines += ["## MITRE ATT&CK Mapping", ""]
    if analysis.mitre_mapping:
        lines += [
            "| Technique ID | Technique Name | Confidence | Justification |",
            "|---|---|---|---|",
        ]
        for m in analysis.mitre_mapping:
            lines.append(
                f"| {m.technique_id} | {m.technique_name} | {m.confidence.value} | {m.justification} |"
            )
    else:
        lines.append("_No MITRE ATT&CK techniques mapped._")
    lines.append("")

    # Recommended actions
    lines += ["## Recommended Actions", ""]
    if analysis.recommended_actions:
        for i, action in enumerate(analysis.recommended_actions, 1):
            lines += [
                f"### {i}. [{action.priority.value}] {action.action}",
                "",
                f"**Rationale:** {action.rationale}",
                "",
            ]
    else:
        lines.append("_No actions recommended._")
        lines.append("")

    # Questions for analyst
    lines += ["## Questions for Analyst", ""]
    if analysis.questions_for_analyst:
        for q in analysis.questions_for_analyst:
            lines.append(f"- {q}")
    else:
        lines.append("_No open questions._")
    lines.append("")

    # Raw alert fields
    if alert.fields:
        lines += ["## Extracted Alert Fields", ""]
        lines += ["| Field | Value |", "|---|---|"]
        for k, v in alert.fields.items():
            lines.append(f"| `{k}` | `{v}` |")
        lines.append("")

    lines += [
        "---",
        "",
        "_Report generated by SOC Assistant v0.1.0_",
    ]

    return "\n".join(lines)


def save_report(path: str | Path, content: str) -> Path:
    """Write the markdown report to disk, creating parent dirs as needed."""
    report_path = Path(path)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(content, encoding="utf-8")
    return report_path
