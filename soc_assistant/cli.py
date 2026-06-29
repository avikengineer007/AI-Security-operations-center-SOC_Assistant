"""
soc_assistant/cli.py

Click-based CLI entry point.

Usage:
    soc-assistant analyze --file alert.json
    soc-assistant analyze --paste
    soc-assistant analyze --paste --save report.md
    soc-assistant analyze --file alert.json --save report.md --model claude-opus-4-5
    soc-assistant analyze --file alert.json --no-log
"""

from __future__ import annotations

import sys
from pathlib import Path

# pyrefly: ignore [missing-import]
import click
# pyrefly: ignore [missing-import]
from dotenv import load_dotenv
# pyrefly: ignore [missing-import]
from rich.console import Console
# pyrefly: ignore [missing-import]
from rich.text import Text

from soc_assistant import __version__
from soc_assistant.analyzer import DEFAULT_MODEL, analyze
from soc_assistant.ingest import from_file, from_paste
from soc_assistant.render import render_markdown, render_terminal, save_report
from soc_assistant import storage

# Load .env from CWD (or any parent) so analysts can drop a .env next to their scripts
load_dotenv()

console = Console()
err_console = Console(stderr=True)


# ---------------------------------------------------------------------------
# CLI group
# ---------------------------------------------------------------------------

@click.group()
@click.version_option(__version__, prog_name="soc-assistant")
def cli() -> None:
    """SOC Assistant — AI-powered security alert analyzer powered by Claude."""


# ---------------------------------------------------------------------------
# analyze subcommand
# ---------------------------------------------------------------------------

@cli.command("analyze")
@click.option(
    "--file", "-f",
    "alert_file",
    type=click.Path(exists=True, dir_okay=False, readable=True),
    default=None,
    help="Path to a .json, .log, or .txt alert file.",
)
@click.option(
    "--paste", "-p",
    "use_paste",
    is_flag=True,
    default=False,
    help="Read alert from stdin (multiline paste).",
)
@click.option(
    "--save", "--report", "-s", "-r",
    "save_path",
    type=click.Path(dir_okay=False, writable=True),
    default=None,
    help="Save a Markdown incident report to this path.",
)
@click.option(
    "--model", "-m",
    default=DEFAULT_MODEL,
    show_default=True,
    help="Claude model to use for analysis.",
)
@click.option(
    "--no-log",
    "skip_log",
    is_flag=True,
    default=False,
    help="Skip writing to the audit log.",
)
def analyze_cmd(
    alert_file: str | None,
    use_paste: bool,
    save_path: str | None,
    model: str,
    skip_log: bool,
) -> None:
    """Analyze a security alert using Claude and display structured results."""

    # --- Validate input flags ------------------------------------------------
    if alert_file and use_paste:
        err_console.print("[bold red]Error:[/bold red] Use either --file or --paste, not both.")
        sys.exit(1)
    if not alert_file and not use_paste:
        err_console.print(
            "[bold red]Error:[/bold red] You must specify either [cyan]--file PATH[/cyan] "
            "or [cyan]--paste[/cyan]."
        )
        sys.exit(1)

    # --- Ingest --------------------------------------------------------------
    try:
        if alert_file:
            console.print(f"[dim]Loading alert from:[/dim] [cyan]{alert_file}[/cyan]")
            alert = from_file(alert_file)
        else:
            alert = from_paste()
    except (FileNotFoundError, ValueError) as exc:
        err_console.print(f"[bold red]Ingest error:[/bold red] {exc}")
        sys.exit(1)

    # --- Analyze -------------------------------------------------------------
    console.print(f"\n[dim]Sending alert to Claude ([cyan]{model}[/cyan])…[/dim]")
    try:
        analysis, duration_ms = analyze(alert, model=model)
    except Exception as exc:
        err_console.print(f"\n[bold red]Analysis failed:[/bold red] {exc}")
        sys.exit(1)

    # --- Render to terminal --------------------------------------------------
    render_terminal(alert, analysis, duration_ms)

    # --- Save Markdown report ------------------------------------------------
    if save_path:
        md_content = render_markdown(alert, analysis)
        saved = save_report(save_path, md_content)
        console.print(
            f"\n[bold green]✓[/bold green] Report saved to [cyan]{saved}[/cyan]"
        )

    # --- Audit log -----------------------------------------------------------
    if not skip_log:
        try:
            log_path = storage.append_log(alert, analysis, model=model, duration_ms=duration_ms)
            console.print(
                f"[dim]Audit entry written to [cyan]{log_path}[/cyan][/dim]"
            )
        except Exception as exc:
            # Non-fatal — warn but don't crash
            err_console.print(
                f"[yellow]Warning:[/yellow] Could not write audit log: {exc}"
            )


# ---------------------------------------------------------------------------
# logs subcommand — convenience viewer for the audit trail
# ---------------------------------------------------------------------------

@cli.command("logs")
@click.option(
    "--last", "-n",
    default=10,
    show_default=True,
    help="Show the last N audit entries.",
)
def logs_cmd(last: int) -> None:
    """View recent entries in the audit log."""
    from rich.table import Table
    from rich import box

    entries = storage.read_log(n=last)
    if not entries:
        console.print("[dim]No audit log entries found. Run an analysis first.[/dim]")
        return

    table = Table(
        title=f"Last {min(last, len(entries))} Audit Entries",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
        border_style="#4a4a8a",
    )
    table.add_column("Timestamp", style="dim", no_wrap=True)
    table.add_column("Source", style="cyan")
    table.add_column("Severity", no_wrap=True)
    table.add_column("Model", style="dim")
    table.add_column("FP?", no_wrap=True)
    table.add_column("ms", justify="right", style="dim")

    for entry in entries:
        sev = entry.analysis.severity_assessment.value
        fp = "[yellow]Yes[/yellow]" if entry.analysis.is_likely_false_positive else "[green]No[/green]"
        table.add_row(
            entry.run_timestamp[:19].replace("T", " "),
            entry.alert.source,
            sev,
            entry.model,
            fp,
            str(entry.duration_ms),
        )

    console.print(table)


# ---------------------------------------------------------------------------
# Entrypoint guard (for running as `python -m soc_assistant.cli`)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    cli()
