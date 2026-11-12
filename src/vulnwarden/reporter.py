"""Terminal reporting and Markdown audit report generation."""

from __future__ import annotations

from pathlib import Path
from typing import Sequence

from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from vulnwarden.ai_engine import TriageResult
from vulnwarden.sarif_parser import SarifFinding

console = Console()


def _verdict_style(verdict: str) -> str:
    if verdict == "TRUE_POSITIVE":
        return "bold red"
    return "green"


def _severity_style(severity: str) -> str:
    mapping = {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "cyan",
        "INFO": "dim",
    }
    return mapping.get(severity, "white")


def create_progress() -> Progress:
    """Return a sober progress bar instance for the triage loop."""
    return Progress(
        SpinnerColumn(style="dim"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=30),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    )


def print_summary_table(
    results: Sequence[tuple[SarifFinding, TriageResult | Exception]],
) -> None:
    """Render a concise summary table of all triage outcomes."""
    table = Table(
        title="Triage Summary",
        show_header=True,
        header_style="bold",
        border_style="dim",
        expand=False,
    )
    table.add_column("File:Line", style="cyan", no_wrap=True)
    table.add_column("Rule", style="white")
    table.add_column("Verdict", justify="center")
    table.add_column("Confidence", justify="right")
    table.add_column("Severity", justify="center")

    for finding, outcome in results:
        loc = f"{finding.file_path}:{finding.start_line}"
        rule = finding.rule_id

        if isinstance(outcome, Exception):
            verdict_text = Text("ERROR", style="bold red")
            confidence = "-"
            severity_text = Text("-", style="dim")
        else:
            verdict_text = Text(outcome.verdict, style=_verdict_style(outcome.verdict))
            confidence = f"{outcome.confidence}%"
            severity_text = Text(outcome.severity, style=_severity_style(outcome.severity))

        table.add_row(loc, rule, verdict_text, confidence, severity_text)

    console.print()
    console.print(table)
    console.print()


def print_true_positive_details(
    results: Sequence[tuple[SarifFinding, TriageResult | Exception]],
) -> None:
    """Display detailed panels for every TRUE_POSITIVE finding."""
    true_positives = [
        (f, r) for f, r in results if isinstance(r, TriageResult) and r.verdict == "TRUE_POSITIVE"
    ]

    if not true_positives:
        return

    console.print("[bold]True Positive Details[/bold]")
    console.print()

    for finding, result in true_positives:
        header = f"{finding.file_path}:{finding.start_line}  |  {finding.rule_id}"
        body_parts: list[str] = [
            f"[bold]Severity[/bold]   : {result.severity}",
            f"[bold]Confidence[/bold] : {result.confidence}%",
            "",
            "[bold]Reasoning[/bold]",
            result.reasoning,
        ]

        panel_content = "\n".join(body_parts)

        console.print(
            Panel(
                panel_content,
                title=header,
                border_style="red",
                expand=False,
            )
        )

        if result.remediation_patch:
            # Guess language from file extension for syntax highlighting
            ext = Path(finding.file_path).suffix.lstrip(".").lower()
            lang_map = {
                "py": "python",
                "js": "javascript",
                "ts": "typescript",
                "go": "go",
                "java": "java",
                "rb": "ruby",
                "php": "php",
                "rs": "rust",
                "c": "c",
                "cpp": "cpp",
                "h": "c",
                "cs": "csharp",
                "sh": "bash",
                "yaml": "yaml",
                "yml": "yaml",
                "json": "json",
                "tf": "hcl",
            }
            language = lang_map.get(ext, "text")

            syntax = Syntax(
                result.remediation_patch,
                language,
                theme="monokai",
                line_numbers=False,
                word_wrap=True,
            )
            console.print(
                Panel(
                    syntax,
                    title="Remediation Patch",
                    border_style="green",
                    expand=False,
                )
            )
        console.print()


def generate_markdown_report(
    results: Sequence[tuple[SarifFinding, TriageResult | Exception]],
    output_path: Path,
    *,
    model: str,
    sarif_file: Path,
) -> None:
    """
    Write a complete Markdown audit report suitable for a Pull Request description.
    """
    true_positives = [
        (f, r) for f, r in results if isinstance(r, TriageResult) and r.verdict == "TRUE_POSITIVE"
    ]
    false_positives = [
        (f, r) for f, r in results if isinstance(r, TriageResult) and r.verdict == "FALSE_POSITIVE"
    ]
    errors = [(f, e) for f, e in results if isinstance(e, Exception)]

    lines: list[str] = []
    lines.append("# VulnWarden Audit Report")
    lines.append("")
    lines.append(f"- **SARIF source** : `{sarif_file}`")
    lines.append(f"- **Model**        : `{model}`")
    lines.append(f"- **Total findings**: {len(results)}")
    lines.append(f"- **True positives**: {len(true_positives)}")
    lines.append(f"- **False positives**: {len(false_positives)}")
    if errors:
        lines.append(f"- **Errors**        : {len(errors)}")
    lines.append("")

    # Summary table
    lines.append("## Summary")
    lines.append("")
    lines.append("| File:Line | Rule | Verdict | Confidence | Severity |")
    lines.append("|-----------|------|---------|------------|----------|")
    for finding, outcome in results:
        loc = f"`{finding.file_path}:{finding.start_line}`"
        rule = f"`{finding.rule_id}`"
        if isinstance(outcome, Exception):
            lines.append(f"| {loc} | {rule} | ERROR | - | - |")
        else:
            lines.append(
                f"| {loc} | {rule} | **{outcome.verdict}** | {outcome.confidence}% | {outcome.severity} |"
            )
    lines.append("")

    # True positives details
    if true_positives:
        lines.append("## True Positives – Action Required")
        lines.append("")
        for idx, (finding, result) in enumerate(true_positives, 1):
            lines.append(f"### {idx}. `{finding.file_path}:{finding.start_line}` – `{finding.rule_id}`")
            lines.append("")
            lines.append(f"- **Severity**   : `{result.severity}`")
            lines.append(f"- **Confidence** : {result.confidence}%")
            lines.append(f"- **Original message** : {finding.message}")
            lines.append("")
            lines.append("**Reasoning**")
            lines.append("")
            lines.append(result.reasoning)
            lines.append("")
            if result.remediation_patch:
                lines.append("**Proposed remediation**")
                lines.append("")
                ext = Path(finding.file_path).suffix.lstrip(".").lower() or "text"
                lines.append(f"```{ext}")
                lines.append(result.remediation_patch.rstrip())
                lines.append("```")
                lines.append("")
            lines.append("---")
            lines.append("")

    # False positives (collapsed style)
    if false_positives:
        lines.append("## False Positives (dismissed)")
        lines.append("")
        lines.append("<details>")
        lines.append("<summary>Click to expand dismissed findings</summary>")
        lines.append("")
        for finding, result in false_positives:
            lines.append(
                f"- `{finding.file_path}:{finding.start_line}` (`{finding.rule_id}`) – "
                f"{result.confidence}% – {result.reasoning}"
            )
        lines.append("")
        lines.append("</details>")
        lines.append("")

    if errors:
        lines.append("## Errors during triage")
        lines.append("")
        for finding, err in errors:
            lines.append(f"- `{finding.file_path}:{finding.start_line}` : `{type(err).__name__}: {err}`")
        lines.append("")

    lines.append("---")
    lines.append("*Generated by [VulnWarden](https://github.com/0xBrdn/vulnwarden)*")
    lines.append("")

    output_path.write_text("\n".join(lines), encoding="utf-8")


def has_true_positives(
    results: Sequence[tuple[SarifFinding, TriageResult | Exception]],
) -> bool:
    """Return True if at least one TRUE_POSITIVE is present."""
    return any(
        isinstance(r, TriageResult) and r.verdict == "TRUE_POSITIVE" for _, r in results
    )