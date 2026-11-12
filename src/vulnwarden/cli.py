"""VulnWarden CLI entry point."""

from pathlib import Path
from typing import Optional

import httpx
import typer
from rich.console import Console
from rich.panel import Panel

from vulnwarden import __version__
from vulnwarden.ai_engine import TriageResult, triage_finding
from vulnwarden.reporter import (
    create_progress,
    generate_markdown_report,
    has_true_positives,
    print_summary_table,
    print_true_positive_details,
)
from vulnwarden.sarif_parser import parse_sarif

app = typer.Typer(
    name="vulnwarden",
    help="Automated vulnerability triage and remediation generation powered by local LLM (Ollama).",
    add_completion=False,
    no_args_is_help=True,
)
console = Console()

OLLAMA_BASE_URL = "http://localhost:11434"
DEFAULT_MODEL = "qwen2.5-coder:14b"


def _print_info(message: str) -> None:
    console.print(f"[*] {message}")


def _print_success(message: str) -> None:
    console.print(f"[+] {message}")


def _print_error(message: str) -> None:
    console.print(f"[!] {message}", style="bold red")


def _print_warning(message: str) -> None:
    console.print(f"[!] {message}", style="yellow")


@app.command()
def triage(
    sarif_file: Path = typer.Argument(
        ...,
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        help="Path to the SARIF file to triage.",
    ),
    model: str = typer.Option(
        DEFAULT_MODEL,
        "--model",
        "-m",
        help="Ollama model to use for triage and remediation.",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Optional path to write a Markdown audit report (ready for PR).",
    ),
) -> None:
    """Triage vulnerabilities from a SARIF report using a local LLM."""
    _print_info(f"VulnWarden v{__version__}")
    _print_info(f"Loading SARIF file: {sarif_file}")
    _print_info(f"Using model: {model}")

    if output:
        _print_info(f"Markdown report will be written to: {output}")

    # ------------------------------------------------------------------
    # 1. Parse SARIF
    # ------------------------------------------------------------------
    try:
        findings = parse_sarif(sarif_file)
    except FileNotFoundError as exc:
        _print_error(str(exc))
        raise typer.Exit(code=1)
    except ValueError as exc:
        _print_error(f"SARIF parsing error: {exc}")
        raise typer.Exit(code=1)
    except OSError as exc:
        _print_error(f"I/O error while reading SARIF: {exc}")
        raise typer.Exit(code=1)

    count = len(findings)
    if count == 0:
        _print_warning("No findings extracted from the SARIF file")
        raise typer.Exit(code=0)

    _print_success(f"Extracted {count} finding(s) from SARIF")
    console.print()

    # ------------------------------------------------------------------
    # 2. AI triage with progress bar
    # ------------------------------------------------------------------
    results: list[tuple] = []

    with create_progress() as progress:
        task_id = progress.add_task("Analysing findings...", total=count)

        for idx, finding in enumerate(findings, 1):
            short_loc = f"{Path(finding.file_path).name}:{finding.start_line}"
            progress.update(
                task_id,
                description=f"Analysing [{idx}/{count}] {short_loc}",
            )

            try:
                result = triage_finding(finding, model=model)
                results.append((finding, result))
            except (ConnectionError, TimeoutError, ValueError, RuntimeError) as exc:
                results.append((finding, exc))
                _print_warning(f"Failed on {short_loc}: {exc}")

            progress.advance(task_id)

    # ------------------------------------------------------------------
    # 3. Terminal report
    # ------------------------------------------------------------------
    print_summary_table(results)
    print_true_positive_details(results)

    # ------------------------------------------------------------------
    # 4. Optional Markdown report
    # ------------------------------------------------------------------
    if output is not None:
        try:
            generate_markdown_report(
                results,
                output,
                model=model,
                sarif_file=sarif_file,
            )
            _print_success(f"Markdown audit report written to: {output}")
        except OSError as exc:
            _print_error(f"Could not write report: {exc}")

    # ------------------------------------------------------------------
    # 5. Exit code
    # ------------------------------------------------------------------
    if has_true_positives(results):
        _print_error("One or more TRUE_POSITIVE findings remain – action required")
        raise typer.Exit(code=1)

    _print_success("No true positives remaining – clean triage")
    raise typer.Exit(code=0)


@app.command("check-health")
def check_health(
    model: str = typer.Option(
        DEFAULT_MODEL,
        "--model",
        "-m",
        help="Ollama model to verify availability.",
    ),
) -> None:
    """Check if the local Ollama server is reachable and the requested model is available."""
    _print_info(f"VulnWarden v{__version__}")
    _print_info(f"Checking Ollama server at {OLLAMA_BASE_URL}")
    _print_info(f"Requested model: {model}")

    try:
        with httpx.Client(timeout=5.0) as client:
            response = client.get(f"{OLLAMA_BASE_URL}/api/tags")
            response.raise_for_status()
            data = response.json()
    except httpx.ConnectError:
        _print_error(f"Cannot connect to Ollama at {OLLAMA_BASE_URL}")
        _print_error("Ensure Ollama is running (ollama serve)")
        raise typer.Exit(code=1)
    except httpx.TimeoutException:
        _print_error(f"Timeout while connecting to Ollama at {OLLAMA_BASE_URL}")
        raise typer.Exit(code=1)
    except httpx.HTTPStatusError as exc:
        _print_error(f"Ollama returned HTTP {exc.response.status_code}")
        raise typer.Exit(code=1)
    except Exception as exc:
        _print_error(f"Unexpected error while contacting Ollama: {exc}")
        raise typer.Exit(code=1)

    _print_success("Ollama server is reachable")

    models = data.get("models", [])
    model_names = [m.get("name", "") for m in models]

    available = False
    matched_name = None
    for name in model_names:
        if name == model or name.startswith(f"{model}:") or model.startswith(f"{name}:"):
            available = True
            matched_name = name
            break
        base = name.split(":")[0]
        if base == model.split(":")[0]:
            available = True
            matched_name = name
            break

    if available:
        _print_success(f"Model available: {matched_name}")
        console.print(
            Panel(
                f"Server: {OLLAMA_BASE_URL}\nModel: {matched_name}\nStatus: Ready",
                title="Health Check",
                border_style="green",
            )
        )
        raise typer.Exit(code=0)
    else:
        _print_error(f"Model '{model}' not found on the Ollama server")
        if model_names:
            _print_info("Available models:")
            for name in sorted(model_names):
                console.print(f"    - {name}")
        else:
            _print_warning("No models are currently installed")
        _print_info(f"Pull the model with: ollama pull {model}")
        raise typer.Exit(code=1)


@app.callback()
def main() -> None:
    """VulnWarden - Automated vulnerability triage powered by local LLM."""
    pass


if __name__ == "__main__":
    app()