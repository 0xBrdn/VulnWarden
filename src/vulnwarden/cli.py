"""VulnWarden CLI entry point."""

from pathlib import Path
from typing import Optional

import httpx
import typer
from rich.console import Console
from rich.panel import Panel

from vulnwarden import __version__

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
        help="Optional path to write the triage report (JSON or Markdown).",
    ),
) -> None:
    """Triage vulnerabilities from a SARIF report using a local LLM."""
    _print_info(f"VulnWarden v{__version__}")
    _print_info(f"Loading SARIF file: {sarif_file}")
    _print_info(f"Using model: {model}")

    if output:
        _print_info(f"Output will be written to: {output}")

    # Placeholder for future implementation
    _print_warning("Triage engine not yet implemented. Coming in next steps.")
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
            # Check server reachability
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

    # Ollama model names can be exact or with :latest
    available = False
    matched_name = None
    for name in model_names:
        if name == model or name.startswith(f"{model}:") or model.startswith(f"{name}:"):
            available = True
            matched_name = name
            break
        # Also match without tag
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