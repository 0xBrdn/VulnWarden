# VulnWarden

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg?style=flat-square)](https://www.python.org/downloads/)
[![Ollama](https://img.shields.io/badge/ollama-local%20LLM-green.svg?style=flat-square)](https://ollama.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)
[![SARIF 2.1.0](https://img.shields.io/badge/SARIF-2.1.0-orange.svg?style=flat-square)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)

CLI tool for automated vulnerability triage and remediation generation powered by a local LLM (Ollama).

VulnWarden consumes SARIF 2.1.0 reports (SecretHound, Semgrep, Trivy, CodeQL, …), extracts findings with surrounding source context, and asks a local model to decide whether each alert is a true positive or a false positive. For true positives it also proposes a concrete remediation patch.

Author: **0xBrdn**  
License: MIT

---

## Architecture

```
src/vulnwarden/
├── cli.py            # Typer entry-point (triage, check-health)
├── sarif_parser.py   # SARIF 2.1.0 parser (camelCase + snake_case)
├── ai_engine.py      # Ollama /api/chat client + TriageResult schema
└── reporter.py       # Rich progress / table / panels + Markdown report
```

Data flow:

1. `parse_sarif()` → list of `SarifFinding` (rule, message, path, line, ±10-line context)
2. `triage_finding()` → structured `TriageResult` via Ollama (`format: json`)
3. `reporter` renders terminal summary + optional PR-ready Markdown report

---

## Requirements

- Python 3.12+
- A running Ollama instance (`ollama serve`)
- At least one model pulled (default: `qwen2.5-coder:14b`)

```bash
ollama pull qwen2.5-coder:14b
```

---

## Installation

```bash
# From source (recommended while developing)
git clone https://github.com/0xBrdn/vulnwarden.git
cd vulnwarden
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

Or install the package only:

```bash
pip install .
```

---

## Usage

### Health check

```bash
vulnwarden check-health
vulnwarden check-health --model qwen2.5-coder:14b
```

### Triage a SARIF report

```bash
vulnwarden triage path/to/scan.sarif
vulnwarden triage path/to/scan.sarif --model qwen2.5-coder:14b
vulnwarden triage path/to/scan.sarif --output audit-report.md
```

### Typical pipeline with SecretHound

```bash
secrethound scan . --format sarif > scan.sarif
vulnwarden triage scan.sarif --output audit-report.md
```

The Markdown report is designed to be pasted directly into a GitHub / GitLab pull-request description.

---

## Exit codes

| Code | Meaning                                      |
|------|----------------------------------------------|
| 0    | No true positives (or empty SARIF)           |
| 1    | At least one `TRUE_POSITIVE` remains         |

This makes the tool suitable for CI gates:

```bash
vulnwarden triage scan.sarif --output report.md || exit 1
```

---

## Development

```bash
# Run the test suite
pytest -q

# With coverage
pytest --cov=vulnwarden --cov-report=term-missing
```

Tests cover:

- SARIF parsing for both camelCase (Semgrep/Trivy) and snake_case (SecretHound)
- Source context window extraction
- AI engine validation with mocked Ollama responses (`TRUE_POSITIVE` / `FALSE_POSITIVE`)

---

## Design notes

- **Zero external LLM dependency** – only a local Ollama server is required.
- **Structured outputs** – the model is forced to return JSON that is validated by a strict Pydantic model (`TriageResult`).
- **Dual SARIF dialect** – both the official camelCase schema and the snake_case variant emitted by SecretHound are accepted.
- **Sober terminal UI** – Rich progress bar, colour-coded table and syntax-highlighted remediation panels. No emojis.
- **PR-ready report** – the generated Markdown contains a summary table, detailed true-positive sections and a collapsible false-positive list.

---

## License

MIT – see [LICENSE](LICENSE).
