# VulnWarden

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg?style=flat-square)](https://www.python.org/downloads/)
[![Ollama](https://img.shields.io/badge/ollama-local%20LLM-green.svg?style=flat-square)](https://ollama.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)
[![SARIF 2.1.0](https://img.shields.io/badge/SARIF-2.1.0-orange.svg?style=flat-square)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)

CLI tool for automated vulnerability triage and remediation suggestions, powered by a local LLM (Ollama). No code leaves your machine.

VulnWarden consumes SARIF 2.1.0 reports (SecretHound, Semgrep, Trivy, CodeQL, ...), extracts each finding with its surrounding source context, and asks a local model to decide whether the alert is a true positive or a false positive. For true positives it also proposes a remediation patch.

It is meant to reduce alert fatigue, not to replace human review: see [Limitations](#limitations).

---

## Why a local model

Source code and detected credentials are sensitive data. Sending them to a third-party API is often not acceptable under company policy or data-protection rules (GDPR, Swiss nDSG). VulnWarden only talks to a local Ollama server, so the whole analysis stays on the machine or inside the internal network.

---

## Quick start

```bash
ollama pull qwen2.5-coder:14b

secrethound scan . --format sarif > scan.sarif
vulnwarden triage scan.sarif --output audit-report.md
```

A sample of the generated report is available in [`examples/sample-report.md`](examples/sample-report.md).

---

## Evaluation

The triage engine is evaluated with `benchmarks/run_benchmark.py` against `benchmarks/dataset.json`: 20 hand-labelled findings.

- **10 true positives**: cloud credentials, private key, database URI with password, tokens, signing secret, webhook.
- **10 false positives**: documentation examples, mocked test keys, content hashes, `.env.example` placeholders, commented-out and revoked credentials, and comments containing instruction-like text.

```bash
python benchmarks/run_benchmark.py
python benchmarks/run_benchmark.py --model qwen2.5-coder:14b --timeout 120
```

Results with `qwen2.5-coder:14b`, run locally on a MacBook Pro:

| Metric | Value |
|--------|-------|
| Accuracy | 0.900 (18/20) |
| Precision | 0.833 |
| Recall | 1.000 |
| F1-score | 0.909 |
| Average latency | 4.50 s per finding (min 3.56 s, max 9.81 s) |

| | Predicted true positive | Predicted false positive |
|---|---|---|
| **Actually true positive** | 10 | 0 |
| **Actually false positive** | 2 | 8 |

No real secret was missed. Both errors are false alarms: a placeholder database URI in `.env.example` and a test-only JWT secret in `conftest.py`. For a security gate this is the safer failure mode, at the cost of some extra manual review.

**How to read these numbers.** The dataset is small and was labelled by the author, so the results describe the behaviour of the tool on representative cases and are not a general accuracy claim. Results come from a single run of a non-deterministic model.

The benchmark exits with a non-zero code if a true positive is missed, an injection case fails, or a request errors out, so it can be used as a regression check when changing the prompt or the model.

---

## Limitations

- **Review is still required.** A verdict comes from a language model and can be wrong. Treat it as a prioritisation aid, not as a decision.
- **Remediation patches are suggestions.** They can be incomplete or not match the project's conventions (for example, an environment-variable lookup with a hardcoded fallback value still leaves a secret in the code). A leaked credential must always be rotated, whatever patch is applied.
- **Prompt injection.** The analysed source code is part of the prompt, so a malicious comment can try to steer the verdict. The prompt and the strict JSON schema reduce this risk but do not remove it. The current dataset contains two instruction-like comments, but in both cases the correct verdict is the one the injected text asks for, so they do not yet prove resistance. Cases where the injection pushes towards the wrong verdict are the next addition to the benchmark.
- **Non-determinism.** The same finding can receive different verdicts across runs and across models.
- **Context window.** Only about 10 lines around the finding are sent. Risk that depends on code elsewhere in the project is not visible to the model.
- **Scope.** Designed and tested on secret-detection findings. Other SARIF rule types (SAST, dependency or container findings) are parsed but not yet part of the benchmark.

---

## Architecture

```
src/vulnwarden/
├── cli.py            # Typer entry-point (triage, check-health)
├── sarif_parser.py   # SARIF 2.1.0 parser (camelCase + snake_case)
├── ai_engine.py      # Ollama /api/chat client + TriageResult schema
└── reporter.py       # Rich progress / table / panels + Markdown report
benchmarks/
├── dataset.json      # 20 hand-labelled findings
└── run_benchmark.py  # Confusion matrix, latency, injection cases
examples/
└── sample-report.md  # Example of a generated report
```

Data flow:

1. `parse_sarif()` returns a list of `SarifFinding` (rule, message, path, line, +/-10-line context)
2. `triage_finding()` returns a structured `TriageResult` via Ollama (`format: json`)
3. `reporter` renders the terminal summary and an optional PR-ready Markdown report

---

## Requirements

- Python 3.12+
- A running Ollama instance (`ollama serve`)
- At least one model pulled (default: `qwen2.5-coder:14b`)

---

## Installation

```bash
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

The Markdown report contains a summary table, detailed true-positive sections with reasoning and a proposed patch, and a collapsible list of dismissed false positives. It is designed to be pasted into a GitHub or GitLab pull-request description.

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

# Run the triage benchmark (requires a running Ollama instance)
python benchmarks/run_benchmark.py
```

Tests cover:

- SARIF parsing for both camelCase (Semgrep/Trivy) and snake_case (SecretHound)
- Source context window extraction
- AI engine validation with mocked Ollama responses (`TRUE_POSITIVE` / `FALSE_POSITIVE`)

---

## Design notes

- **No external LLM dependency**: only a local Ollama server is required.
- **Structured outputs**: the model is forced to return JSON that is validated by a strict Pydantic model (`TriageResult`).
- **Dual SARIF dialect**: both the official camelCase schema and the snake_case variant emitted by SecretHound are accepted.
- **Sober terminal UI**: Rich progress bar, colour-coded table and syntax-highlighted remediation panels.
- **Safe reporting**: secrets are obfuscated in the original message shown in reports.

---

## License

MIT, see [LICENSE](LICENSE).
