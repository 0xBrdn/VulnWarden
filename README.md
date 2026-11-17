<h1 align="center">VulnWarden</h1>

<p align="center">
  <b>Triage SARIF findings with a local LLM, fully offline</b><br>
  a CLI that separates true positives from false positives and proposes remediation patches, with no code leaving your machine.
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-F5C518?style=for-the-badge" alt="License MIT"></a>
  <img src="https://img.shields.io/badge/Python-3.12+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.12+">
  <img src="https://img.shields.io/badge/Ollama-Local_LLM-2E7D32?style=for-the-badge" alt="Ollama local LLM">
  <img src="https://img.shields.io/badge/Input-SARIF_2.1.0-E65100?style=for-the-badge" alt="SARIF 2.1.0 input">
  <img src="https://img.shields.io/badge/Mode-Fully_offline-0D47A1?style=for-the-badge" alt="Fully offline">
  <img src="https://img.shields.io/badge/Model-qwen2.5--coder:14b-555555?style=for-the-badge" alt="Default model qwen2.5-coder:14b">
</p>

<p align="center">
  <a href="#quickstart">Quickstart</a> ·
  <a href="#features">Features</a> ·
  <a href="#evaluation">Evaluation</a> ·
  <a href="#limitations">Limitations</a> ·
  <a href="#responsible-use">Responsible use</a> ·
  <a href="#license">License</a>
</p>

VulnWarden consumes SARIF 2.1.0 reports (SecretHound, Semgrep, Trivy, CodeQL, ...), extracts each finding
with its surrounding source context, and asks a local model to decide whether the alert is a true positive
or a false positive. For true positives it also proposes a remediation patch. It only talks to a local
Ollama server and it never sends anything over the network to a third party.

It is meant to reduce alert fatigue, not to replace human review: read the [limitations](#limitations)
before relying on a verdict.

New here? Run `ollama pull qwen2.5-coder:14b`, then `vulnwarden triage scan.sarif --output audit-report.md`
on any SARIF file.

## Why it exists

Scanners are noisy. Documentation examples, mocked test keys and `.env.example` placeholders all look like
secrets to a regex, and teams end up ignoring the whole report. Source code and detected credentials are
also sensitive data: sending them to a third-party API is often not acceptable under company policy or
data-protection rules (GDPR, Swiss nDSG). VulnWarden keeps the whole analysis on the machine or inside the
internal network.

## Features

### Local-only triage

Every finding goes to a local Ollama instance through the `/api/chat` endpoint. There is no external LLM
dependency and nothing leaves the machine.

### Context-aware verdicts

Each finding is parsed with its rule, message, path, line and about 10 lines of surrounding source, then
the model returns a verdict: `TRUE_POSITIVE` or `FALSE_POSITIVE`, with its reasoning.

### Structured, validated output

The model is forced to answer in JSON (`format: json`), and the answer is validated by a strict Pydantic
model (`TriageResult`). A malformed answer is rejected instead of silently trusted.

### Remediation suggestions

For true positives, VulnWarden proposes a patch. Patches are suggestions, see the
[limitations](#limitations): a leaked credential must always be rotated.

### PR-ready Markdown report

The report contains a summary table, detailed true-positive sections with reasoning and a proposed patch,
and a collapsible list of dismissed false positives. It is designed to be pasted into a GitHub or GitLab
pull-request description. Secrets are obfuscated in the original message shown in reports.

### Two SARIF dialects

Both the official camelCase schema (Semgrep, Trivy) and the snake_case variant emitted by SecretHound are
accepted.

### CI gate

The exit code is 1 when at least one `TRUE_POSITIVE` remains, so the tool can block a pipeline.

| Code | Meaning |
| :--- | :--- |
| 0 | No true positives (or empty SARIF) |
| 1 | At least one `TRUE_POSITIVE` remains |

```sh
vulnwarden triage scan.sarif --output report.md || exit 1
```

## System architecture

```text
+-----------------------------------+
|        SARIF 2.1.0 report         |
|  [ SecretHound | Semgrep |        |
|    Trivy | CodeQL | ... ]         |
+-----------------+-----------------+
                  | scan.sarif
                  v
+-----------------------------------+
|         sarif_parser.py           |
|  - camelCase + snake_case         |
|  - rule, message, path, line      |
|  - +/- 10-line source context     |
+-----------------+-----------------+
                  | list[SarifFinding]
                  v
+-----------------------------------+
|           ai_engine.py            |
|  - Ollama /api/chat (format: json)|
|  - strict TriageResult schema     |
+-----------------+-----------------+
                  | TRUE_POSITIVE / FALSE_POSITIVE + patch
                  v
+-----------------------------------+
|           reporter.py             |
|  - Rich progress, table, panels   |
|  - PR-ready Markdown report       |
|  - exit code 0 / 1                |
+-----------------------------------+
```

Data flow:

1. `parse_sarif()` returns a list of `SarifFinding` (rule, message, path, line, +/-10-line context).
2. `triage_finding()` returns a structured `TriageResult` via Ollama (`format: json`).
3. `reporter` renders the terminal summary and an optional PR-ready Markdown report.

## Quickstart

### Prerequisites

- Python 3.12+
- A running Ollama instance (`ollama serve`)
- At least one model pulled (default: `qwen2.5-coder:14b`)

### Install

```sh
git clone https://github.com/0xBrdn/vulnwarden.git
cd vulnwarden
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

Or install the package only:

```sh
pip install .
```

### Run a triage

```sh
ollama pull qwen2.5-coder:14b

secrethound scan . --format sarif > scan.sarif
vulnwarden triage scan.sarif --output audit-report.md
```

A sample of the generated report is available in [`examples/sample-report.md`](examples/sample-report.md).

### Health check

```sh
vulnwarden check-health
vulnwarden check-health --model qwen2.5-coder:14b
```

### Triage options

```sh
vulnwarden triage path/to/scan.sarif
vulnwarden triage path/to/scan.sarif --model qwen2.5-coder:14b
vulnwarden triage path/to/scan.sarif --output audit-report.md
```

### Tests

```sh
pytest -q                                          # test suite
pytest --cov=vulnwarden --cov-report=term-missing  # with coverage
python benchmarks/run_benchmark.py                 # triage benchmark (needs Ollama)
```

Tests cover:

- SARIF parsing for both camelCase (Semgrep/Trivy) and snake_case (SecretHound)
- Source context window extraction
- AI engine validation with mocked Ollama responses (`TRUE_POSITIVE` / `FALSE_POSITIVE`)

## Evaluation

The triage engine is evaluated with `benchmarks/run_benchmark.py` against `benchmarks/dataset.json`:
20 hand-labelled findings.

- **10 true positives**: cloud credentials, private key, database URI with password, tokens, signing
  secret, webhook.
- **10 false positives**: documentation examples, mocked test keys, content hashes, `.env.example`
  placeholders, commented-out and revoked credentials, and comments containing instruction-like text.

```sh
python benchmarks/run_benchmark.py
python benchmarks/run_benchmark.py --model qwen2.5-coder:14b --timeout 120
```

Results with `qwen2.5-coder:14b`, run locally on a MacBook Pro:

| Metric | Value |
| :--- | :--- |
| Accuracy | 0.900 (18/20) |
| Precision | 0.833 |
| Recall | 1.000 |
| F1-score | 0.909 |
| Average latency | 4.50 s per finding (min 3.56 s, max 9.81 s) |

| | Predicted true positive | Predicted false positive |
| :--- | :--- | :--- |
| **Actually true positive** | 10 | 0 |
| **Actually false positive** | 2 | 8 |

No real secret was missed. Both errors are false alarms: a placeholder database URI in `.env.example` and a
test-only JWT secret in `conftest.py`. For a security gate this is the safer failure mode, at the cost of
some extra manual review.

**How to read these numbers.** The dataset is small and was labelled by the author, so the results describe
the behaviour of the tool on representative cases and are not a general accuracy claim. Results come from a
single run of a non-deterministic model.

The benchmark exits with a non-zero code if a true positive is missed, an injection case fails, or a
request errors out, so it can be used as a regression check when changing the prompt or the model.

## Limitations

- **Review is still required.** A verdict comes from a language model and can be wrong. Treat it as a
  prioritisation aid, not as a decision.
- **Remediation patches are suggestions.** They can be incomplete or not match the project's conventions
  (for example, an environment-variable lookup with a hardcoded fallback value still leaves a secret in the
  code). A leaked credential must always be rotated, whatever patch is applied.
- **Prompt injection.** The analysed source code is part of the prompt, so a malicious comment can try to
  steer the verdict. The prompt and the strict JSON schema reduce this risk but do not remove it. The
  current dataset contains two instruction-like comments, but in both cases the correct verdict is the one
  the injected text asks for, so they do not yet prove resistance. Cases where the injection pushes towards
  the wrong verdict are the next addition to the benchmark.
- **Non-determinism.** The same finding can receive different verdicts across runs and across models.
- **Context window.** Only about 10 lines around the finding are sent. Risk that depends on code elsewhere
  in the project is not visible to the model.
- **Scope.** Designed and tested on secret-detection findings. Other SARIF rule types (SAST, dependency or
  container findings) are parsed but not yet part of the benchmark.

## Responsible use

This section is a plain-language summary and **not legal advice**.

**You may**

- Triage reports from code that you own, or on which you hold the authorization of the owner.
- Use it as a CI gate and as a first-pass filter before human review.
- Read, modify and redistribute the source code under the terms of the MIT license.

**You must not**

- Dismiss a finding on the sole basis of a `FALSE_POSITIVE` verdict for a credential you have not checked.
- Point it at a remote, third-party Ollama endpoint with sensitive code: the privacy guarantee only holds
  if the Ollama server is local or inside your internal network.
- Share generated reports publicly without checking them: they can still contain sensitive context from
  your source code.

## Repository layout

| Path | Contents |
| :--- | :--- |
| `src/vulnwarden/cli.py` | Typer entry-point (`triage`, `check-health`) |
| `src/vulnwarden/sarif_parser.py` | SARIF 2.1.0 parser (camelCase and snake_case) |
| `src/vulnwarden/ai_engine.py` | Ollama `/api/chat` client and `TriageResult` schema |
| `src/vulnwarden/reporter.py` | Rich progress, table and panels, Markdown report |
| `benchmarks/` | `dataset.json` (20 labelled findings) and `run_benchmark.py` |
| `examples/` | `sample-report.md`, an example of a generated report |

## Design notes

- **No external LLM dependency**: only a local Ollama server is required.
- **Structured outputs**: the model is forced to return JSON validated by a strict Pydantic model.
- **Dual SARIF dialect**: the official camelCase schema and SecretHound's snake_case variant are both accepted.
- **Sober terminal UI**: Rich progress bar, colour-coded table and syntax-highlighted remediation panels.
- **Safe reporting**: secrets are obfuscated in the original message shown in reports.

## License

VulnWarden is free software under the [MIT License](LICENSE).
