#!/usr/bin/env python3
"""
Standalone benchmark for VulnWarden triage_finding.

Loads the hand-labelled dataset, calls the local Ollama model
(qwen2.5-coder:14b by default), measures average latency and prints
a confusion-matrix style report including prompt-injection resistance.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

# Allow running from the repo root or from benchmarks/
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT / "src"))

from vulnwarden.ai_engine import TriageResult, triage_finding
from vulnwarden.sarif_parser import ContextLine, SarifFinding

DATASET_PATH = Path(__file__).resolve().parent / "dataset.json"
DEFAULT_MODEL = "qwen2.5-coder:14b"
PROMPT_INJECTION_IDS = {
    "fp_prompt_injection_comment",
    "fp_prompt_injection_aggressive",
}


def load_dataset(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, list) or len(data) == 0:
        raise ValueError(f"Dataset at {path} is empty or not a list")
    return data


def case_to_finding(case: dict) -> SarifFinding:
    context = [
        ContextLine(line_number=c["line_number"], content=c["content"])
        for c in case.get("context", [])
    ]
    return SarifFinding(
        rule_id=case["rule_id"],
        message=case["message"],
        file_path=case["file_path"],
        start_line=case["start_line"],
        context=context,
        context_available=bool(context),
    )


def run_benchmark(model: str = DEFAULT_MODEL, timeout: float = 120.0) -> None:
    cases = load_dataset(DATASET_PATH)
    print(f"Loaded {len(cases)} labelled cases from {DATASET_PATH.name}")
    print(f"Model          : {model}")
    print(f"Ollama endpoint: http://localhost:11434/api/chat")
    print("-" * 72)

    # Counters for the classic 2x2 confusion matrix
    tp = fp = tn = fn = 0
    latencies: list[float] = []
    injection_results: list[tuple[str, str, str]] = []  # id, expected, predicted
    errors: list[tuple[str, str]] = []

    for i, case in enumerate(cases, start=1):
        case_id = case["id"]
        expected = case["expected_verdict"]
        finding = case_to_finding(case)

        print(f"[{i:02d}/{len(cases)}] {case_id:<35} ", end="", flush=True)
        t0 = time.perf_counter()
        try:
            result: TriageResult = triage_finding(
                finding, model=model, timeout=timeout
            )
            elapsed = time.perf_counter() - t0
            latencies.append(elapsed)
            predicted = result.verdict

            # Confusion matrix update
            if expected == "TRUE_POSITIVE" and predicted == "TRUE_POSITIVE":
                tp += 1
                mark = "TP"
            elif expected == "FALSE_POSITIVE" and predicted == "FALSE_POSITIVE":
                tn += 1
                mark = "TN"
            elif expected == "FALSE_POSITIVE" and predicted == "TRUE_POSITIVE":
                fp += 1
                mark = "FP"
            else:  # expected TRUE_POSITIVE, predicted FALSE_POSITIVE
                fn += 1
                mark = "FN"

            print(
                f"{mark}  pred={predicted:<15} conf={result.confidence:3d}  "
                f"{elapsed:6.2f}s"
            )

            if case_id in PROMPT_INJECTION_IDS:
                injection_results.append((case_id, expected, predicted))

        except Exception as exc:
            elapsed = time.perf_counter() - t0
            latencies.append(elapsed)
            errors.append((case_id, str(exc)))
            print(f"ERR  {type(exc).__name__}: {exc}  ({elapsed:.2f}s)")

    # ------------------------------------------------------------------
    # Summary metrics
    # ------------------------------------------------------------------
    total = tp + tn + fp + fn
    accuracy = (tp + tn) / total if total else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall)
        else 0.0
    )
    avg_latency = sum(latencies) / len(latencies) if latencies else 0.0

    print()
    print("=" * 72)
    print("CONFUSION MATRIX / METRICS")
    print("=" * 72)
    print(f"  True  Positives (TP) : {tp:3d}")
    print(f"  True  Negatives (TN) : {tn:3d}")
    print(f"  False Positives (FP) : {fp:3d}")
    print(f"  False Negatives (FN) : {fn:3d}")
    print()
    print(f"  Accuracy  : {accuracy:.3f}  ({tp + tn}/{total})")
    print(f"  Precision : {precision:.3f}  (TP / (TP+FP))")
    print(f"  Recall    : {recall:.3f}  (TP / (TP+FN))")
    print(f"  F1-score  : {f1:.3f}")
    print()
    print(f"  Average latency : {avg_latency:.2f} s  (n={len(latencies)})")
    if latencies:
        print(f"  Min / Max       : {min(latencies):.2f} s / {max(latencies):.2f} s")

    # ------------------------------------------------------------------
    # Prompt-injection resistance
    # ------------------------------------------------------------------
    print()
    print("=" * 72)
    print("PROMPT-INJECTION RESISTANCE")
    print("=" * 72)
    if not injection_results:
        print("  (no dedicated prompt-injection cases in the dataset)")
    else:
        for case_id, expected, predicted in injection_results:
            status = "RESISTED" if predicted == expected else "FAILED"
            print(f"  {case_id:<40} expected={expected}  got={predicted}  → {status}")
        resisted = sum(1 for _, e, p in injection_results if e == p)
        print(
            f"\n  Resisted {resisted}/{len(injection_results)} injection attempts"
        )

    if errors:
        print()
        print("=" * 72)
        print("ERRORS")
        print("=" * 72)
        for case_id, msg in errors:
            print(f"  {case_id}: {msg}")

    print()
    # Non-zero exit if any true positive was missed or any injection succeeded
    failed_injections = sum(
        1 for _, e, p in injection_results if e != p
    )
    if fn > 0 or failed_injections > 0 or errors:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Run VulnWarden triage benchmark against the hand-labelled dataset"
    )
    parser.add_argument(
        "--model",
        default=DEFAULT_MODEL,
        help=f"Ollama model name (default: {DEFAULT_MODEL})",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=120.0,
        help="Per-request timeout in seconds (default: 120)",
    )
    args = parser.parse_args()
    run_benchmark(model=args.model, timeout=args.timeout)