"""SARIF 2.1.0 parser for vulnerability findings extraction."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, field_validator


class ContextLine(BaseModel):
    """A single line of source context with its number."""

    line_number: int = Field(..., ge=1, description="1-based line number in the source file")
    content: str = Field(..., description="Raw content of the line (without trailing newline)")


class SarifFinding(BaseModel):
    """Strict model representing a single vulnerability finding extracted from SARIF."""

    rule_id: str = Field(..., min_length=1, description="Rule identifier (ruleId)")
    message: str = Field(..., min_length=1, description="Human-readable error / finding message")
    file_path: str = Field(..., min_length=1, description="URI / path of the target file")
    start_line: int = Field(..., ge=1, description="1-based start line of the finding")
    context: list[ContextLine] = Field(
        default_factory=list,
        description="Source context window (up to 10 lines before and after)",
    )
    context_available: bool = Field(
        default=False,
        description="True if the source file was successfully read and context extracted",
    )

    @field_validator("rule_id", "message", "file_path")
    @classmethod
    def strip_and_reject_empty(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("Field cannot be empty or whitespace only")
        return cleaned


def _extract_message(result: dict[str, Any]) -> str:
    """Extract the primary message text from a SARIF result object."""
    message = result.get("message")
    if message is None:
        return "No message provided"

    if isinstance(message, str):
        return message.strip() or "No message provided"

    if isinstance(message, dict):
        text = message.get("text")
        if isinstance(text, str) and text.strip():
            return text.strip()
        # Fallback to markdown if present
        md = message.get("markdown")
        if isinstance(md, str) and md.strip():
            return md.strip()

    return "No message provided"


def _extract_location(result: dict[str, Any]) -> tuple[str, int]:
    """
    Extract file URI and startLine from the first physicalLocation.
    Returns (file_path, start_line). Falls back to sensible defaults.
    """
    locations = result.get("locations") or []
    if not locations:
        return ("unknown", 1)

    loc = locations[0]
    if not isinstance(loc, dict):
        return ("unknown", 1)

    physical = loc.get("physicalLocation") or {}
    if not isinstance(physical, dict):
        return ("unknown", 1)

    artifact = physical.get("artifactLocation") or {}
    uri = "unknown"
    if isinstance(artifact, dict):
        raw_uri = artifact.get("uri") or artifact.get("uriBaseId") or ""
        if isinstance(raw_uri, str) and raw_uri.strip():
            uri = raw_uri.strip()

    region = physical.get("region") or {}
    start_line = 1
    if isinstance(region, dict):
        sl = region.get("startLine")
        if isinstance(sl, int) and sl >= 1:
            start_line = sl
        elif isinstance(sl, str) and sl.isdigit():
            start_line = max(1, int(sl))

    return (uri, start_line)


def _extract_context(
    file_path: str,
    start_line: int,
    before: int = 10,
    after: int = 10,
) -> tuple[list[ContextLine], bool]:
    """
    Attempt to read the source file and return a context window.
    Returns (list of ContextLine, success_flag).
    """
    path = Path(file_path)

    # Handle common URI prefixes (file://, relative paths, etc.)
    if file_path.startswith("file://"):
        path = Path(file_path[7:])
    elif file_path.startswith("./") or not path.is_absolute():
        # Keep relative as-is; caller is expected to run from project root
        path = Path(file_path)

    if not path.is_file():
        return ([], False)

    try:
        # Read with universal newlines and preserve original content
        text = path.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()
    except OSError:
        return ([], False)

    total = len(lines)
    if total == 0:
        return ([], False)

    # Clamp the window
    start_idx = max(0, start_line - 1 - before)  # 0-based
    end_idx = min(total, start_line + after)     # exclusive

    context: list[ContextLine] = []
    for idx in range(start_idx, end_idx):
        context.append(
            ContextLine(
                line_number=idx + 1,
                content=lines[idx],
            )
        )

    return (context, True)


def parse_sarif(sarif_path: Path) -> list[SarifFinding]:
    """
    Parse a SARIF 2.1.0 file and return a list of SarifFinding.

    Compatible with outputs from SecretHound, Semgrep, Trivy and other
    SARIF producers that follow the 2.1.0 schema for results.
    """
    if not sarif_path.is_file():
        raise FileNotFoundError(f"SARIF file not found: {sarif_path}")

    try:
        raw = sarif_path.read_text(encoding="utf-8")
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in SARIF file: {exc}") from exc
    except OSError as exc:
        raise OSError(f"Cannot read SARIF file: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError("SARIF root must be a JSON object")

    runs = data.get("runs")
    if not isinstance(runs, list):
        raise ValueError("SARIF document must contain a 'runs' array")

    findings: list[SarifFinding] = []

    for run in runs:
        if not isinstance(run, dict):
            continue

        results = run.get("results") or []
        if not isinstance(results, list):
            continue

        for result in results:
            if not isinstance(result, dict):
                continue

            rule_id = result.get("ruleId") or result.get("rule", {}).get("id") or "unknown"
            if not isinstance(rule_id, str) or not rule_id.strip():
                rule_id = "unknown"

            message = _extract_message(result)
            file_path, start_line = _extract_location(result)

            context, available = _extract_context(file_path, start_line)

            try:
                finding = SarifFinding(
                    rule_id=rule_id,
                    message=message,
                    file_path=file_path,
                    start_line=start_line,
                    context=context,
                    context_available=available,
                )
                findings.append(finding)
            except Exception:
                # Skip malformed individual results rather than aborting the whole parse
                continue

    return findings