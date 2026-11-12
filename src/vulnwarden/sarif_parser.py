"""SARIF 2.1.0 parser for vulnerability findings extraction.

Supports both standard camelCase (Semgrep, Trivy, etc.) and
snake_case (SecretHound) field names.
"""

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

    rule_id: str = Field(..., min_length=1, description="Rule identifier (ruleId / rule_id)")
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


def _get(d: dict[str, Any], *candidates: str, default: Any = None) -> Any:
    """
    Return the first present key among the candidates (supports camelCase + snake_case).
    """
    for key in candidates:
        if key in d and d[key] is not None:
            return d[key]
    return default


def _extract_message(result: dict[str, Any]) -> str:
    """Extract the primary message text from a SARIF result object."""
    message = _get(result, "message")
    if message is None:
        return "No message provided"

    if isinstance(message, str):
        return message.strip() or "No message provided"

    if isinstance(message, dict):
        text = _get(message, "text")
        if isinstance(text, str) and text.strip():
            return text.strip()
        md = _get(message, "markdown")
        if isinstance(md, str) and md.strip():
            return md.strip()

    return "No message provided"


def _extract_location(result: dict[str, Any]) -> tuple[str, int]:
    """
    Extract file URI and startLine.

    Accepts both conventions:
      - Standard SARIF 2.1.0 (camelCase):
          locations[0].physicalLocation.artifactLocation.uri
          locations[0].physicalLocation.region.startLine
      - SecretHound (snake_case):
          locations[0].physical_location.artifact_location.uri
          locations[0].physical_location.region.start_line

    Returns (file_path, start_line). Falls back to ("unknown", 1) when keys are missing.
    """
    try:
        locations = _get(result, "locations")
        if not isinstance(locations, list) or len(locations) == 0:
            return ("unknown", 1)

        loc = locations[0]
        if not isinstance(loc, dict):
            return ("unknown", 1)

        physical = _get(loc, "physicalLocation", "physical_location")
        if not isinstance(physical, dict):
            return ("unknown", 1)

        artifact = _get(physical, "artifactLocation", "artifact_location")
        if not isinstance(artifact, dict):
            return ("unknown", 1)

        uri = _get(artifact, "uri")
        if not isinstance(uri, str) or not uri.strip():
            return ("unknown", 1)

        region = _get(physical, "region")
        start_line = 1
        if isinstance(region, dict):
            sl = _get(region, "startLine", "start_line")
            if isinstance(sl, int) and sl >= 1:
                start_line = sl
            elif isinstance(sl, str) and sl.isdigit():
                start_line = max(1, int(sl))

        return (uri.strip(), start_line)

    except (KeyError, TypeError, IndexError, AttributeError):
        return ("unknown", 1)


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
    if not file_path or file_path == "unknown":
        return ([], False)

    cleaned = file_path.strip()

    # Strip file:// scheme if present
    if cleaned.startswith("file://"):
        cleaned = cleaned[7:]

    path = Path(cleaned)

    # Resolve relative paths against the current working directory
    if not path.is_absolute():
        path = Path.cwd() / path

    if not path.is_file():
        return ([], False)

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()
    except OSError:
        return ([], False)

    total = len(lines)
    if total == 0:
        return ([], False)

    start_idx = max(0, start_line - 1 - before)
    end_idx = min(total, start_line + after)

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

    Compatible with:
    - Standard camelCase producers (Semgrep, Trivy, CodeQL, ...)
    - snake_case producers (SecretHound)
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

        results = run.get("results")
        if not isinstance(results, list):
            continue

        for result in results:
            if not isinstance(result, dict):
                continue

            # Accept both ruleId (standard) and rule_id (SecretHound)
            rule_id = _get(result, "ruleId", "rule_id")
            if not isinstance(rule_id, str) or not rule_id.strip():
                # Last-chance fallback for nested rule object
                rule_obj = _get(result, "rule")
                if isinstance(rule_obj, dict):
                    rule_id = _get(rule_obj, "id")
                elif isinstance(rule_obj, str):
                    rule_id = rule_obj
                else:
                    rule_id = None

            if not isinstance(rule_id, str) or not rule_id.strip():
                rule_id = "unknown"
            else:
                rule_id = rule_id.strip()

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