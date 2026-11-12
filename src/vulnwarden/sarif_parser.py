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


def _safe_get(d: Any, *keys: str, default: Any = None) -> Any:
    """Safely traverse nested dicts without raising."""
    cur = d
    for key in keys:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(key, default)
        if cur is default:
            return default
    return cur


def _extract_location(result: dict[str, Any]) -> tuple[str, int]:
    """
    Extract file URI and startLine from the first physicalLocation.

    Follows the SARIF 2.1.0 standard path used by SecretHound, Semgrep, Trivy:
      result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
      result["locations"][0]["physicalLocation"]["region"]["startLine"]

    Returns (file_path, start_line). Falls back to ("unknown", 1).
    """
    locations = result.get("locations")
    if not isinstance(locations, list) or not locations:
        return ("unknown", 1)

    loc = locations[0]
    if not isinstance(loc, dict):
        return ("unknown", 1)

    # Standard path
    physical = loc.get("physicalLocation")
    if not isinstance(physical, dict):
        # Some producers put artifactLocation directly under the location object
        physical = loc

    artifact = physical.get("artifactLocation") if isinstance(physical, dict) else None
    uri = "unknown"
    if isinstance(artifact, dict):
        raw_uri = artifact.get("uri")
        if isinstance(raw_uri, str) and raw_uri.strip():
            uri = raw_uri.strip()
        else:
            # Fallback sometimes seen
            raw_uri = artifact.get("uriBaseId")
            if isinstance(raw_uri, str) and raw_uri.strip():
                uri = raw_uri.strip()

    # Also try the very common alternative where uri lives one level higher
    if uri == "unknown":
        alt = _safe_get(loc, "physicalLocation", "address", "uri")
        if isinstance(alt, str) and alt.strip():
            uri = alt.strip()

    region = physical.get("region") if isinstance(physical, dict) else None
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
    if not file_path or file_path == "unknown":
        return ([], False)

    # Normalize common URI forms produced by SecretHound / Semgrep / etc.
    cleaned = file_path.strip()
    if cleaned.startswith("file://"):
        cleaned = cleaned[7:]          # strip scheme
        if cleaned.startswith("//"):
            cleaned = cleaned[1:]      # file://// -> rare, normalize lightly

    path = Path(cleaned)

    # Relative paths are resolved against the current working directory
    if not path.is_file() and not path.is_absolute():
        path = Path.cwd() / cleaned

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

            # Prefer the standard SARIF field used by SecretHound / Semgrep / Trivy
            rule_id = result.get("ruleId")
            if not isinstance(rule_id, str) or not rule_id.strip():
                # Fallback: some tools nest it under "rule"
                rule_obj = result.get("rule")
                if isinstance(rule_obj, dict):
                    rule_id = rule_obj.get("id")
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