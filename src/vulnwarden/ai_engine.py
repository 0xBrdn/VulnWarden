"""AI triage engine powered by local Ollama (structured JSON outputs)."""

from __future__ import annotations

import json
from typing import Any, Literal, Optional

import httpx
from pydantic import BaseModel, Field, field_validator

from vulnwarden.sarif_parser import SarifFinding

OLLAMA_CHAT_URL = "http://localhost:11434/api/chat"
DEFAULT_TIMEOUT = 120.0  # seconds – large models can be slow


class TriageResult(BaseModel):
    """Structured result returned by the LLM for a single finding."""

    verdict: Literal["TRUE_POSITIVE", "FALSE_POSITIVE"] = Field(
        ...,
        description="Whether the finding is a real vulnerability or a false positive",
    )
    confidence: int = Field(
        ...,
        ge=0,
        le=100,
        description="Confidence score from 0 to 100",
    )
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] = Field(
        ...,
        description="Assessed severity of the finding",
    )
    reasoning: str = Field(
        ...,
        min_length=10,
        max_length=800,
        description="Concise technical explanation (2-3 sentences max)",
    )
    remediation_patch: Optional[str] = Field(
        None,
        description="Proposed code fix when verdict is TRUE_POSITIVE, otherwise null",
    )

    @field_validator("reasoning")
    @classmethod
    def clean_reasoning(cls, v: str) -> str:
        cleaned = " ".join(v.strip().split())
        if len(cleaned) < 10:
            raise ValueError("reasoning must be a meaningful technical explanation")
        return cleaned


def _build_context_block(finding: SarifFinding) -> str:
    """Format the source context window for the prompt."""
    if not finding.context_available or not finding.context:
        return "(Source context unavailable – file could not be read)"

    lines: list[str] = []
    for ctx in finding.context:
        marker = ">>>" if ctx.line_number == finding.start_line else "   "
        lines.append(f"{marker} {ctx.line_number:4d} | {ctx.content}")
    return "\n".join(lines)


def _build_messages(finding: SarifFinding) -> list[dict[str, str]]:
    """Construct the system + user messages for the triage request."""
    system_prompt = """You are a senior Application Security (AppSec) engineer performing automated vulnerability triage.
Your task is to analyse a static-analysis finding and decide whether it is a TRUE_POSITIVE or a FALSE_POSITIVE.

Rules you MUST follow:
1. Output ONLY valid JSON that matches the required schema. No markdown, no extra text.
2. Be concise: reasoning must be 2-3 short technical sentences maximum.
3. Common false-positive patterns: test keys, mock data, example files, documentation, generated code, commented-out secrets, non-production configuration.
4. If the finding is a TRUE_POSITIVE, provide a concrete remediation_patch (the corrected code snippet). If FALSE_POSITIVE, set remediation_patch to null.
5. Severity must reflect real-world exploitability and impact, not just the original tool rating.
6. Confidence must honestly reflect how certain you are given the available context.
"""

    context_block = _build_context_block(finding)

    user_prompt = f"""Analyse the following security finding:

Rule ID     : {finding.rule_id}
File        : {finding.file_path}
Line        : {finding.start_line}
Message     : {finding.message}

Source context (>>> marks the reported line): {context_block}

Respond with a single JSON object containing exactly these keys:
- verdict: "TRUE_POSITIVE" or "FALSE_POSITIVE"
- confidence: integer 0-100
- severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
- reasoning: short technical justification
- remediation_patch: string with the fixed code, or null
"""

    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]


def _get_json_schema() -> dict[str, Any]:
    """Return the JSON schema used by Ollama structured outputs."""
    schema = TriageResult.model_json_schema()
    # Ollama expects a clean schema; remove Pydantic-specific metadata if needed
    return schema


def triage_finding(
    finding: SarifFinding,
    model: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    base_url: str = OLLAMA_CHAT_URL,
) -> TriageResult:
    """
    Send a single SarifFinding to the local Ollama instance and return a validated TriageResult.

    Raises:
        ConnectionError: when Ollama is unreachable.
        TimeoutError: when the request exceeds the configured timeout.
        ValueError: when the response cannot be parsed or fails validation.
        RuntimeError: for unexpected HTTP errors.
    """
    messages = _build_messages(finding)
    payload = {
        "model": model,
        "messages": messages,
        "stream": False,
        "format": "json",  # request structured JSON output
        "options": {
            "temperature": 0.1,  # low temperature for deterministic triage
        },
    }

    try:
        with httpx.Client(timeout=timeout) as client:
            response = client.post(base_url, json=payload)
            response.raise_for_status()
            data = response.json()
    except httpx.ConnectError as exc:
        raise ConnectionError(
            f"Cannot connect to Ollama at {base_url}. Is the server running?"
        ) from exc
    except httpx.TimeoutException as exc:
        raise TimeoutError(
            f"Ollama request timed out after {timeout}s (model={model})"
        ) from exc
    except httpx.HTTPStatusError as exc:
        raise RuntimeError(
            f"Ollama returned HTTP {exc.response.status_code}: {exc.response.text[:200]}"
        ) from exc
    except Exception as exc:
        raise RuntimeError(f"Unexpected error while calling Ollama: {exc}") from exc

    # Extract the assistant message content
    try:
        content = data["message"]["content"]
    except (KeyError, TypeError) as exc:
        raise ValueError(
            f"Unexpected Ollama response structure: {json.dumps(data)[:300]}"
        ) from exc

    if not isinstance(content, str) or not content.strip():
        raise ValueError("Ollama returned an empty message content")

    # Parse JSON
    try:
        raw_result = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Ollama did not return valid JSON. Raw content: {content[:400]}"
        ) from exc

    # Validate against the strict Pydantic model
    try:
        result = TriageResult.model_validate(raw_result)
    except Exception as exc:
        raise ValueError(
            f"Ollama JSON failed schema validation: {exc}. Raw: {raw_result}"
        ) from exc

    # Extra business rule: remediation_patch must be null on FALSE_POSITIVE
    if result.verdict == "FALSE_POSITIVE" and result.remediation_patch is not None:
        # Soft correction rather than hard failure
        result = result.model_copy(update={"remediation_patch": None})

    return result


def triage_findings(
    findings: list[SarifFinding],
    model: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
) -> list[tuple[SarifFinding, TriageResult | Exception]]:
    """
    Triage a list of findings sequentially.
    Returns a list of (finding, result_or_exception) pairs so the caller
    can decide how to handle partial failures.
    """
    results: list[tuple[SarifFinding, TriageResult | Exception]] = []
    for finding in findings:
        try:
            result = triage_finding(finding, model=model, timeout=timeout)
            results.append((finding, result))
        except Exception as exc:
            results.append((finding, exc))
    return results