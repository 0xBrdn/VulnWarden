"""Tests for VulnWarden SARIF parsing, context extraction and AI triage engine."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from vulnwarden.ai_engine import TriageResult, triage_finding
from vulnwarden.sarif_parser import SarifFinding, parse_sarif


# ---------------------------------------------------------------------------
# Fixtures & sample data
# ---------------------------------------------------------------------------

CAMEL_CASE_SARIF = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {"driver": {"name": "semgrep"}},
            "results": [
                {
                    "ruleId": "python.lang.security.audit.hardcoded-password",
                    "message": {"text": "Hardcoded password detected"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "app/config.py"},
                                "region": {"startLine": 12},
                            }
                        }
                    ],
                }
            ],
        }
    ],
}

SNAKE_CASE_SARIF = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {"driver": {"name": "SecretHound"}},
            "results": [
                {
                    "rule_id": "generic-api-key",
                    "message": {"text": "Generic API key found"},
                    "locations": [
                        {
                            "physical_location": {
                                "artifact_location": {"uri": "src/secrets.py"},
                                "region": {"start_line": 5},
                            }
                        }
                    ],
                }
            ],
        }
    ],
}


@pytest.fixture
def tmp_source_file(tmp_path: Path) -> Path:
    """Create a small Python source file used for context extraction tests."""
    content = "\n".join(
        [
            "import os",
            "",
            "def connect():",
            "    # line 4",
            "    password = 'super-secret-value'",  # line 5 – target
            "    return password",
            "",
            "def unused():",
            "    pass",
            "    # trailing lines for context window",
            "    x = 1",
            "    y = 2",
            "    z = 3",
        ]
    )
    path = tmp_path / "src" / "secrets.py"
    path.parent.mkdir(parents=True)
    path.write_text(content, encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# SARIF parsing – camelCase (standard)
# ---------------------------------------------------------------------------

def test_parse_camel_case_sarif(tmp_path: Path) -> None:
    sarif_file = tmp_path / "camel.sarif"
    sarif_file.write_text(json.dumps(CAMEL_CASE_SARIF), encoding="utf-8")

    findings = parse_sarif(sarif_file)

    assert len(findings) == 1
    f = findings[0]
    assert isinstance(f, SarifFinding)
    assert f.rule_id == "python.lang.security.audit.hardcoded-password"
    assert f.file_path == "app/config.py"
    assert f.start_line == 12
    assert "Hardcoded password" in f.message


# ---------------------------------------------------------------------------
# SARIF parsing – snake_case (SecretHound)
# ---------------------------------------------------------------------------

def test_parse_snake_case_sarif(tmp_path: Path) -> None:
    sarif_file = tmp_path / "snake.sarif"
    sarif_file.write_text(json.dumps(SNAKE_CASE_SARIF), encoding="utf-8")

    findings = parse_sarif(sarif_file)

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "generic-api-key"
    assert f.file_path == "src/secrets.py"
    assert f.start_line == 5
    assert "Generic API key" in f.message


# ---------------------------------------------------------------------------
# Context extraction
# ---------------------------------------------------------------------------

def test_context_extraction(tmp_path: Path, tmp_source_file: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Make the relative path resolve correctly
    monkeypatch.chdir(tmp_path)

    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "results": [
                    {
                        "rule_id": "generic-api-key",
                        "message": {"text": "Secret found"},
                        "locations": [
                            {
                                "physical_location": {
                                    "artifact_location": {"uri": "src/secrets.py"},
                                    "region": {"start_line": 5},
                                }
                            }
                        ],
                    }
                ]
            }
        ],
    }
    sarif_file = tmp_path / "ctx.sarif"
    sarif_file.write_text(json.dumps(sarif), encoding="utf-8")

    findings = parse_sarif(sarif_file)
    assert len(findings) == 1
    f = findings[0]

    assert f.context_available is True
    assert len(f.context) > 0

    # The reported line must be present and marked by its number
    target_lines = [c for c in f.context if c.line_number == 5]
    assert len(target_lines) == 1
    assert "super-secret-value" in target_lines[0].content

    # Window should include lines before and after
    line_numbers = [c.line_number for c in f.context]
    assert min(line_numbers) <= 5
    assert max(line_numbers) >= 5


def test_context_unavailable_for_missing_file(tmp_path: Path) -> None:
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "results": [
                    {
                        "ruleId": "test-rule",
                        "message": {"text": "missing file"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "does/not/exist.py"},
                                    "region": {"startLine": 1},
                                }
                            }
                        ],
                    }
                ]
            }
        ],
    }
    sarif_file = tmp_path / "missing.sarif"
    sarif_file.write_text(json.dumps(sarif), encoding="utf-8")

    findings = parse_sarif(sarif_file)
    assert len(findings) == 1
    assert findings[0].context_available is False
    assert findings[0].context == []


# ---------------------------------------------------------------------------
# AI engine – mocked Ollama responses
# ---------------------------------------------------------------------------

def _make_finding() -> SarifFinding:
    return SarifFinding(
        rule_id="generic-api-key",
        message="Possible API key",
        file_path="src/secrets.py",
        start_line=5,
        context=[],
        context_available=False,
    )


def test_triage_true_positive_mocked() -> None:
    finding = _make_finding()

    mock_response = {
        "message": {
            "content": json.dumps(
                {
                    "verdict": "TRUE_POSITIVE",
                    "confidence": 92,
                    "severity": "HIGH",
                    "reasoning": "Hardcoded secret in production code path. Should be moved to environment variable.",
                    "remediation_patch": "password = os.environ.get('APP_PASSWORD')",
                }
            )
        }
    }

    with patch("vulnwarden.ai_engine.httpx.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value.__enter__.return_value = mock_client
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = mock_response
        mock_client.post.return_value = mock_resp

        result = triage_finding(finding, model="dummy-model")

    assert isinstance(result, TriageResult)
    assert result.verdict == "TRUE_POSITIVE"
    assert result.confidence == 92
    assert result.severity == "HIGH"
    assert result.remediation_patch is not None
    assert "os.environ" in result.remediation_patch


def test_triage_false_positive_mocked() -> None:
    finding = _make_finding()

    mock_response = {
        "message": {
            "content": json.dumps(
                {
                    "verdict": "FALSE_POSITIVE",
                    "confidence": 88,
                    "severity": "INFO",
                    "reasoning": "Value appears only in unit-test fixture and is not used in production code.",
                    "remediation_patch": None,
                }
            )
        }
    }

    with patch("vulnwarden.ai_engine.httpx.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value.__enter__.return_value = mock_client
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = mock_response
        mock_client.post.return_value = mock_resp

        result = triage_finding(finding, model="dummy-model")

    assert isinstance(result, TriageResult)
    assert result.verdict == "FALSE_POSITIVE"
    assert result.confidence == 88
    assert result.severity == "INFO"
    assert result.remediation_patch is None


def test_triage_invalid_json_raises() -> None:
    finding = _make_finding()

    mock_response = {"message": {"content": "this is not json"}}

    with patch("vulnwarden.ai_engine.httpx.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value.__enter__.return_value = mock_client
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = mock_response
        mock_client.post.return_value = mock_resp

        with pytest.raises(ValueError, match="valid JSON"):
            triage_finding(finding, model="dummy-model")