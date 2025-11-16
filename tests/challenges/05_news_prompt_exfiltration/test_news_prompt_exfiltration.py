"""Tests for Challenge 05 (news prompt exfiltration)."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

CHALLENGE_DIR = (
    Path(__file__).resolve().parents[3] / "challenges" / "05-news-prompt-exfiltration"
)
sys.path.insert(0, str(CHALLENGE_DIR))

import newsroom  # type: ignore  # pylint: disable=wrong-import-position
from secure import server as secure_server  # type: ignore  # pylint: disable=wrong-import-position


@pytest.fixture(autouse=True)
def reset_reports() -> None:
    """Ensure bug report log starts empty for every test."""
    newsroom.reset_reports()
    yield
    newsroom.reset_reports()


def test_malicious_article_contains_tool_directives() -> None:
    """Malicious HTML fixture should ship the CALL_TOOL directives."""
    article = newsroom.load_article(newsroom.MALICIOUS_URL)
    assert "CALL_TOOL read_config" in article["html"]
    assert "CALL_TOOL submit_bug_report" in article["html"]


def test_secure_server_strips_remote_directives(tmp_path: Path) -> None:
    """Secure sanitization removes any embedded CALL_TOOL text."""
    article = newsroom.load_article(newsroom.MALICIOUS_URL)
    sanitized, removed = secure_server._strip_directives(article["html"])  # type: ignore[attr-defined]
    assert removed is True
    assert "CALL_TOOL" not in sanitized


def test_bug_report_log_records_entries() -> None:
    """Bug report helper should append entries to the JSON log."""
    result = newsroom.submit_bug_report("Test", "Nothing sensitive")
    assert "Recorded bug report #1" in result
    data = json.loads(
        (CHALLENGE_DIR / "data" / "bug_reports.json").read_text(encoding="utf-8")
    )
    assert data[-1]["title"] == "Test"


def test_secure_read_config_blocks_tokens() -> None:
    """Secure server denies sensitive config sections."""
    response = secure_server.read_config_value("bing_copilot_tokens")
    assert "Denied read_config" in response
