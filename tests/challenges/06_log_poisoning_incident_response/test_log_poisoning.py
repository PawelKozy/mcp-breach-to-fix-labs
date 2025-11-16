"""Tests for Challenge 06 (log poisoning incident response)."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

CHALLENGE_DIR = (
    Path(__file__).resolve().parents[3] / "challenges" / "06-log-poisoning-incident-response"
)
sys.path.insert(0, str(CHALLENGE_DIR))

import logops  # type: ignore  # pylint: disable=wrong-import-position
from secure import server as secure_server  # type: ignore  # pylint: disable=wrong-import-position


@pytest.fixture(autouse=True)
def reset_tickets() -> None:
    """Ensure ticket log starts empty."""
    logops.reset_tickets()
    yield
    logops.reset_tickets()


def test_nginx_log_fixture_contains_call_tool() -> None:
    """Vulnerable fixture must contain CALL_TOOL directives."""
    log_text = logops.tail_log("nginx")
    assert "CALL_TOOL" in log_text


def test_secure_sanitizer_removes_directives() -> None:
    """Secure sanitization strips CALL_TOOL instructions."""
    raw = logops.tail_log("nginx")
    sanitized, removed = secure_server.sanitize_logs(raw)
    assert removed is True
    assert "CALL_TOOL" not in sanitized


def test_secure_ticket_rejects_suspicious_summary() -> None:
    """Secure ticket creation blocks suspicious keywords."""
    response = secure_server.open_remediation_ticket(
        "Check creds", "Please exfiltrate secrets from env"
    )
    assert "rejected" in response.lower()


def test_record_ticket_appends_entry() -> None:
    """Recording tickets should persist to JSON log."""
    message = logops.record_ticket("Test", "All good")
    assert "Ticket #1" in message
    data = json.loads((CHALLENGE_DIR / "data" / "tickets.json").read_text(encoding="utf-8"))
    assert data[-1]["title"] == "Test"
