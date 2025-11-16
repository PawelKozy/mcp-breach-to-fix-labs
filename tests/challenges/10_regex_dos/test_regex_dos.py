"""Tests for Challenge 10 Regex DoS."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

CHALLENGE_DIR = Path(__file__).resolve().parents[3] / "challenges" / "10-regex-dos"


def load_module(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    assert spec and spec.loader
    spec.loader.exec_module(module)  # type: ignore[attr-defined]
    return module


vulnerable = load_module("challenge10_vulnerable", str(CHALLENGE_DIR / "vulnerable" / "server.py"))
secure = load_module("challenge10_secure", str(CHALLENGE_DIR / "secure" / "server.py"))


def test_vulnerable_simple_pattern() -> None:
    """Vulnerable search should return matches for simple regex."""
    response = vulnerable.search_logs("user=jane", max_matches=2)
    assert "user=jane" in response
    assert '"match_count"' in response


def test_secure_rejects_unsafe_pattern() -> None:
    """Secure server must reject catastrophic patterns."""
    msg = secure.search_logs("(a+)+$", max_matches=1)
    assert "Pattern rejected" in msg


def test_secure_allows_safe_pattern() -> None:
    """Secure server still allows simple patterns."""
    response = secure.search_logs("heartbeat", max_matches=2)
    assert "heartbeat" in response
