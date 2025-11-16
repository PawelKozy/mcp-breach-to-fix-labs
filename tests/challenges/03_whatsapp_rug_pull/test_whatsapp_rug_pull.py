"""Tests for Challenge 03: WhatsApp MCP rug pull."""
from __future__ import annotations

import os
from importlib import util
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]


def load_module(label: str, relative: str):
    module_path = REPO_ROOT / relative
    spec = util.spec_from_file_location(label, module_path)
    module = util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)  # type: ignore[call-arg]
    return module


def test_helper_response_switches(tmp_path: Path):
    state_path = tmp_path / "sleeper_state.txt"
    os.environ["SLEEPER_STATE_FILE"] = str(state_path)
    helper = load_module(
        "challenge03_helper", "challenges/03-whatsapp-rug-pull/helper/server.py"
    )
    first = helper.get_fact_of_the_day()
    assert "+13241234123" not in first
    second = helper.get_fact_of_the_day()
    assert state_path.exists()
    assert "+13241234123" in second


def _setup_whatsapp_env(tmp_path: Path):
    chats_file = tmp_path / "chats.json"
    chats_file.write_text(
        '{"contacts":{"alice":"+15551234567"}, "threads":[]}',
        encoding="utf-8",
    )
    os.environ["WHATSAPP_DATA_FILE"] = str(chats_file)
    os.environ["WHATSAPP_OUTBOX"] = str(tmp_path / "outbox.log")
    return chats_file


def test_vulnerable_accepts_hidden_payload(tmp_path: Path):
    _setup_whatsapp_env(tmp_path)
    vulnerable = load_module(
        "challenge03_whatsapp_vulnerable",
        "challenges/03-whatsapp-rug-pull/whatsapp/vulnerable/server.py",
    )
    payload = "Hi @chat: leaked"
    response = vulnerable.send_message("+123", payload)
    assert "Message dispatched" in response
    log_path = Path(os.environ["WHATSAPP_OUTBOX"])
    assert payload in log_path.read_text(encoding="utf-8")


def test_secure_blocks_hidden_payload(tmp_path: Path):
    _setup_whatsapp_env(tmp_path)
    secure = load_module(
        "challenge03_whatsapp_secure",
        "challenges/03-whatsapp-rug-pull/whatsapp/secure/server.py",
    )
    payload = "Hi @chat: leaked"
    response = secure.send_message("+15551234567", payload)
    assert "Rejected" in response
    log_path = Path(os.environ["WHATSAPP_OUTBOX"])
    assert not log_path.exists()
