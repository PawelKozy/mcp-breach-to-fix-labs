"""Challenge 03 - Secure WhatsApp MCP bridge."""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict

from mcp.server.fastmcp import FastMCP

APP_NAME = "Challenge 03: WhatsApp Bridge (Secure)"
INSTRUCTIONS = (
    "Exposes list_chats and send_message while enforcing tenant-scoped contacts, "
    "payload inspection, and sanitation to defeat MCP rug pulls."
)

log = logging.getLogger("challenge03.whatsapp.secure")

mcp = FastMCP(name=APP_NAME, instructions=INSTRUCTIONS, streamable_http_path="/mcp/stream")
mcp.app = mcp.streamable_http_app()


def _base_data_file() -> Path:
    override = os.environ.get("WHATSAPP_DATA_FILE")
    if override:
        return Path(override)
    candidate = Path(__file__).resolve().parent / "data" / "whatsapp_chats.json"
    if candidate.exists():
        return candidate
    return Path(__file__).resolve().parents[2] / "data" / "whatsapp_chats.json"


STATE_FILE = Path(
    os.environ.get(
        "WHATSAPP_STATE_FILE",
        Path(__file__).parent / "runtime_whatsapp_chats.json",
    )
)


def _ensure_state_file() -> None:
    if STATE_FILE.exists():
        return
    STATE_FILE.write_text(_base_data_file().read_text(encoding="utf-8"), encoding="utf-8")


def _load_state() -> Dict[str, Any]:
    _ensure_state_file()
    with STATE_FILE.open(encoding="utf-8") as handle:
        return json.load(handle)


def _outbox_path() -> Path:
    target = os.environ.get("WHATSAPP_OUTBOX", Path(__file__).parent / "sent_messages.log")
    return Path(target)


def _log_sent(recipient: str, body: str) -> None:
    path = _outbox_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(f"TO={recipient}\n{body}\n---\n")


def _normalize(recipient: str) -> str:
    return recipient.strip().lower()


def _resolve_contact(recipient: str, contacts: Dict[str, str]) -> str | None:
    normalized = _normalize(recipient)
    for alias, number in contacts.items():
        if normalized == alias.lower() or normalized == number.lower():
            return number
    return None


def _looks_malicious(body: str) -> bool:
    lowered = body.lower()
    red_flags = ["@recipient", "@chat", "http://", "https://", "flag{", "list_chats"]
    return any(flag in lowered for flag in red_flags) or len(body) > 512


def _append_message(alias: str, body: str) -> None:
    data = _load_state()
    thread = None
    for entry in data["threads"]:
        if alias in {entry["title"], entry["chat_id"]}:
            thread = entry
            break
    if thread is None:
        thread = {
            "chat_id": f"chat_{alias}",
            "title": alias,
            "messages": [],
        }
        data["threads"].append(thread)
    thread["messages"].append({"from": "me", "body": body})
    STATE_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


@mcp.tool()
def list_chats() -> str:
    """Return sanitized chat summaries."""
    data = _load_state()
    lines = []
    for thread in data["threads"]:
        lines.append(f"Chat: {thread['title']} ({thread['chat_id']})")
        last = thread["messages"][-1]
        snippet = last["body"][:60]
        lines.append(f"  Last message from {last['from']}: {snippet}")
    return "\n".join(lines)


@mcp.tool()
def send_message(recipient: str, body: str) -> str:
    """Send a WhatsApp message with recipient and payload validation."""
    data = _load_state()
    contacts = data["contacts"]
    number = _resolve_contact(recipient, contacts)
    if number is None:
        return "Rejected: recipient not in trusted contact list."
    if _looks_malicious(body):
        log.warning("Blocked suspicious payload destined for %s", recipient)
        return "Rejected: message body appears to contain hidden instructions."
    _log_sent(number, body)
    _append_message(recipient, body)
    return f"Message dispatched to {number}."


if __name__ == "__main__":
    import uvicorn

    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="[%(asctime)s] %(levelname)s %(name)s: %(message)s",
    )
    host = os.environ.get("CHALLENGE_HOST", "0.0.0.0")
    port = int(os.environ.get("CHALLENGE_PORT", "8000"))
    log.info("Starting secure WhatsApp bridge on %s:%s", host, port)
    uvicorn.run("server:mcp.app", host=host, port=port, log_level="info")
