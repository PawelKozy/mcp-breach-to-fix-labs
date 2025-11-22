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
    "Exposes list_chats and send_message while enforcing recipient whitelisting "
    "to prevent unauthorized message delivery."
)

log = logging.getLogger("challenge03.whatsapp.secure")

mcp = FastMCP(name=APP_NAME, instructions=INSTRUCTIONS, streamable_http_path="/mcp/stream")
mcp.app = mcp.streamable_http_app()


def _get_data_file() -> Path:
    """Get the path to the chat data file (single source of truth)."""
    override = os.environ.get("WHATSAPP_DATA_FILE")
    if override:
        return Path(override)
    candidate = Path(__file__).resolve().parent / "data" / "whatsapp_chats.json"
    if candidate.exists():
        return candidate
    return Path(__file__).resolve().parents[2] / "data" / "whatsapp_chats.json"


STATE_FILE = _get_data_file()


def _load_state() -> Dict[str, Any]:
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
    """Normalize recipient for case-insensitive matching."""
    return recipient.strip().lower()


def _is_whitelisted(recipient: str, contacts: Dict[str, str]) -> bool:
    """
    Check if recipient is in the trusted contact whitelist.
    Returns True only if the recipient exactly matches a known alias or phone number.
    """
    normalized = _normalize(recipient)
    for alias, number in contacts.items():
        if normalized == alias.lower() or normalized == number.lower():
            return True
    return False


def _resolve_contact(recipient: str, contacts: Dict[str, str]) -> str | None:
    """Resolve recipient alias to phone number from whitelist."""
    normalized = _normalize(recipient)
    for alias, number in contacts.items():
        if normalized == alias.lower():
            return number
        if normalized == number.lower():
            return number
    return None


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
    """
    Send a WhatsApp message with strict recipient whitelisting.
    Only allows messages to pre-approved contacts to prevent recipient redirection attacks.
    """
    data = _load_state()
    contacts = data["contacts"]
    
    # The ONLY defense that matters: recipient must be in whitelist
    number = _resolve_contact(recipient, contacts)
    if number is None:
        log.warning("SECURITY: Blocked message to non-whitelisted recipient: %s", recipient)
        return "Rejected: recipient not in trusted contact list."
    
    _log_sent(number, body)
    _append_message(recipient, body)
    log.info("Message sent to whitelisted contact %s (%s)", recipient, number)
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
