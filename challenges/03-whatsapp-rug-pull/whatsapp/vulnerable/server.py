"""Challenge 03 - Vulnerable WhatsApp MCP bridge."""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict

from mcp.server.fastmcp import FastMCP

APP_NAME = "Challenge 03: WhatsApp Bridge (Vulnerable)"
INSTRUCTIONS = (
    "Exposes list_chats and send_message tools. This build simulates trusting any "
    "instructions supplied by other MCP servers and never revalidates recipients or message bodies."
)

log = logging.getLogger("challenge03.whatsapp.vulnerable")

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


def _append_message(recipient: str, body: str) -> None:
    data = _load_state()
    thread = None
    for entry in data["threads"]:
        if recipient in {entry["title"], entry["chat_id"]}:
            thread = entry
            break
    if thread is None:
        thread = {
            "chat_id": f"chat_{recipient}",
            "title": recipient,
            "messages": [],
        }
        data["threads"].append(thread)
    thread["messages"].append({"from": "me", "body": body})
    STATE_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


@mcp.tool()
def list_chats() -> str:
    """Return latest WhatsApp chats and messages."""
    data = _load_state()
    lines = []
    for thread in data["threads"]:
        lines.append(f"Chat: {thread['title']} ({thread['chat_id']})")
        for message in thread["messages"]:
            lines.append(f"  {message['from']}: {message['body']}")
    return "\n".join(lines)


@mcp.tool()
def send_message(recipient: str, body: str) -> str:
    """Send a WhatsApp message without inspecting the payload."""
    _log_sent(recipient, body)
    _append_message(recipient, body)
    log.warning("Sent message to %s with %s bytes", recipient, len(body))
    return f"Message dispatched to {recipient}."


if __name__ == "__main__":
    import uvicorn

    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="[%(asctime)s] %(levelname)s %(name)s: %(message)s",
    )
    host = os.environ.get("CHALLENGE_HOST", "0.0.0.0")
    port = int(os.environ.get("CHALLENGE_PORT", "8000"))
    log.info("Starting vulnerable WhatsApp bridge on %s:%s", host, port)
    uvicorn.run("server:mcp.app", host=host, port=port, log_level="info")
