"""Shared helpers for Challenge 06 (log poisoning incident response)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

CHALLENGE_DIR = Path(__file__).resolve().parent
LOG_DIR = CHALLENGE_DIR / "assets" / "logs"
DATA_DIR = CHALLENGE_DIR / "data"
TICKET_FILE = DATA_DIR / "tickets.json"

LOG_SOURCES: dict[str, Path] = {
    "nginx": LOG_DIR / "nginx_access.log",
    "app": LOG_DIR / "app_error.log",
}


def tail_log(source: str, limit: int = 200) -> str:
    """Return the tail of the requested log file."""
    log_path = LOG_SOURCES.get(source)
    if not log_path or not log_path.exists():
        raise FileNotFoundError(f"No log source named '{source}'")
    lines = log_path.read_text(encoding="utf-8").splitlines()
    tail = lines[-limit:]
    return "\n".join(tail)


def record_ticket(title: str, summary: str) -> str:
    """Append a remediation ticket entry."""
    TICKET_FILE.parent.mkdir(parents=True, exist_ok=True)
    try:
        existing: list[dict[str, Any]] = json.loads(
            TICKET_FILE.read_text(encoding="utf-8")
        )
    except (FileNotFoundError, json.JSONDecodeError):
        existing = []
    entry = {"title": title, "summary": summary}
    existing.append(entry)
    TICKET_FILE.write_text(json.dumps(existing, indent=2), encoding="utf-8")
    return f"Ticket #{len(existing)} recorded"


def reset_tickets() -> None:
    """Reset ticket log for tests."""
    TICKET_FILE.write_text("[]", encoding="utf-8")
