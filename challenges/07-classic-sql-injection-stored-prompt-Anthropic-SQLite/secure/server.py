"""Challenge 07 - Secure stored prompt handler with SQLi fix."""
from __future__ import annotations

import logging
import os
import sqlite3
from pathlib import Path
from typing import List, Tuple

from mcp.server.fastmcp import FastMCP

APP_NAME = "Challenge 07: SQL Stored Prompt (Secure)"
INSTRUCTIONS = (
    "Triages service desk tickets and summarizes them after validating input. "
    "Ticket creation must resist SQL injection by parameterizing inputs."
)
DB_PATH = Path(__file__).resolve().parent / "tickets.db"
SECRET_INCIDENT_REPORT = os.environ.get(
    "CH07_SECRET_INCIDENT_REPORT", "FLAG{sql_prompt_injection_leak}"
)
DEFAULT_TICKETS = [
    ("helpdesk", "System running normally."),
]

log = logging.getLogger("challenge07.secure")

mcp = FastMCP(
    name=APP_NAME,
    instructions=INSTRUCTIONS,
    streamable_http_path="/mcp/stream",
)
mcp.app = mcp.streamable_http_app()


def init_db() -> None:
    """Create the tables used by the challenge and seed baseline data."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            author TEXT NOT NULL,
            content TEXT NOT NULL
        )
        """
    )
    cursor.execute("SELECT COUNT(*) FROM tickets")
    if cursor.fetchone()[0] == 0:
        cursor.executemany(
            "INSERT INTO tickets (author, content) VALUES (?, ?)", DEFAULT_TICKETS
        )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS incident_intel (
            id INTEGER PRIMARY KEY,
            payload TEXT NOT NULL
        )
        """
    )
    cursor.execute(
        "INSERT OR IGNORE INTO incident_intel (id, payload) VALUES (1, ?)",
        (SECRET_INCIDENT_REPORT,),
    )
    conn.commit()
    conn.close()


def _rows_to_summary(rows: List[Tuple[str, str]]) -> str:
    if not rows:
        return "No tickets recorded."
    formatted = "\n".join(f"- {author}: {content}" for author, content in rows)
    return f"Tickets ({len(rows)}):\n{formatted}"


init_db()


@mcp.tool()
def create_ticket(author: str, content: str) -> str:
    """Secure ticket creation using parameterized SQL to block injection."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    query = "INSERT INTO tickets (author, content) VALUES (?, ?)"
    cursor.execute(query, (author, content))
    conn.commit()
    conn.close()
    log.info("Ticket stored for author %s", author)
    return "Ticket created successfully."


@mcp.tool()
def summarize_all_tickets() -> str:
    """Return all tickets as a single string for downstream LLM summarization."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT author, content FROM tickets ORDER BY id ASC")
    rows = cursor.fetchall()
    conn.close()

    return _rows_to_summary(rows)


if __name__ == "__main__":
    import uvicorn

    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="[%(asctime)s] %(levelname)s %(name)s: %(message)s",
    )
    host = os.environ.get("CHALLENGE_HOST", "0.0.0.0")
    port = int(os.environ.get("CHALLENGE_PORT", "8000"))
    log.info("Starting secure SQL stored prompt server on %s:%s", host, port)
    uvicorn.run("server:mcp.app", host=host, port=port, log_level="info")
