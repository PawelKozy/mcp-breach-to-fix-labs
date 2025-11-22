"""Challenge 04 - Vulnerable Xata read-only bypass."""
from __future__ import annotations

import json
import logging
import os
from typing import Any

import psycopg
from mcp.server.fastmcp import FastMCP

APP_NAME = "Challenge 04: Xata Readonly (Vulnerable)"
INSTRUCTIONS = (
    "Proxy to a Postgres read replica."
)
PG_DSN = os.environ.get(
    "PG_DSN", "postgresql://mcp:password@localhost:5440/xata"
)

log = logging.getLogger("challenge04.vulnerable")

mcp = FastMCP(
    name=APP_NAME,
    instructions=INSTRUCTIONS,
    streamable_http_path="/mcp/stream",
)
mcp.app = mcp.streamable_http_app()


def _run_sql(query: str) -> str:
    with psycopg.connect(PG_DSN, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(query)
            if cur.description:
                rows = cur.fetchall()
                payload: list[dict[str, Any]] = [
                    {cur.description[i][0]: value for i, value in enumerate(row)}
                    for row in rows
                ]
                return json.dumps(payload, indent=2)
            return f"Command completed ({cur.rowcount} rows affected)."


@mcp.tool()
def run_query(sql: str) -> str:
    """Execute a SQL query routed to the replica."""
    # Naively enforce read-only by checking the first keyword.
    if not sql.strip().lower().startswith("select"):
        return "Read-only mode: query rejected."
    try:
        return _run_sql(sql)
    except Exception as exc:  # pragma: no cover - demo server
        log.exception("Query failed")
        return f"Database error: {exc}"


if __name__ == "__main__":
    import uvicorn

    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="[%(asctime)s] %(levelname)s %(name)s: %(message)s",
    )
    host = os.environ.get("CHALLENGE_HOST", "0.0.0.0")
    port = int(os.environ.get("CHALLENGE_PORT", "8000"))
    log.info("Starting vulnerable Xata proxy on %s:%s", host, port)
    uvicorn.run("server:mcp.app", host=host, port=port, log_level="info")
