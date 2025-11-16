"""Challenge 04 - Secure Xata read-only proxy."""
from __future__ import annotations

import json
import logging
import os
from typing import Any

import psycopg
import sqlparse
from mcp.server.fastmcp import FastMCP

APP_NAME = "Challenge 04: Xata Readonly (Secure)"
INSTRUCTIONS = "Only supports single-statement SELECT queries against the replica."
PG_DSN = os.environ.get(
    "PG_DSN", "postgresql://mcp:password@localhost:5440/xata"
)

log = logging.getLogger("challenge04.secure")

mcp = FastMCP(
    name=APP_NAME,
    instructions=INSTRUCTIONS,
    streamable_http_path="/mcp/stream",
)
mcp.app = mcp.streamable_http_app()


def _validate(sql: str) -> str:
    statements = [s for s in sqlparse.split(sql) if s.strip()]
    if len(statements) != 1:
        raise ValueError("Only a single statement is permitted.")
    parsed = sqlparse.parse(statements[0])[0]
    if parsed.get_type() != "SELECT":
        raise ValueError("Only SELECT statements are permitted.")
    return statements[0]


def _run_sql(query: str) -> str:
    with psycopg.connect(PG_DSN, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(query)
            rows = cur.fetchall()
            payload: list[dict[str, Any]] = [
                {cur.description[i][0]: value for i, value in enumerate(row)}
                for row in rows
            ]
            return json.dumps(payload, indent=2)


@mcp.tool()
def run_query(sql: str) -> str:
    """Execute a single SELECT statement with enforced read-only guarantees."""
    try:
        validated = _validate(sql)
    except ValueError as exc:
        return f"Rejected: {exc}"
    except Exception as exc:  # pragma: no cover
        return f"Rejected: malformed SQL ({exc})"

    try:
        return _run_sql(validated)
    except Exception as exc:  # pragma: no cover
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
    log.info("Starting secure Xata proxy on %s:%s", host, port)
    uvicorn.run("server:mcp.app", host=host, port=port, log_level="info")
