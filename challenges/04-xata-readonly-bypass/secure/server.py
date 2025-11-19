"""Challenge 04 - Secure Xata read-only proxy."""
from __future__ import annotations

import json
import logging
import os
from typing import Any

import psycopg
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


def _validate(sql: str) -> None:
    """Basic validation - reject obvious multi-statement attacks.
    
    NOTE: This is NOT the primary security control. Simple string checks like
    semicolon detection can be bypassed with SQL comments, CTEs, or other tricks.
    The REAL protection is SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY
    at the database level. This validation is just a first line of defense to
    catch obvious attacks before they hit the database.
    
    
    The database is the security boundary, not Python code.
    """
    sql_stripped = sql.strip()
    
    # Reject empty queries
    if not sql_stripped:
        raise ValueError("Empty query not permitted.")
    
    # Reject queries containing semicolons (multi-statement indicator)
    if ';' in sql_stripped:
        raise ValueError("Multiple statements not permitted (semicolon detected).")
    
    # Reject non-SELECT statements (basic check)
    if not sql_stripped.upper().startswith('SELECT'):
        raise ValueError("Only SELECT statements are permitted.")


def _run_sql(query: str) -> str:
    with psycopg.connect(PG_DSN) as conn:
        with conn.cursor() as cur:
            # Enforce read-only at database session level
            # This is the PRIMARY security control - prevents ALL write operations
            cur.execute("SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY")
            cur.execute(query)
            conn.commit()
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
        _validate(sql)
    except ValueError as exc:
        log.warning("Rejected query: %s (reason: %s)", sql[:100], exc)
        return f"Rejected: {exc}"
    except Exception as exc:  # pragma: no cover
        log.warning("Rejected malformed query: %s", sql[:100])
        return f"Rejected: malformed SQL ({exc})"

    try:
        return _run_sql(sql)
    except Exception as exc:  # pragma: no cover
        log.exception("Query failed")
        return "Database error: Query execution failed."


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
