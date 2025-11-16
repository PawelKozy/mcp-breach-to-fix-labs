"""Challenge 10 - Vulnerable regex log search (DoS)."""
from __future__ import annotations

import json
import logging
import os
import re
import sys
import time
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

CURRENT_DIR = Path(__file__).resolve().parent
sys.path.append(str(CURRENT_DIR.parent))

from logtools import head_lines, load_log_text  # type: ignore  # pylint: disable=wrong-import-position

APP_NAME = "Challenge 10: Regex Log Search (Vulnerable)"
INSTRUCTIONS = (
    "Security automation gateway that lets you run arbitrary regular expressions "
    "against the live export log to build incident summaries."
)

log = logging.getLogger("challenge10.vulnerable")

mcp = FastMCP(
    name=APP_NAME,
    instructions=INSTRUCTIONS,
    streamable_http_path="/mcp/stream",
)
mcp.app = mcp.streamable_http_app()


@mcp.tool()
def describe_log() -> dict[str, Any]:
    """Return a quick preview of the log contents."""
    return {"samples": head_lines(5), "size_bytes": len(load_log_text())}


@mcp.tool()
def search_logs(pattern: str, max_matches: int = 50) -> str:
    """Run an arbitrary regex over the entire log export."""
    start = time.perf_counter()
    try:
        compiled = re.compile(pattern)
    except re.error as exc:
        return f"Regex error: {exc}"
    matches = compiled.findall(load_log_text())
    duration = time.perf_counter() - start
    limited = matches[:max_matches]
    result = {
        "pattern": pattern,
        "match_count": len(matches),
        "returned": limited,
        "truncated": len(matches) > len(limited),
        "duration_seconds": duration,
    }
    return json.dumps(result, indent=2)


if __name__ == "__main__":
    import uvicorn

    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="[%(asctime)s] %(levelname)s %(name)s: %(message)s",
    )
    host = os.environ.get("CHALLENGE_HOST", "0.0.0.0")
    port = int(os.environ.get("CHALLENGE_PORT", "8000"))
    log.info("Starting vulnerable regex log search on %s:%s", host, port)
    uvicorn.run("server:mcp.app", host=host, port=port, log_level="info")
