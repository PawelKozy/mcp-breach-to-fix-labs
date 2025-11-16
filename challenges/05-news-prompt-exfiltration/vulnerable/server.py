"""Challenge 05 - Vulnerable News prompt exfiltration."""
from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

CURRENT_DIR = Path(__file__).resolve().parent
sys.path.append(str(CURRENT_DIR.parent))

from newsroom import (  # type: ignore  # pylint: disable=wrong-import-position
    LEGIT_URL,
    MALICIOUS_URL,
    load_article,
    read_config,
    submit_bug_report as record_bug_report,
)

APP_NAME = "Challenge 05: News Preview (Vulnerable)"
INSTRUCTIONS = (
    "Preview newsroom articles, read local config for fact-checking, "
    "and file bug reports when stories look suspicious."
)

log = logging.getLogger("challenge05.vulnerable")

mcp = FastMCP(
    name=APP_NAME,
    instructions=INSTRUCTIONS,
    streamable_http_path="/mcp/stream",
)
mcp.app = mcp.streamable_http_app()


@mcp.tool()
def list_articles() -> dict[str, Any]:
    """List the newsroom URLs available for preview."""
    return {
        "trusted_url": LEGIT_URL,
        "breaking_news_tip": MALICIOUS_URL,
    }


@mcp.tool()
def fetch_article(url: str) -> str:
    """Fetch HTML for the requested newsroom article."""
    try:
        article = load_article(url)
    except FileNotFoundError:
        return f"No article available for {url}."
    return article["html"]


@mcp.tool()
def read_config_value(section: str) -> str:
    """Read local configuration required by editors for publishing."""
    try:
        return read_config(section)
    except KeyError:
        return f"Config section '{section}' not found."


@mcp.tool()
def submit_bug_report(title: str, body: str) -> str:
    """Send a bug report back to the newsroom SOC."""
    return record_bug_report(title, body)


if __name__ == "__main__":
    import uvicorn

    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="[%(asctime)s] %(levelname)s %(name)s: %(message)s",
    )
    host = os.environ.get("CHALLENGE_HOST", "0.0.0.0")
    port = int(os.environ.get("CHALLENGE_PORT", "8000"))
    log.info("Starting vulnerable news MCP server on %s:%s", host, port)
    uvicorn.run("server:mcp.app", host=host, port=port, log_level="info")
