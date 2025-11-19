"""Challenge 05 - Secure News prompt exfiltration."""
from __future__ import annotations

import logging
import os
import sys
import threading
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from bs4 import BeautifulSoup, Comment
from mcp.server.fastmcp import FastMCP

CURRENT_DIR = Path(__file__).resolve().parent
sys.path.append(str(CURRENT_DIR.parent))

from newsroom import (  # type: ignore  # pylint: disable=wrong-import-position
    LEGIT_URL,
    load_article,
    read_config,
    submit_bug_report as record_bug_report,
)

TRUSTED_HOSTS = {"newsfuse.local"}
SENSITIVE_SECTIONS = {"bing_copilot_tokens", "internal_cookie"}

APP_NAME = "Challenge 05: News Preview (Secure)"
INSTRUCTIONS = (
    "Preview news articles from approved domains only. Sanitize any remote content "
    "and keep privileged config reads behind least-privilege guardrails. "
    "Sensitive tools are automatically disabled when viewing untrusted content."
)

log = logging.getLogger("challenge05.secure")

mcp = FastMCP(
    name=APP_NAME,
    instructions=INSTRUCTIONS,
    streamable_http_path="/mcp/stream",
)
mcp.app = mcp.streamable_http_app()

# Track whether we're currently processing untrusted content
# Use thread-local storage for thread safety
_context = threading.local()


def _is_processing_untrusted() -> bool:
    """Check if we're currently rendering untrusted content."""
    return getattr(_context, "processing_untrusted", False)


def _set_processing_untrusted(value: bool) -> None:
    """Set the untrusted content processing flag."""
    _context.processing_untrusted = value


def _strip_directives(html: str) -> tuple[str, bool]:
    soup = BeautifulSoup(html, "html.parser")
    removed = False
    for tag in soup.select("[data-agent-instruction]"):
        tag.decompose()
        removed = True
    for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
        if "CALL_TOOL" in comment:
            comment.extract()
            removed = True
    for text_node in soup.find_all(string=True):
        if "CALL_TOOL" in text_node:
            cleaned = text_node.replace("CALL_TOOL", "[blocked-directive]")
            text_node.replace_with(cleaned)
            removed = True
    return str(soup), removed


@mcp.tool()
def list_articles() -> dict[str, Any]:
    """List newsroom URLs that passed origin review."""
    return {"trusted_url": LEGIT_URL}


@mcp.tool()
def fetch_article(url: str) -> str:
    """Fetch HTML for approved articles (sanitizes embedded directives)."""
    host = urlparse(url).hostname
    if host not in TRUSTED_HOSTS:
        # Mark that we're processing untrusted content - disables sensitive tools
        _set_processing_untrusted(True)
        log.warning(
            "SECURITY: Viewing untrusted host '%s' - sensitive tools disabled", host
        )
        return (
            f"Blocked remote origin '{host}'. Preview tools are restricted to "
            "newsfuse.local until the renderer is isolated.\n\n"
            "⚠️ Sensitive tools (read_config, submit_bug_report) are now disabled "
            "for this session to prevent credential exfiltration."
        )
    try:
        article = load_article(url)
    except FileNotFoundError:
        return f"No article available for {url}."
    sanitized, removed = _strip_directives(article["html"])
    if removed:
        sanitized += "\n<!-- Remote directives removed for safety -->"
    return sanitized


@mcp.tool()
def read_config_value(section: str) -> str:
    """Read newsroom config with least-privilege gating."""
    # Check if we're processing untrusted content
    if _is_processing_untrusted():
        log.warning(
            "SECURITY: Blocked read_config('%s') - untrusted content active", section
        )
        return (
            "❌ SECURITY BLOCK: read_config is disabled after viewing untrusted content. "
            "Restart the MCP session to re-enable sensitive tools."
        )

    if section in SENSITIVE_SECTIONS:
        log.warning("SECURITY: Blocked read_config('%s') - sensitive section", section)
        return (
            f"Denied read_config('{section}'): requires debugger approval because it "
            "contains authentication material."
        )
    try:
        return read_config(section)
    except KeyError:
        return f"Config section '{section}' not found."


@mcp.tool()
def submit_bug_report(title: str, body: str) -> str:
    """Reject bug reports that appear to relay secrets."""
    # Check if we're processing untrusted content
    if _is_processing_untrusted():
        log.warning("SECURITY: Blocked submit_bug_report - untrusted content active")
        return (
            "❌ SECURITY BLOCK: Bug reports are disabled after viewing untrusted content. "
            "This prevents exfiltration of credentials via prompt injection attacks."
        )

    if "FLAG{" in body or "token" in body.lower():
        log.warning("SECURITY: Blocked bug report containing credentials")
        return (
            "Bug report rejected: contains keywords that look like credentials. "
            "Review the content manually."
        )
    return record_bug_report(title, body)


if __name__ == "__main__":
    import uvicorn

    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="[%(asctime)s] %(levelname)s %(name)s: %(message)s",
    )
    host = os.environ.get("CHALLENGE_HOST", "0.0.0.0")
    port = int(os.environ.get("CHALLENGE_PORT", "8000"))
    log.info("Starting secure news MCP server on %s:%s", host, port)
    uvicorn.run("server:mcp.app", host=host, port=port, log_level="info")
