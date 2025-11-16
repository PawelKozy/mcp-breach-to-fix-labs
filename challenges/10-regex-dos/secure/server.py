"""Challenge 10 - Secure regex log search (DoS mitigated)."""
from __future__ import annotations

import json
import logging
import os
import re
import sys
import time
from pathlib import Path
from typing import Any

import regex
from mcp.server.fastmcp import FastMCP

CURRENT_DIR = Path(__file__).resolve().parent
sys.path.append(str(CURRENT_DIR.parent))

from logtools import head_lines, load_log_text  # type: ignore  # pylint: disable=wrong-import-position

APP_NAME = "Challenge 10: Regex Log Search (Secure)"
INSTRUCTIONS = (
    "Security automation gateway for searching logs with regex filters. "
    "Patterns are validated and executed with strict timeouts to prevent DoS."
)
MAX_PATTERN_LENGTH = 128
REGEX_TIMEOUT = 0.15

log = logging.getLogger("challenge10.secure")

mcp = FastMCP(
    name=APP_NAME,
    instructions=INSTRUCTIONS,
    streamable_http_path="/mcp/stream",
)
mcp.app = mcp.streamable_http_app()


def _validate_pattern(pattern: str) -> str | None:
    if len(pattern) > MAX_PATTERN_LENGTH:
        return f"Pattern too long ({len(pattern)} chars). Max allowed is {MAX_PATTERN_LENGTH}."
    if pattern.count("(") - pattern.count("\\(") > 12:
        return "Pattern rejected: too many capturing groups for automated review."
    if re.search(r"(\+|\*)\)\+", pattern):
        return "Pattern rejected: nested quantifiers (catastrophic backtracking risk)."
    if re.search(r"(?:\+|\*)(?:\+|\*)", pattern):
        return "Pattern rejected: overlapping quantifiers detected."
    return None


@mcp.tool()
def describe_log() -> dict[str, Any]:
    """Return a sanitized preview of the log contents."""
    return {"samples": head_lines(5), "size_bytes": len(load_log_text())}


@mcp.tool()
def search_logs(pattern: str, max_matches: int = 50) -> str:
    """Run a regex with DoS protection."""
    validation_error = _validate_pattern(pattern)
    if validation_error:
        return validation_error
    try:
        compiled = regex.compile(pattern)
    except regex.error as exc:  # type: ignore[attr-defined]
        return f"Regex error: {exc}"
    start = time.perf_counter()
    try:
        matches = compiled.findall(
            load_log_text(), overlapped=False, timeout=REGEX_TIMEOUT
        )
    except regex.TimeoutError:
        return (
            "Pattern rejected: execution exceeded timeout threshold. "
            "Refine the regex to avoid catastrophic backtracking."
        )
    duration = time.perf_counter() - start
    limited = matches[:max_matches]
    result = {
        "pattern": pattern,
        "match_count": len(matches),
        "returned": limited,
        "truncated": len(matches) > len(limited),
        "duration_seconds": duration,
        "timeout_seconds": REGEX_TIMEOUT,
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
    log.info("Starting secure regex log search on %s:%s", host, port)
    uvicorn.run("server:mcp.app", host=host, port=port, log_level="info")
