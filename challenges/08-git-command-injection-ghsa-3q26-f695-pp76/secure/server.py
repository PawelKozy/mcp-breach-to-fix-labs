"""Challenge 08 - Secure git MCP server hardened against GHSA-3q26-f695-pp76."""
from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import List

from mcp.server.fastmcp import FastMCP

APP_NAME = "Challenge 08: Git Command Injection (Secure)"
INSTRUCTIONS = (
    "Provides helpers around git repositories. This build validates repo names and "
    "invokes git with safe argument lists to block command injection."
)
REPO_ROOT = Path(os.environ.get("CH08_REPO_ROOT", Path(__file__).resolve().parent / "repos"))
SAFE_REPO_NAME = re.compile(r"^[A-Za-z0-9._-]+$")

log = logging.getLogger("challenge08.secure")

mcp = FastMCP(
    name=APP_NAME,
    instructions=INSTRUCTIONS,
    streamable_http_path="/mcp/stream",
)
mcp.app = mcp.streamable_http_app()


def _ensure_repo_root() -> None:
    REPO_ROOT.mkdir(parents=True, exist_ok=True)


def _sanitize_repo_name(repo_name: str) -> Path:
    if not SAFE_REPO_NAME.fullmatch(repo_name):
        raise ValueError("Invalid repository name. Use letters, numbers, dots, underscores, or dashes.")
    return REPO_ROOT / repo_name


def _run_git(args: List[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )


def _format_result(result: subprocess.CompletedProcess[str]) -> str:
    output = (result.stdout + result.stderr).strip()
    if not output:
        output = f"git exited with code {result.returncode}"
    return output


@mcp.tool()
def init_bare_repository(repo_name: str) -> str:
    """Initialize a bare git repo using safe subprocess invocation."""
    _ensure_repo_root()
    try:
        target = _sanitize_repo_name(repo_name)
    except ValueError as exc:
        return str(exc)
    if target.exists():
        shutil.rmtree(target, ignore_errors=True)
    args = ["git", "init", "--bare", str(target)]
    log.info("Executing secure git command: %s", args)
    result = _run_git(args)
    return _format_result(result)


@mcp.tool()
def list_repositories() -> str:
    """List bare repositories initialized on disk."""
    _ensure_repo_root()
    entries: List[str] = sorted(p.name for p in REPO_ROOT.iterdir() if p.is_dir())
    return "\n".join(entries) if entries else "No repositories yet."


if __name__ == "__main__":
    import uvicorn

    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="[%(asctime)s] %(levelname)s %(name)s: %(message)s",
    )
    host = os.environ.get("CHALLENGE_HOST", "0.0.0.0")
    port = int(os.environ.get("CHALLENGE_PORT", "8000"))
    log.info("Starting secure git MCP server on %s:%s (root=%s)", host, port, REPO_ROOT)
    uvicorn.run("server:mcp.app", host=host, port=port, log_level="info")
