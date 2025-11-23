"""Challenge 08 - Vulnerable git MCP server (GHSA-3q26-f695-pp76)."""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import List

from mcp.server.fastmcp import FastMCP

APP_NAME = "Challenge 08: Git Command Injection (Vulnerable)"
INSTRUCTIONS = (
    "Provides helpers around git repositories. Operators can initialize bare repos "
    "and list them. WARNING: this build intentionally mirrors CVE GHSA-3q26-f695-pp76."
)
REPO_ROOT = Path(os.environ.get("CH08_REPO_ROOT", Path(__file__).resolve().parent / "repos"))

log = logging.getLogger("challenge08.vulnerable")

mcp = FastMCP(
    name=APP_NAME,
    instructions=INSTRUCTIONS,
    streamable_http_path="/mcp/stream",
)
mcp.app = mcp.streamable_http_app()


def _ensure_repo_root() -> None:
    REPO_ROOT.mkdir(parents=True, exist_ok=True)


def _run_shell(command: str) -> subprocess.CompletedProcess[str]:
    """Wrapper so tests can monkeypatch command execution."""
    return subprocess.run(
        command,
        shell=True,
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
    """Initialize a bare git repo. Vulnerable: repo_name is interpolated into a shell command."""
    _ensure_repo_root()
    target = REPO_ROOT / repo_name
    if target.exists():
        shutil.rmtree(target, ignore_errors=True)
    command = f"git init --bare {target}"
    log.info("Executing command: %s", command)
    result = _run_shell(command)
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
    log.info("Starting vulnerable git MCP server on %s:%s (root=%s)", host, port, REPO_ROOT)
    uvicorn.run("server:mcp.app", host=host, port=port, log_level="info")
