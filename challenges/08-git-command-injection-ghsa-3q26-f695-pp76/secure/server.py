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
# Remove dots to prevent path traversal; only allow alphanumeric, underscore, dash
SAFE_REPO_NAME = re.compile(r"^[A-Za-z0-9_-]+$")
MAX_REPO_NAME_LENGTH = 100

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
    """Validate and sanitize repository name to prevent command injection and path traversal."""
    # Input validation
    if not repo_name or not repo_name.strip():
        raise ValueError("Repository name cannot be empty")
    
    if len(repo_name) > MAX_REPO_NAME_LENGTH:
        raise ValueError(f"Repository name too long (max {MAX_REPO_NAME_LENGTH} characters)")
    
    # Pattern validation (no shell metacharacters, no dots for traversal)
    if not SAFE_REPO_NAME.fullmatch(repo_name):
        raise ValueError(
            "Invalid repository name. Use only letters, numbers, underscores, or dashes."
        )
    
    # Path traversal prevention - ensure resolved path stays under REPO_ROOT
    target = REPO_ROOT / repo_name
    try:
        resolved = target.resolve()
        repo_root_resolved = REPO_ROOT.resolve()
        
        # Check if resolved path is actually under REPO_ROOT
        if not resolved.is_relative_to(repo_root_resolved):
            log.warning("SECURITY: Path traversal attempt blocked: %s", repo_name)
            raise ValueError("Path traversal detected")
    except (ValueError, OSError) as e:
        log.warning("SECURITY: Invalid repository path: %s - %s", repo_name, e)
        raise ValueError("Invalid repository path")
    
    return target


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
    """Initialize a bare git repo using safe subprocess invocation and input validation."""
    _ensure_repo_root()
    try:
        target = _sanitize_repo_name(repo_name)
    except ValueError as exc:
        log.warning("Rejected repository creation: %s", exc)
        return str(exc)
    
    # Remove existing repository safely
    if target.exists():
        # Security check: ensure it's not a symlink
        if target.is_symlink():
            log.warning("SECURITY: Refusing to remove symlink: %s", target)
            return "Error: Repository path is a symlink"
        
        # Double-check path containment before destructive operation (prevent TOCTOU)
        try:
            resolved = target.resolve()
            if not resolved.is_relative_to(REPO_ROOT.resolve()):
                log.warning("SECURITY: Path escape detected before removal: %s", target)
                return "Error: Path validation failed"
        except (ValueError, OSError) as e:
            log.warning("SECURITY: Path resolution failed: %s", e)
            return "Error: Invalid path"
        
        # Safe removal with error handling
        try:
            shutil.rmtree(target)
            log.info("Removed existing repository: %s", repo_name)
        except OSError as e:
            log.error("Failed to remove existing repository %s: %s", repo_name, e)
            return f"Error: Cannot remove existing repository: {e}"
    
    # Execute git with safe argument list (no shell interpolation)
    args = ["git", "init", "--bare", str(target)]
    log.info("Executing secure git command: %s", args)
    result = _run_git(args)
    return _format_result(result)


@mcp.tool()
def list_repositories() -> str:
    """List bare repositories with safety limits."""
    _ensure_repo_root()
    
    try:
        # Only list actual directories, not symlinks (prevent symlink attacks)
        entries = [
            p.name
            for p in REPO_ROOT.iterdir()
            if p.is_dir() and not p.is_symlink()
        ]
        
        if not entries:
            return "No repositories yet."
        
        # Sort and limit results to prevent resource exhaustion
        MAX_REPOS_TO_LIST = 1000
        sorted_entries = sorted(entries)
        
        if len(sorted_entries) > MAX_REPOS_TO_LIST:
            log.warning("Repository list truncated: %d total", len(sorted_entries))
            return (
                f"Showing first {MAX_REPOS_TO_LIST} of {len(sorted_entries)} repositories:\n"
                + "\n".join(sorted_entries[:MAX_REPOS_TO_LIST])
            )
        
        return "\n".join(sorted_entries)
    except OSError as e:
        log.error("Error listing repositories: %s", e)
        return "Error: Unable to list repositories"


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
