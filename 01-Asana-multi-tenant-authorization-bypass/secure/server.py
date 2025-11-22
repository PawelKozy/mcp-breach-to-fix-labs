"""Challenge 01 - Secure predictable-ID confused deputy mitigation."""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Dict, List

from mcp.server.fastmcp import FastMCP

APP_NAME = "Challenge 01: Predictable CRM IDs (Secure)"
INSTRUCTIONS = (
    "MCP proxy that enforces tenant scoping, tenant-specific service tokens, and "
    "filters project listings per tenant."
)
# Support both Docker (/app/data) and local execution (./data relative to challenge root)
DATA_DIR = Path(os.environ.get("DATA_PATH", "/app/data"))
if not DATA_DIR.exists():
    # Fallback for local execution from secure/ directory
    DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DATA_FILE = DATA_DIR / "projects.json"

# Note: Per-tenant service tokens are defined here as defense-in-depth but not
# fully utilized in this simplified demo. The PRIMARY fix is authorization enforcement
# (tenant scoping in _crm_fetch). In production, you'd also use these per-tenant tokens
# to make backend API calls with least-privilege credentials specific to each tenant.
TENANT_CONFIG: Dict[str, Dict[str, str]] = {
    "tenant_alpha": {
        "api_key": os.environ.get("CH01_TENANT_ALPHA_KEY", "alpha-api-key"),
        "service_token": os.environ.get("CH01_TENANT_ALPHA_TOKEN", "crm-token-alpha"),
    },
    "tenant_bravo": {
        "api_key": os.environ.get("CH01_TENANT_BRAVO_KEY", "bravo-api-key"),
        "service_token": os.environ.get("CH01_TENANT_BRAVO_TOKEN", "crm-token-bravo"),
    },
}

log = logging.getLogger("challenge01.secure")

mcp = FastMCP(
    name=APP_NAME,
    instructions=INSTRUCTIONS,
    streamable_http_path="/mcp/stream",
)
mcp.app = mcp.streamable_http_app()


def _load_projects() -> List[Dict[str, str]]:
    with DATA_FILE.open(encoding="utf-8") as handle:
        return json.load(handle)


def _tenant_from_key(api_key: str) -> str:
    for tenant, cfg in TENANT_CONFIG.items():
        if cfg["api_key"] == api_key:
            return tenant
    raise ValueError("Invalid API key.")


def _crm_fetch(project_id: str, tenant: str) -> Dict[str, str]:
    """
    Fetch a project from CRM backend with tenant scoping.
    Returns the project only if it belongs to the specified tenant.
    Raises KeyError for both non-existent projects and unauthorized access
    to prevent information disclosure.
    """
    for project in _load_projects():
        if project["project_id"] == project_id:
            if project["tenant"] != tenant:
                # Return same error as "not found" to prevent enumeration
                raise KeyError(f"Project {project_id} not found.")
            return project
    raise KeyError(f"Project {project_id} not found.")


@mcp.tool()
def fetch_project(project_id: str, api_key: str) -> str:
    """Proxy a CRM project fetch while enforcing tenant ownership.
    
    Security fixes:
    1. Authorization added: Validates project belongs to caller's tenant
    2. Consistent errors: Returns same message for 'not found' and 'unauthorized'
       to prevent project ID enumeration
    """
    try:
        tenant = _tenant_from_key(api_key)
    except ValueError as exc:
        log.warning("Invalid API key attempt: %s", api_key[:10] + "...")
        return str(exc)

    try:
        # ✓ Authorization enforced: _crm_fetch verifies project.tenant == tenant
        project = _crm_fetch(project_id, tenant)
    except KeyError as exc:
        log.warning("Tenant %s failed to access project %s", tenant, project_id)
        # Same error message whether project doesn't exist or is unauthorized
        return str(exc)

    log.info("Tenant %s successfully fetched project %s", tenant, project_id)
    return json.dumps(project, indent=2)


if __name__ == "__main__":
    import uvicorn

    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="[%(asctime)s] %(levelname)s %(name)s: %(message)s",
    )
    host = os.environ.get("CHALLENGE_HOST", "0.0.0.0")
    port = int(os.environ.get("CHALLENGE_PORT", "8000"))
    log.info("Starting secure CRM proxy on %s:%s", host, port)
    uvicorn.run("server:mcp.app", host=host, port=port, log_level="info")
