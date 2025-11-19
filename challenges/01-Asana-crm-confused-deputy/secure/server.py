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
DATA_FILE = Path(__file__).resolve().parent / "data" / "projects.json"

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
    """Proxy a CRM project fetch while enforcing tenant ownership."""
    try:
        tenant = _tenant_from_key(api_key)
    except ValueError as exc:
        log.warning("Invalid API key attempt: %s", api_key[:10] + "...")
        return str(exc)

    try:
        project = _crm_fetch(project_id, tenant)
    except KeyError as exc:
        log.warning("Tenant %s failed to access project %s", tenant, project_id)
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
