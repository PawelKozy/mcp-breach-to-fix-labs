"""Challenge 01 - Vulnerable predictable-ID confused deputy."""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Dict, List

from mcp.server.fastmcp import FastMCP

APP_NAME = "Challenge 01: Predictable CRM IDs (Vulnerable)"
INSTRUCTIONS = (
    "Acts as an MCP proxy to a CRM backend. Uses one high-privilege service token for "
    "every request and never verifies that project IDs belong to the caller's tenant."
)
# Support both Docker (/app/data) and local execution (./data relative to challenge root)
DATA_DIR = Path(os.environ.get("DATA_PATH", "/app/data"))
if not DATA_DIR.exists():
    # Fallback for local execution from vulnerable/ directory
    DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DATA_FILE = DATA_DIR / "projects.json"
GLOBAL_CRM_SERVICE_TOKEN = os.environ.get("CH01_GLOBAL_CRM_TOKEN", "crm-service-root-token")

API_KEYS: Dict[str, str] = {
    "alpha-api-key": "tenant_alpha",
    "bravo-api-key": "tenant_bravo",
}

log = logging.getLogger("challenge01.vulnerable")

mcp = FastMCP(
    name=APP_NAME,
    instructions=INSTRUCTIONS,
    streamable_http_path="/mcp/stream",
)
mcp.app = mcp.streamable_http_app()


def _load_projects() -> List[Dict[str, str]]:
    with DATA_FILE.open(encoding="utf-8") as handle:
        return json.load(handle)


def _validate_api_key(api_key: str) -> str:
    tenant = API_KEYS.get(api_key)
    if not tenant:
        raise ValueError("Invalid API key.")
    return tenant


def _crm_fetch(project_id: str, service_token: str) -> Dict[str, str]:
    """Simulate a backend CRM API call.
    
    In a real confused deputy scenario, this 'backend' would be a separate service
    (like Asana's API) that trusts the MCP proxy's service token. The proxy has
    elevated privileges but fails to verify which tenant initiated the request.
    
    The vulnerability: This function returns ANY project as long as the service token
    is valid, without checking tenant ownership.
    """
    # In the vulnerable build, any caller with the shared service token can fetch any project.
    if service_token != GLOBAL_CRM_SERVICE_TOKEN:
        raise PermissionError("Invalid CRM service token.")
    for project in _load_projects():
        if project["project_id"] == project_id:
            return project
    raise KeyError(f"Project {project_id} not found.")


@mcp.tool()
def fetch_project(project_id: str, api_key: str) -> str:
    """Proxy a CRM project fetch without tenant scoping.
    
    The vulnerability: This function authenticates the API key (confirms it's valid)
    but never authorizes the request (doesn't verify the project belongs to the
    caller's tenant). An attacker with valid credentials for Tenant B can request
    projects belonging to Tenant A.
    """
    try:
        # ✓ Authentication: Validates the API key is legitimate
        _validate_api_key(api_key)
    except ValueError as exc:
        return str(exc)

    try:
        # ✗ Authorization missing: Never checks if project belongs to this tenant
        project = _crm_fetch(project_id, GLOBAL_CRM_SERVICE_TOKEN)
    except KeyError as exc:
        return str(exc)
    except PermissionError as exc:
        return str(exc)

    log.warning("Tenant with API key %s fetched project %s", api_key, project_id)
    pretty = json.dumps(project, indent=2)
    return f"Project data:\n{pretty}"


if __name__ == "__main__":
    import uvicorn

    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="[%(asctime)s] %(levelname)s %(name)s: %(message)s",
    )
    host = os.environ.get("CHALLENGE_HOST", "0.0.0.0")
    port = int(os.environ.get("CHALLENGE_PORT", "8000"))
    log.info("Starting vulnerable CRM proxy on %s:%s", host, port)
    uvicorn.run("server:mcp.app", host=host, port=port, log_level="info")
