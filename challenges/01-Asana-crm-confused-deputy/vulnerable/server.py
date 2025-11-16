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
DATA_FILE = Path(__file__).resolve().parent / "data" / "projects.json"
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
    # In the vulnerable build, any caller with the shared service token can fetch any project.
    if service_token != GLOBAL_CRM_SERVICE_TOKEN:
        raise PermissionError("Invalid CRM service token.")
    for project in _load_projects():
        if project["project_id"] == project_id:
            return project
    raise KeyError(f"Project {project_id} not found.")


@mcp.tool()
def fetch_project(project_id: str, api_key: str) -> str:
    """Proxy a CRM project fetch without tenant scoping."""
    try:
        _validate_api_key(api_key)
    except ValueError as exc:
        return str(exc)

    try:
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
