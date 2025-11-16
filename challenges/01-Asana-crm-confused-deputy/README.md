# Challenge 01: Predictable CRM IDs (Confused Deputy)

Based on the Asana MCP disclosure and similar SaaS bugs, this challenge shows how a multi-tenant MCP proxy can expose another customer's CRM data when it uses a single high-privilege service token and fails to verify tenant ownership. The vulnerable server accepts any `project_id`, forwards it to the CRM backend with a shared token, and returns whatever comes back. Because project IDs are predictable (e.g., `CRM-2001`), an attacker can list global IDs and fetch another tenant's dossier, including `FLAG{confused_deputy_leak}`.

The secure server closes the gap with per-tenant tokens, server-side scoping (`WHERE tenant_id = ?` checks), and careful filtering of project lists.

## Running the Challenge

```bash
cd challenges/01-Asana-crm-confused-deputy
python -m venv .venv && source .venv/bin/activate  # optional
pip install -r requirements.txt

# Vulnerable server on :8000
python vulnerable/server.py

# Secure server on :8000
python secure/server.py
```

### Docker Compose

```bash
docker compose up challenge-01-vulnerable   # http://localhost:8001/mcp/stream
docker compose up challenge-01-secure       # http://localhost:9001/mcp/stream
```

## Exploit Walkthrough (Cursor-Friendly)

1. Connect Cursor to the vulnerable endpoint (`http://localhost:8001/mcp/stream`).
2. Ask for available tools (only `fetch_project` is exposed).
3. As Tenant Alpha (legitimate user), fetch your own project to learn the ID pattern:
   ```json
   {
     "tool": "fetch_project",
     "arguments": { "project_id": "CRM-1001", "api_key": "alpha-api-key" }
   }
   ```
   You receive the expected payload for Tenant Alpha. Because IDs are incremental (`CRM-xxxx`), an attacker can easily guess other IDs.
4. Now impersonate Tenant Bravo (attacker) and fetch Alpha's project:
   ```json
   {
     "tool": "fetch_project",
     "arguments": { "project_id": "CRM-1001", "api_key": "bravo-api-key" }
   }
   ```
   Because the proxy uses the same high-privilege token for everyone, it happily returns Alpha's project data. Use `CRM-2001` to exfiltrate Bravo's dossier with `FLAG{confused_deputy_leak}` to prove cross-tenant exposure.
5. Repeat against the secure endpoint (`http://localhost:9001/mcp/stream`). The secure `fetch_project` rejects any project whose tenant doesn't match the caller, even if you guess the ID correctly.

## Secure Design Principles Demonstrated

- **Server-side scoping** - Every project lookup verifies that `project.tenant` matches the caller's tenant before returning data.
- **Per-tenant service credentials** - The secure proxy derives a unique service token per tenant. Even if an attacker guessed the ID, the downstream CRM rejects requests signed with the wrong token.
- **Runtime isolation** - The secure server never reuses global caches for multiple tenants; it filters ID listings and only decrypts blobs scoped to the active tenant. Real deployments would isolate processes/containers per tenant to reinforce this behavior.
- **Cross-tenant regression tests** - See `tests/challenges/01_crm_confused_deputy/test_worker_cache_leak.py` for a reproducible leak demonstration (vulnerable build) and the locked-down behavior (secure build).

Use this challenge to practice spotting predictable-ID/"confused deputy" flaws in MCP tools and to reinforce the mitigations Asana and similar vendors now apply: tenant-aware queries, scoped credentials, and runtime state hygiene.
