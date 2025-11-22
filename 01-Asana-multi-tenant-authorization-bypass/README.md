# Challenge 01: Multi-Tenant Authorization Bypass

https://www.upguard.com/blog/asana-discloses-data-exposure-bug-in-mcp-server
This challenge reproduces a category of multi-tenant authorization vulnerabilities similar to patterns disclosed in real-world MCP integrations (including references to Asana's MCP). While we don't have access to the actual vulnerable code from those incidents, this challenge demonstrates a common pattern: **an MCP proxy that authenticates users but fails to authorize resource access based on tenant ownership**.

The vulnerable server authenticates API keys correctly but never verifies that the requested project belongs to the caller's tenant. By exploiting predictable project IDs (`CRM-1001`, `CRM-2001`), an attacker with valid credentials for Tenant B can access Tenant A's confidential data, including `FLAG{confused_deputy_leak}`.

**Bonus vulnerability**: The error messages differ for 'not found' vs 'unauthorized', allowing attackers to enumerate valid project IDs even when access is blocked.

The secure server fixes this by enforcing tenant-scoped authorization checks and returning consistent error messages for all unauthorized access attempts.

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

## Credential Reference

- **Tenant Alpha**: `api_key=alpha-api-key`, owns project `CRM-1001` (Customer Onboarding Playbook)
- **Tenant Bravo**: `api_key=bravo-api-key`, owns project `CRM-2001` (M&A Dossier - contains flag)

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
   The server **authenticates** the API key (confirms it's valid) but **never authorizes** the access (doesn't check if CRM-1001 belongs to tenant_bravo). It happily returns Alpha's project data. Use `CRM-2001` to exfiltrate Bravo's dossier with `FLAG{confused_deputy_leak}` in the `notes` field to prove cross-tenant exposure.
5. Repeat against the secure endpoint (`http://localhost:9001/mcp/stream`). The secure `fetch_project` rejects any project whose tenant doesn't match the caller, even if you guess the ID correctly.

## Secure Design Principles Demonstrated

### Primary Fix: Authorization Enforcement
- **Server-side tenant scoping** - Every project lookup verifies that `project.tenant` matches the caller's tenant before returning data. This is the core fix that prevents unauthorized cross-tenant access.

### Defense-in-Depth Improvements
- **Consistent error responses** - The secure version returns identical "not found" errors for both non-existent projects and unauthorized access attempts, preventing attackers from enumerating valid project IDs through error message differences.
- **Comprehensive audit logging** - All access attempts, including failures, are logged with tenant context to enable detection of enumeration attacks and unauthorized access patterns.
- **Per-tenant service tokens (defined but not fully utilized)** - The secure version defines per-tenant backend credentials as a defense-in-depth pattern. In production, you'd use these to make downstream API calls with least-privilege credentials specific to each tenant.

### Additional Production Considerations
- **Use non-sequential IDs** - While this demo uses predictable IDs (`CRM-1001`, `CRM-2001`) to clearly illustrate the vulnerability, production systems should use UUIDs or cryptographically random identifiers to make enumeration attacks infeasible.
- **Rate limiting** - Implement rate limits on failed access attempts to slow down brute-force enumeration attacks.
- **Runtime isolation** - Real deployments should consider isolating processes/containers per tenant to reinforce security boundaries at the infrastructure level.

### Testing
- **Cross-tenant regression tests** - See `tests/challenges/01_crm_confused_deputy/test_worker_cache_leak.py` for automated tests that verify the vulnerability in the unsafe version and confirm it's fixed in the secure version.

Use this challenge to practice identifying multi-tenant authorization bypasses in MCP tools and understand the layered mitigations required to prevent them.
