# MCP-breach-to-fix-labs

Hands-on lab of ten Model Context Protocol (MCP) challenges reproduced from real CVEs and public incident reports. I’ve run every exploit end-to-end with Cursor, so the steps aren’t theoretical—they’re the exact tool calls the assistants followed. Every scenario ships in two modes:

- **Vulnerable** - intentionally exploitable implementation you can reproduce end-to-end in Cursor/Codex.
- **Secure** - minimal fix focusing on the specific control the incident highlighted (not a "perfect" rewrite).

These labs were fully battle-tested with Claude/Cursor, ensuring the exact exploit/mitigation flow is reproducible.

Each challenge includes Docker services, FastMCP servers, fixtures, pytest regressions, and screenshots that prove the exploit really runs-no theoretical write-ups.

## Challenge Catalog

| # | Challenge | Scenario Highlights |
|---|-----------|---------------------|
| 01 | CRM Confused Deputy | Shared CRM token + predictable IDs leak other tenants’ records. Secure version scopes credentials per tenant. |
| 02 | Filesystem Prefix Bypass (CVE-2025-53110) | Naive `startswith` path check vs. canonical path enforcement. |
| 03 | WhatsApp MCP Rug Pull | Tool descriptions change after approval to exfiltrate chat history; secure build freezes definitions. |
| 04 | Xata Read-Only Bypass | Multi-statement SELECT; attacker appends `DELETE` to mutate data. Secure build uses sqlparse to enforce single statements. |
| 05 | News Prompt Exfiltration | Malicious article tells the agent to dump config + email it back. Secure build sanitizes remote HTML and gates tools. |
| 06 | Log Poisoning Incident Response | SOC “instructions” inside logs coerce the agent to rotate secrets to attacker-controlled values. Secure build strips directives & blocks sensitive tickets. |
| 07 | Classic SQL Injection (Stored Prompt) | Ticketing app stores malicious prompts via SQLi; secure build parameterizes. |
| 08 | Git Command Injection (GHSA-3q26-f695-pp76) | `git init` helper shells out with unsanitized repo names; secure uses execFile / allowlist. |
| 09 | GitHub Public Issue Injection | Public issue text tricks MCP to leak private repo data; secure build sanitizes + scopes tokens. |
| 10 | Regex Log Search DoS | Analyst regex tool allows catastrophic backtracking; secure build validates patterns and enforces timeouts with `regex`. |

Each challenge stores proof captures under `challenges/<nn>-<slug>/screenshots/` for quick reference.

## Getting Started

```bash
# install deps and run pytest
python -m venv .venv && source .venv/bin/activate
pip install -r challenges/01-Asana-crm-confused-deputy/requirements.txt  # repeat per challenge if needed
python -m pytest tests
```

### Running a Challenge with Docker Compose

Every challenge registers two services in `docker-compose.yml` named `challenge-<nn>-<mode>`.

```bash
# vulnerable CRM proxy on http://localhost:8001/mcp/stream
docker compose up filesystem-bypass-prefix-vulnerable

# hardened build on http://localhost:9001/mcp/stream
docker compose up filesystem-bypass-prefix-secure
```

Swap `<nn>` to launch other scenarios. Compose images are lightweight (`python:3.10-slim`) and self-contained.

### Local Iteration

```bash
uvicorn server:mcp.app --reload --app-dir challenges/06-log-poisoning-incident-response/vulnerable
```

The same command works for secure builds by changing the path.

## Project Structure

```
challenges/
  01-Asana-crm-confused-deputy/
    vulnerable|secure/            # FastMCP servers + Dockerfiles
    data/                         # Shared fixtures
  ...
assets/
  screenshots/challenge-*/        # Evidence captured from real runs
tests/
  challenges/<nn>_<slug>/         # Pytest coverage for each exploit & fix
```

## Philosophy

- **Real exploits**: Every README includes the exact MCP calls we used in Codex to trigger the issue.
- **Documented fixes**: Secure builds focus on the control that stopped the real incident (least privilege, sanitization, validation, etc.).
- **Automated proofs**: Pytest suites assert that the vulnerable behavior still reproduces and the secure behavior blocks it.

---

Pull requests welcome—add a new scenario by mirroring the existing pattern (vulnerable + secure servers, README, Dockerfiles, pytest).
