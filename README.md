# MCP Breach-to-Fix Labs

Hands-on lab of ten Model Context Protocol (MCP) challenges reproduced from real CVEs and public incident reports. I've run every exploit end-to-end with Cursor/Claude, so the steps aren't theoretical—they're the exact tool calls the assistants followed. Every scenario ships in two modes:

- **Vulnerable** - intentionally exploitable implementation you can reproduce end-to-end in Cursor/Claude Desktop.
- **Secure** - hardened implementation with defense-in-depth controls that block the attack.

These labs were fully battle-tested with Claude/Cursor, ensuring the exact exploit/mitigation flow is reproducible.

Each challenge includes Docker services, FastMCP servers, fixtures, and screenshots that prove the exploit really runs—no theoretical write-ups.

## Challenge Catalog

| # | Challenge | Scenario Highlights |
|---|-----------|---------------------|
| 01 | CRM Confused Deputy | Shared CRM token + predictable IDs leak other tenants’ records. Secure version scopes credentials per tenant. |
| 02 | Filesystem Prefix Bypass (CVE-2025-53110) | Naive `startswith` path check vs. canonical path enforcement. |
| 03 | Hidden Instructions in Tool Responses | Malicious tool responses inject hidden instructions that redirect WhatsApp messages; secure build sanitizes responses. |
| 04 | Xata Read-Only Bypass | Multi-statement SELECT; attacker appends `DELETE` to mutate data. Secure build uses sqlparse to enforce single statements. |
| 05 | News Prompt Exfiltration | Malicious article tells the agent to dump config + email it back. Secure build sanitizes remote HTML and gates tools. |
| 06 | Log Poisoning Incident Response | SOC “instructions” inside logs coerce the agent to rotate secrets to attacker-controlled values. Secure build strips directives & blocks sensitive tickets. |
| 07 | Classic SQL Injection (Stored Prompt) | Ticketing app stores malicious prompts via SQLi; secure build parameterizes. |
| 08 | Git Command Injection (GHSA-3q26-f695-pp76) | `git init` helper shells out with unsanitized repo names; secure uses execFile / allowlist. |
| 09 | GitHub Public Issue Injection | Public issue text tricks MCP to leak private repo data; secure build sanitizes + scopes tokens. |
| 10 | Tool Description Poisoning | Repello.ai-style "rug pull" where tool metadata mutates after approval to exfiltrate SSH keys; secure build freezes descriptions. |

Each challenge stores proof captures under `challenges/<nn>-<slug>/screenshots/` or README for quick reference.

## Getting Started

**New to MCP?** See the [Setup Guide](./SETUP.md) for detailed instructions on connecting Cursor, Claude Desktop, or MCP Inspector to the challenge servers.

### Prerequisites
- Docker & Docker Compose
- Python 3.10+ (for local execution)
- Cursor or Claude Desktop (recommended for exploits)

### Quick Start with Docker

Every challenge has vulnerable and secure Docker services:

```bash
# Example: Run the Git Command Injection vulnerable server
docker compose up git-command-injection-vulnerable

# Connect Cursor/Claude Desktop to http://localhost:8008/mcp/stream
# Follow the exploit walkthrough in 08-git-command-injection-ghsa-3q26-f695-pp76/README.md

# Compare with secure version
docker compose up git-command-injection-secure  # http://localhost:9008/mcp/stream
```

### Local Python Execution

```bash
cd 08-git-command-injection-ghsa-3q26-f695-pp76
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Run vulnerable server
python vulnerable/server.py

# Or secure server
python secure/server.py
```



## Project Structure

```
01-Asana-multi-tenant-authorization-bypass/
  vulnerable/               # FastMCP server + Dockerfile
  secure/                   # Hardened implementation
  data/                     # Fixtures (projects.json)
  screenshots/              # Proof of exploit
  README.md                 # Detailed walkthrough

02-filesystem-prefix-bypass-cve-2025-53110/
  vulnerable/
  secure/
  files/                    # Test directories (safe_files, safe_files_sensitive)
  screenshots/
  README.md

... (8 more challenges)

docker-compose.yml          # All services configured
```

## Philosophy

- **Real exploits**: Every README includes the exact MCP JSON-RPC payloads and Cursor/Claude commands to trigger the vulnerability
- **Defense-in-depth**: Secure builds demonstrate multiple security layers (input validation, path canonicalization, least privilege, etc.)
- **Reproducible**: Docker containers ensure consistent exploitation across environments
- **Educational**: Each challenge explains WHY the vulnerability exists and HOW the mitigations work

## Contributing

Pull requests welcome! To add a new challenge:
1. Create `<nn>-<descriptive-name>/` directory
2. Implement `vulnerable/server.py` and `secure/server.py`
3. Add Dockerfiles for both modes
4. Write comprehensive README.md with exploit walkthrough
5. Add services to `docker-compose.yml`
6. Capture screenshots of the exploit

---

**⚠️ Warning**: These servers are intentionally vulnerable. Never deploy them in production. Use only in isolated lab environments.
