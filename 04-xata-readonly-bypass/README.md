# Challenge 04: Xata Read-Only Bypass

This scenario recreates the xata-mcp vulnerability disclosed by Node.js Security. The MCP server proxies user-supplied SQL to a Postgres read replica and attempts to enforce read-only semantics by wrapping queries in `BEGIN TRANSACTION READ ONLY`. However, the Postgres driver (`pg` in Node.js, `psycopg` in Python) executes **multiple statements** when separated by semicolons. An attacker can inject `COMMIT;` to exit the read-only transaction, then execute destructive commands even though the tool advertises "read-only" semantics.

## The Core Vulnerability

The vulnerable code assumes that `BEGIN TRANSACTION READ ONLY` provides absolute protection:

```python
cur.execute("BEGIN TRANSACTION READ ONLY")
cur.execute(sql)  # ← Accepts multiple statements!
```

**Attack vector:** An attacker sends `SELECT * FROM table; COMMIT; DELETE FROM table;` which:
1. Executes the SELECT within the read-only transaction
2. Commits to **exit** the read-only transaction
3. Executes DELETE in a **new implicit transaction** with write permissions

This bypasses the read-only constraint entirely, demonstrating why transaction-level enforcement is insufficient when drivers allow multi-statement execution.

## Services

- `xata-db` - PostgreSQL 15 preloaded with `tenant_documents` containing `FLAG{transaction_commit_escapes_readonly}` under tenant `bravo`.
- `xata-readonly-bypass-vulnerable` - MCP tool `run_query(sql)` that wraps queries in `BEGIN TRANSACTION READ ONLY` but still forwards multi-statement payloads to Postgres.
- `xata-readonly-bypass-secure` - Hardened tool that rejects obvious multi-statement attacks (semicolon check) and enforces `SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY` at the database level as the **primary security control**.

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

1. **Connect** Cursor to `xata-readonly-bypass-vulnerable` at `http://localhost:8020/mcp/stream`.

2. **Verify read access** with a benign SELECT:
   ```json
   {
     "tool": "run_query",
     "arguments": {"sql": "SELECT * FROM tenant_documents"}
   }
   ```
   The server returns both rows (`alpha` and `bravo`), proving read access works. You'll see the FLAG in tenant `bravo`'s document.
![alt text](image.png)
3. **Bypass read-only mode** by escaping the transaction with `COMMIT`:
   ```json
   {
     "tool": "run_query",
     "arguments": {
       "sql": "SELECT 1; COMMIT; DELETE FROM tenant_documents WHERE tenant='bravo';"
     }
   }
   ```
   ![alt text](image-1.png)
   **What happens:**
   - `SELECT 1` executes within the `BEGIN TRANSACTION READ ONLY` 
   - `COMMIT` **exits** that read-only transaction
   - `DELETE FROM tenant_documents WHERE tenant='bravo'` runs in a **new implicit transaction** with default (read-write) permissions
   - The vulnerable server returns success, and tenant `bravo`'s FLAG is **gone**
![alt text](image-2.png)

4. **Test the secure version** by repeating against `xata-readonly-bypass-secure` (`http://localhost:9020/mcp/stream`). The secure tool rejects the payload with "Rejected: Multiple statements not permitted (semicolon detected)" and logs the attempt. The database remains intact because:
   - Basic input validation rejects queries containing semicolons (defense against obvious multi-statement attacks)
   - `SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY` provides the **primary security control** at the database level - even if validation is bypassed, PostgreSQL will reject ALL write operations for the entire session

> **LLM quirk:** During testing, Cursor initially refused to run the multi-statement payload because overly specific tool descriptions (like "Execute a SELECT query against the read-only replica") caused the client to infer that DELETE/INSERT were off-limits and block the request before it reached the server. Using more generic descriptions like "Execute a SQL query" allows you to test the actual server-side vulnerability.

## Secure Design Principles Demonstrated

- **Database-level enforcement (PRIMARY)** - Use `SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY` to enforce read-only at the PostgreSQL session level. This is the **real security boundary** - even if client-side validation is bypassed, the database will reject all write operations.
- **Input validation (SECONDARY)** - Reject queries containing semicolons and non-SELECT statements as a first line of defense. This catches obvious attacks but should never be relied upon as the sole protection.
- **Defense in depth** - Layer client-side validation with server-side database enforcement. If validation has bugs (e.g., comment bypasses, encoding tricks), the database still prevents writes.
- **Auditing** - Log all rejected attempts with truncated query details so security teams can investigate suspicious clients without exposing sensitive data.
- **Sanitized error messages** - Return generic "Query execution failed" to clients while logging detailed errors server-side to prevent information leakage.

### Why Not sqlparse?

Earlier versions of this challenge used `sqlparse` for statement validation. **This was removed** because:
- `sqlparse` is a **formatting library**, not a security tool
- Can be bypassed with SQL comments, CTEs, nested statements, and other dialect-specific tricks
- Gives false confidence that "parsing = security"

**The lesson:** Don't rely on Python libraries to enforce SQL semantics. Let the **database** be the security boundary with proper configuration (`SET SESSION ... READ ONLY`, read-only database users, or database-level permissions).

## Real-World Impact

This vulnerability class has appeared in multiple MCP servers beyond Xata:
- **Data loss:** Attackers delete production data in supposedly "read-only" analytics tools
- **Privilege escalation:** Execute `CREATE USER` or `GRANT` statements via "SELECT-only" interfaces
- **Denial of service:** Run `SET statement_timeout TO 1` or terminate backend processes with `pg_terminate_backend()`
- **Compliance violations:** Unauthorized data modification triggers audit failures and regulatory penalties

The root cause is a **dangerous assumption**: developers trust that database drivers will honor application-level semantics. In reality, drivers like `pg` (Node.js) and `psycopg` (Python) execute **all statements** in a multi-statement string, regardless of transaction state.

## References

- [Original disclosure by Node.js Security](https://www.nodejs-security.com/blog/sql-injection-and-bypassing-read-only-mode-in-xata-mcp-server)
- [GitHub Security Advisory GHSA-w22h-m48w-8jgw](https://github.com/xataio/agent/security/advisories/GHSA-w22h-m48w-8jgw)
- [Xata's fix: Complete removal of flawed MCP server](https://github.com/xataio/agent/commit/30aecbcf95390594fbef3a2ab5504118982e4e7e)

The sample Postgres instance is seeded with `FLAG{transaction_commit_escapes_readonly}` under tenant `bravo`. After running the exploit with `COMMIT; DELETE ...`, the FLAG is deleted, demonstrating that transaction-level read-only mode alone cannot prevent data mutation when multi-statement execution is allowed.
