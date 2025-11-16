# Challenge 10: Regex Log Search DoS

This slot now simulates a real availability bug: an MCP tool that lets analysts run arbitrary regular expressions over large log exports. Without safeguards, attackers submit catastrophic patterns that peg the CPU for tens of seconds, freezing the entire assistant. The secure variant demonstrates timeouts and validation that keep the service responsive.

## Services

| Service name              | Description                                           | Port |
|---------------------------|-------------------------------------------------------|------|
| `challenge-10-vulnerable` | Accepts any regex and runs it across the full log     | 8010 |
| `challenge-10-secure`     | Validates patterns and enforces regex timeouts        | 9010 |

Both services expose `describe_log` (preview samples) and `search_logs(pattern, max_matches)` backed by the same 1.5 MB `requests.log` (including an 8 KB line of repeated `a` characters to make catastrophic backtracking obvious).

## Local Development

```bash
cd challenges/10-regex-dos
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Vulnerable
python vulnerable/server.py

# Secure
python secure/server.py
```

### Docker Compose

```bash
docker compose up challenge-10-vulnerable   # http://localhost:8010/mcp/stream
docker compose up challenge-10-secure       # http://localhost:9010/mcp/stream
```

## Exploit Walkthrough

1. Connect Cursor (or any MCP client) to `http://localhost:8010/mcp/stream`.
2. Call `describe_log` to preview the export.
3. Run a catastrophic regex:
   ```json
   {
     "tool": "search_logs",
     "arguments": {"pattern": "(a+)+$", "max_matches": 5}
   }
   ```
   The vulnerable server forwards the pattern directly to Python's `re` module over the entire log. The `(a+)+$` pattern triggers catastrophic backtracking on the 8 KB line of repeated `a` characters, pegging a CPU core for tens of seconds. Cursor cannot use other tools while this request is stuck - classic regex DoS.
4. Gather proof:
   - The JSON response (if it ever returns) shows a huge `duration_seconds`.
   - Watch the Uvicorn logs: you will see `duration_seconds` taking tens of seconds for the malicious pattern while benign patterns complete in milliseconds.
5. Repeat against `http://localhost:9010/mcp/stream` (secure mode). The same payload now returns immediately with:
   ```
   Pattern rejected: execution exceeded timeout threshold. Refine the regex...
   ```
   Safe patterns such as `INFO user=jane` still succeed, proving the mitigation.

## Secure Design Principles Demonstrated

1. **Validate regexes** - reject overly long patterns or those with suspicious nesting before execution.
2. **Enforce timeouts** - leverage the `regex` module's per-call timeout so catastrophic backtracking cannot monopolize the worker.
3. **Fail fast** - respond with actionable guidance instead of letting abusive filters freeze the MCP session.

This DoS challenge replaces the original prompt-injection warm-up and ensures the workshop now covers availability attacks alongside confidentiality/integrity bugs.
