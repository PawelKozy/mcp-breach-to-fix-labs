# Challenge 08: Git Command Injection (GHSA-3q26-f695-pp76)

This module recreates the `@cyanheads/git-mcp-server` advisory (GHSA-3q26-f695-pp76). The original server concatenated user-supplied repository arguments into a `git` shell command. Attackers could smuggle additional shell operators (e.g., `&& python -c ...`) and execute arbitrary commands under the MCP server's privileges. We provide vulnerable and secure builds so you can prove the exploit with any MCP client (Cursor, Claude Desktop, MCP Inspector, etc.).

## Running the Challenge

### Local Python
```bash
cd challenges/08-git-command-injection-ghsa-3q26-f695-pp76
python -m venv .venv && source .venv/bin/activate  # optional
pip install -r requirements.txt

# Vulnerable
python vulnerable/server.py

# Secure
python secure/server.py
```

### Docker Compose
From the repo root:
```bash
docker compose up git-command-injection-vulnerable   # http://localhost:8008/mcp/stream
docker compose up git-command-injection-secure       # http://localhost:9008/mcp/stream
```

## Exploit Walkthrough (Cursor-Friendly)

1. Connect your MCP client to the vulnerable endpoint (`http://localhost:8008/mcp/stream`).
2. Enumerate tools—you should see:
   - `init_bare_repository(repo_name: str)`
   - `list_repositories()`
3. Call `init_bare_repository` with this JSON payload (Cursor lets you paste it directly):
   ```json
   {
     "tool": "init_bare_repository",
     "arguments": {
       "repo_name": "mirror && python -c \"import pathlib;print(pathlib.Path('/app/secrets/deployment_token.txt').read_text())\""
     }
   }
   ```
   The vulnerable server builds `git init --bare /app/.../mirror && python -c ...` and runs it via the shell. Git initializes the repo, then Python prints the secret deployed token (`FLAG{git_command_injection_cve}`).
4. Ask the client to show the tool result—the secret appears in the response stream. `list_repositories()` will still work, but more importantly you proved arbitrary command execution purely from the repo argument.

## Secure Build Behavior

`secure/server.py` addresses the CVE by:

1. Validating `repo_name` with `^[A-Za-z0-9._-]+$` (no shell metacharacters or traversal).
2. Invoking Git with a list of arguments: `["git", "init", "--bare", "/app/repos/<name>"]`. No shell interpolation occurs, so even crafty strings remain literal data.

Repeating the JSON payload above now returns `Invalid repository name...` and nothing executes.

## Files of Interest

- `vulnerable/server.py` – command injection via f-string and `shell=True`.
- `secure/server.py` – sanitizes input and uses safe subprocess arguments.
- `secrets/deployment_token.txt` – the sensitive token you extract in the exploit.
- `tests/challenges/08_git_command_injection/test_git_command_injection.py` – regression showing the vulnerable build leaks the secret while the secure build blocks it.

Use this challenge to highlight how unvalidated CLI arguments inside MCP tools can instantly become remote code execution vectors.***
