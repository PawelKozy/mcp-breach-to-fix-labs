# Challenge 08: Command Injection in MCP CLI Wrappers

**CVE References:**
- [GHSA-3q26-f695-pp76](https://github.com/advisories/GHSA-3q26-f695-pp76) - Git MCP Server
- [GHSA-4hqq-7q79-932p](https://github.com/advisories/GHSA-4hqq-7q79-932p) - Kubernetes MCP Server (CVE-2025-59377)

This challenge demonstrates a **critical vulnerability pattern** found in multiple production MCP servers. Both the Git MCP server (`@cyanheads/git-mcp-server`) and Kubernetes MCP server (`feiskyer/mcp-kubernetes-server`) made the same deadly mistake: concatenating user-supplied arguments into shell commands executed with `subprocess.run(shell=True)`.

Our implementation recreates the Git variant, but the vulnerability class applies to any MCP server wrapping CLI tools. Attackers can smuggle shell metacharacters (e.g., `&& python -c ...`, `; curl`, `$(command)`) to execute arbitrary commands under the MCP server's privileges. We provide vulnerable and secure builds so you can prove the exploit with any MCP client (Cursor, Claude Desktop, MCP Inspector, etc.).

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

The secure server implements **defense-in-depth** with multiple security layers:

### 1. Input Validation (Defense Layer 1)
```python
MAX_REPO_NAME_LENGTH = 100
SAFE_REPO_NAME = re.compile(r"^[A-Za-z0-9_-]+$")  # No dots, no shell chars

# Validates:
- Empty or whitespace-only names
- Length limits (max 100 characters)
- Only alphanumeric, underscore, dash (no dots to prevent path traversal)
- No shell metacharacters (&&, ;, |, $, `, etc.)
```

### 2. Path Traversal Prevention (Defense Layer 2)
```python
# Resolve paths and ensure they stay under REPO_ROOT
resolved = target.resolve()
if not resolved.is_relative_to(REPO_ROOT.resolve()):
    raise ValueError("Path traversal detected")
```

### 3. Safe Subprocess Invocation (Defense Layer 3 - PRIMARY)
```python
# Use argument list instead of shell string
args = ["git", "init", "--bare", str(target)]
subprocess.run(args, shell=False)  # No shell interpolation!
```

### 4. Symlink Attack Prevention (Defense Layer 4)
```python
# Refuse to remove or list symlinks
if target.is_symlink():
    return "Error: Repository path is a symlink"
```

### 5. Error Handling (Defense Layer 5)
```python
try:
    shutil.rmtree(target)  # No silent failures
except OSError as e:
    return f"Error: Cannot remove existing repository: {e}"
```

Repeating the exploit against the secure server:
- **Input validation** rejects shell metacharacters like `&&`
- **Path traversal checks** block attempts to escape REPO_ROOT
- **Safe subprocess invocation** treats the entire string as a literal repo name
- Attack returns `Invalid repository name...` and nothing executes

## Defensive Takeaways

**Why This Pattern is Widespread:** Many MCP servers act as bridges to existing CLI tools (git, kubectl, docker, terraform, etc.). Developers often reach for `shell=True` because it's convenient for string interpolation, not realizing it creates a Remote Code Execution vector. The fact that both Git and Kubernetes MCP servers independently made this mistake shows how easy it is to get wrong.

1. **Never use shell=True with user input** - The vulnerable server uses `subprocess.run(command, shell=True)` which invokes a shell interpreter. Always use argument lists: `subprocess.run(["git", "init", ...], shell=False)`. This is the PRIMARY defense against command injection.

2. **Validate input format strictly** - Use allowlists (regex patterns) instead of blocklists. The secure version only allows `[A-Za-z0-9_-]+` which eliminates both shell metacharacters AND path traversal attempts.

3. **Prevent path traversal separately** - Even with safe subprocess invocation, validate that resolved paths stay within expected boundaries using `.resolve()` and `.is_relative_to()`.

4. **Protect against symlink attacks** - Symlinks can bypass path restrictions. Check `is_symlink()` before operations and when listing directories.

5. **Length limits prevent resource exhaustion** - Enforce maximum input length (100 chars) and output size (1000 repos) to prevent denial-of-service attacks.

6. **Never bake secrets into Docker images** - The Dockerfiles mount secrets at runtime via volumes (`./secrets:/app/secrets:ro`) instead of `COPY secrets /app/secrets`. Secrets in image layers are permanent and accessible to anyone with pull access.

7. **Fail loudly, not silently** - Use proper error handling instead of `ignore_errors=True`. Log security events for audit trails and monitoring.

8. **Defense-in-depth** - Layer multiple controls: input validation + path checks + safe subprocess + symlink detection + error handling. If one layer fails, others still protect you.

**Real-World Impact:** The Kubernetes variant (GHSA-4hqq-7q79-932p) was rated CVSS 9.8 Critical because it was exploitable by **unauthenticated remote attackers** with no user interaction required. Even "read-only" mode didn't prevent RCE. This demonstrates how command injection remains one of the most dangerous vulnerability classes—it grants attackers complete control over the server process and often the entire host system.

This challenge shows how a "simple" CLI wrapper tool can become remote code execution when subprocess invocation isn't done safely. Any MCP server that wraps shell commands (git, kubectl, docker, aws-cli, terraform, etc.) is vulnerable if using `shell=True` with user-controlled input.
