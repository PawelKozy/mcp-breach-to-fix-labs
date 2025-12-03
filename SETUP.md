# MCP Client Setup Guide

This guide walks you through connecting MCP clients (Cursor, Claude Desktop, or MCP Inspector) to the challenge servers. All challenges expose their MCP servers over HTTP at `http://localhost:<port>/mcp/stream` using the SSE (Server-Sent Events) transport.

## Prerequisites

- Docker & Docker Compose installed
- An MCP-compatible client (Cursor, Claude Desktop, or MCP Inspector)
- Challenge server running via `docker compose up <service-name>`

## Quick Reference

| Challenge | Vulnerable Port | Secure Port | Docker Service (vulnerable) |
|-----------|----------------|-------------|----------------------------|
| 01 - Multi-Tenant Authorization | 8001 | 9001 | `challenge-01-vulnerable` |
| 02 - Filesystem Prefix Bypass | 8002 | 9002 | `filesystem-bypass-prefix-vulnerable` |
| 03 - Hidden Instructions (Helper) | 8003 | — | `whatsapp-rug-helper` |
| 03 - Hidden Instructions (WhatsApp) | 8004 | 9004 | `whatsapp-rug-whatsapp-vulnerable` |
| 04 - Xata Read-Only Bypass | 8020 | 9020 | `xata-readonly-bypass-vulnerable` |
| 05 - News Prompt Exfiltration | 8005 | 9005 | `news-prompt-exfiltration-vulnerable` |
| 06 - Log Poisoning | 8006 | 9006 | `log-poisoning-incident-vulnerable` |
| 07 - SQL Injection Stored Prompt | 9007 | 9907 | `sql-stored-prompt-vulnerable` |
| 08 - Git Command Injection | 8008 | 9008 | `git-command-injection-vulnerable` |
| 09 - GitHub Public Issue Injection | 8009 | 9009 | `github-public-issue-vulnerable` |
| 10 - Tool Description Poisoning | 8010 | 9010 | `challenge-10-vulnerable` |

> **Note:** Challenge 04 uses port 8020/9020 (not 8004/9004) because Challenge 03 requires two services.

---

## Option 1: Cursor IDE (Recommended)

**Cursor** is the most common MCP client for security engineers—it combines VS Code functionality with native Claude integration.

### Installation

1. Download Cursor from [cursor.sh](https://cursor.sh/)
2. Install and launch Cursor


### Connecting to a Challenge Server

1. **Start a challenge server**:
   ```bash
   docker compose up git-command-injection-vulnerable
   # Server exposes MCP at http://localhost:8008/mcp/stream
   ```

2. **Open MCP Settings in Cursor**:
   - Navigate to **File** → **Preferences** → **Tools & MCP**
   - Click **New MCP Server**

3. **Add the server configuration**:
   ```json
   {
     "mcpServers": {
       "git-command-injection-vulnerable": {
         "type": "streamable-http",
         "url": "http://localhost:8008/mcp/stream"
       }
     }
   }
   ```

4. **Start exploiting**:
   - Follow the exploit walkthrough in the challenge's `README.md`
   - Paste MCP JSON-RPC payloads directly into the chat

### Connecting Multiple Servers

You can add both vulnerable and secure servers simultaneously to compare behavior:

```json
{
  "mcpServers": {
    "git-vulnerable": {
      "type": "streamable-http",
      "url": "http://localhost:8008/mcp/stream"
    },
    "git-secure": {
      "type": "streamable-http",
      "url": "http://localhost:9008/mcp/stream"
    }
  }
}
```

Claude can use tools from all configured servers simultaneously. This is useful for comparing vulnerable vs. secure behavior side-by-side.

---

## Option 2: Claude Desktop

**Claude Desktop** is Anthropic's standalone MCP client. It's ideal if you want to test exploits without the full IDE.

### Installation

1. Download Claude Desktop:
   - **Windows**: [Download from Anthropic](https://claude.ai/download)
   - **Mac**: `brew install --cask claude`
   - **Linux**: Not officially supported (use Cursor or MCP Inspector)

2. Launch Claude Desktop and sign in

### Connecting to a Challenge Server

1. **Locate the config file**:
   - **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
   - **Mac**: `~/Library/Application Support/Claude/claude_desktop_config.json`

2. **Edit the config** (create if it doesn't exist):
   ```json
   {
     "mcpServers": {
       "filesystem-prefix-bypass": {
         "type": "streamable-http",
         "url": "http://localhost:8002/mcp/stream"
       }
     }
   }
   ```

3. **Start the challenge server**:
   ```bash
   docker compose up filesystem-prefix-bypass-vulnerable
   ```

4. **Restart Claude Desktop** completely (quit and relaunch)

5. **Test the connection**:
   - Ask: "What MCP tools are available?"
   - Claude should list tools like `list_files`, `read_file`, `read_file_contents`

6. **Run the exploit**:
   - Follow the challenge's `README.md` exploit walkthrough
   - Example: "List files in `safe_files_sensitive` using the `list_files` tool"

### Troubleshooting

- **"No tools available"**: Ensure the Docker container is running and the port matches
- **Connection refused**: Check that the server is bound to `0.0.0.0` (not just `127.0.0.1`)
- **Config ignored**: Verify the JSON syntax is correct and the file is saved

---

## Option 3: MCP Inspector (Debugging & Validation)

**MCP Inspector** is the official debugging tool for MCP servers. Use it to:
- Validate that your MCP server exposes tools correctly
- Test tool invocations without an AI model in the loop
- Inspect raw JSON-RPC messages

### Installation

```bash
npm install -g @modelcontextprotocol/inspector
# Or use npx (no install required):
npx @modelcontextprotocol/inspector
```

### Using the Inspector

1. **Start a challenge server**:
   ```bash
   docker compose up xata-readonly-bypass-vulnerable
   # Server available at http://localhost:8004/mcp/stream
   ```

2. **Launch the inspector**:
   ```bash
   npx @modelcontextprotocol/inspector http://localhost:8004/mcp/stream
   ```

   Output:
   ```
   MCP Inspector
   Connected to: http://localhost:8004/mcp/stream
   
   Available tools:
   - execute_query(query: string): Execute a SQL query
   
   Type 'help' for commands
   ```

3. **List available tools**:
   ```
   > tools
   [
     {
       "name": "execute_query",
       "description": "Execute a SQL query against the read-only replica",
       "inputSchema": { "type": "object", "properties": { ... } }
     }
   ]
   ```

4. **Invoke a tool manually**:
   ```
   > call execute_query {"query": "SELECT * FROM users; COMMIT; DELETE FROM users WHERE id > 0;"}
   
   Result:
   {
     "content": [
       {
         "type": "text",
         "text": "Query executed successfully\n\n| id | name | email |\n|-----|------|-------|\n..."
       }
     ]
   }
   ```

5. **Inspect raw JSON-RPC**:
   ```
   > raw
   --> {"jsonrpc": "2.0", "method": "tools/call", "params": {...}, "id": 1}
   <-- {"jsonrpc": "2.0", "result": {...}, "id": 1}
   ```

### Use Cases

- **Challenge development**: Verify your server exposes tools correctly before testing with Claude
- **Exploit validation**: Confirm that payloads trigger the vulnerability at the protocol level
- **Mitigation testing**: Ensure the secure server rejects malicious inputs with proper error messages

---

## Troubleshooting

### Connection Issues

**Problem**: "Connection Refused" or "ECONNREFUSED"

**Fix**:
1. Verify the container is running: `docker compose ps`
2. Check server logs: `docker compose logs <service-name>`
3. Ensure the correct port is used (see Quick Reference table above)

### Challenge-Specific Issues

- **Challenge 03 (Hidden Instructions)**: Requires TWO servers running (`helper` on 8013, `whatsapp-vulnerable` on 8003)
- **Challenge 04 (Xata)**: Requires PostgreSQL database container (`xata-db`) to be running
- **Challenge 10 (Tool Poisoning)**: Tool description mutates after first call—restart the server to reset

---

## Security Notes

⚠️ **These servers are intentionally vulnerable.** Do not:
- Expose them to the internet (bind to `localhost` only)
- Run them on production systems
- Use them with real credentials or sensitive data

✅ **Safe usage**:
- Run in isolated Docker containers (as configured in `docker-compose.yml`)
- Use on local development machines or dedicated lab VMs
- Connect only from `localhost` MCP clients

---

## Next Steps

1. **Pick a challenge** from the [main README](./README.md)
2. **Start the vulnerable server**: `docker compose up <challenge>-vulnerable`
3. **Configure your MCP client** using the examples above
4. **Follow the exploit walkthrough** in the challenge's `README.md`
5. **Test the secure version** to see how mitigations block the attack

For detailed exploitation steps, see each challenge's `README.md` file.
