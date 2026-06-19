[![MseeP.ai Security Assessment Badge](https://mseep.net/pr/r0hitpilla-bcheck-mcp-server-badge.png)](https://mseep.ai/app/r0hitpilla-bcheck-mcp-server)

# Burp BChecks MCP Server

Autonomous BCheck security researcher for Claude Desktop. Reads real HTTP traffic from Burp Suite proxy history, writes custom BCheck DSL scripts targeting exact injection points, deploys them, and runs active scans.

## How It Works

```
Burp proxy traffic
      ↓
get_proxy_http_history  (Burp MCP)
      ↓
analyze_request_tool    → extracts every injection point from raw HTTP
      ↓
Claude writes custom BCheck DSL  (targeted per-request, not templates)
      ↓
write_bcheck_tool       → validates + deploys to bchecks/
      ↓
create_scan_tool → get_scan_status_tool → get_scan_issues_tool
```

## Prerequisites

- Burp Suite Professional
- Python 3.11+
- Claude Desktop

---

## Setup

### 1. Clone the repo

```bash
git clone https://github.com/r0hitpilla/Burp-Bchecks-MCP.git
cd Burp-Bchecks-MCP
```

### 2. Install the package

```bash
pip install -e .
```

Verify:
```bash
which bcheck-mcp
# /home/<user>/.local/bin/bcheck-mcp
```

### 3. Create the bchecks directory

```bash
mkdir -p ~/Burp-Bchecks-MCP/bchecks
```

### 4. Get the Burp MCP proxy jar

Download `mcp-proxy-all.jar` from the [PortSwigger BApp Store](https://portswigger.net/bappstore) or the [Burp MCP GitHub](https://github.com/PortSwigger/mcp-burp-proxy) and place it at:

```
~/.BurpSuite/mcp-proxy/mcp-proxy-all.jar
```

---

## Burp Suite Pro Configuration

### 1. Enable REST API

`Settings` → `Suite` → `REST API` → tick **Service running** → port `1337`

### 2. Start the MCP proxy

The MCP proxy bridges Burp's internal API over SSE on port 9876. Start Burp Pro first, then:

```bash
/path/to/BurpSuitePro/jre/bin/java \
  -jar ~/.BurpSuite/mcp-proxy/mcp-proxy-all.jar \
  --sse-url http://127.0.0.1:9876
```

### 3. Set the BChecks watched directory

`Extensions` → `BChecks` (shown as **Custom scan checks** in some versions) → folder icon → set to:

```
/path/to/Burp-Bchecks-MCP/bchecks
```

Burp hot-reloads `.bcheck` files from this directory automatically.

### 4. Proxy your browser through Burp

- `Proxy` → `Intercept` → **OFF**
- Browser proxy: `127.0.0.1:8080`
- Browse your target to populate proxy history

---

## Claude Desktop Configuration

Edit your Claude Desktop config:

- **Linux:** `~/.config/Claude/claude_desktop_config.json`
- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "bcheck-mcp": {
      "command": "/home/<your-user>/.local/bin/bcheck-mcp",
      "env": {
        "BURP_API_URL": "http://127.0.0.1:1337/v0.1",
        "BURP_API_KEY": "",
        "BCHECK_DIR": "/home/<your-user>/Burp-Bchecks-MCP/bchecks",
        "ALLOWED_TARGETS": "https://your-target.com",
        "BCHECK_RELOAD_WAIT": "3",
        "SCAN_TIMEOUT_MINUTES": "30"
      }
    },
    "burp": {
      "command": "/path/to/BurpSuitePro/jre/bin/java",
      "args": [
        "-jar",
        "/home/<your-user>/.BurpSuite/mcp-proxy/mcp-proxy-all.jar",
        "--sse-url",
        "http://127.0.0.1:9876"
      ]
    }
  }
}
```

**Replace:**
- `<your-user>` → your Linux/macOS username
- `ALLOWED_TARGETS` → comma-separated list of your target URLs
- `BURP_API_KEY` → your Burp REST API key if you set one
- `/path/to/BurpSuitePro` → your actual Burp install path

Restart Claude Desktop after editing.

---

## Usage

In Claude Desktop:

> *"Look at my Burp proxy history for target.com, find the login and API requests, analyze them for injection points, write custom BCheck scripts, deploy them, and run a scan."*

Claude will:
1. Call `get_proxy_http_history` (Burp MCP) — read real traffic
2. Call `analyze_request_tool` — map params, body format, injection points
3. Call `get_bcheck_syntax_guide_tool` — read DSL spec
4. Write targeted BCheck DSL for each endpoint
5. Call `write_bcheck_tool` — validate and deploy
6. Call `create_scan_tool` — launch scan
7. Poll `get_scan_status_tool` → report via `get_scan_issues_tool`

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `BURP_API_URL` | `http://127.0.0.1:1337/v0.1` | Burp REST API URL |
| `BURP_API_KEY` | `` | API key (empty if none) |
| `BCHECK_DIR` | `~/Burp-Bchecks-MCP/bchecks` | Watched .bcheck directory |
| `ALLOWED_TARGETS` | `` | Comma-separated scan whitelist (empty = allow all) |
| `BCHECK_RELOAD_WAIT` | `3` | Seconds before scan starts after deploy |
| `SCAN_TIMEOUT_MINUTES` | `30` | Max scan duration |

---

## MCP Tools

| Tool | Description |
|---|---|
| `analyze_request_tool` | Parse raw HTTP → injection points + vuln suggestions |
| `write_bcheck_tool` | Validate + deploy BCheck DSL |
| `get_bcheck_syntax_guide_tool` | Full BCheck v2-beta DSL reference |
| `create_scan_tool` | Launch Burp active scan |
| `get_scan_status_tool` | Poll scan progress |
| `get_scan_issues_tool` | Retrieve findings |
| `list_deployed_checks_tool` | List deployed .bcheck files |
