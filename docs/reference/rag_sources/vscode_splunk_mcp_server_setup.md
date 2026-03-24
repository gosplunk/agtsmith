# Splunk MCP Server Setup Guide for Visual Studio Code

## Overview

This guide explains how to configure the **Splunk MCP Server** (Model Context Protocol) to connect Visual Studio Code AI assistants (like GitHub Copilot) to your Splunk deployment for live searches, SPL generation, and more.

> **Note**: For AppInspect MCP setup (local app validation), see the separate document: `mcp_document.md`

---

## Prerequisites

1. **Enable API Access**:
   - **Splunk Cloud Platform**: Enable REST API access for your deployment
   - See: [Accessing the Splunk Cloud Platform REST API](https://help.splunk.com/?resourceId=SplunkCloud_RESTTUT_RESTandCloud)

2. **Enable Token Authentication**:
   - Enable token authentication for your Splunk instance
   - See: [Enable token authentication for a Splunk platform instance](https://help.splunk.com/?resourceId=SplunkCloud_Security_EnableTokenAuth)

### Step 1: Install MCP Server App on Splunk

1. Download the **Splunk MCP Server** app from [Splunkbase](https://splunkbase.splunk.com)
2. Install on your Splunk deployment:
   - **Splunk Cloud**: Use the standard add-on installation process
   - **Splunk Enterprise**: Copy to `$SPLUNK_HOME/etc/apps/`
3. Restart Splunk when prompted

### Step 2: Configure Role-Based Access

The MCP Server app adds two capabilities:

| Capability | Description |
|------------|-------------|
| `mcp_tool_execute` | Grants users access to use MCP server tools |
| `mcp_tool_admin` | Grants administrative access for tool management and token creation |

Add `mcp_tool_execute` to roles that should access MCP functionality.

### Step 3: Configure VS Code Connection

**Option A: Manual Configuration (Recommended for Workshops)**

1. Open Command Palette: `Cmd+Shift+P` (macOS) or `Ctrl+Shift+P` (Windows/Linux)
2. Type: `MCP: Open User Configuration`
3. Add the following configuration:

```json
{
  "servers": {
    "splunk-mcp-server": {
      "type": "stdio",
      "command": "npx",
      "args": [
        "-y",
        "mcp-remote",
        "https://your-splunk-instance.splunkcloud.com:8089/services/mcp",
        "--header",
        "Authorization: Bearer <Your-Splunk-Token>"
      ],
      "env": {
        "NODE_TLS_REJECT_UNAUTHORIZED": "0"
      }
    }
  }
}
```

> ⚠️ **Note**: The `NODE_TLS_REJECT_UNAUTHORIZED` environment variable disables SSL certificate verification. **Only use this for development or testing environments** with self-signed certificates. Remove this setting for production Splunk Cloud instances with valid SSL certificates.

> **Note**: The Splunk official documentation shows `mcpServers` as the key, but VS Code requires `servers`. All MCP servers must be defined directly under the `servers` key.

**Configuration Details:**

| Parameter | Description |
|-----------|-------------|
| `npx` | Node.js package runner |
| `-y` | Auto-confirm npx prompts |
| `mcp-remote` | MCP remote connection package |
| URL | Your Splunk instance MCP endpoint (port 8089) |
| `--header` | HTTP header for authentication |
| `Authorization: Bearer` | Your Splunk authentication token |
| `NODE_TLS_REJECT_UNAUTHORIZED` | Set to `"0"` for self-signed certs (testing only) |

**Option B: Using Command Palette**

1. Open Command Palette: `Cmd+Shift+P` (macOS) or `Ctrl+Shift+P` (Windows/Linux)
2. Type: `MCP: Add Server`
3. Select transport type: `Command (stdio)`
4. Enter the command: `npx`
5. Enter server name: `splunk-mcp-server`
6. Select scope: `Global` (adds to user profile)
7. **Add connection details**: After the server is created, open your `mcp.json` file to add the full configuration:
   - Command Palette → `MCP: Open User Configuration`
   - Update the `splunk-mcp-server` entry with your Splunk URL, token, and env settings

The user configuration file is located at:
- **macOS**: `~/Library/Application Support/Code/User/mcp.json`
- **Windows**: `%APPDATA%\Code\User\mcp.json`
- **Linux**: `~/.config/Code/User/mcp.json`

### Step 4: Start the MCP Server

1. Open Command Palette: `Cmd+Shift+P` (macOS) or `Ctrl+Shift+P` (Windows/Linux)
2. Type: `MCP: List Servers`
3. Select `splunk`
4. Choose `Start Server`

Alternatively:
1. Open Extensions view: `Cmd+Shift+X`
2. Type `@mcp` in the search box
3. Look under **"MCP SERVERS - INSTALLED"** section
4. Right-click on `splunk` and select **Start**

### Step 5: Verify the Server is Running

1. Open Command Palette: `Cmd+Shift+P` (macOS) or `Ctrl+Shift+P` (Windows/Linux)
2. Type: `MCP: List Servers`
3. The `splunk` server should show as running (green indicator)

---

## MCP Server Tools

When connected to Splunk, these tools become available:

| Tool | Description |
|------|-------------|
| `run_search` | Execute SPL searches against Splunk |
| `generate_spl` | AI-assisted SPL query generation |
| `explain_spl` | Get explanations of SPL queries |
| `optimize_spl` | Optimize SPL for performance |
| `ask_splunk_question` | Natural language questions about your data |
| `list_indexes` | List available indexes |
| `list_sourcetypes` | List available sourcetypes |

*Note: AI tools require Splunk AI Assistant for SPL to be installed.*

---

## Verify Installation

### Check MCP Server Status in VS Code

1. Press `Cmd+Shift+P` (macOS) or `Ctrl+Shift+P` (Windows/Linux)
2. Type "MCP: List Servers"
3. Verify your servers appear in the list

### Test Connection

In GitHub Copilot Chat:

```
# Test Splunk connection
Run a search: index=_internal | head 10
```

---

## Troubleshooting

### MCP Server Not Connecting

1. **Verify token is valid**:
   ```bash
   curl -k -H "Authorization: Bearer YOUR_TOKEN" \
     https://your-splunk:8089/services/server/info
   ```

2. **Check firewall/network access** to port 8089

3. **Verify capabilities** are assigned to your user role

### VS Code Not Detecting MCP

1. Reload VS Code window (`Cmd+Shift+P` → "Reload Window")
2. Check Output panel for MCP errors (View → Output → "MCP")

### Server Not Appearing in Chat

1. Ensure the server is started (Command Palette → `MCP: List Servers` → select server → `Start Server`)
2. Try restarting VS Code
3. Run `MCP: Reset Cached Tools` from Command Palette

### Trust Prompt

When starting the server for the first time, VS Code will prompt you to trust the server. Select the server link to review the configuration, then confirm trust.

---

## Managing MCP Servers

### Start a Server
- Command Palette → `MCP: List Servers` → select server → `Start Server`

### Stop a Server
- Command Palette → `MCP: List Servers` → select server → `Stop Server`

### Remove a Server
- Command Palette → `MCP: List Servers` → select server → `Uninstall`
- Or manually edit the `mcp.json` file

### View Server Logs
- Command Palette → `MCP: List Servers` → select server → `Show Output`

### Reset Server Tools Cache
- Command Palette → `MCP: Reset Cached Tools`

---

## Configuration File Locations

| Type | Location |
|------|----------|
| **User (Global)** | `~/Library/Application Support/Code/User/mcp.json` |
| **Workspace** | `.vscode/mcp.json` (in project root) |

---

## References

- [Official Splunk MCP Server Documentation](https://help.splunk.com/en/splunk-cloud-platform/mcp-server-for-splunk-platform/configure-the-splunk-mcp-server)
- [Connecting to MCP Server and Admin Settings](https://help.splunk.com/en/splunk-cloud-platform/mcp-server-for-splunk-platform/connecting-to-mcp-server-and-admin-settings)
- [MCP Server Tools Reference](https://help.splunk.com/en/splunk-cloud-platform/mcp-server-for-splunk-platform/mcp-server-tools)
- [Splunk AI Assistant for SPL](https://docs.splunk.com/Documentation/AIAssistant/latest/User/AboutAIAssistant)
- [Model Context Protocol](https://modelcontextprotocol.io/)

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | February 2026 | Initial setup guide with official Splunk MCP |

---

## Author

Tim Cordova
