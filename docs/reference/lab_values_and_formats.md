# Runtime Values And Formats

This reference explains the format of the values A.G.E.N.T. Smith expects without embedding any live lab secrets or machine-specific addresses.

## Endpoint Format Examples
- Ollama host: `http://<ollama-host-ip>:11434`
- Splunk base URL: `https://<splunk-host-ip>:8089`
- Splunk MCP URL: `https://<splunk-host-ip>:8089/services/mcp`

## Authorization Header Format
```http
Authorization: Bearer <splunk_mcp_token>
```

## MCP Client Config Pattern
```json
{
  "mcpServers": {
    "splunk-mcp-server": {
      "command": "npx",
      "args": [
        "-y",
        "mcp-remote",
        "https://<splunk-host-ip>:8089/services/mcp",
        "--header",
        "Authorization: Bearer ${SPLUNK_LAB_BEARER_TOKEN}"
      ]
    }
  }
}
```

## Notes
- These are examples only.
- Real values belong in `config/ui.env`.
- Do not commit live tokens or environment-specific addresses.

