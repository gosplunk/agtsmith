#!/usr/bin/env bash
set -euo pipefail

: "${SPLUNK_USER:?Set SPLUNK_USER}"
: "${SPLUNK_PASS:?Set SPLUNK_PASS}"

# Splunk MCP Server 1.x requires encrypted tokens from the app REST handler,
# not standard /services/authorization/tokens static JWTs.
TOKEN_USER="${MCP_TOKEN_USER:-mcp}"
MCP_TOKEN_URL="https://127.0.0.1:8089/servicesNS/nobody/Splunk_MCP_Server/mcp_token?output_mode=json"

curl -sk -u "${SPLUNK_USER}:${SPLUNK_PASS}" \
  -X POST "${MCP_TOKEN_URL}" \
  -d "username=${TOKEN_USER}" \
  -d "action=rotate" >/dev/null

fetch_resp=$(curl -sk -u "${SPLUNK_USER}:${SPLUNK_PASS}" \
  "${MCP_TOKEN_URL}&username=${TOKEN_USER}")

token=$(python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('token',''))" <<<"${fetch_resp}" 2>/dev/null || true)

if [[ -z "${token:-}" ]]; then
  echo "Failed to mint encrypted MCP token for user ${TOKEN_USER}." >&2
  echo "Response: ${fetch_resp}" >&2
  exit 1
fi

echo "MCP bearer token (store in config/ui.env only — do not commit):"
echo "SPLUNK_LAB_BEARER_TOKEN=${token}"
