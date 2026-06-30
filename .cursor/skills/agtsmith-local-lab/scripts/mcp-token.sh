#!/usr/bin/env bash
set -euo pipefail

: "${SPLUNK_USER:?Set SPLUNK_USER}"
: "${SPLUNK_PASS:?Set SPLUNK_PASS}"

NAME="${MCP_TOKEN_NAME:-agtsmith-dev}"
EXPIRES="${MCP_TOKEN_EXPIRES:-+30d}"

resp=$(curl -sk -u "${SPLUNK_USER}:${SPLUNK_PASS}" \
  -X POST "https://127.0.0.1:8089/services/authorization/tokens?output_mode=json" \
  -d "name=${NAME}" \
  -d "audience=mcp" \
  -d "expires_on=${EXPIRES}")

token=$(python3 -c "import json,sys; d=json.load(sys.stdin); print(d['entry'][0]['content']['token'])" <<<"$resp" 2>/dev/null || true)

if [[ -z "${token:-}" ]]; then
  echo "Failed to create token. Response:" >&2
  echo "$resp" >&2
  exit 1
fi

echo "MCP bearer token (store in config/ui.env only — do not commit):"
echo "SPLUNK_LAB_BEARER_TOKEN=${token}"
