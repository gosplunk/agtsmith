#!/usr/bin/env bash
set -euo pipefail

echo "=== agtsmith local lab preflight ==="

check() {
  local label="$1" cmd="$2"
  if eval "$cmd" >/dev/null 2>&1; then
    echo "OK  $label"
  else
    echo "FAIL $label"
    return 1
  fi
}

check "Splunk Web :8000" "curl -sf -o /dev/null http://127.0.0.1:8000"
check "Splunk API :8089" "curl -skf -o /dev/null https://127.0.0.1:8089"
check "MCP endpoint" "curl -skf -o /dev/null -X POST https://127.0.0.1:8089/services/mcp -H 'Content-Type: application/json' -d '{}'"
check "Ollama (optional)" "curl -sf -o /dev/null http://127.0.0.1:11434/api/tags" || echo "WARN Ollama not reachable (required for live investigations)"
check "agtsmith sidecar (optional)" "curl -sf -o /dev/null http://127.0.0.1:8787/login" || echo "WARN sidecar not up — run make docker-deploy-up"

test -d /opt/splunk && echo "OK  Splunk home /opt/splunk" || echo "WARN /opt/splunk not found"
echo "=== done ==="
