#!/usr/bin/env bash
set -euo pipefail

echo "=== agtsmith local lab preflight ==="

failed=0

check() {
  local label="$1" cmd="$2"
  if eval "$cmd" >/dev/null 2>&1; then
    echo "OK  $label"
  else
    echo "FAIL $label"
    failed=1
  fi
}

warn_check() {
  local label="$1" cmd="$2" hint="$3"
  if eval "$cmd" >/dev/null 2>&1; then
    echo "OK  $label"
  else
    echo "WARN $label — $hint"
  fi
}

check "Splunk Web :8000" "curl -sf -o /dev/null http://127.0.0.1:8000"
check "Splunk API :8089" "curl -skf -o /dev/null https://127.0.0.1:8089"
if curl -sk -o /dev/null -w '%{http_code}' -X POST https://127.0.0.1:8089/services/mcp -H 'Content-Type: application/json' -d '{}' | grep -qE '^(200|400|401|405)$'; then
  echo "OK  MCP endpoint"
else
  echo "FAIL MCP endpoint"
  failed=1
fi
warn_check "Ollama" "curl -sf -o /dev/null http://127.0.0.1:11434/api/tags" "required for live investigations"
warn_check "agtsmith sidecar" "curl -sf -o /dev/null http://127.0.0.1:8787/login" "run make docker-deploy-up"

test -d /opt/splunk && echo "OK  Splunk home /opt/splunk" || echo "WARN /opt/splunk not found"
echo "=== done ==="
exit $failed
