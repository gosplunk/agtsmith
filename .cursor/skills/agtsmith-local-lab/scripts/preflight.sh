#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../../" && pwd)"
PYTHON_BIN="${ROOT}/.venv/bin/python"
if [[ ! -x "${PYTHON_BIN}" ]]; then
  PYTHON_BIN="python3"
fi

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

ENV_PROFILE_PATH="${ROOT}/artifacts/environment/environment_profile_latest.json"
SKILLPACK_PATH="${ROOT}/artifacts/knowledge/spl_skillpack_latest.json"
ENV_PROFILE_MAX_AGE_MINUTES="${ENV_PROFILE_MAX_AGE_MINUTES:-11520}"
SKILLPACK_MAX_AGE_MINUTES="${SKILLPACK_MAX_AGE_MINUTES:-11520}"

if [[ -f "${ENV_PROFILE_PATH}" ]]; then
  if "${PYTHON_BIN}" "${ROOT}/scripts/check_environment_profile_freshness.py" \
      --path "${ENV_PROFILE_PATH}" \
      --max-age-minutes "${ENV_PROFILE_MAX_AGE_MINUTES}" >/dev/null 2>&1; then
    echo "OK  environment profile freshness"
  else
    echo "WARN environment profile stale or invalid — run make env-profile-refresh"
  fi
else
  echo "WARN environment profile missing (${ENV_PROFILE_PATH}) — run make env-profile-refresh"
fi

if [[ -f "${SKILLPACK_PATH}" ]]; then
  skillpack_age_min="$(
    "${PYTHON_BIN}" - <<'PY' "${SKILLPACK_PATH}"
import sys
from datetime import datetime, timezone
from pathlib import Path
p = Path(sys.argv[1])
mtime = datetime.fromtimestamp(p.stat().st_mtime, tz=timezone.utc)
print((datetime.now(timezone.utc) - mtime).total_seconds() / 60.0)
PY
  )"
  if awk -v age="${skillpack_age_min}" -v max="${SKILLPACK_MAX_AGE_MINUTES}" 'BEGIN { exit !(age <= max) }'; then
    echo "OK  skillpack freshness"
  else
    echo "WARN skillpack stale — run make spl-skillpack-refresh"
  fi
else
  echo "WARN skillpack missing (${SKILLPACK_PATH}) — run make spl-skillpack-refresh"
fi

if [[ -f "${ROOT}/scripts/spl_autonomy_manifest.py" ]]; then
  "${PYTHON_BIN}" - <<'PY' "${ROOT}"
import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(sys.argv[1]) / "scripts"))
from spl_autonomy_manifest import build_manifest
print("manifest_hashes=" + json.dumps({
    "env_profile_hash": build_manifest().get("env_profile_hash"),
    "skillpack_hash": build_manifest().get("skillpack_hash"),
    "git_sha": build_manifest().get("git_sha"),
}, sort_keys=True))
PY
fi

UI_ENV_PATH="${ROOT}/config/ui.env"
if [[ -f "${UI_ENV_PATH}" ]]; then
  # shellcheck disable=SC1090
  set +u
  source "${UI_ENV_PATH}" 2>/dev/null || true
  set -u
  if [[ -n "${SPLUNK_USER:-}" && -n "${SPLUNK_PASS:-}" ]]; then
    if ! curl -skf -o /dev/null https://127.0.0.1:8089/services/server/info \
      -H "Authorization: Bearer ${SPLUNK_LAB_BEARER_TOKEN:-invalid}"; then
      echo "WARN MCP bearer token rejected — run make lab-data-refresh-mcp-token"
    else
      echo "OK  MCP bearer token"
    fi
  fi
fi
if [[ "${LAB_DATA_ENABLED:-0}" == "1" ]]; then
  HEC_URL="${SPLUNK_HEC_URL:-https://127.0.0.1:8088/services/collector/event}"
  warn_check "Splunk HEC (lab data)" "curl -skf -o /dev/null -X POST '${HEC_URL}' -H 'Authorization: Splunk test' -H 'Content-Type: application/json' -d '{}'" "enable HEC and set SPLUNK_HEC_URL/SPLUNK_HEC_TOKEN in config/ui.env — see docs/runbooks/lab_data_generator.md"
fi

echo "=== done ==="
exit $failed
