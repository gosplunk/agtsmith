#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../../" && pwd)"
UI_ENV="${ROOT}/config/ui.env"
PYTHON_BIN="${ROOT}/.venv/bin/python"
if [[ ! -x "${PYTHON_BIN}" ]]; then
  PYTHON_BIN="python3"
fi

: "${SPLUNK_USER:?Set SPLUNK_USER}"
: "${SPLUNK_PASS:?Set SPLUNK_PASS}"

TOKEN_USER="${MCP_TOKEN_USER:-mcp}"
FORCE_ROTATE=0
for arg in "$@"; do
  if [[ "${arg}" == "--force-rotate" ]]; then
    FORCE_ROTATE=1
  fi
done

ARGS=(--token-user "${TOKEN_USER}")
if [[ "${FORCE_ROTATE}" == "1" ]]; then
  ARGS+=(--force-rotate)
fi

if [[ -f "${UI_ENV}" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "${UI_ENV}" 2>/dev/null || true
  set +a
fi

export SPLUNK_USER SPLUNK_PASS
OUT="$(
  PYTHONPATH="${ROOT}:${ROOT}/scripts" "${PYTHON_BIN}" "${ROOT}/scripts/lab_data/refresh_mcp_token.py" \
    --ui-env "${UI_ENV}" \
    "${ARGS[@]}"
)"
echo "${OUT}" >&2

TOKEN="$(grep '^SPLUNK_LAB_BEARER_TOKEN=' "${UI_ENV}" | cut -d= -f2-)"

if [[ -z "${TOKEN}" ]]; then
  echo "Failed to ensure encrypted MCP token for user ${TOKEN_USER}." >&2
  exit 1
fi

echo "MCP bearer token (store in config/ui.env only — do not commit):"
echo "SPLUNK_LAB_BEARER_TOKEN=${TOKEN}"
