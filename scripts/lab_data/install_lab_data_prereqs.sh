#!/usr/bin/env bash
# One-time Splunk lab prep: enable HEC, store Splunk admin creds, mint HEC token, bootstrap lab data.
# Run from repo root:  cd ~/ai_projects/agtsmith && make lab-data-install
#
# Splunk credential options (pick one):
#   A) SPLUNK_PASS already in config/ui.env (dev user) — preferred after manual password set
#   B) SPLUNK_ADMIN_USER + SPLUNK_ADMIN_PASS in config/ui.env — REST password set for dev
#   C) sudo /opt/splunk/bin/splunk edit user ...  (root CLI — splunkd runs as root on this host)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
UI_ENV="${ROOT}/config/ui.env"
PYTHON_BIN="${ROOT}/.venv/bin/python"
SPLUNK_HOME="${SPLUNK_HOME:-/opt/splunk}"
LAYOUT="${LAB_DATA_LAYOUT:-existing_lab}"

if [[ ! -f "${ROOT}/Makefile" ]] || ! grep -q 'lab-data-install' "${ROOT}/Makefile" 2>/dev/null; then
  echo "[lab-data-install] ERROR: run from agtsmith repo (cd ~/ai_projects/agtsmith)" >&2
  exit 1
fi

if [[ ! -x "${PYTHON_BIN}" ]]; then
  PYTHON_BIN="python3"
fi

upsert_ui_env() {
  local key="$1" value="$2"
  "${PYTHON_BIN}" - <<'PY' "${UI_ENV}" "${key}" "${value}"
import re, sys
from pathlib import Path
path = Path(sys.argv[1])
key, value = sys.argv[2], sys.argv[3]
text = path.read_text(encoding="utf-8") if path.is_file() else ""
pattern = rf"^{re.escape(key)}=.*$"
line = f"{key}={value}"
if re.search(pattern, text, flags=re.M):
    text = re.sub(pattern, line, text, count=1, flags=re.M)
else:
    text = text.rstrip() + "\n" + line + "\n"
path.write_text(text, encoding="utf-8")
PY
}

has_ui_key() {
  local key="$1"
  grep -q "^${key}=" "${UI_ENV}" 2>/dev/null
}

echo "[lab-data-install] repo=${ROOT}"
cp -n "${ROOT}/config/ui.env.example" "${UI_ENV}" 2>/dev/null || true

if ! has_ui_key "SPLUNK_USER"; then
  upsert_ui_env "SPLUNK_USER" "dev"
fi

if ! has_ui_key "SPLUNK_PASS"; then
  DEV_PASS="$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(18))
PY
)"
  echo "[lab-data-install] SPLUNK_PASS missing — configuring dev user password"

  set -a
  # shellcheck disable=SC1090
  source "${UI_ENV}" 2>/dev/null || true
  set +a

  if [[ -n "${SPLUNK_ADMIN_PASS:-}" ]]; then
    echo "[lab-data-install] setting dev password via REST (SPLUNK_ADMIN_*)"
    PYTHONPATH="${ROOT}:${ROOT}/scripts" "${PYTHON_BIN}" \
      "${ROOT}/scripts/lab_data/set_splunk_user_password.py" \
      --user dev --password "${DEV_PASS}"
    upsert_ui_env "SPLUNK_PASS" "${DEV_PASS}"
  elif sudo -n "${SPLUNK_HOME}/bin/splunk" list user dev >/dev/null 2>&1; then
    echo "[lab-data-install] setting dev password via root splunk CLI"
    sudo "${SPLUNK_HOME}/bin/splunk" edit user dev -password "${DEV_PASS}"
    upsert_ui_env "SPLUNK_PASS" "${DEV_PASS}"
  elif sudo -n -u splunk "${SPLUNK_HOME}/bin/splunk" list user dev >/dev/null 2>&1; then
    echo "[lab-data-install] setting dev password via splunk OS user CLI"
    sudo -u splunk "${SPLUNK_HOME}/bin/splunk" edit user dev -password "${DEV_PASS}"
    upsert_ui_env "SPLUNK_PASS" "${DEV_PASS}"
  else
    echo "[lab-data-install] ERROR: cannot set dev password automatically." >&2
    echo "[lab-data-install] This host runs splunkd as root with root-owned /opt/splunk/etc/users." >&2
    echo "[lab-data-install] Fix (pick one):" >&2
    echo "  1) sudo /opt/splunk/bin/splunk edit user dev -password '<pass>' -auth admin:<adminpass>" >&2
    echo "  2) Add SPLUNK_PASS=<pass> to config/ui.env (if password already set)" >&2
    echo "  3) Add SPLUNK_ADMIN_USER=admin and SPLUNK_ADMIN_PASS=<adminpass> to config/ui.env" >&2
    echo "  4) bash scripts/lab_data/fix_splunk_permissions.sh  then retry" >&2
    echo "[lab-data-install] Then: cd ${ROOT} && make lab-data-install" >&2
    exit 1
  fi
fi

set -a
# shellcheck disable=SC1090
source "${UI_ENV}"
set +a
export SPLUNK_USER SPLUNK_PASS

echo "[lab-data-install] verifying Splunk REST login for ${SPLUNK_USER}"
if ! PYTHONPATH="${ROOT}:${ROOT}/scripts" "${PYTHON_BIN}" - <<'PY'
import sys
from lab_data.receivers_client import ReceiversClient
from lab_data.config import load_ui_env
client = ReceiversClient.from_env(load_ui_env())
sys.exit(0 if client.ping() else 1)
PY
then
  echo "[lab-data-install] ERROR: SPLUNK_USER/SPLUNK_PASS auth failed against Splunk REST" >&2
  exit 1
fi

echo "[lab-data-install] refreshing MCP bearer token"
PYTHONPATH="${ROOT}:${ROOT}/scripts" "${PYTHON_BIN}" "${ROOT}/scripts/lab_data/refresh_mcp_token.py"

echo "[lab-data-install] enabling HEC + minting token via REST"
PYTHONPATH="${ROOT}:${ROOT}/scripts" "${PYTHON_BIN}" "${ROOT}/scripts/lab_data/setup_hec.py" --layout "${LAYOUT}"

echo "[lab-data-install] bootstrapping lab data"
"${PYTHON_BIN}" "${ROOT}/scripts/lab_data/run_lab_data.py" -- \
  make -C "${ROOT}" lab-data-bootstrap "LAB_DATA_LAYOUT=${LAYOUT}"

echo "[lab-data-install] complete"
