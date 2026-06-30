#!/usr/bin/env bash
# Write gitignored config/ui.env for local Splunk + MCP (sandbox).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
: "${SPLUNK_USER:?Set SPLUNK_USER}"
: "${SPLUNK_PASS:?Set SPLUNK_PASS}"

TOKEN="$("${ROOT}/.cursor/skills/agtsmith-local-lab/scripts/mcp-token.sh" | awk -F= '/SPLUNK_LAB_BEARER_TOKEN=/{print $2}')"

if [[ -z "${TOKEN}" ]]; then
  echo "Failed to mint MCP token" >&2
  exit 1
fi

cp -n "${ROOT}/config/ui.env.example" "${ROOT}/config/ui.env" 2>/dev/null || true

python3 - <<PY
from pathlib import Path
import re

path = Path("${ROOT}/config/ui.env")
text = path.read_text(encoding="utf-8") if path.exists() else Path("${ROOT}/config/ui.env.example").read_text(encoding="utf-8")
updates = {
    "OLLAMA_HOST": "http://127.0.0.1:11434",
    "SPLUNK_BASE_URL": "https://127.0.0.1:8089",
    "SPLUNK_WEB_URL": "http://127.0.0.1:8000",
    "SPLUNK_MCP_URL": "https://127.0.0.1:8089/services/mcp",
    "SPLUNK_LAB_BEARER_TOKEN": "${TOKEN}",
    "AGTSMITH_CASE_BACKEND": "kvstore",
}
for key, value in updates.items():
    pattern = rf"^{re.escape(key)}=.*$"
    line = f"{key}={value}"
    if re.search(pattern, text, flags=re.M):
        text = re.sub(pattern, line, text, count=1, flags=re.M)
    else:
        text = text.rstrip() + "\\n" + line + "\\n"
path.write_text(text, encoding="utf-8")
print(f"Wrote {path} (token not printed)")
PY
