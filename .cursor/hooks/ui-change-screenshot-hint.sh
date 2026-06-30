#!/usr/bin/env bash
input=$(cat)
file_path=$(echo "$input" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('file_path',''))" 2>/dev/null || echo "")

if echo "$file_path" | grep -qE '(web_ui_server\.py|splunk_app/appserver/)'; then
  echo '{"followup_message":"UI changed — consider: make screenshots SCREENSHOT_VERSION=<version>"}'
fi
exit 0
