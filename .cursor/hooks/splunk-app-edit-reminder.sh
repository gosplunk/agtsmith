#!/usr/bin/env bash
input=$(cat)
file_path=$(echo "$input" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('file_path',''))" 2>/dev/null || echo "")

if echo "$file_path" | grep -q '^splunk_app/'; then
  echo '{"followup_message":"Splunk app file changed — run: make splunk-app-install-local && sudo -u splunk /opt/splunk/bin/splunk restart"}'
fi
exit 0
