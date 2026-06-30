#!/usr/bin/env bash
# Block git operations that would commit secret files.
input=$(cat)
command=$(echo "$input" | python3 -c "import json,sys; print(json.load(sys.stdin).get('command',''))" 2>/dev/null || echo "")

if echo "$command" | grep -qE 'git add.*(config/ui\.env|\.env|passwords\.conf)'; then
  echo '{"permission":"deny","user_message":"Blocked: cannot git-add secret config files.","agent_message":"Use config/ui.env.example only in commits."}'
  exit 0
fi

if echo "$command" | grep -qE 'git commit' && git diff --cached --name-only 2>/dev/null | grep -qE '^(config/ui\.env|\.env)$'; then
  echo '{"permission":"deny","user_message":"Blocked: staged secret files detected.","agent_message":"Unstage config/ui.env before commit."}'
  exit 0
fi

echo '{"permission":"allow"}'
exit 0
