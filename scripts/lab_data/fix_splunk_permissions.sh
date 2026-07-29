#!/usr/bin/env bash
# Fix common Splunk permission issues when splunkd runs as root but CLI uses -u splunk.
set -euo pipefail

SPLUNK_HOME="${SPLUNK_HOME:-/opt/splunk}"

echo "[fix-splunk-perms] splunkd process user:"
ps -o user= -p "$(pgrep -xo splunkd || true)" 2>/dev/null || true

echo "[fix-splunk-perms] ensuring splunk OS user owns etc/users, etc/auth, var (requires sudo)"
sudo chown -R splunk:splunk \
  "${SPLUNK_HOME}/etc/users" \
  "${SPLUNK_HOME}/etc/auth" \
  "${SPLUNK_HOME}/var" \
  "${SPLUNK_HOME}/etc/system/local" 2>/dev/null || true

echo "[fix-splunk-perms] done — retry splunk CLI or use REST via scripts/lab_data/set_splunk_user_password.py"
