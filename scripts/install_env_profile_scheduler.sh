#!/usr/bin/env bash
set -euo pipefail

# Install/update a user cron entry to refresh environment profile weekly.
# Default cadence: Sunday at 04:00 local time.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DAY_OF_WEEK="${1:-0}"
HOUR="${2:-4}"
MINUTE="${3:-0}"
LOG_FILE="${ROOT_DIR}/artifacts/environment/environment_profile_refresh_cron.log"
MARKER="# SOC_ENV_PROFILE_REFRESH"

if ! [[ "${DAY_OF_WEEK}" =~ ^[0-6]$ ]]; then
  echo "day_of_week must be an integer from 0 to 6 (0=Sunday)"
  exit 1
fi
if ! [[ "${HOUR}" =~ ^[0-9]+$ ]] || (( HOUR < 0 || HOUR > 23 )); then
  echo "hour must be an integer from 0 to 23"
  exit 1
fi
if ! [[ "${MINUTE}" =~ ^[0-9]+$ ]] || (( MINUTE < 0 || MINUTE > 59 )); then
  echo "minute must be an integer from 0 to 59"
  exit 1
fi

CRON_EXPR="${MINUTE} ${HOUR} * * ${DAY_OF_WEEK}"
ENTRY="${CRON_EXPR} cd ${ROOT_DIR} && make env-profile-refresh >> ${LOG_FILE} 2>&1 ${MARKER}"

TMP="$(mktemp)"
trap 'rm -f "${TMP}"' EXIT

crontab -l 2>/dev/null | grep -v "${MARKER}" > "${TMP}" || true
echo "${ENTRY}" >> "${TMP}"
crontab "${TMP}"

echo "installed cron entry:"
echo "${ENTRY}"
