#!/usr/bin/env bash
set -euo pipefail

# Install/update a user cron entry to refresh environment profile on a schedule.
# Default cadence: every 45 minutes (ops inventory). Weekly mode remains available.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INTERVAL_MIN="${INTERVAL_MIN:-45}"
DAY_OF_WEEK="${1:-}"
HOUR="${2:-4}"
MINUTE="${3:-0}"
LOG_FILE="${ROOT_DIR}/artifacts/environment/environment_profile_refresh_cron.log"
MARKER="# SOC_ENV_PROFILE_REFRESH"

if [[ -n "${DAY_OF_WEEK}" ]]; then
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
else
  if ! [[ "${INTERVAL_MIN}" =~ ^[0-9]+$ ]] || (( INTERVAL_MIN < 15 || INTERVAL_MIN > 1440 )); then
    echo "INTERVAL_MIN must be an integer from 15 to 1440"
    exit 1
  fi
  # Cron's */45 minute syntax runs at :00 and :45, creating alternating
  # 45/15-minute gaps. Poll freshness every 15 minutes instead and refresh
  # only when the configured interval has elapsed.
  CRON_EXPR="*/15 * * * *"
fi

if [[ -n "${DAY_OF_WEEK}" ]]; then
  ENTRY="${CRON_EXPR} cd ${ROOT_DIR} && make env-profile-refresh >> ${LOG_FILE} 2>&1 ${MARKER}"
else
  ENTRY="${CRON_EXPR} cd ${ROOT_DIR} && { .venv/bin/python scripts/check_environment_profile_freshness.py --max-age-minutes ${INTERVAL_MIN} >/dev/null 2>&1 || make env-profile-refresh >> ${LOG_FILE} 2>&1; } ${MARKER}"
fi

TMP="$(mktemp)"
trap 'rm -f "${TMP}"' EXIT

crontab -l 2>/dev/null | grep -v "${MARKER}" > "${TMP}" || true
echo "${ENTRY}" >> "${TMP}"
crontab "${TMP}"

echo "installed cron entry:"
echo "${ENTRY}"
