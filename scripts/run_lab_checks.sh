#!/usr/bin/env bash
set -euo pipefail

# One-command lab validation wrapper.
# Runs:
# 1) template safety preflight
# 2) regression run with artifact + history snapshot
# 3) trend summary with threshold alert mode

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/run_lab_checks.sh [max_abs_delta] [write_snapshot:0|1] [refresh_status_json:0|1] [quick_mode:0|1]
  ./scripts/run_lab_checks.sh [--max-abs-delta N] [--snapshot|--no-snapshot] [--refresh-status|--no-refresh-status] [--quick|--no-quick]

Examples:
  ./scripts/run_lab_checks.sh 0 1 1 0
  ./scripts/run_lab_checks.sh --max-abs-delta 0 --snapshot --refresh-status
  ./scripts/run_lab_checks.sh --quick --no-snapshot --refresh-status
USAGE
}

MAX_ABS_DELTA="0"
WRITE_SNAPSHOT="0"
REFRESH_STATUS_JSON="1"
QUICK_MODE="0"

# Backward-compatible positional args if first arg is not an option.
if [[ "${1:-}" != --* && "${1:-}" != "-h" && "${1:-}" != "--help" && $# -gt 0 ]]; then
  MAX_ABS_DELTA="${1:-0}"
  WRITE_SNAPSHOT="${2:-0}"
  REFRESH_STATUS_JSON="${3:-1}"
  QUICK_MODE="${4:-0}"
else
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --max-abs-delta)
        shift
        MAX_ABS_DELTA="${1:-0}"
        ;;
      --snapshot)
        WRITE_SNAPSHOT="1"
        ;;
      --no-snapshot)
        WRITE_SNAPSHOT="0"
        ;;
      --refresh-status)
        REFRESH_STATUS_JSON="1"
        ;;
      --no-refresh-status)
        REFRESH_STATUS_JSON="0"
        ;;
      --quick)
        QUICK_MODE="1"
        ;;
      --no-quick)
        QUICK_MODE="0"
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        echo "Unknown option: $1"
        usage
        exit 1
        ;;
    esac
    shift
  done
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ -f ".venv/bin/activate" ]]; then
  # shellcheck disable=SC1091
  source .venv/bin/activate
fi

echo "=== Lab Checks Wrapper ==="
echo "args: <max_abs_delta> [write_snapshot:0|1] [refresh_status_json:0|1] [quick_mode:0|1]"
echo "named flags: --max-abs-delta N --snapshot --refresh-status --quick"
echo "threshold.max_abs_delta=${MAX_ABS_DELTA}"
echo "snapshot.write=${WRITE_SNAPSHOT}"
echo "status_json.refresh=${REFRESH_STATUS_JSON}"
echo "quick_mode=${QUICK_MODE}"

if [[ "${QUICK_MODE}" == "1" ]]; then
  echo
  echo "[quick] Skipping live preflight/regression/trend query steps"
  echo "[quick] Showing artifact-only status"
  python scripts/show_lab_status.py
else
  echo
  echo "[1/3] Template preflight"
  python scripts/check_query_templates.py

  echo
  echo "[2/3] Regression run"
  python scripts/run_template_regression.py

  echo
  echo "[3/3] Trend threshold check"
  python scripts/summarize_regression_trends.py --max-abs-delta "${MAX_ABS_DELTA}"
fi

echo
echo "All checks completed successfully."

if [[ "${REFRESH_STATUS_JSON}" == "1" ]]; then
  echo
  echo "[optional] Refreshing latest status JSON"
  python scripts/show_lab_status.py --json-out docs/logs/latest_status.json
fi

if [[ "${WRITE_SNAPSHOT}" == "1" ]]; then
  echo
  echo "[optional] Writing operator snapshot bundle"
  python scripts/write_operator_snapshot.py
fi
