#!/usr/bin/env bash
# Single-process planner bake-off: fast models first, sleep inhibited, merge on success.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
OUT="$ROOT/artifacts/model_eval/planner_bakeoff"
LOCK="$OUT/.bakeoff.lock"
LOG="$OUT/run_full.log"
PY="$ROOT/.venv/bin/python"
export PYTHONPATH="$ROOT/scripts${PYTHONPATH:+:$PYTHONPATH}"

mkdir -p "$OUT"
exec 9>"$LOCK"
if ! flock -n 9; then
  echo "planner bake-off already running (lock: $LOCK)" >&2
  exit 1
fi

if [[ -f "$OUT/planner_eval_latest.json" ]] && [[ ! -f "$OUT/planner_eval_prior5_backup.json" ]]; then
  cp "$OUT/planner_eval_latest.json" "$OUT/planner_eval_prior5_backup.json"
fi

MODELS="$($PY -c 'from evaluate_planner_models import BAKEOFF_REMAINING_MODELS; print(BAKEOFF_REMAINING_MODELS)')"
SKIP="$($PY -c 'from evaluate_planner_models import BAKEOFF_SKIP_MODELS; print(BAKEOFF_SKIP_MODELS)')"

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] bakeoff start" | tee -a "$LOG"

EVAL_CMD=(
  "$PY" scripts/evaluate_planner_models.py
  --models "$MODELS"
  --skip-models "$SKIP"
)

if command -v systemd-inhibit >/dev/null 2>&1; then
  systemd-inhibit --what=sleep:idle --who=agtsmith --why="planner bake-off" \
    "${EVAL_CMD[@]}" >>"$LOG" 2>&1
else
  "${EVAL_CMD[@]}" >>"$LOG" 2>&1
fi

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] eval done, merging" | tee -a "$LOG"
"$PY" scripts/merge_planner_bakeoff_results.py | tee -a "$LOG"

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] bakeoff complete" | tee -a "$LOG"
