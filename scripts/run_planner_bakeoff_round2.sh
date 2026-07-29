#!/usr/bin/env bash
# Round 2 planner bake-off: pull five user-requested models, eval, merge with prior 19.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
OUT="$ROOT/artifacts/model_eval/planner_bakeoff"
LOCK="$OUT/.bakeoff.lock"
LOG="$OUT/run_round2.log"
PY="$ROOT/.venv/bin/python"
export PYTHONPATH="$ROOT/scripts${PYTHONPATH:+:$PYTHONPATH}"

mkdir -p "$OUT"
exec 9>"$LOCK"
if ! flock -n 9; then
  echo "planner bake-off already running (lock: $LOCK)" >&2
  exit 1
fi

if [[ ! -f "$OUT/planner_eval_merged_base.json" ]]; then
  cp "$OUT/planner_eval_latest.json" "$OUT/planner_eval_merged_base.json"
fi

MODELS="$($PY -c 'from evaluate_planner_models import BAKEOFF_ROUND2_MODELS; print(BAKEOFF_ROUND2_MODELS)')"
echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] round2 start" | tee -a "$LOG"

pull_model() {
  local tag="$1"
  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] pull $tag" | tee -a "$LOG"
  if ollama pull "$tag" >>"$LOG" 2>&1; then
    return 0
  fi
  return 1
}

IFS=',' read -ra TAGS <<< "$MODELS"
for tag in "${TAGS[@]}"; do
  tag="${tag// /}"
  [[ -z "$tag" ]] && continue
  if ollama show "$tag" >/dev/null 2>&1; then
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] already installed: $tag" | tee -a "$LOG"
    continue
  fi
  if ! pull_model "$tag"; then
    if [[ "$tag" == *"Ministral-3-3B-Reasoning"* ]]; then
      FALLBACK="TechyShishy/ministral-3:3b-reasoning-2512-q4_K_M"
      echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Q5_K_M pull failed; fallback $FALLBACK" | tee -a "$LOG"
      pull_model "$FALLBACK"
      MODELS="${MODELS/$tag/$FALLBACK}"
    elif [[ "$tag" == *"Impulse2000/smollm3"* ]]; then
      FALLBACK="alibayram/smollm3"
      echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Impulse2000 pull failed; fallback $FALLBACK" | tee -a "$LOG"
      pull_model "$FALLBACK"
      MODELS="${MODELS/$tag/$FALLBACK}"
    else
      echo "failed to pull $tag" | tee -a "$LOG" >&2
      exit 1
    fi
  fi
done

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] eval models: $MODELS" | tee -a "$LOG"

EVAL_CMD=(
  "$PY" scripts/evaluate_planner_models.py
  --models "$MODELS"
  --skip-models ""
)

if command -v systemd-inhibit >/dev/null 2>&1; then
  systemd-inhibit --what=sleep:idle --who=agtsmith --why="planner bake-off round2" \
    "${EVAL_CMD[@]}" >>"$LOG" 2>&1
else
  "${EVAL_CMD[@]}" >>"$LOG" 2>&1
fi

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] eval done, merging" | tee -a "$LOG"
"$PY" scripts/merge_planner_bakeoff_results.py | tee -a "$LOG"
echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] round2 complete" | tee -a "$LOG"
