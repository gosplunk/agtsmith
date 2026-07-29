#!/usr/bin/env bash
# Planner bake-off resume: no-op — dense qwen3:30b was skipped; bake-off marked complete in PAUSED.json.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
OUT="$ROOT/artifacts/model_eval/planner_bakeoff"
LOG="$OUT/run_full.log"
PY="$ROOT/.venv/bin/python"

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] bake-off resume: nothing to run (qwen3:30b dense skipped/removed; see PAUSED.json)" | tee -a "$LOG"
echo "Planner bake-off is complete. Optional merge: $PY scripts/merge_planner_bakeoff_results.py" >&2
exit 0
