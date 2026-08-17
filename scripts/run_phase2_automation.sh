#!/usr/bin/env bash
# Phase 2 SPL quality program — automated gate runner (host .venv + config/ui.env).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
LOG_DIR="${ROOT}/artifacts/spl_autonomy/phase2_automation"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
MAIN_LOG="${LOG_DIR}/run_${STAMP}.log"
SUMMARY="${LOG_DIR}/run_${STAMP}_summary.json"

mkdir -p "$LOG_DIR"
export PYTHONPATH=.:scripts

log() {
  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*" | tee -a "$MAIN_LOG"
}

run_step() {
  local id="$1"
  shift
  local start end dur rc
  log "BEGIN ${id}: $*"
  start=$(date +%s)
  set +e
  "$@" >>"$MAIN_LOG" 2>&1
  rc=$?
  set -e
  end=$(date +%s)
  dur=$((end - start))
  if [[ $rc -eq 0 ]]; then
    log "PASS ${id} (${dur}s)"
  else
    log "FAIL ${id} exit=${rc} (${dur}s)"
  fi
  printf '{"id":"%s","command":"%s","exit_code":%s,"duration_s":%s,"status":"%s"}\n' \
    "$id" "$*" "$rc" "$dur" "$( [[ $rc -eq 0 ]] && echo pass || echo fail )" >> "${LOG_DIR}/steps_${STAMP}.jsonl"
  return "$rc"
}

CONTINUE_ON_FAIL="${CONTINUE_ON_FAIL:-1}"

step() {
  if run_step "$@"; then
    return 0
  fi
  if [[ "$CONTINUE_ON_FAIL" == "1" ]]; then
    log "WARN continuing after failure (CONTINUE_ON_FAIL=1)"
    return 0
  fi
  exit 1
}

log "phase2 automation started stamp=${STAMP}"
log "log=${MAIN_LOG}"

# --- Phase A: offline / CI gates ---
step "check-internal-oracles" make check-internal-spl-oracles
step "check-linux-oracles" make check-linux-spl-oracles
step "internal-offline" make internal-spl-accuracy-offline
step "linux-offline" make linux-spl-accuracy-offline
step "operational-offline" make operational-spl-accuracy-offline
step "check-gold-oracles" make check-gold-oracles

# --- Phase B: discover + cards (refresh artifacts) ---
step "internal-discover" make internal-spl-discover
step "linux-discover" make linux-spl-discover
step "internal-cards" make internal-sourcetype-cards
step "linux-cards" make linux-sourcetype-cards

# --- Phase C: live template accuracy ---
step "internal-template-live" make internal-spl-accuracy
step "linux-template-live" make linux-spl-accuracy
step "operational-template-live" make operational-spl-accuracy

# --- Phase D: live multimodel (long) ---
export AGTSMITH_TEMPLATE_OVERRIDE=fallback
export AGTSMITH_WRITER_MODE=constrained
step "operational-multimodel-live" make operational-spl-accuracy-multimodel
step "internal-multimodel-live" make internal-spl-accuracy-multimodel
step "linux-multimodel-live" make linux-spl-accuracy-multimodel

# --- Phase E: profile + live domain ---
step "env-profile-check" make env-profile-check
step "env-profile-refresh" make env-profile-refresh
step "live-domain-offline" make live-domain-benchmark-offline
step "live-domain-live" make live-domain-benchmark

# --- Phase F: report ---
step "spl-phase-report" make spl-phase-report

python3 - <<PY >>"$MAIN_LOG" 2>&1
import json
from pathlib import Path

root = Path("${ROOT}")
steps = []
jsonl = Path("${LOG_DIR}/steps_${STAMP}.jsonl")
if jsonl.is_file():
    for line in jsonl.read_text().splitlines():
        if line.strip():
            steps.append(json.loads(line))

def latest_benchmark(rel):
    p = root / rel
    if p.is_file():
        d = json.loads(p.read_text())
        return {
            "path": rel,
            "passed": d.get("passed_count"),
            "total": d.get("case_count"),
            "multi_model": d.get("multi_model"),
            "offline": d.get("offline"),
            "timestamp_utc": d.get("timestamp_utc"),
        }
    parent = root / rel
    if parent.is_dir():
        runs = sorted(parent.glob("run_*.json"), key=lambda x: x.stat().st_mtime)
        if runs:
            d = json.loads(runs[-1].read_text())
            return {
                "path": str(runs[-1].relative_to(root)),
                "passed": d.get("passed_count"),
                "total": d.get("case_count"),
                "multi_model": d.get("multi_model"),
                "offline": d.get("offline"),
                "timestamp_utc": d.get("timestamp_utc"),
            }
    return None

summary = {
    "stamp": "${STAMP}",
    "steps": steps,
    "benchmarks": {
        "internal": latest_benchmark("artifacts/spl_autonomy/internal_benchmark/latest.json"),
        "linux": latest_benchmark("artifacts/spl_autonomy/linux_benchmark/latest.json"),
        "operational": latest_benchmark("artifacts/benchmark/operational_spl_accuracy"),
    },
    "failed_steps": [s["id"] for s in steps if s.get("status") == "fail"],
}
out = Path("${SUMMARY}")
out.write_text(json.dumps(summary, indent=2))
print(json.dumps(summary, indent=2))
PY

log "phase2 automation complete summary=${SUMMARY}"
