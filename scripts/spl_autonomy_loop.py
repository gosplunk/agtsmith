#!/usr/bin/env python3
"""Closed-loop SPL autonomy orchestrator: preflight, benchmark, E2E, propose, re-run."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from spl_autonomy_manifest import write_run_manifest
from spl_improvement_loop import process_benchmark_report

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT = PROJECT_ROOT / "artifacts" / "spl_autonomy"
DEFAULT_CASES = PROJECT_ROOT / "benchmarks" / "pilot_live_20_cases.json"
PROMOTION_HISTORY = PROJECT_ROOT / "artifacts" / "learning" / "promotion_history.jsonl"
PYTHON = PROJECT_ROOT / ".venv" / "bin" / "python"


def _python_cmd() -> str:
    return str(PYTHON if PYTHON.is_file() else Path(sys.executable))


def _run(cmd: list[str], *, allow_fail: bool = False) -> subprocess.CompletedProcess[str]:
    print(f"[spl-autonomy-loop] exec: {' '.join(cmd)}")
    env = os.environ.copy()
    env.setdefault("PYTHONPATH", f"{PROJECT_ROOT}:{PROJECT_ROOT / 'scripts'}")
    proc = subprocess.run(cmd, cwd=PROJECT_ROOT, text=True, capture_output=True, env=env)
    if proc.stdout.strip():
        print(proc.stdout.rstrip())
    if proc.stderr.strip():
        print(proc.stderr.rstrip(), file=sys.stderr)
    if proc.returncode != 0 and not allow_fail:
        raise RuntimeError(f"command failed ({proc.returncode}): {' '.join(cmd)}")
    return proc


def _preflight() -> dict[str, Any]:
    script = PROJECT_ROOT / ".cursor" / "skills" / "agtsmith-local-lab" / "scripts" / "preflight.sh"
    if not script.is_file():
        return {"ok": False, "skipped": True, "reason": "preflight_script_missing"}
    proc = _run(["bash", str(script)], allow_fail=True)
    return {"ok": proc.returncode == 0, "exit_code": proc.returncode}


def _run_hardening_subset(out_dir: Path, cases: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    _run(
        [
            _python_cmd(),
            "scripts/run_spl_hardening_benchmark.py",
            "--cases",
            str(cases),
            "--out-dir",
            str(out_dir),
        ]
    )
    latest = out_dir / "spl_hardening_benchmark_latest.json"
    if not latest.is_file():
        scoped = sorted(out_dir.glob("spl_hardening_benchmark_latest_*.json"))
        if scoped:
            latest = scoped[-1]
    return latest


def _run_investigation_e2e(out_dir: Path) -> dict[str, Any]:
    script = PROJECT_ROOT / "scripts" / "investigation_e2e.py"
    if not script.is_file():
        return {"skipped": True, "reason": "investigation_e2e_missing"}
    env = os.environ.copy()
    env["SPL_AUTONOMY_OUT"] = str(out_dir)
    env.setdefault("PYTHONPATH", f"{PROJECT_ROOT}:{PROJECT_ROOT / 'scripts'}")
    proc = subprocess.run(
        [_python_cmd(), str(script)],
        cwd=PROJECT_ROOT,
        text=True,
        capture_output=True,
        env=env,
    )
    if proc.stdout.strip():
        print(proc.stdout.rstrip())
    if proc.stderr.strip():
        print(proc.stderr.rstrip(), file=sys.stderr)
    return {"exit_code": proc.returncode, "skipped": False}


def _summarize_benchmark(report_path: Path, *, min_pass_score: int) -> dict[str, Any]:
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    results = payload.get("results", [])
    if not isinstance(results, list):
        results = []
    scores = [int(row.get("score", 0)) for row in results if isinstance(row, dict)]
    auth_scores = [
        int(row.get("score", 0))
        for row in results
        if isinstance(row, dict) and "auth" in str(row.get("family", "")).lower()
    ]
    pass_rate = round((sum(1 for score in scores if score >= min_pass_score) / len(scores)) * 100, 2) if scores else 0.0
    auth_pass_rate = (
        round((sum(1 for score in auth_scores if score >= min_pass_score) / len(auth_scores)) * 100, 2)
        if auth_scores
        else pass_rate
    )
    return {
        "case_count": len(results),
        "pass_rate_pct": pass_rate,
        "auth_pass_rate_pct": auth_pass_rate,
        "avg_score": payload.get("summary", {}).get("avg_score", 0.0),
        "failing_case_count": payload.get("summary", {}).get("failing_case_count", 0),
    }


def _promote_if_requested(*, promote: bool, summary: dict[str, Any], min_pass_score: int) -> dict[str, Any]:
    if not promote:
        return {"promoted": False, "reason": "promote_not_requested"}
    pass_rate = float(summary.get("pass_rate_pct", 0.0))
    auth_pass_rate = float(summary.get("auth_pass_rate_pct", pass_rate))
    if pass_rate < 85.0 or auth_pass_rate < 95.0:
        return {
            "promoted": False,
            "reason": "promotion_gates_failed",
            "pass_rate_pct": pass_rate,
            "auth_pass_rate_pct": auth_pass_rate,
        }
    build_script = PROJECT_ROOT / "scripts" / "build_spl_skillpack.py"
    if not build_script.is_file():
        return {"promoted": False, "reason": "build_spl_skillpack_missing"}
    _run([_python_cmd(), str(build_script)])
    PROMOTION_HISTORY.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "action": "promote_skillpack",
        "pass_rate_pct": pass_rate,
        "auth_pass_rate_pct": auth_pass_rate,
        "min_pass_score": min_pass_score,
    }
    with PROMOTION_HISTORY.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=True) + "\n")
    return {"promoted": True, "promotion_history": str(PROMOTION_HISTORY)}


def main() -> int:
    parser = argparse.ArgumentParser(description="Run SPL autonomy closed loop")
    parser.add_argument("--out-dir", default=str(DEFAULT_OUT))
    parser.add_argument("--cases", default=str(DEFAULT_CASES))
    parser.add_argument("--min-pass-score", type=int, default=85)
    parser.add_argument("--promote", action="store_true", help="Auto-promote skillpack when gates pass")
    parser.add_argument("--skip-preflight", action="store_true")
    parser.add_argument("--skip-e2e", action="store_true")
    args = parser.parse_args()

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = Path(args.out_dir) / "runs" / stamp
    benchmark_dir = run_dir / "benchmark"
    run_dir.mkdir(parents=True, exist_ok=True)

    preflight = {"skipped": True} if args.skip_preflight else _preflight()
    if not args.skip_preflight and not preflight.get("ok", False):
        print("SKIP spl-autonomy-loop: local lab preflight failed")
        write_run_manifest(run_dir, extra={"status": "skipped_preflight", "preflight": preflight})
        return 0

    baseline_report = _run_hardening_subset(benchmark_dir, Path(args.cases))
    baseline_summary = _summarize_benchmark(baseline_report, min_pass_score=args.min_pass_score)

    improvement = process_benchmark_report(baseline_report, min_pass_score=args.min_pass_score)

    rerun_report = _run_hardening_subset(benchmark_dir / "rerun", Path(args.cases))
    rerun_summary = _summarize_benchmark(rerun_report, min_pass_score=args.min_pass_score)

    e2e = {"skipped": True} if args.skip_e2e else _run_investigation_e2e(run_dir)

    promotion = _promote_if_requested(
        promote=args.promote,
        summary=rerun_summary,
        min_pass_score=args.min_pass_score,
    )

    manifest_extra = {
        "status": "completed",
        "preflight": preflight,
        "cases_path": str(Path(args.cases)),
        "baseline_report": str(baseline_report),
        "rerun_report": str(rerun_report),
        "baseline_summary": baseline_summary,
        "rerun_summary": rerun_summary,
        "improvement": improvement,
        "investigation_e2e": e2e,
        "promotion": promotion,
    }
    manifest_path = write_run_manifest(run_dir, extra=manifest_extra)
    summary_path = run_dir / "loop_summary.json"
    summary_path.write_text(json.dumps(manifest_extra, indent=2) + "\n", encoding="utf-8")

    print("=== SPL Autonomy Loop ===")
    print(f"run_dir={run_dir}")
    print(f"manifest={manifest_path}")
    print(f"baseline_pass_rate_pct={baseline_summary.get('pass_rate_pct')}")
    print(f"rerun_pass_rate_pct={rerun_summary.get('pass_rate_pct')}")
    print(f"candidates_proposed={improvement.get('candidates_proposed', 0)}")
    print(f"promoted={promotion.get('promoted', False)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
