#!/usr/bin/env python3
"""Extended SPL autonomy loop with long-horizon phase gates and fix dispatch."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from spl_autonomy_fix_dispatch import build_fix_plan
from spl_autonomy_manifest import write_run_manifest
from spl_improvement_loop import process_benchmark_report

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT = PROJECT_ROOT / "artifacts" / "spl_autonomy"
DEFAULT_CASES = PROJECT_ROOT / "benchmarks" / "pilot_live_20_cases.json"
LOOP_STATE_PATH = DEFAULT_OUT / "loop_state.json"
PHASE_PROGRESS_PATH = PROJECT_ROOT / "artifacts" / "spl_autonomy" / "phase_progress.json"
PROMOTION_HISTORY = PROJECT_ROOT / "artifacts" / "learning" / "promotion_history.jsonl"
PYTHON = PROJECT_ROOT / ".venv" / "bin" / "python"


def _python_cmd() -> str:
    return str(PYTHON if PYTHON.is_file() else Path(sys.executable))


def _run(cmd: list[str], *, allow_fail: bool = False, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    print(f"[spl-autonomy-loop] exec: {' '.join(cmd)}")
    merged = os.environ.copy()
    merged.setdefault("PYTHONPATH", f"{PROJECT_ROOT}:{PROJECT_ROOT / 'scripts'}")
    if env:
        merged.update(env)
    proc = subprocess.run(cmd, cwd=PROJECT_ROOT, text=True, capture_output=True, env=merged)
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
    failures = [
        {"reason": row.get("failure_reason", row.get("notes", ""))}
        for row in results
        if isinstance(row, dict) and int(row.get("score", 0)) < min_pass_score
    ]
    return {
        "case_count": len(results),
        "pass_rate_pct": pass_rate,
        "auth_pass_rate_pct": auth_pass_rate,
        "avg_score": payload.get("summary", {}).get("avg_score", 0.0),
        "failing_case_count": payload.get("summary", {}).get("failing_case_count", 0),
        "failures": failures,
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


def _load_loop_state() -> dict[str, Any]:
    if not LOOP_STATE_PATH.is_file():
        return {"iteration": 0, "history": []}
    try:
        data = json.loads(LOOP_STATE_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {"iteration": 0, "history": []}
    return data if isinstance(data, dict) else {"iteration": 0, "history": []}


def _save_loop_state(state: dict[str, Any]) -> None:
    LOOP_STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    LOOP_STATE_PATH.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")


def _gate_env() -> dict[str, str]:
    env = {
        "AGTSMITH_TEMPLATE_OVERRIDE": "fallback",
        "AGTSMITH_WRITER_MODE": os.getenv("AGTSMITH_WRITER_MODE", "constrained"),
    }
    if os.getenv("SPLUNK_LAB_BEARER_TOKEN"):
        env["SPLUNK_LAB_BEARER_TOKEN"] = os.environ["SPLUNK_LAB_BEARER_TOKEN"]
    return env


def _run_phase_gate(phase: int, *, quick: bool, use_existing: bool) -> dict[str, Any]:
    cmd = [_python_cmd(), "scripts/run_spl_phase_gate.py", f"--phase={phase}"]
    if quick:
        cmd.append("--quick")
    if use_existing:
        cmd.append("--use-existing")
    proc = _run(cmd, allow_fail=True, env=_gate_env())
    gate_payload: dict[str, Any] = {"exit_code": proc.returncode, "stdout": proc.stdout[-4000:]}
    if PHASE_PROGRESS_PATH.is_file():
        try:
            progress = json.loads(PHASE_PROGRESS_PATH.read_text(encoding="utf-8"))
            gate_payload["phase_metrics"] = progress.get("phases", {}).get(str(phase), {})
        except Exception:
            pass
    return gate_payload


def _execute_fix_actions(actions: list[str], *, quick: bool, offline: bool = False) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for action in actions:
        if action == "rebuild_cards":
            proc = _run([_python_cmd(), "scripts/build_sourcetype_cards.py"], allow_fail=True)
            results.append({"action": action, "exit_code": proc.returncode})
        elif action == "refresh_profile" and not offline:
            proc = _run(["make", "env-profile-refresh"], allow_fail=True)
            results.append({"action": action, "exit_code": proc.returncode})
        elif action == "refresh_profile" and offline:
            results.append({"action": action, "skipped": True, "reason": "offline_mode"})
        elif action == "rebuild_embedding_index":
            flag = "--skip-embed" if offline else ""
            cmd = [_python_cmd(), "scripts/build_spl_embedding_index.py"]
            if flag:
                cmd.append(flag)
            proc = _run(cmd, allow_fail=True)
            results.append({"action": action, "exit_code": proc.returncode})
        elif action == "writer_eval" and not offline:
            target = "model-spl-eval-quick" if quick else "model-spl-eval"
            proc = _run(["make", target], allow_fail=True, env=_gate_env())
            results.append({"action": action, "exit_code": proc.returncode})
        elif action == "writer_eval" and offline:
            results.append({"action": action, "skipped": True, "reason": "offline_mode"})
        elif action == "phase_gate":
            proc = _run([_python_cmd(), "scripts/run_spl_phase_gate.py", "--phase=5", "--use-existing"], allow_fail=True)
            results.append({"action": action, "exit_code": proc.returncode})
        else:
            results.append({"action": action, "skipped": True})
    return results


def _long_horizon_loop(args: argparse.Namespace) -> int:
    loop_state = _load_loop_state()
    iteration = int(loop_state.get("iteration", 0))
    history: list[dict[str, Any]] = list(loop_state.get("history", []))
    prev_writer_avg: float | None = None
    plateau_hits = 0

    for step in range(args.max_iterations):
        iteration += 1
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        run_dir = Path(args.out_dir) / "long_horizon" / stamp
        run_dir.mkdir(parents=True, exist_ok=True)

        if iteration == 1 and not args.skip_baseline_gate:
            _run_phase_gate(0, quick=args.quick, use_existing=args.use_existing_artifacts)

        if args.use_existing_artifacts:
            report = PROJECT_ROOT / "artifacts" / "spl_hardening" / "benchmark_latest.json"
            if not report.is_file():
                benchmark_dir = run_dir / "benchmark"
                benchmark_dir.mkdir(parents=True, exist_ok=True)
                report = benchmark_dir / "offline_stub.json"
                report.write_text(
                    json.dumps(
                        {
                            "summary": {"avg_score": 76.56, "failing_case_count": 1},
                            "results": [{"score": 70, "failure_reason": "environment:unknown_sourcetype"}],
                        },
                        indent=2,
                    ),
                    encoding="utf-8",
                )
        else:
            benchmark_dir = run_dir / "benchmark"
            report = _run_hardening_subset(benchmark_dir, Path(args.cases))
        summary = _summarize_benchmark(report, min_pass_score=args.min_pass_score)
        fix_plan = build_fix_plan(list(summary.get("failures", [])))
        fix_results = _execute_fix_actions(
            fix_plan.get("actions", []),
            quick=args.quick,
            offline=args.use_existing_artifacts,
        )
        improvement = process_benchmark_report(report, min_pass_score=args.min_pass_score)

        gate = _run_phase_gate(min(5, args.phase), quick=args.quick, use_existing=True)
        writer_avg = None
        phase_metrics = gate.get("phase_metrics", {})
        if isinstance(phase_metrics, dict):
            metrics = phase_metrics.get("metrics", {})
            if isinstance(metrics, dict):
                writer_avg = float(metrics.get("writer_avg", 0) or 0) or None

        if writer_avg is not None and prev_writer_avg is not None:
            if abs(writer_avg - prev_writer_avg) < 0.5:
                plateau_hits += 1
            else:
                plateau_hits = 0
        if writer_avg is not None:
            prev_writer_avg = writer_avg

        record = {
            "iteration": iteration,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "summary": summary,
            "fix_plan": fix_plan,
            "fix_results": fix_results,
            "improvement": improvement,
            "gate": gate,
            "writer_avg": writer_avg,
        }
        history.append(record)
        loop_state = {"iteration": iteration, "history": history, "updated_at": datetime.now(timezone.utc).isoformat()}
        _save_loop_state(loop_state)
        write_run_manifest(run_dir, extra={"long_horizon": record})

        if not args.use_existing_artifacts and plateau_hits >= 3:
            report_path = Path(args.out_dir) / "long_horizon_final_report.json"
            report_path.write_text(
                json.dumps({"iterations": iteration, "history": history, "plateau": True}, indent=2) + "\n",
                encoding="utf-8",
            )
            print(f"plateau_detected iterations={iteration} report={report_path}")
            return 0

    report_path = Path(args.out_dir) / "long_horizon_final_report.json"
    report_path.write_text(
        json.dumps({"iterations": iteration, "history": history}, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"long_horizon_complete iterations={iteration} report={report_path}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Run SPL autonomy closed loop")
    parser.add_argument("--out-dir", default=str(DEFAULT_OUT))
    parser.add_argument("--cases", default=str(DEFAULT_CASES))
    parser.add_argument("--min-pass-score", type=int, default=85)
    parser.add_argument("--promote", action="store_true", help="Auto-promote skillpack when gates pass")
    parser.add_argument("--skip-preflight", action="store_true")
    parser.add_argument("--skip-e2e", action="store_true")
    parser.add_argument("--long-horizon", action="store_true", help="Run iterative long-horizon autonomy loop")
    parser.add_argument("--max-iterations", type=int, default=10)
    parser.add_argument("--phase", type=int, default=5)
    parser.add_argument("--quick", action="store_true")
    parser.add_argument("--use-existing-artifacts", action="store_true")
    parser.add_argument("--skip-baseline-gate", action="store_true")
    args = parser.parse_args()

    if args.long_horizon:
        return _long_horizon_loop(args)

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
