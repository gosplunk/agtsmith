#!/usr/bin/env python3
"""Long-horizon ten-domain SPL learning loop: bootstrap lab data, benchmark, fix, iterate."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from spl_autonomy_fix_dispatch import build_fix_plan
from spl_improvement_loop import process_benchmark_report
from ten_domain_registry import (
    TARGET_PASS_RATE_PCT,
    TEN_DOMAINS,
    domains_by_id,
    lab_domains_for_ids,
    live_cluster_domains,
    oracle_domains,
    score_snapshot_row,
    THEME_TO_DOMAIN,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT = PROJECT_ROOT / "artifacts" / "spl_autonomy" / "ten_domain_loop"
STATE_PATH = DEFAULT_OUT / "state.json"
CYCLES_PATH = DEFAULT_OUT / "cycles.jsonl"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _python_cmd() -> str:
    venv = PROJECT_ROOT / ".venv" / "bin" / "python"
    return str(venv if venv.is_file() else Path(sys.executable))


def _gate_env() -> dict[str, str]:
    env = {
        "AGTSMITH_TEMPLATE_OVERRIDE": "fallback",
        "AGTSMITH_WRITER_MODE": os.getenv("AGTSMITH_WRITER_MODE", "constrained"),
        "PYTHONPATH": f"{PROJECT_ROOT}:{PROJECT_ROOT / 'scripts'}",
    }
    ui_env = PROJECT_ROOT / "config" / "ui.env"
    if ui_env.is_file():
        for line in ui_env.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            env[key.strip()] = value.strip().strip('"').strip("'")
    return env


def _log(msg: str, *, log_path: Path) -> None:
    line = f"[{_utc_now()}] {msg}"
    print(line, flush=True)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")


def _run(cmd: list[str], *, env: dict[str, str] | None = None, allow_fail: bool = False) -> int:
    merged = os.environ.copy()
    merged.update(_gate_env())
    if env:
        merged.update(env)
    print(f"+ {' '.join(cmd)}", flush=True)
    proc = subprocess.run(cmd, cwd=str(PROJECT_ROOT), env=merged)
    if proc.returncode != 0 and not allow_fail:
        raise RuntimeError(f"command failed ({proc.returncode}): {' '.join(cmd)}")
    return proc.returncode


def _read_oracle_report(report_glob: str) -> dict[str, Any] | None:
    path = PROJECT_ROOT / report_glob
    if not path.is_file():
        parent = path.parent
        if parent.is_dir():
            runs = sorted(parent.glob("run_*.json"), key=lambda p: p.stat().st_mtime)
            if runs:
                path = runs[-1]
            else:
                return None
        else:
            return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _oracle_score(domain_id: str, report_glob: str) -> dict[str, Any]:
    payload = _read_oracle_report(report_glob)
    if not isinstance(payload, dict):
        return score_snapshot_row(domain_id, pass_rate_pct=None, passed=None, total=None)
    passed = int(payload.get("passed_count", 0) or 0)
    total = int(payload.get("case_count", 0) or 0)
    rate = payload.get("pass_rate_pct")
    if rate is None and total:
        rate = round((passed / total) * 100, 1)
    return score_snapshot_row(domain_id, pass_rate_pct=float(rate) if rate is not None else None, passed=passed, total=total, path=str(report_glob))


def _latest_live_report() -> Path | None:
    root = PROJECT_ROOT / "artifacts" / "spl_autonomy" / "live_benchmark"
    if not root.is_dir():
        return None
    dirs = [p for p in root.iterdir() if p.is_dir()]
    if not dirs:
        return None
    latest = max(dirs, key=lambda p: p.stat().st_mtime)
    report = latest / "report.json"
    return report if report.is_file() else None


def _live_cluster_scores(report_path: Path | None) -> dict[str, dict[str, Any]]:
    scores: dict[str, dict[str, Any]] = {}
    for domain in live_cluster_domains():
        scores[domain.id] = score_snapshot_row(domain.id, pass_rate_pct=None, passed=None, total=None)
    if report_path is None or not report_path.is_file():
        return scores
    try:
        payload = json.loads(report_path.read_text(encoding="utf-8"))
    except Exception:
        return scores
    buckets: dict[str, list[float]] = {domain.id: [] for domain in live_cluster_domains()}
    for row in payload.get("results", []):
        if not isinstance(row, dict) or row.get("status") != "completed":
            continue
        theme = str(row.get("theme", ""))
        domain_id = THEME_TO_DOMAIN.get(theme)
        if not domain_id:
            continue
        comparison = row.get("comparison", {})
        if isinstance(comparison, dict):
            buckets.setdefault(domain_id, []).append(float(comparison.get("score", 0) or 0))
    for domain_id, values in buckets.items():
        if not values:
            continue
        passed = sum(1 for score in values if score >= TARGET_PASS_RATE_PCT)
        total = len(values)
        rate = round((passed / total) * 100, 1)
        scores[domain_id] = score_snapshot_row(
            domain_id,
            pass_rate_pct=rate,
            passed=passed,
            total=total,
            path=str(report_path.relative_to(PROJECT_ROOT)),
        )
    return scores


def _all_meet_target(scores: dict[str, dict[str, Any]]) -> bool:
    if len(scores) < len(TEN_DOMAINS):
        return False
    return all(row.get("meets_target") for row in scores.values() if row.get("pass_rate_pct") is not None)


def _bootstrap(*, skip_lab: bool, log_path: Path) -> None:
    _log("bootstrap: check-internal-spl-oracles", log_path=log_path)
    _run(["make", "check-internal-spl-oracles"], allow_fail=True)
    _run(["make", "check-linux-spl-oracles"], allow_fail=True)
    _run(["make", "check-gold-oracles"], allow_fail=True)
    if skip_lab:
        _log("bootstrap: skip lab ingest (SKIP_LAB_BOOTSTRAP=1)", log_path=log_path)
        _run(["make", "env-profile-refresh"], allow_fail=True)
        return
    _log("bootstrap: lab-data-expanded-bootstrap (authentic sourcetype fixtures)", log_path=log_path)
    _run(["make", "lab-data-expanded-bootstrap"], allow_fail=True)


def _event_set_names_for_lab_domains(lab_domains: list[str]) -> list[str]:
    try:
        from lab_data_generate import load_event_catalog
    except ImportError:
        return []
    catalog = load_event_catalog()
    sets_raw = catalog.get("event_sets", {})
    if not isinstance(sets_raw, dict):
        return []
    names: list[str] = []
    wanted = set(lab_domains)
    for name, row in sets_raw.items():
        if not isinstance(row, dict):
            continue
        if str(row.get("domain", "")).strip() in wanted:
            names.append(str(name))
    return names


def _generate_lab_for_domains(domain_ids: list[str], log_path: Path) -> None:
    lab_domains = lab_domains_for_ids(domain_ids)
    event_sets = _event_set_names_for_lab_domains(lab_domains)
    if not event_sets:
        return
    _log(f"lab-data refresh domains={lab_domains} event_sets={len(event_sets)}", log_path=log_path)
    _run(["make", "lab-data-provision", "LAB_DATA_LAYOUT=expanded_lab"], allow_fail=True)
    _run(["make", "lab-data-hec-sync", "LAB_DATA_LAYOUT=expanded_lab"], allow_fail=True)
    for event_set in event_sets:
        _run(
            [
                _python_cmd(),
                "scripts/lab_data_generate.py",
                "--layout",
                "expanded_lab",
                "--hours",
                "24",
                "--count",
                "80",
                "--event-set",
                event_set,
            ],
            allow_fail=True,
        )
    _run(["make", "lab-data-verify", "LAB_DATA_LAYOUT=expanded_lab"], allow_fail=True)
    _run(["make", "env-profile-refresh"], allow_fail=True)


def _run_oracle_benchmark(domain_id: str, make_target: str, *, log_path: Path) -> None:
    _log(f"benchmark {domain_id}: make {make_target}", log_path=log_path)
    _run(["make", make_target], allow_fail=True)


def _run_live_benchmark(*, full_pipeline: bool, log_path: Path) -> Path | None:
    cmd = [
        _python_cmd(),
        "scripts/run_live_domain_benchmark.py",
        "--out-root",
        "artifacts/spl_autonomy/live_benchmark",
        "--cases-from-json",
    ]
    if full_pipeline:
        cmd.append("--use-full-pipeline")
    _log(f"live-domain benchmark full_pipeline={full_pipeline}", log_path=log_path)
    _run(cmd, allow_fail=True)
    return _latest_live_report()


def _execute_fixes(failures: list[dict[str, Any]], log_path: Path) -> dict[str, Any]:
    plan = build_fix_plan(failures)
    _log(f"fix_plan primary={plan.get('primary_class')} actions={plan.get('actions')}", log_path=log_path)
    results: list[dict[str, Any]] = []
    for action in plan.get("actions", []):
        if action == "rebuild_cards":
            rc = _run([_python_cmd(), "scripts/build_sourcetype_cards.py"], allow_fail=True)
            results.append({"action": action, "exit_code": rc})
        elif action == "refresh_profile":
            rc = _run(["make", "env-profile-refresh"], allow_fail=True)
            results.append({"action": action, "exit_code": rc})
        elif action == "rebuild_embedding_index":
            rc = _run([_python_cmd(), "scripts/build_spl_embedding_index.py"], allow_fail=True)
            results.append({"action": action, "exit_code": rc})
        elif action == "writer_constrained":
            os.environ["AGTSMITH_WRITER_MODE"] = "constrained"
            results.append({"action": action, "applied": True})
        elif action == "structure_validate":
            rc = _run([_python_cmd(), "scripts/run_spl_phase_gate.py", "--phase=5", "--use-existing"], allow_fail=True)
            results.append({"action": action, "exit_code": rc})
        else:
            results.append({"action": action, "skipped": True})
    return {"plan": plan, "results": results}


def _collect_oracle_failures(scores: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    failures: list[dict[str, Any]] = []
    for domain in oracle_domains():
        row = scores.get(domain.id, {})
        if row.get("meets_target"):
            continue
        failures.append({"reason": f"oracle:{domain.id}:pass_rate={row.get('pass_rate_pct')}"})
    return failures


def _save_state(state: dict[str, Any]) -> None:
    DEFAULT_OUT.mkdir(parents=True, exist_ok=True)
    state["updated_at"] = _utc_now()
    STATE_PATH.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")


def _append_cycle(record: dict[str, Any]) -> None:
    DEFAULT_OUT.mkdir(parents=True, exist_ok=True)
    with CYCLES_PATH.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=True) + "\n")


def run_loop(args: argparse.Namespace) -> int:
    DEFAULT_OUT.mkdir(parents=True, exist_ok=True)
    log_path = DEFAULT_OUT / f"run_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.log"
    deadline = time.time() + args.max_hours * 3600
    _log(f"ten-domain loop start max_hours={args.max_hours} target={TARGET_PASS_RATE_PCT}%", log_path=log_path)

    if not args.skip_bootstrap:
        _bootstrap(skip_lab=args.skip_lab_bootstrap, log_path=log_path)

    cycle = 0
    state: dict[str, Any] = {"cycle": 0, "scores": {}, "complete": False}
    live_full_pipeline = False

    while time.time() < deadline and cycle < args.max_cycles:
        cycle += 1
        _log(f"=== cycle {cycle} ===", log_path=log_path)
        scores: dict[str, dict[str, Any]] = {}

        for domain in oracle_domains():
            _run_oracle_benchmark(domain.id, str(domain.make_template), log_path=log_path)
            scores[domain.id] = _oracle_score(domain.id, str(domain.report_glob))

        live_report = _run_live_benchmark(full_pipeline=live_full_pipeline, log_path=log_path)
        scores.update(_live_cluster_scores(live_report))

        failing = [domain_id for domain_id, row in scores.items() if not row.get("meets_target")]
        _log(f"cycle {cycle} scores={json.dumps({k: v.get('pass_rate_pct') for k, v in scores.items()})}", log_path=log_path)
        _log(f"cycle {cycle} failing={failing}", log_path=log_path)

        record = {
            "cycle": cycle,
            "timestamp_utc": _utc_now(),
            "scores": scores,
            "failing": failing,
            "live_full_pipeline": live_full_pipeline,
        }
        _append_cycle(record)
        state = {"cycle": cycle, "scores": scores, "failing": failing, "complete": False}
        _save_state(state)

        if not failing:
            _log("all ten domains meet target — done", log_path=log_path)
            state["complete"] = True
            _save_state(state)
            break

        if time.time() >= deadline:
            break

        _generate_lab_for_domains(failing, log_path=log_path)

        for domain in oracle_domains():
            if domain.id not in failing:
                continue
            if domain.make_multimodel:
                _run_oracle_benchmark(domain.id, str(domain.make_multimodel), log_path=log_path)
                scores[domain.id] = _oracle_score(domain.id, str(domain.report_glob))

        if any(domain_id in failing for domain_id in [d.id for d in live_cluster_domains()]):
            live_full_pipeline = True
            live_report = _run_live_benchmark(full_pipeline=True, log_path=log_path)
            scores.update(_live_cluster_scores(live_report))

        fix_payload = _execute_fixes(_collect_oracle_failures(scores), log_path=log_path)
        if live_report and live_report.is_file():
            try:
                process_benchmark_report(live_report, min_pass_score=int(TARGET_PASS_RATE_PCT))
            except Exception as exc:
                _log(f"improvement_loop warn: {type(exc).__name__}:{exc}", log_path=log_path)

        record["post_fix_scores"] = scores
        record["fix"] = fix_payload
        _append_cycle(record)
        state["scores"] = scores
        state["failing"] = [domain_id for domain_id, row in scores.items() if not row.get("meets_target")]
        _save_state(state)

        if _all_meet_target(scores):
            _log("all ten domains meet target after fixes — done", log_path=log_path)
            state["complete"] = True
            _save_state(state)
            break

    summary = {
        "completed": state.get("complete", False),
        "cycles": cycle,
        "final_scores": state.get("scores", {}),
        "failing": state.get("failing", []),
        "deadline_utc": datetime.fromtimestamp(deadline, tz=timezone.utc).isoformat(),
        "log_path": str(log_path.relative_to(PROJECT_ROOT)),
        "state_path": str(STATE_PATH.relative_to(PROJECT_ROOT)),
    }
    summary_path = DEFAULT_OUT / "final_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    _log(f"finished complete={summary['completed']} summary={summary_path}", log_path=log_path)
    return 0 if summary["completed"] else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Ten-domain SPL learning loop (8h autonomous target)")
    parser.add_argument("--max-hours", type=float, default=8.0, help="Wall-clock budget (default: 8)")
    parser.add_argument("--max-cycles", type=int, default=12, help="Maximum benchmark/fix cycles")
    parser.add_argument("--skip-bootstrap", action="store_true")
    parser.add_argument("--skip-lab-bootstrap", action="store_true", help="Skip expanded lab ingest on bootstrap")
    args = parser.parse_args(argv)
    return run_loop(args)


if __name__ == "__main__":
    raise SystemExit(main())
