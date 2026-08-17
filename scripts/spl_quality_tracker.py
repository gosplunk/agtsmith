#!/usr/bin/env python3
"""SPL quality program tracker: domain registry, job launcher, progress snapshots."""

from __future__ import annotations

import html
import json
import os
import re
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TRACKER_ROOT = PROJECT_ROOT / "artifacts" / "spl_autonomy" / "quality_tracker"
STATE_PATH = TRACKER_ROOT / "state.json"
JOBS_DIR = TRACKER_ROOT / "jobs"

PHASE_SLO = {
    1: {"template_pct": 90, "multimodel_pct": 80, "label": "Phase 1 — Prove harness"},
    2: {"template_pct": 100, "multimodel_pct": 95, "label": "Phase 2 — Lock platform quality"},
    3: {"template_pct": 100, "multimodel_pct": 95, "label": "Phase 3 — Expand coverage"},
}

_JOB_LOCK = threading.Lock()
_ACTIVE_THREAD: threading.Thread | None = None


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _job_def(
    job_id: str,
    label: str,
    make_target: str,
    *,
    tier: str,
    kind: str,
    estimated_minutes: int = 5,
    env: dict[str, str] | None = None,
    updates_scores: bool = False,
) -> dict[str, Any]:
    return {
        "id": job_id,
        "label": label,
        "make_target": make_target,
        "tier": tier,
        "kind": kind,
        "estimated_minutes": estimated_minutes,
        "env": env or {},
        "updates_scores": updates_scores,
    }


DOMAIN_PROGRAMS: list[dict[str, Any]] = [
    {
        "id": "internal",
        "title": "Splunk Internal Indexes",
        "subtitle": "_internal · _audit · _introspection",
        "phase_target": 2,
        "case_count": 10,
        "oracle_path": "benchmarks/internal_spl_oracles.json",
        "benchmark_dir": "artifacts/spl_autonomy/internal_benchmark",
        "improvement_log": "artifacts/spl_autonomy/internal_benchmark/improvement_log.json",
        "catalog_path": "artifacts/environment/internal_index_catalog.json",
        "cards_path": "artifacts/environment/internal_sourcetype_cards.json",
        "doc_path": "docs/project/internal_spl_benchmark.md",
        "jobs": [
            _job_def("internal-discover", "Discover index catalog", "internal-spl-discover", tier="setup", kind="discover", estimated_minutes=1),
            _job_def("internal-check-oracles", "Validate oracle corpus", "check-internal-spl-oracles", tier="gate", kind="oracle_check", estimated_minutes=1),
            _job_def("internal-offline", "Offline routing gate", "internal-spl-accuracy-offline", tier="gate", kind="offline", estimated_minutes=1),
            _job_def("internal-cards", "Build sourcetype cards", "internal-sourcetype-cards", tier="setup", kind="cards", estimated_minutes=3),
            _job_def("internal-template", "Live template accuracy", "internal-spl-accuracy", tier="live", kind="template_live", estimated_minutes=3, updates_scores=True),
            _job_def(
                "internal-multimodel",
                "Live multimodel accuracy",
                "internal-spl-accuracy-multimodel",
                tier="live",
                kind="multimodel_live",
                estimated_minutes=45,
                env={"AGTSMITH_TEMPLATE_OVERRIDE": "fallback", "AGTSMITH_WRITER_MODE": "constrained"},
                updates_scores=True,
            ),
        ],
    },
    {
        "id": "linux",
        "title": "Linux Data Domain",
        "subtitle": "index=linux · auth · sudo · audit",
        "phase_target": 2,
        "case_count": 10,
        "oracle_path": "benchmarks/linux_spl_oracles.json",
        "benchmark_dir": "artifacts/spl_autonomy/linux_benchmark",
        "improvement_log": "artifacts/spl_autonomy/linux_benchmark/improvement_log.json",
        "catalog_path": "artifacts/environment/linux_index_catalog.json",
        "cards_path": "artifacts/environment/linux_sourcetype_cards.json",
        "doc_path": "docs/project/linux_spl_benchmark.md",
        "jobs": [
            _job_def("linux-discover", "Discover index catalog", "linux-spl-discover", tier="setup", kind="discover", estimated_minutes=1),
            _job_def("linux-check-oracles", "Validate oracle corpus", "check-linux-spl-oracles", tier="gate", kind="oracle_check", estimated_minutes=1),
            _job_def("linux-offline", "Offline routing gate", "linux-spl-accuracy-offline", tier="gate", kind="offline", estimated_minutes=1),
            _job_def("linux-cards", "Build sourcetype cards", "linux-sourcetype-cards", tier="setup", kind="cards", estimated_minutes=4),
            _job_def("linux-template", "Live template accuracy", "linux-spl-accuracy", tier="live", kind="template_live", estimated_minutes=3, updates_scores=True),
            _job_def(
                "linux-multimodel",
                "Live multimodel accuracy",
                "linux-spl-accuracy-multimodel",
                tier="live",
                kind="multimodel_live",
                estimated_minutes=45,
                env={"AGTSMITH_TEMPLATE_OVERRIDE": "fallback", "AGTSMITH_WRITER_MODE": "constrained"},
                updates_scores=True,
            ),
        ],
    },
    {
        "id": "operational",
        "title": "Operational SPL",
        "subtitle": "Cross-index SOC-shaped questions",
        "phase_target": 2,
        "case_count": None,
        "oracle_path": "benchmarks/operational_spl_accuracy.json",
        "benchmark_dir": "artifacts/benchmark/operational_spl_accuracy",
        "benchmark_dir_offline": "artifacts/benchmark/operational_spl_accuracy_offline",
        "improvement_log": None,
        "catalog_path": None,
        "cards_path": None,
        "doc_path": "docs/project/spl_self_improvement_plan.md",
        "jobs": [
            _job_def("operational-offline", "Offline gate (make check)", "operational-spl-accuracy-offline", tier="gate", kind="offline", estimated_minutes=1),
            _job_def("operational-template", "Live template accuracy", "operational-spl-accuracy", tier="live", kind="template_live", estimated_minutes=5, updates_scores=True),
            _job_def(
                "operational-multimodel",
                "Live multimodel accuracy",
                "operational-spl-accuracy-multimodel",
                tier="live",
                kind="multimodel_live",
                estimated_minutes=60,
                env={"AGTSMITH_TEMPLATE_OVERRIDE": "fallback", "AGTSMITH_WRITER_MODE": "constrained"},
                updates_scores=True,
            ),
        ],
    },
    {
        "id": "live_domain",
        "title": "Live Domain Benchmark",
        "subtitle": "Profile-grounded linux · web · windows · cloud",
        "phase_target": 2,
        "case_count": 20,
        "oracle_path": "benchmarks/live_domain_benchmark.json",
        "benchmark_dir": "artifacts/spl_autonomy/live_benchmark",
        "improvement_log": None,
        "catalog_path": "artifacts/environment/environment_profile_latest.json",
        "cards_path": None,
        "doc_path": "docs/project/live_domain_spl_benchmark.md",
        "jobs": [
            _job_def("live-domain-offline", "Offline compare", "live-domain-benchmark-offline", tier="gate", kind="offline", estimated_minutes=2),
            _job_def("live-domain-live", "Live MCP benchmark", "live-domain-benchmark", tier="live", kind="template_live", estimated_minutes=10, updates_scores=True),
            _job_def("env-profile-check", "Environment profile freshness", "env-profile-check", tier="setup", kind="profile_check", estimated_minutes=1),
            _job_def("env-profile-refresh", "Refresh Data Domains profile", "env-profile-refresh", tier="setup", kind="profile_refresh", estimated_minutes=15),
        ],
    },
    {
        "id": "release",
        "title": "Release & Autonomy Gates",
        "subtitle": "Phase gates · hardening · nightly loop",
        "phase_target": 3,
        "case_count": None,
        "oracle_path": None,
        "benchmark_dir": "artifacts/spl_autonomy",
        "improvement_log": None,
        "catalog_path": None,
        "cards_path": None,
        "doc_path": "docs/project/internal_spl_phase3.md",
        "jobs": [
            _job_def("make-check", "Full make check", "check", tier="gate", kind="ci", estimated_minutes=3),
            _job_def("spl-phase-report", "SPL phase progress report", "spl-phase-report", tier="gate", kind="phase_report", estimated_minutes=1),
            _job_def("spl-autonomy-check", "SPL autonomy check subset", "spl-autonomy-check", tier="live", kind="autonomy", estimated_minutes=20),
            _job_def("check-gold-oracles", "Gold oracle validation", "check-gold-oracles", tier="gate", kind="oracle_check", estimated_minutes=1),
        ],
    },
]


def _programs_by_id() -> dict[str, dict[str, Any]]:
    return {str(row["id"]): row for row in DOMAIN_PROGRAMS}


def _jobs_by_id() -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for program in DOMAIN_PROGRAMS:
        for job in program.get("jobs", []):
            enriched = dict(job)
            enriched["domain_id"] = program["id"]
            enriched["domain_title"] = program["title"]
            out[str(job["id"])] = enriched
    return out


def _load_json(path: Path) -> Any:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _load_state() -> dict[str, Any]:
    data = _load_json(STATE_PATH)
    if not isinstance(data, dict):
        data = {"runs": [], "job_last_success": {}, "updated_at": None}
    data.setdefault("runs", [])
    data.setdefault("job_last_success", {})
    return data


def _save_state(state: dict[str, Any]) -> None:
    TRACKER_ROOT.mkdir(parents=True, exist_ok=True)
    state["updated_at"] = _utc_now()
    STATE_PATH.write_text(json.dumps(state, indent=2), encoding="utf-8")


def _parse_benchmark_report(path: Path) -> dict[str, Any] | None:
    data = _load_json(path)
    if not isinstance(data, dict):
        return None
    passed = int(data.get("passed_count", 0) or 0)
    total = int(data.get("case_count", 0) or 0)
    rate = round((passed / total) * 100, 1) if total else None
    return {
        "path": str(path.relative_to(PROJECT_ROOT)),
        "timestamp_utc": data.get("timestamp_utc"),
        "passed_count": passed,
        "case_count": total,
        "pass_rate_pct": data.get("pass_rate_pct", rate),
        "multi_model": bool(data.get("multi_model")),
        "offline": bool(data.get("offline")),
        "failure_taxonomy": data.get("failure_taxonomy", {}),
        "informative_case_count": data.get("informative_case_count"),
    }


def _latest_benchmark_in_dir(dir_rel: str) -> dict[str, Any] | None:
    root = PROJECT_ROOT / dir_rel
    latest = root / "latest.json"
    if latest.is_file():
        parsed = _parse_benchmark_report(latest)
        if parsed:
            return parsed
    history = root / "history"
    if history.is_dir():
        files = sorted(history.glob("run_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        if files:
            return _parse_benchmark_report(files[0])
    # operational uses flat run_*.json
    if root.is_dir():
        files = sorted(root.glob("run_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        if files:
            return _parse_benchmark_report(files[0])
    return None


def _latest_live_domain_report() -> dict[str, Any] | None:
    root = PROJECT_ROOT / "artifacts" / "spl_autonomy" / "live_benchmark"
    if not root.is_dir():
        return None
    dirs = [p for p in root.iterdir() if p.is_dir()]
    if not dirs:
        return None
    latest_dir = max(dirs, key=lambda p: p.stat().st_mtime)
    report = latest_dir / "report.json"
    data = _load_json(report)
    if not isinstance(data, dict):
        return None
    summary = data.get("summary", data)
    if not isinstance(summary, dict):
        summary = data
    passed = summary.get("passed", summary.get("passed_count"))
    total = summary.get("total", summary.get("case_count"))
    return {
        "path": str(report.relative_to(PROJECT_ROOT)),
        "timestamp_utc": summary.get("timestamp_utc") or data.get("timestamp_utc"),
        "passed_count": passed,
        "case_count": total,
        "pass_rate_pct": summary.get("pass_rate_pct"),
        "multi_model": bool(summary.get("multi_model")),
        "offline": bool(summary.get("offline") or summary.get("skip_mcp")),
        "failure_taxonomy": summary.get("failure_taxonomy", {}),
    }


def _improvement_summary(path_rel: str | None) -> dict[str, Any] | None:
    if not path_rel:
        return None
    data = _load_json(PROJECT_ROOT / path_rel)
    if not isinstance(data, dict):
        return None
    ideas = data.get("ideas", [])
    kept = sum(1 for row in ideas if isinstance(row, dict) and row.get("status") == "kept")
    final = data.get("final", {})
    baseline = data.get("baseline", {})
    return {
        "program": data.get("program"),
        "ideas_total": len(ideas) if isinstance(ideas, list) else 0,
        "ideas_kept": kept,
        "baseline": baseline,
        "final": final,
        "path": path_rel,
    }


def _score_for_kind(program: dict[str, Any], kind: str) -> dict[str, Any] | None:
    benchmark_dir = str(program.get("benchmark_dir") or "")
    if kind == "offline" and program.get("benchmark_dir_offline"):
        offline = _latest_benchmark_in_dir(str(program["benchmark_dir_offline"]))
        if offline:
            return offline
    if program["id"] == "live_domain":
        report = _latest_live_domain_report()
        return report
    if program["id"] == "release":
        phase = _load_json(PROJECT_ROOT / "artifacts" / "spl_autonomy" / "phase_progress.json")
        return {"phase_progress": phase} if phase else None
    latest = _latest_benchmark_in_dir(benchmark_dir)
    if not latest:
        return None
    if kind == "template_live":
        if latest.get("multi_model"):
            history = PROJECT_ROOT / benchmark_dir / "history"
            if history.is_dir():
                for path in sorted(history.glob("run_*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
                    parsed = _parse_benchmark_report(path)
                    if parsed and not parsed.get("multi_model"):
                        return parsed
            return None
        return latest
    if kind == "multimodel_live":
        if latest.get("multi_model"):
            return latest
        history = PROJECT_ROOT / benchmark_dir / "history"
        if history.is_dir():
            for path in sorted(history.glob("run_*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
                parsed = _parse_benchmark_report(path)
                if parsed and parsed.get("multi_model"):
                    return parsed
        return None
    if kind == "offline":
        if latest.get("offline"):
            return latest
    return latest


def _phase_status(template_pct: float | None, multimodel_pct: float | None, phase_target: int) -> dict[str, Any]:
    slo = PHASE_SLO.get(phase_target, PHASE_SLO[2])
    template_ok = template_pct is not None and template_pct >= slo["template_pct"]
    multimodel_ok = multimodel_pct is not None and multimodel_pct >= slo["multimodel_pct"]
    if template_ok and multimodel_ok:
        status = "complete"
    elif template_ok or multimodel_pct is not None or template_pct is not None:
        status = "in_progress"
    else:
        status = "not_started"
    return {
        "status": status,
        "template_ok": template_ok,
        "multimodel_ok": multimodel_ok,
        "template_target_pct": slo["template_pct"],
        "multimodel_target_pct": slo["multimodel_pct"],
        "phase_label": slo["label"],
    }


def _job_completion(state: dict[str, Any], job_id: str) -> dict[str, Any] | None:
    for row in reversed(state.get("runs", [])):
        if isinstance(row, dict) and row.get("job_id") == job_id and row.get("status") in {"success", "failed"}:
            return row
    return None


def build_program_snapshot(program: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    template_score = _score_for_kind(program, "template_live")
    multimodel_score = _score_for_kind(program, "multimodel_live")
    offline_score = _score_for_kind(program, "offline")
    template_pct = template_score.get("pass_rate_pct") if template_score else None
    multimodel_pct = multimodel_score.get("pass_rate_pct") if multimodel_score else None
    phase = _phase_status(
        float(template_pct) if template_pct is not None else None,
        float(multimodel_pct) if multimodel_pct is not None else None,
        int(program.get("phase_target", 2)),
    )
    jobs_out: list[dict[str, Any]] = []
    for job in program.get("jobs", []):
        job_id = str(job["id"])
        last = _job_completion(state, job_id)
        last_success = state.get("job_last_success", {}).get(job_id)
        running = _find_running_job(state, job_id)
        jobs_out.append(
            {
                **job,
                "last_run": last,
                "last_success": last_success,
                "running": running,
                "completed": bool(last and last.get("status") == "success"),
            }
        )
    artifact_exists = {
        "oracle": bool(program.get("oracle_path") and (PROJECT_ROOT / str(program["oracle_path"])).is_file()),
        "catalog": bool(program.get("catalog_path") and (PROJECT_ROOT / str(program["catalog_path"])).is_file()),
        "cards": bool(program.get("cards_path") and (PROJECT_ROOT / str(program["cards_path"])).is_file()),
    }
    return {
        "id": program["id"],
        "title": program["title"],
        "subtitle": program.get("subtitle", ""),
        "phase_target": program.get("phase_target", 2),
        "case_count": program.get("case_count"),
        "doc_path": program.get("doc_path"),
        "phase": phase,
        "scores": {
            "template_live": template_score,
            "multimodel_live": multimodel_score,
            "offline": offline_score,
        },
        "improvement": _improvement_summary(program.get("improvement_log")),
        "artifacts": artifact_exists,
        "jobs": jobs_out,
    }


def _find_running_job(state: dict[str, Any], job_id: str | None = None) -> dict[str, Any] | None:
    for row in reversed(state.get("runs", [])):
        if not isinstance(row, dict):
            continue
        if row.get("status") != "running":
            continue
        if job_id and row.get("job_id") != job_id:
            continue
        return row
    return None


def build_dashboard_snapshot() -> dict[str, Any]:
    state = _load_state()
    programs = [build_program_snapshot(program, state) for program in DOMAIN_PROGRAMS]
    active = _find_running_job(state)
    recent = [row for row in reversed(state.get("runs", []) if isinstance(state.get("runs"), list) else [])][:20]
    phase2_complete = sum(1 for row in programs if row.get("phase", {}).get("status") == "complete" and row.get("phase_target") == 2)
    phase2_total = sum(1 for row in programs if row.get("phase_target") == 2)
    return {
        "updated_at": state.get("updated_at"),
        "phase_slo": PHASE_SLO,
        "programs": programs,
        "active_job": active,
        "recent_runs": recent,
        "summary": {
            "phase2_domains_complete": phase2_complete,
            "phase2_domains_total": phase2_total,
            "programs_total": len(programs),
        },
    }


def _tail_log(path: Path, *, max_lines: int = 400) -> str:
    if not path.is_file():
        return ""
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return ""
    return "\n".join(lines[-max_lines:])


def _extract_pass_line(log_text: str) -> dict[str, Any] | None:
    for line in reversed(log_text.splitlines()):
        if '"passed"' in line and '"total"' in line:
            try:
                start = line.find("{")
                if start >= 0:
                    payload = json.loads(line[start:])
                    if isinstance(payload, dict) and "passed" in payload:
                        return payload
            except Exception:
                continue
    return None


def _run_job_thread(run_id: str) -> None:
    state = _load_state()
    run_row = next((row for row in state.get("runs", []) if row.get("run_id") == run_id), None)
    if not isinstance(run_row, dict):
        return
    job_id = str(run_row.get("job_id", ""))
    jobs = _jobs_by_id()
    job = jobs.get(job_id)
    if not job:
        run_row["status"] = "failed"
        run_row["error"] = "unknown_job"
        run_row["ended_at"] = _utc_now()
        _save_state(state)
        return

    log_path = JOBS_DIR / f"{run_id}.log"
    JOBS_DIR.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env.update({str(k): str(v) for k, v in (job.get("env") or {}).items()})
    cmd = ["make", str(job["make_target"])]
    started = time.monotonic()
    exit_code = 1
    try:
        with log_path.open("w", encoding="utf-8") as handle:
            handle.write(f"[spl-quality-tracker] started={_utc_now()} make_target={job['make_target']}\n")
            handle.flush()
            proc = subprocess.Popen(
                cmd,
                cwd=str(PROJECT_ROOT),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                env=env,
            )
            run_row["pid"] = proc.pid
            _save_state(state)
            if proc.stdout is not None:
                for line in proc.stdout:
                    handle.write(line)
                    handle.flush()
                proc.stdout.close()
            exit_code = proc.wait()
            handle.write(f"\n[spl-quality-tracker] exit_code={exit_code} duration_s={time.monotonic()-started:.1f}\n")
    except Exception as exc:
        with log_path.open("a", encoding="utf-8") as handle:
            handle.write(f"\n[spl-quality-tracker] exception={type(exc).__name__}:{exc}\n")
        exit_code = 1
        run_row["error"] = f"{type(exc).__name__}:{exc}"

    duration_ms = int((time.monotonic() - started) * 1000)
    run_row["ended_at"] = _utc_now()
    run_row["duration_ms"] = duration_ms
    run_row["exit_code"] = exit_code
    run_row["status"] = "success" if exit_code == 0 else "failed"
    run_row["log_path"] = str(log_path.relative_to(PROJECT_ROOT))
    run_row["result_hint"] = _extract_pass_line(_tail_log(log_path, max_lines=2000))
    if exit_code == 0:
        state.setdefault("job_last_success", {})[job_id] = {
            "run_id": run_id,
            "ended_at": run_row["ended_at"],
            "duration_ms": duration_ms,
            "result_hint": run_row.get("result_hint"),
        }
    _save_state(state)


def start_job(job_id: str, *, started_by: str = "") -> dict[str, Any]:
    global _ACTIVE_THREAD
    jobs = _jobs_by_id()
    if job_id not in jobs:
        return {"ok": False, "error": "unknown_job", "job_id": job_id}
    with _JOB_LOCK:
        state = _load_state()
        if _find_running_job(state):
            return {"ok": False, "error": "job_already_running", "active_job": _find_running_job(state)}
        run_id = uuid.uuid4().hex[:12]
        run_row = {
            "run_id": run_id,
            "job_id": job_id,
            "domain_id": jobs[job_id]["domain_id"],
            "make_target": jobs[job_id]["make_target"],
            "label": jobs[job_id]["label"],
            "status": "running",
            "started_at": _utc_now(),
            "started_by": started_by,
            "ended_at": None,
            "duration_ms": None,
            "exit_code": None,
            "log_path": str((JOBS_DIR / f"{run_id}.log").relative_to(PROJECT_ROOT)),
        }
        state.setdefault("runs", []).append(run_row)
        _save_state(state)
        thread = threading.Thread(target=_run_job_thread, args=(run_id,), daemon=True)
        _ACTIVE_THREAD = thread
        thread.start()
    return {"ok": True, "run": run_row}


def get_run_log(run_id: str, *, tail_lines: int = 400) -> dict[str, Any]:
    state = _load_state()
    run_row = next((row for row in state.get("runs", []) if row.get("run_id") == run_id), None)
    if not isinstance(run_row, dict):
        return {"ok": False, "error": "run_not_found"}
    log_path = PROJECT_ROOT / str(run_row.get("log_path", ""))
    return {
        "ok": True,
        "run": run_row,
        "log_tail": _tail_log(log_path, max_lines=tail_lines),
        "complete": run_row.get("status") in {"success", "failed"},
    }


def spl_quality_page_body() -> str:
    return _SPL_QUALITY_PAGE_HTML


_SPL_QUALITY_PAGE_HTML = """
<style>
  .sq-shell { display:flex; flex-direction:column; gap:18px; }
  .sq-hero { background:linear-gradient(135deg,#0f2740,#132f4f 55%,#0b1a2a); border:1px solid #234567; border-radius:14px; padding:18px 20px; }
  .sq-hero h1 { margin:0 0 6px; font-size:24px; color:#f8fafc; }
  .sq-hero p { margin:0; color:#9fb4cc; line-height:1.5; max-width:860px; }
  .sq-summary { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:12px; }
  .sq-stat { background:#101c2c; border:1px solid #223246; border-radius:12px; padding:14px; }
  .sq-stat .label { color:#8aa0b8; font-size:12px; text-transform:uppercase; letter-spacing:.06em; }
  .sq-stat .value { color:#f8fafc; font-size:22px; font-weight:700; margin-top:6px; }
  .sq-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(340px,1fr)); gap:16px; }
  .sq-card { background:#0f1724; border:1px solid #223246; border-radius:14px; padding:16px; display:flex; flex-direction:column; gap:12px; }
  .sq-card-head { display:flex; justify-content:space-between; gap:12px; align-items:flex-start; }
  .sq-card h2 { margin:0; font-size:18px; color:#f8fafc; }
  .sq-sub { color:#8aa0b8; font-size:13px; margin-top:4px; }
  .sq-badge { display:inline-flex; align-items:center; gap:6px; border-radius:999px; padding:4px 10px; font-size:12px; font-weight:600; }
  .sq-badge.complete { background:#12321f; color:#86efac; border:1px solid #166534; }
  .sq-badge.in_progress { background:#2a2410; color:#fde68a; border:1px solid #854d0e; }
  .sq-badge.not_started { background:#1f2937; color:#cbd5e1; border:1px solid #475569; }
  .sq-badge.running { background:#172554; color:#93c5fd; border:1px solid #1d4ed8; }
  .sq-scores { display:grid; grid-template-columns:1fr 1fr; gap:8px; }
  .sq-score { background:#111827; border:1px solid #243041; border-radius:10px; padding:10px; }
  .sq-score .k { color:#8aa0b8; font-size:11px; text-transform:uppercase; }
  .sq-score .v { color:#f8fafc; font-size:18px; font-weight:700; margin-top:4px; }
  .sq-score .m { color:#64748b; font-size:11px; margin-top:4px; }
  .sq-jobs { display:flex; flex-direction:column; gap:8px; }
  .sq-job { display:grid; grid-template-columns:1fr auto; gap:8px; align-items:center; background:#111827; border:1px solid #243041; border-radius:10px; padding:10px 12px; }
  .sq-job-title { color:#e2e8f0; font-size:13px; font-weight:600; }
  .sq-job-meta { color:#64748b; font-size:11px; margin-top:3px; }
  .sq-btn { border:1px solid #2563eb; background:#1d4ed8; color:#fff; border-radius:8px; padding:7px 12px; font-size:12px; cursor:pointer; }
  .sq-btn.secondary { background:#172033; border-color:#334155; color:#cbd5e1; }
  .sq-btn:disabled { opacity:.45; cursor:not-allowed; }
  .sq-active { background:#0b1220; border:1px solid #1e3a5f; border-radius:14px; padding:14px; }
  .sq-active h3 { margin:0 0 8px; color:#f8fafc; font-size:16px; }
  .sq-log { background:#020617; color:#cbd5e1; border:1px solid #1e293b; border-radius:10px; padding:12px; max-height:320px; overflow:auto; font:12px/1.45 ui-monospace, SFMono-Regular, Menlo, monospace; white-space:pre-wrap; }
  .sq-history { width:100%; border-collapse:collapse; font-size:12px; }
  .sq-history th, .sq-history td { border-bottom:1px solid #223246; padding:8px 6px; text-align:left; color:#cbd5e1; }
  .sq-history th { color:#8aa0b8; font-size:11px; text-transform:uppercase; }
  .sq-improve { background:#101c2c; border:1px dashed #334155; border-radius:10px; padding:10px; color:#94a3b8; font-size:12px; }
</style>
<div class="sq-shell">
  <section class="sq-hero">
    <h1>SPL Quality Tracker</h1>
    <p>Host-side benchmark console for agtsmith SPL programs. Launch <code>make</code> gates per data domain, track Phase 1–3 progress, and review live logs plus latest pass rates from oracle harnesses. Start with <code>make spl-quality-tracker</code> (not the :8787 sidecar).</p>
  </section>
  <section class="sq-summary" id="sq-summary"></section>
  <section class="sq-active" id="sq-active-panel" hidden>
    <h3 id="sq-active-title">Running…</h3>
    <div id="sq-active-meta" class="sq-sub"></div>
    <pre id="sq-active-log" class="sq-log"></pre>
  </section>
  <section class="sq-grid" id="sq-programs"></section>
  <section class="sq-card">
    <h2>Recent runs</h2>
    <table class="sq-history"><thead><tr><th>When</th><th>Domain</th><th>Job</th><th>Status</th><th>Duration</th><th>Result</th></tr></thead><tbody id="sq-history"></tbody></table>
  </section>
</div>
<script>
(function(){
  const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const fmtDur = (ms) => {
    if (ms == null) return '—';
    const s = Math.round(ms / 1000);
    if (s < 60) return s + 's';
    return Math.floor(s/60) + 'm ' + (s%60) + 's';
  };
  const fmtScore = (row, target) => {
    if (!row) return { text:'—', meta:'Not run yet' };
    const pct = row.pass_rate_pct != null ? row.pass_rate_pct : (row.passed_count != null && row.case_count ? Math.round((row.passed_count/row.case_count)*1000)/10 : null);
    const text = row.passed_count != null && row.case_count != null ? `${row.passed_count}/${row.case_count}` : '—';
    const meta = pct != null ? `${pct}% · target ${target}%` : (row.timestamp_utc || '').slice(0,19);
    return { text, meta };
  };
  let pollTimer = null;
  let activeRunId = null;

  async function fetchStatus(){
    const resp = await fetch('/api/spl-quality/status', { credentials:'same-origin' });
    if (!resp.ok) throw new Error('status ' + resp.status);
    return resp.json();
  }

  async function startJob(jobId){
    const resp = await fetch('/api/spl-quality/run', {
      method:'POST', credentials:'same-origin',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ job_id: jobId })
    });
    const data = await resp.json();
    if (!resp.ok || !data.ok) throw new Error(data.error || 'start failed');
    activeRunId = data.run.run_id;
    return data.run.run_id;
  }

  async function showRunLog(runId){
    const resp = await fetch('/api/spl-quality/log?run_id=' + encodeURIComponent(runId), { credentials:'same-origin' });
    if (!resp.ok) return null;
    const data = await resp.json();
    if (!data.ok) return null;
    const panel = document.getElementById('sq-active-panel');
    panel.hidden = false;
    const run = data.run || {};
    document.getElementById('sq-active-title').textContent = run.label || run.make_target || 'Job run';
    document.getElementById('sq-active-meta').textContent = `${run.domain_id || ''} · make ${run.make_target || ''} · ${run.status || 'running'} · ${fmtDur(run.duration_ms)}`;
    document.getElementById('sq-active-log').textContent = data.log_tail || '';
    return data;
  }

  async function waitForRun(runId){
    while (true) {
      const data = await showRunLog(runId);
      if (!data) throw new Error('log poll failed');
      if (data.complete) {
        if (data.run && data.run.status === 'failed') {
          const tail = (data.log_tail || '').split('\n').slice(-10).join('\n');
          alert('Job failed. Last log lines:\n\n' + tail);
        }
        return data.run;
      }
      await new Promise((r) => setTimeout(r, 2000));
    }
  }

  async function pollLog(){
    if (!activeRunId) return;
    const resp = await fetch('/api/spl-quality/log?run_id=' + encodeURIComponent(activeRunId), { credentials:'same-origin' });
    if (!resp.ok) return;
    const data = await resp.json();
    if (!data.ok) return;
    document.getElementById('sq-active-log').textContent = data.log_tail || '';
    if (data.complete) {
      activeRunId = null;
      render(await fetchStatus());
    }
  }

  function render(data){
    const summary = data.summary || {};
    document.getElementById('sq-summary').innerHTML = [
      ['Phase 2 domains complete', `${summary.phase2_domains_complete || 0}/${summary.phase2_domains_total || 0}`],
      ['Programs tracked', String(summary.programs_total || 0)],
      ['Active job', data.active_job ? data.active_job.label : 'None'],
      ['Last refresh', (data.updated_at || '').replace('T',' ').slice(0,19) + ' UTC']
    ].map(([k,v]) => `<div class="sq-stat"><div class="label">${esc(k)}</div><div class="value">${esc(v)}</div></div>`).join('');

    const active = data.active_job;
    const panel = document.getElementById('sq-active-panel');
    if (active) {
      panel.hidden = false;
      activeRunId = active.run_id;
      document.getElementById('sq-active-title').textContent = active.label || active.make_target;
      document.getElementById('sq-active-meta').textContent = `${active.domain_id} · make ${active.make_target} · started ${(active.started_at||'').replace('T',' ').slice(0,19)} UTC`;
      if (!pollTimer) pollTimer = setInterval(pollLog, 2000);
    } else {
      panel.hidden = true;
      if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
    }

    document.getElementById('sq-programs').innerHTML = (data.programs || []).map((p) => {
      const phase = p.phase || {};
      const tpl = fmtScore((p.scores||{}).template_live, phase.template_target_pct || 100);
      const mm = fmtScore((p.scores||{}).multimodel_live, phase.multimodel_target_pct || 95);
      const jobs = (p.jobs || []).map((j) => {
        const last = j.last_run;
        const meta = last ? `Last: ${last.status} · ${fmtDur(last.duration_ms)}` : 'Never run';
        const disabled = !!data.active_job;
        return `<div class="sq-job"><div><div class="sq-job-title">${esc(j.label)}</div><div class="sq-job-meta">${esc(j.make_target)} · ~${j.estimated_minutes||'?'}m · ${esc(meta)}</div></div><button class="sq-btn" data-job-id="${esc(j.id)}" ${disabled?'disabled':''}>Run</button></div>`;
      }).join('');
      const improve = p.improvement ? `<div class="sq-improve"><strong>Improvement log:</strong> ${esc(p.improvement.ideas_kept||0)} kept / ${esc(p.improvement.ideas_total||0)} ideas · final template ${esc((p.improvement.final||{}).template_live || '—')} · multimodel ${esc((p.improvement.final||{}).multimodel_live || '—')}</div>` : '';
      return `<article class="sq-card"><div class="sq-card-head"><div><h2>${esc(p.title)}</h2><div class="sq-sub">${esc(p.subtitle || '')}${p.case_count ? ' · ' + p.case_count + ' oracle cases' : ''}</div></div><span class="sq-badge ${esc(phase.status||'not_started')}">${esc((phase.phase_label||'Phase').split('—')[0].trim())}</span></div><div class="sq-scores"><div class="sq-score"><div class="k">Template live</div><div class="v">${esc(tpl.text)}</div><div class="m">${esc(tpl.meta)}</div></div><div class="sq-score"><div class="k">Multimodel live</div><div class="v">${esc(mm.text)}</div><div class="m">${esc(mm.meta)}</div></div></div>${improve}<div class="sq-jobs">${jobs}</div><div><button class="sq-btn secondary" data-run-domain="${esc(p.id)}" ${data.active_job?'disabled':''}>Run all gates for domain</button></div></article>`;
    }).join('');

    document.getElementById('sq-history').innerHTML = (data.recent_runs || []).map((r) => {
      const hint = r.result_hint ? `${r.result_hint.passed}/${r.result_hint.total}` : (r.exit_code != null ? 'exit ' + r.exit_code : '—');
      return `<tr><td>${esc((r.started_at||'').replace('T',' ').slice(0,19))}</td><td>${esc(r.domain_id)}</td><td>${esc(r.label || r.make_target)}</td><td>${esc(r.status)}</td><td>${esc(fmtDur(r.duration_ms))}</td><td>${esc(hint)}</td></tr>`;
    }).join('');

    document.querySelectorAll('[data-job-id]').forEach((btn) => {
      btn.addEventListener('click', async () => {
        btn.disabled = true;
        try {
          const runId = await startJob(btn.getAttribute('data-job-id'));
          render(await fetchStatus());
          await showRunLog(runId);
          await waitForRun(runId);
          activeRunId = null;
          render(await fetchStatus());
        } catch (err) { alert(err.message || err); }
        btn.disabled = false;
      });
    });
    document.querySelectorAll('[data-run-domain]').forEach((btn) => {
      btn.addEventListener('click', async () => {
        const domainId = btn.getAttribute('data-run-domain');
        const program = (data.programs || []).find((p) => p.id === domainId);
        if (!program) return;
        btn.disabled = true;
        for (const job of (program.jobs || [])) {
          try {
            const runId = await startJob(job.id);
            render(await fetchStatus());
            const finished = await waitForRun(runId);
            if (finished && finished.status === 'failed') break;
          } catch (err) { alert(err.message || err); break; }
        }
        activeRunId = null;
        btn.disabled = false;
        render(await fetchStatus());
      });
    });
  }

  async function boot(){
    try {
      render(await fetchStatus());
      setInterval(async () => { try { render(await fetchStatus()); } catch (_) {} }, 8000);
    } catch (err) {
      document.getElementById('sq-summary').innerHTML = `<div class="sq-stat"><div class="label">Error</div><div class="value">${esc(err.message||err)}</div></div>`;
    }
  }
  boot();
})();
</script>
"""


def api_get_status() -> dict[str, Any]:
    return build_dashboard_snapshot()


def api_post_run(payload: dict[str, Any], *, started_by: str = "") -> dict[str, Any]:
    job_id = str(payload.get("job_id", "")).strip()
    if not job_id:
        return {"ok": False, "error": "job_id_required"}
    return start_job(job_id, started_by=started_by)


def api_get_log(run_id: str) -> dict[str, Any]:
    return get_run_log(run_id)


def render_standalone_page() -> str:
    body = spl_quality_page_body()
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SPL Quality Tracker</title>
  <style>
    body {{ margin:0; background:#0b1220; color:#e2e8f0; font-family:system-ui,-apple-system,sans-serif; }}
    code {{ background:#172033; padding:2px 6px; border-radius:4px; font-size:12px; }}
  </style>
</head>
<body>
{body}
</body>
</html>"""


def _json_response(handler: Any, status: int, payload: dict[str, Any]) -> None:
    body = json.dumps(payload).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(body)


def _html_response(handler: Any, status: int, html_text: str) -> None:
    body = html_text.encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(body)


def run_standalone_server(*, host: str = "127.0.0.1", port: int = 8791) -> None:
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from urllib.parse import parse_qs, urlparse

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: Any) -> None:
            return

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path in {"/", "/spl-quality"}:
                _html_response(self, 200, render_standalone_page())
                return
            if parsed.path == "/api/spl-quality/status":
                _json_response(self, 200, api_get_status())
                return
            if parsed.path == "/api/spl-quality/log":
                qs = parse_qs(parsed.query or "")
                run_id = (qs.get("run_id") or [""])[0].strip()
                if not run_id:
                    _json_response(self, 400, {"ok": False, "error": "run_id_required"})
                    return
                payload = api_get_log(run_id)
                status = 200 if payload.get("ok") else 404
                _json_response(self, status, payload)
                return
            _json_response(self, 404, {"ok": False, "error": "not_found"})

        def do_POST(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path != "/api/spl-quality/run":
                _json_response(self, 404, {"ok": False, "error": "not_found"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0") or "0")
            except ValueError:
                length = 0
            raw = self.rfile.read(length).decode("utf-8", errors="replace") if length > 0 else "{}"
            try:
                payload = json.loads(raw) if raw.strip() else {}
            except json.JSONDecodeError:
                _json_response(self, 400, {"ok": False, "error": "invalid_json"})
                return
            if not isinstance(payload, dict):
                _json_response(self, 400, {"ok": False, "error": "payload_must_be_object"})
                return
            result = api_post_run(payload, started_by="local")
            if not result.get("ok"):
                if result.get("error") == "job_already_running":
                    _json_response(self, 409, result)
                    return
                _json_response(self, 400, result)
                return
            _json_response(self, 202, result)

    server = ThreadingHTTPServer((host, port), Handler)
    print(f"[spl-quality-tracker] listening on http://{host}:{port}/", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("[spl-quality-tracker] stopped", flush=True)


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="SPL quality program tracker (host-side dev console)")
    parser.add_argument("--serve", action="store_true", help="Run standalone web UI on localhost")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host for --serve (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8791, help="Bind port for --serve (default: 8791)")
    args = parser.parse_args(argv)
    if args.serve:
        run_standalone_server(host=args.host, port=args.port)
        return 0
    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
