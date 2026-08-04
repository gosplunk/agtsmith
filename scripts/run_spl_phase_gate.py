#!/usr/bin/env python3
"""Progressive phase gate runner for SPL autonomy loop."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PROGRESS_PATH = PROJECT_ROOT / "artifacts" / "spl_autonomy" / "phase_progress.json"
WRITER_EVAL_DIR = PROJECT_ROOT / "artifacts" / "model_eval"
HARDENING_DIR = PROJECT_ROOT / "artifacts" / "benchmark"
OPERATIONAL_DIR = PROJECT_ROOT / "artifacts" / "benchmark" / "operational_spl_accuracy"

PHASE_NAMES = {
    0: "baseline",
    1: "sourcetype_cards",
    2: "embedding_rag",
    3: "constrained_writer",
    4: "field_binding",
    5: "structure_validate",
    6: "domain_knowledge",
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_progress() -> dict[str, Any]:
    if not PROGRESS_PATH.is_file():
        return {"phases": {}, "baseline": None, "updated_at": None}
    try:
        data = json.loads(PROGRESS_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {"phases": {}, "baseline": None, "updated_at": None}
    if not isinstance(data, dict):
        return {"phases": {}, "baseline": None, "updated_at": None}
    data.setdefault("phases", {})
    return data


def _save_progress(data: dict[str, Any]) -> None:
    PROGRESS_PATH.parent.mkdir(parents=True, exist_ok=True)
    data["updated_at"] = _utc_now()
    PROGRESS_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _latest_json(dir_path: Path, pattern: str) -> Path | None:
    if not dir_path.is_dir():
        return None
    files = sorted(dir_path.glob(pattern), key=lambda p: p.stat().st_mtime, reverse=True)
    return files[0] if files else None


def _run(cmd: list[str], *, env: dict[str, str] | None = None) -> int:
    merged = os.environ.copy()
    if env:
        merged.update(env)
    print("+", " ".join(cmd), flush=True)
    return subprocess.call(cmd, cwd=str(PROJECT_ROOT), env=merged)


def _writer_metrics_from(path: Path | None) -> dict[str, Any]:
    if not path or not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    if not isinstance(data, dict):
        return {}
    summary = data.get("summary", {})
    writer_avg = 0.0
    if isinstance(summary, dict):
        writer_avg = float(summary.get("avg_score", summary.get("average_score", 0)) or 0)
    if not writer_avg:
        writer_avg = float(data.get("recommended_score", 0) or 0)
    if not writer_avg:
        ranked = data.get("ranked", [])
        if isinstance(ranked, list) and ranked and isinstance(ranked[0], dict):
            writer_avg = float(ranked[0].get("avg_score", 0) or 0)
    writer_cases = int(data.get("test_case_count", 0) or 0)
    if isinstance(summary, dict) and not writer_cases:
        writer_cases = int(summary.get("cases", summary.get("total_cases", 0)) or 0)
    return {
        "writer_avg": writer_avg,
        "writer_pass_rate": float(summary.get("pass_rate", 0) or 0) if isinstance(summary, dict) else 0.0,
        "writer_cases": writer_cases,
        "writer_artifact": str(path),
    }


def _hardening_metrics_from(path: Path | None) -> dict[str, Any]:
    if not path or not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    summary = data.get("summary", data) if isinstance(data, dict) else {}
    if not isinstance(summary, dict):
        return {}
    total = int(summary.get("case_count", summary.get("total", summary.get("cases", 0))) or 0)
    passed = int(summary.get("passed", summary.get("pass_count", 0)) or 0)
    if total and not passed:
        passed = int(
            round(total * float(summary.get("pass_rate_pct", 0) or 0) / 100.0)
        )
    rate = float(summary.get("pass_rate_pct", summary.get("pass_rate", 0)) or 0)
    if not rate and total:
        rate = (passed / total * 100.0)
    return {
        "hardening_pass_rate": rate,
        "hardening_passed": passed,
        "hardening_total": total,
        "hardening_artifact": str(path),
    }


def _operational_metrics_from(path: Path | None) -> dict[str, Any]:
    if not path or not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    summary = data.get("summary", data) if isinstance(data, dict) else {}
    if not isinstance(summary, dict):
        return {}
    total = int(summary.get("total", summary.get("cases", 0)) or 0)
    passed = int(summary.get("passed", summary.get("pass_count", 0)) or 0)
    rate = (passed / total * 100.0) if total else float(summary.get("pass_rate", 0) or 0)
    return {
        "operational_pass_rate": rate,
        "operational_passed": passed,
        "operational_total": total,
        "operational_artifact": str(path),
    }


def collect_metrics(*, use_existing: bool) -> dict[str, Any]:
    metrics: dict[str, Any] = {"collected_at": _utc_now(), "use_existing": use_existing}
    writer_path = _latest_json(WRITER_EVAL_DIR, "*writer*.json") or _latest_json(WRITER_EVAL_DIR, "*.json")
    hard_path = _latest_json(HARDENING_DIR, "*.json")
    op_path = _latest_json(OPERATIONAL_DIR, "*.json")
    metrics.update(_writer_metrics_from(writer_path))
    metrics.update(_hardening_metrics_from(hard_path))
    metrics.update(_operational_metrics_from(op_path))

    cards_path = PROJECT_ROOT / "artifacts" / "environment" / "sourcetype_cards.json"
    embed_path = PROJECT_ROOT / "artifacts" / "spl_rag" / "embedding_index.json"
    metrics["cards_available"] = cards_path.is_file()
    metrics["cards_count"] = 0
    if cards_path.is_file():
        try:
            cards = json.loads(cards_path.read_text(encoding="utf-8"))
            metrics["cards_count"] = len(cards) if isinstance(cards, list) else 0
        except Exception:
            pass
    metrics["embedding_index_available"] = embed_path.is_file()
    domain_path = PROJECT_ROOT / "artifacts" / "knowledge" / "spl_domain_patterns.json"
    metrics["domain_patterns_available"] = domain_path.is_file()
    metrics["domain_pattern_count"] = 0
    if domain_path.is_file():
        try:
            domain_payload = json.loads(domain_path.read_text(encoding="utf-8"))
            if isinstance(domain_payload, dict):
                metrics["domain_pattern_count"] = int(domain_payload.get("pattern_count", 0) or 0)
                if not metrics["domain_pattern_count"]:
                    patterns = domain_payload.get("patterns", [])
                    metrics["domain_pattern_count"] = len(patterns) if isinstance(patterns, list) else 0
        except Exception:
            pass
    metrics["writer_mode"] = os.getenv("AGTSMITH_WRITER_MODE", "free")
    metrics["template_override"] = os.getenv("AGTSMITH_TEMPLATE_OVERRIDE", "fallback")
    return metrics


def _load_ui_env() -> dict[str, str]:
    ui_env = PROJECT_ROOT / "config" / "ui.env"
    merged: dict[str, str] = {}
    if not ui_env.is_file():
        return merged
    for line in ui_env.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        merged[key.strip()] = value.strip().strip('"').strip("'")
    return merged


def prepare_phase(phase: int) -> None:
    """Build phase-specific assets before live benchmarks run."""
    py = PROJECT_ROOT / ".venv" / "bin" / "python"
    if not py.is_file():
        py = Path(sys.executable)
    env = {"PYTHONPATH": f"{PROJECT_ROOT}:{PROJECT_ROOT / 'scripts'}"}
    if phase >= 1:
        _run([str(py), "scripts/build_sourcetype_cards.py"], env=env)
    if phase >= 2:
        cmd = [str(py), "scripts/build_spl_embedding_index.py"]
        if str(os.getenv("SPL_EMBEDDING_BUILD_LIVE", "0")).strip().lower() not in {"1", "true", "yes"}:
            cmd.append("--skip-embed")
        _run(cmd, env=env)
    if phase >= 6:
        _run([str(py), "scripts/build_spl_domain_patterns.py"], env=env)


def run_benchmarks(*, quick: bool) -> None:
    gate_env = _load_ui_env()
    gate_env.update(
        {
            "AGTSMITH_TEMPLATE_OVERRIDE": "fallback",
            "AGTSMITH_WRITER_MODE": os.getenv("AGTSMITH_WRITER_MODE", "constrained"),
            "PYTHONPATH": f"{PROJECT_ROOT}:{PROJECT_ROOT / 'scripts'}",
        }
    )
    if os.getenv("SPLUNK_LAB_BEARER_TOKEN"):
        gate_env["SPLUNK_LAB_BEARER_TOKEN"] = os.environ["SPLUNK_LAB_BEARER_TOKEN"]
    writer_target = "model-spl-eval-quick" if quick else "model-spl-eval"
    _run(["make", writer_target], env=gate_env)
    _run(["make", "spl-hardening-benchmark"], env=gate_env)
    if not quick:
        _run(["make", "operational-spl-accuracy-multimodel"], env=gate_env)


def evaluate_gate(phase: int, metrics: dict[str, Any], progress: dict[str, Any]) -> dict[str, Any]:
    baseline = progress.get("baseline") or progress.get("phases", {}).get("0", {}).get("metrics", {})
    prev_key = str(max(0, phase - 1))
    previous = progress.get("phases", {}).get(prev_key, {}).get("metrics", baseline)
    checks: list[dict[str, Any]] = []
    writer_avg = float(metrics.get("writer_avg", 0) or 0)
    base_writer = float(baseline.get("writer_avg", writer_avg) or writer_avg)
    prev_writer = float(previous.get("writer_avg", writer_avg) or writer_avg)
    drop_vs_baseline = base_writer - writer_avg
    drop_vs_prev = prev_writer - writer_avg
    checks.append(
        {
            "name": "writer_avg_not_regress_gt_1pt_vs_prev",
            "pass": drop_vs_prev <= 1.0 or phase == 0,
            "value": writer_avg,
            "prev": prev_writer,
            "drop": drop_vs_prev,
        }
    )
    if phase >= 1:
        checks.append(
            {
                "name": "cards_built",
                "pass": bool(metrics.get("cards_available")) and int(metrics.get("cards_count", 0) or 0) > 0,
                "value": metrics.get("cards_count", 0),
            }
        )
    if phase >= 2:
        checks.append(
            {
                "name": "embedding_index_available",
                "pass": bool(metrics.get("embedding_index_available")),
            }
        )
    if phase >= 3:
        checks.append(
            {
                "name": "writer_mode_constrained",
                "pass": str(metrics.get("writer_mode", "")).lower() == "constrained",
            }
        )
    if phase >= 6:
        pattern_count = int(metrics.get("domain_pattern_count", 0) or 0)
        checks.append(
            {
                "name": "domain_patterns_built",
                "pass": bool(metrics.get("domain_patterns_available")) and pattern_count >= 10,
                "value": pattern_count,
            }
        )
    hard_rate = float(metrics.get("hardening_pass_rate", 0) or 0)
    if hard_rate:
        checks.append({"name": "hardening_pass_rate", "pass": hard_rate >= 90.0, "value": hard_rate})
    passed = all(bool(c.get("pass")) for c in checks)
    return {
        "phase": phase,
        "phase_name": PHASE_NAMES.get(phase, f"phase_{phase}"),
        "passed": passed,
        "checks": checks,
        "writer_avg": writer_avg,
        "drop_vs_baseline": drop_vs_baseline,
        "drop_vs_prev": drop_vs_prev,
    }


def print_report(progress: dict[str, Any]) -> None:
    print("\n=== SPL Phase Progress ===")
    baseline = progress.get("baseline") or progress.get("phases", {}).get("0", {}).get("metrics", {})
    print(f"baseline writer_avg={baseline.get('writer_avg', 'n/a')}")
    for key in sorted(progress.get("phases", {}).keys(), key=lambda x: int(x) if str(x).isdigit() else 999):
        row = progress["phases"][key]
        metrics = row.get("metrics", {})
        gate = row.get("gate", {})
        status = "PASS" if gate.get("passed") else "FAIL"
        print(
            f"phase {key} ({row.get('name', '?')}): {status} "
            f"writer_avg={metrics.get('writer_avg', 'n/a')} "
            f"hardening={metrics.get('hardening_pass_rate', 'n/a')}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description="Run SPL autonomy phase gate")
    parser.add_argument("--phase", type=int, required=True)
    parser.add_argument("--use-existing", action="store_true", help="Reuse latest eval artifacts")
    parser.add_argument("--quick", action="store_true", help="Run quick writer eval only")
    parser.add_argument("--report", action="store_true", help="Print cumulative report and exit")
    parser.add_argument("--skip-live", action="store_true", help="Alias for --use-existing")
    args = parser.parse_args()

    progress = _load_progress()
    if args.report:
        print_report(progress)
        return 0

    use_existing = args.use_existing or args.skip_live
    if not use_existing:
        prepare_phase(args.phase)
        run_benchmarks(quick=args.quick)

    metrics = collect_metrics(use_existing=use_existing)
    gate = evaluate_gate(args.phase, metrics, progress)
    phase_key = str(args.phase)
    progress.setdefault("phases", {})[phase_key] = {
        "name": PHASE_NAMES.get(args.phase, f"phase_{args.phase}"),
        "metrics": metrics,
        "gate": gate,
        "recorded_at": _utc_now(),
    }
    if args.phase == 0:
        progress["baseline"] = metrics
    _save_progress(progress)

    print(json.dumps({"phase": args.phase, "gate": gate, "metrics": metrics}, indent=2))
    if not gate.get("passed"):
        print("PHASE GATE FAILED", file=sys.stderr)
        return 1
    print("PHASE GATE PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
