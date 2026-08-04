#!/usr/bin/env python3
"""Run one SPL improvement cycle: classify failures, refresh assets, re-benchmark."""

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
CYCLE_STATE_PATH = PROJECT_ROOT / "artifacts" / "spl_autonomy" / "improvement_cycles.jsonl"
PYTHON = PROJECT_ROOT / ".venv" / "bin" / "python"


def _py() -> str:
    return str(PYTHON if PYTHON.is_file() else Path(sys.executable))


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


def _run(cmd: list[str], *, env: dict[str, str] | None = None) -> int:
    merged = os.environ.copy()
    merged.update(_load_ui_env())
    merged.setdefault("PYTHONPATH", f"{PROJECT_ROOT}:{PROJECT_ROOT / 'scripts'}")
    if env:
        merged.update(env)
    print("+", " ".join(cmd), flush=True)
    return subprocess.call(cmd, cwd=str(PROJECT_ROOT), env=merged)


def _read_writer_avg() -> float:
    path = PROJECT_ROOT / "artifacts" / "model_eval" / "spl_writer_eval_latest.json"
    if not path.is_file():
        return 0.0
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return 0.0
    return float(data.get("recommended_score", 0) or 0)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run SPL improvement cycle")
    parser.add_argument("--report", default="artifacts/benchmark/spl_hardening_benchmark_latest.json")
    parser.add_argument("--quick", action="store_true")
    parser.add_argument("--skip-eval", action="store_true")
    parser.add_argument("--target-score", type=float, default=85.0)
    parser.add_argument("--max-cycles", type=int, default=5)
    args = parser.parse_args()

    for cycle in range(1, max(1, args.max_cycles) + 1):
        print(f"=== improvement cycle {cycle}/{args.max_cycles} ===", flush=True)
        stamp = datetime.now(timezone.utc).isoformat()
        cycle_before = _read_writer_avg()

        _run([_py(), "scripts/spl_improvement_loop.py", "--report", args.report])
        _run([_py(), "scripts/build_spl_skillpack.py"])
        _run([_py(), "scripts/build_sourcetype_cards.py"])
        _run([_py(), "scripts/build_spl_embedding_index.py", "--skip-embed"])
        _run([_py(), "scripts/build_spl_domain_patterns.py"])

        if not args.skip_eval:
            writer_target = "model-spl-eval-quick" if args.quick else "model-spl-eval"
            gate_env = {
                "AGTSMITH_TEMPLATE_OVERRIDE": "fallback",
                "AGTSMITH_WRITER_MODE": os.getenv("AGTSMITH_WRITER_MODE", "constrained"),
            }
            _run(["make", writer_target], env=gate_env)
            _run(["make", "spl-hardening-benchmark"], env=gate_env)
            _run(["make", "operational-spl-accuracy-multimodel"], env=gate_env)

        after = _read_writer_avg()
        metrics = _collect_board_scores()
        record: dict[str, Any] = {
            "timestamp_utc": stamp,
            "cycle": cycle,
            "writer_avg_before": cycle_before,
            "writer_avg_after": after,
            "delta": round(after - cycle_before, 2),
            "board": metrics,
            "report": args.report,
            "quick": args.quick,
        }
        CYCLE_STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
        with CYCLE_STATE_PATH.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=True) + "\n")
        print(json.dumps(record, indent=2))
        if _board_meets_target(metrics, args.target_score):
            print(f"TARGET MET: all board scores >= {args.target_score}")
            return 0
    print(f"STOP: target {args.target_score} not met after {args.max_cycles} cycles")
    return 1


def _collect_board_scores() -> dict[str, float]:
    metrics: dict[str, float] = {}
    writer_path = PROJECT_ROOT / "artifacts" / "model_eval" / "spl_writer_eval_latest.json"
    if writer_path.is_file():
        try:
            data = json.loads(writer_path.read_text(encoding="utf-8"))
            metrics["writer_avg"] = float(data.get("recommended_score", 0) or 0)
        except Exception:
            metrics["writer_avg"] = 0.0
    hard_path = PROJECT_ROOT / "artifacts" / "benchmark" / "spl_hardening_benchmark_latest.json"
    if hard_path.is_file():
        try:
            summary = json.loads(hard_path.read_text(encoding="utf-8")).get("summary", {})
            metrics["hardening_avg"] = float(summary.get("avg_score", 0) or 0)
            metrics["hardening_pass_rate"] = float(summary.get("pass_rate_pct", 0) or 0)
        except Exception:
            pass
    op_dir = PROJECT_ROOT / "artifacts" / "benchmark" / "operational_spl_accuracy"
    if op_dir.is_dir():
        files = sorted(op_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        for path in files:
            if path.name == "latest.json":
                continue
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                continue
            if not isinstance(payload, dict):
                continue
            if not payload.get("multi_model"):
                continue
            metrics["operational_pass_rate"] = float(payload.get("pass_rate_pct", 0) or 0)
            metrics["operational_avg"] = float(payload.get("avg_score", 0) or 0)
            metrics["operational_source"] = path.name
            break
        if "operational_pass_rate" not in metrics and (op_dir / "latest.json").is_file():
            try:
                payload = json.loads((op_dir / "latest.json").read_text(encoding="utf-8"))
                if payload.get("multi_model"):
                    metrics["operational_pass_rate"] = float(payload.get("pass_rate_pct", 0) or 0)
            except Exception:
                pass
    return metrics


def _board_meets_target(metrics: dict[str, float], target: float) -> bool:
    required = ("writer_avg", "hardening_avg", "hardening_pass_rate", "operational_pass_rate")
    for key in required:
        if float(metrics.get(key, 0) or 0) < target:
            return False
    return True


if __name__ == "__main__":
    raise SystemExit(main())
