#!/usr/bin/env python3
"""Measure plan implementation steps (env, oracle, discovery, post-exec)."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUT_DEFAULT = PROJECT_ROOT / "artifacts/benchmark/plan_implementation_gate_latest.json"


def _run(cmd: list[str], *, cwd: Path | None = None) -> tuple[int, str]:
    proc = subprocess.run(
        cmd,
        cwd=str(cwd or PROJECT_ROOT),
        capture_output=True,
        text=True,
    )
    out = (proc.stdout or "") + (proc.stderr or "")
    return proc.returncode, out.strip()


def _unittest(module: str) -> tuple[bool, str]:
    code, out = _run(
        [
            sys.executable,
            "-m",
            "unittest",
            module,
            "-q",
        ],
        cwd=PROJECT_ROOT,
    )
    return code == 0, out[-800:]


def _script(name: str, *args: str) -> tuple[bool, str]:
    code, out = _run([sys.executable, f"scripts/{name}", *args])
    return code == 0, out[-800:]


def measure_step(step: str) -> dict[str, Any]:
    env = {"PYTHONPATH": ".:scripts"}
    import os

    os.environ.update(env)
    metrics: dict[str, Any] = {"step": step, "timestamp_utc": datetime.now(timezone.utc).isoformat()}

    if step in {"baseline", "step1", "step2", "step3", "step4", "final"}:
        ok, out = _script("check_gold_spl_oracles.py")
        metrics["gold_oracles_pass"] = ok
        ok, out = _script("check_environment_profile_freshness.py", "--max-age-minutes", "10080")
        metrics["profile_freshness_pass"] = ok
        ok, out = _unittest("scripts.tests.test_environment_profile")
        metrics["env_profile_tests_pass"] = ok
        ok, out = _unittest("scripts.tests.test_intent_field_contracts")
        metrics["coherence_tests_pass"] = ok
        ok, out = _unittest("scripts.tests.test_langgraph_coherence_wiring")
        metrics["coherence_wiring_pass"] = ok

    if step in {"step2", "step3", "step4", "final"}:
        ok, out = _unittest("scripts.tests.test_spl_domain_knowledge")
        metrics["domain_knowledge_tests_pass"] = ok
        ok, out = _unittest("scripts.tests.test_oracle_index_collisions")
        metrics["oracle_collision_tests_pass"] = ok

    if step in {"step3", "step4", "final"}:
        ok, out = _unittest("scripts.tests.test_spl_field_discovery")
        metrics["field_discovery_tests_pass"] = ok
        ok, out = _unittest("scripts.tests.test_field_discovery_wiring")
        metrics["field_discovery_wiring_pass"] = ok
        ok, out = _unittest("scripts.tests.test_spl_write_plan_slots")
        metrics["write_plan_slots_tests_pass"] = ok

    if step in {"step4", "final"}:
        ok, out = _unittest("scripts.tests.test_post_execution_diagnostics")
        metrics["post_execution_tests_pass"] = ok

    if step == "final":
        ok, out = _run(
            [
                sys.executable,
                "scripts/run_operational_spl_accuracy.py",
                "--out-dir",
                "artifacts/benchmark/operational_spl_accuracy",
                "--multi-model",
            ],
        )
        metrics["operational_benchmark_ran"] = ok
        op_path = PROJECT_ROOT / "artifacts/benchmark/operational_spl_accuracy/latest.json"
        if op_path.is_file():
            try:
                op = json.loads(op_path.read_text(encoding="utf-8"))
                summary = op.get("summary", op)
                metrics["operational_pass"] = summary.get("passed", summary.get("pass_count"))
                metrics["operational_total"] = summary.get("total", summary.get("case_count"))
            except Exception:
                pass

    bool_keys = [k for k, v in metrics.items() if isinstance(v, bool)]
    metrics["all_pass"] = all(metrics[k] for k in bool_keys) if bool_keys else True
    return metrics


def main() -> int:
    parser = argparse.ArgumentParser(description="Plan implementation gate metrics")
    parser.add_argument("--step", default="final", choices=["baseline", "step1", "step2", "step3", "step4", "final"])
    parser.add_argument("--out", default=str(OUT_DEFAULT))
    args = parser.parse_args()

    payload = measure_step(args.step)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(json.dumps(payload, indent=2))
    return 0 if payload.get("all_pass") else 1


if __name__ == "__main__":
    raise SystemExit(main())
