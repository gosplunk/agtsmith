#!/usr/bin/env python3
"""Build an aggregate-only rollout report from release-gate artifacts."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from spl_autonomy_manifest import build_manifest, file_sha256
from spl_plan_compiler import COMPILER_VERSION
from spl_query_schema import ANALYTICAL_PLAN_VERSION

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT = PROJECT_ROOT / "artifacts" / "benchmark" / "spl_rollout" / "latest.json"
BASELINE_SCORE = 26.4


def _load_summary(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {"status": "missing", "artifact": str(path.relative_to(PROJECT_ROOT))}
    payload = json.loads(path.read_text(encoding="utf-8"))
    summary = payload.get("summary", payload.get("aggregate", {}))
    if not isinstance(summary, dict):
        summary = {}
    return {
        "status": "present",
        "artifact": str(path.relative_to(PROJECT_ROOT)),
        "sha256": file_sha256(path),
        "summary": summary,
    }


def _passed(record: dict[str, Any]) -> bool:
    summary = record.get("summary", {})
    return bool(isinstance(summary, dict) and summary.get("gate_passed"))


def build_report() -> dict[str, Any]:
    artifact_root = PROJECT_ROOT / "artifacts" / "benchmark"
    records = {
        "plan_parity": _load_summary(artifact_root / "spl_plan_parity_latest.json"),
        "train_static": _load_summary(
            artifact_root / "generated_scenarios" / "static" / "observe" / "train" / "latest.json"
        ),
        "dev_static": _load_summary(
            artifact_root / "generated_scenarios" / "static" / "observe" / "dev" / "latest.json"
        ),
        "observe_live": _load_summary(
            artifact_root / "generated_scenarios" / "live" / "observe" / "dev" / "latest.json"
        ),
        "prefer_live": _load_summary(
            artifact_root / "generated_scenarios" / "live" / "prefer" / "dev" / "latest.json"
        ),
        "enforce_live": _load_summary(
            artifact_root / "generated_scenarios" / "live" / "enforce" / "dev" / "latest.json"
        ),
    }
    base_ready = all(
        _passed(records[name]) for name in ("plan_parity", "train_static", "dev_static")
    )
    mode = "observe"
    if base_ready and _passed(records["observe_live"]):
        mode = "prefer"
    if mode == "prefer" and _passed(records["prefer_live"]) and _passed(records["enforce_live"]):
        mode = "enforce"

    holdout_path = artifact_root / "holdout_eval" / "latest.json"
    holdout: dict[str, Any] = {
        "status": "not_run",
        "artifact": str(holdout_path.relative_to(PROJECT_ROOT)),
        "baseline_score": BASELINE_SCORE,
    }
    if holdout_path.is_file():
        payload = json.loads(holdout_path.read_text(encoding="utf-8"))
        score = round(float(payload.get("equivalence_average", 0.0)) * 100.0, 1)
        holdout.update(
            {
                "status": "present",
                "sha256": file_sha256(holdout_path),
                "case_count": int(payload.get("case_count", 0) or 0),
                "aggregate_score": score,
                "delta_vs_baseline": round(score - BASELINE_SCORE, 1),
                "release_threshold": 75.0,
                "gate_passed": score >= 75.0,
            }
        )

    release_ready = mode == "enforce" and bool(holdout.get("gate_passed"))
    return {
        "schema_version": 1,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        **build_manifest(
            extra={
                "analytical_plan_version": ANALYTICAL_PLAN_VERSION,
                "compiler_version": COMPILER_VERSION,
                "artifact_kind": "spl_rollout_report",
            }
        ),
        "selected_mode": mode,
        "base_gates_passed": base_ready,
        "release_ready": release_ready,
        "gates": records,
        # Never copy protected case rows or case-level scores into this report.
        "protected_holdout_aggregate": holdout,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Aggregate SPL rollout report")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()
    report = build_report()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "selected_mode": report["selected_mode"],
                "base_gates_passed": report["base_gates_passed"],
                "release_ready": report["release_ready"],
                "protected_holdout_aggregate": report["protected_holdout_aggregate"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if report["base_gates_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
