#!/usr/bin/env python3
"""Write the typed-plan/template parity release artifact."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from query_policy import validate_query_args
from spl_autonomy_manifest import build_manifest
from spl_plan_compiler import COMPILER_VERSION
from spl_query_schema import ANALYTICAL_PLAN_VERSION
from spl_template_plan_adapter import template_parity_inventory

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT = PROJECT_ROOT / "artifacts" / "benchmark" / "spl_plan_parity_latest.json"


def build_report() -> dict:
    rows = []
    for item in template_parity_inventory():
        policy_ok = True
        policy_reason = "fallback_only"
        if item.status == "represented" and item.plan is not None:
            policy_ok, policy_reason = validate_query_args(
                {
                    "query": item.compiled_query,
                    "earliest_time": item.plan.execution.earliest,
                    "latest_time": item.plan.execution.latest,
                    "row_limit": item.plan.execution.row_limit,
                },
                question=(
                    f"show Splunk internal {item.intent}"
                    if any(branch.index.startswith("_") for branch in item.plan.datasets)
                    else f"show {item.intent}"
                ),
            )
        rows.append(
            {
                "intent": item.intent,
                "status": item.status,
                "reason": item.reason,
                "policy_ok": policy_ok,
                "policy_reason": policy_reason,
            }
        )
    represented = sum(1 for row in rows if row["status"] == "represented")
    fallback_only = sum(1 for row in rows if row["status"] == "fallback_only")
    unsafe = sum(1 for row in rows if not row["policy_ok"])
    return {
        "schema_version": 1,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        **build_manifest(
            extra={
                "analytical_plan_version": ANALYTICAL_PLAN_VERSION,
                "compiler_version": COMPILER_VERSION,
                "artifact_kind": "template_plan_parity",
            }
        ),
        "summary": {
            "template_count": len(rows),
            "represented_count": represented,
            "fallback_only_count": fallback_only,
            "classified_count": represented + fallback_only,
            "policy_safe_count": len(rows) - unsafe,
            "gate_passed": represented + fallback_only == len(rows) and unsafe == 0,
        },
        "templates": rows,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Typed-plan/template parity gate")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()
    report = build_report()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report["summary"], indent=2, sort_keys=True))
    return 0 if report["summary"]["gate_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
