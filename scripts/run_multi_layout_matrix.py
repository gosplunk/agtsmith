#!/usr/bin/env python3
"""Offline multi-layout regression matrix across gold oracle profile fixtures."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

from check_gold_spl_oracles import run_check
from spl_autonomy_manifest import build_manifest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ORACLES_PATH = PROJECT_ROOT / "benchmarks" / "gold_spl_oracles.json"
DEFAULT_OUT_PATH = PROJECT_ROOT / "artifacts" / "benchmark" / "multi_layout_matrix_latest.json"


def _variant_summary(results: list[dict]) -> dict[str, dict]:
    grouped: dict[str, list[dict]] = defaultdict(list)
    for row in results:
        if isinstance(row, dict):
            grouped[str(row.get("variant", "unknown"))].append(row)
    summary: dict[str, dict] = {}
    for variant, rows in sorted(grouped.items()):
        passed = sum(1 for row in rows if row.get("ok"))
        total = len(rows)
        summary[variant] = {
            "cases": total,
            "passed": passed,
            "failed": total - passed,
            "pass_rate_pct": round(100.0 * passed / max(1, total), 1),
        }
    return summary


def run_matrix(
    *,
    oracles_path: Path = DEFAULT_ORACLES_PATH,
    live_profile_path: Path | None = None,
) -> tuple[int, dict]:
    exit_code, report = run_check(oracles_path, live_profile_path=live_profile_path)
    results = report.get("results", [])
    if not isinstance(results, list):
        results = []
    variant_summary = _variant_summary(results)
    manifest = build_manifest(extra={"matrix_type": "multi_layout_offline"})
    payload = {
        **manifest,
        "oracle_count": report.get("oracle_count", len(results)),
        "passed": report.get("passed", 0),
        "failed": report.get("failed", 0),
        "variants": variant_summary,
        "results": results,
    }
    return exit_code, payload


def main() -> int:
    parser = argparse.ArgumentParser(description="Run offline multi-layout gold oracle matrix")
    parser.add_argument("--oracles", default=str(DEFAULT_ORACLES_PATH))
    parser.add_argument("--profile", default="", help="Optional live profile path for existing_lab variants")
    parser.add_argument("--out", default=str(DEFAULT_OUT_PATH))
    args = parser.parse_args()

    live_profile = Path(args.profile).expanduser() if args.profile else None
    exit_code, payload = run_matrix(
        oracles_path=Path(args.oracles),
        live_profile_path=live_profile,
    )

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    print("=== Multi-Layout Matrix ===")
    print(f"oracle_count={payload.get('oracle_count', 0)}")
    print(f"passed={payload.get('passed', 0)}")
    print(f"failed={payload.get('failed', 0)}")
    for variant, stats in sorted((payload.get("variants") or {}).items()):
        print(
            f"variant={variant} pass_rate_pct={stats.get('pass_rate_pct', 0)} "
            f"passed={stats.get('passed', 0)}/{stats.get('cases', 0)}"
        )
    print(f"json={out_path}")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
