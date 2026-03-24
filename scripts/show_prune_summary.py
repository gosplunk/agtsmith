#!/usr/bin/env python3
"""Show current artifact counts and prune keep thresholds."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def count_files(base: Path, pattern: str) -> int:
    if not base.exists():
        return 0
    return len([p for p in base.glob(pattern) if p.is_file()])


def count_dirs(base: Path, pattern: str) -> int:
    if not base.exists():
        return 0
    return len([p for p in base.glob(pattern) if p.is_dir()])


def main() -> int:
    parser = argparse.ArgumentParser(description="Show prune summary")
    parser.add_argument("--keep-regression", type=int, default=100)
    parser.add_argument("--keep-snapshots", type=int, default=50)
    parser.add_argument("--keep-langgraph", type=int, default=200)
    parser.add_argument(
        "--json-out",
        default=None,
        help="Optional path to write summary as JSON",
    )
    args = parser.parse_args()

    regression_count = count_files(Path("docs/logs/template_regression_history"), "template_regression_*.json")
    snapshot_count = count_dirs(Path("docs/logs/operator_snapshot/history"), "snapshot_*")
    langgraph_count = count_files(Path("docs/logs/langgraph_runs"), "langgraph_run_*.json")

    print("=== Prune Summary ===")
    print(f"template_regression_history: count={regression_count} keep={args.keep_regression}")
    print(f"operator_snapshot_history: count={snapshot_count} keep={args.keep_snapshots}")
    print(f"langgraph_runs: count={langgraph_count} keep={args.keep_langgraph}")

    print("\nCandidates estimate (count - keep, minimum 0):")
    print(f"- template_regression_history: {max(0, regression_count - args.keep_regression)}")
    print(f"- operator_snapshot_history: {max(0, snapshot_count - args.keep_snapshots)}")
    print(f"- langgraph_runs: {max(0, langgraph_count - args.keep_langgraph)}")

    if args.json_out:
        out = Path(args.json_out)
        out.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "counts": {
                "template_regression_history": regression_count,
                "operator_snapshot_history": snapshot_count,
                "langgraph_runs": langgraph_count,
            },
            "keep": {
                "template_regression_history": args.keep_regression,
                "operator_snapshot_history": args.keep_snapshots,
                "langgraph_runs": args.keep_langgraph,
            },
            "candidates_estimate": {
                "template_regression_history": max(0, regression_count - args.keep_regression),
                "operator_snapshot_history": max(0, snapshot_count - args.keep_snapshots),
                "langgraph_runs": max(0, langgraph_count - args.keep_langgraph),
            },
        }
        out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"json={out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
