#!/usr/bin/env python3
"""Verify required LangGraph telemetry artifacts exist."""

from __future__ import annotations

from pathlib import Path

REQUIRED = [
    Path("docs/logs/langgraph_runs/latest_index.csv"),
    Path("docs/logs/langgraph_runs/latest_policy_summary.json"),
    Path("docs/logs/langgraph_runs/latest_policy_rows.csv"),
    Path("docs/logs/langgraph_policy_summary_history/latest_trend.csv"),
]


def main() -> int:
    print("=== LangGraph Telemetry Artifacts Check ===")
    failed: list[str] = []
    for p in REQUIRED:
        if p.exists():
            print(f"[PASS] {p}")
        else:
            print(f"[FAIL] {p} missing")
            failed.append(str(p))

    if failed:
        print("status=FAIL")
        for i, path in enumerate(failed, start=1):
            print(f"{i}. missing: {path}")
        return 1

    print("status=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

