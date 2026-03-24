#!/usr/bin/env python3
"""Check freshness of LangGraph policy summary artifacts."""

from __future__ import annotations

import argparse
import time
from pathlib import Path

REQUIRED = [
    Path("docs/logs/langgraph_runs/latest_policy_summary.json"),
    Path("docs/logs/langgraph_runs/latest_policy_rows.csv"),
]


def main() -> int:
    parser = argparse.ArgumentParser(description="Check LangGraph policy artifact freshness")
    parser.add_argument("--max-age-minutes", type=int, default=180, help="Max age in minutes (default: 180)")
    args = parser.parse_args()

    now = time.time()
    max_age_sec = args.max_age_minutes * 60

    print("=== LangGraph Policy Freshness Check ===")
    print(f"max_age_minutes={args.max_age_minutes}")

    failed: list[str] = []
    for p in REQUIRED:
        if not p.exists():
            print(f"[FAIL] {p} missing")
            failed.append(f"missing: {p}")
            continue
        age_sec = now - p.stat().st_mtime
        age_min = age_sec / 60.0
        if age_sec <= max_age_sec:
            print(f"[PASS] {p} age_minutes={age_min:.1f}")
        else:
            print(f"[FAIL] {p} age_minutes={age_min:.1f}")
            failed.append(f"stale: {p} age_minutes={age_min:.1f}")

    if failed:
        print("status=FAIL")
        for i, item in enumerate(failed, start=1):
            print(f"{i}. {item}")
        return 1

    print("status=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

