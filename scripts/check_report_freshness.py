#!/usr/bin/env python3
"""Check freshness of key report artifacts.

Fails with non-zero exit if any required file is older than max allowed age.
"""

from __future__ import annotations

import argparse
import time
from pathlib import Path

REQUIRED_FILES = [
    "docs/logs/status_report.md",
    "docs/logs/status_report.json",
    "docs/logs/latest_status.json",
    "docs/logs/template_regression_latest.json",
]


def main() -> int:
    parser = argparse.ArgumentParser(description="Check report freshness")
    parser.add_argument(
        "--max-age-minutes",
        type=int,
        default=180,
        help="Maximum allowed age in minutes for each required report file",
    )
    args = parser.parse_args()

    now = time.time()
    max_age_sec = args.max_age_minutes * 60

    print("=== Report Freshness Check ===")
    print(f"max_age_minutes={args.max_age_minutes}")

    failed = []
    for rel in REQUIRED_FILES:
        p = Path(rel)
        if not p.exists():
            failed.append(f"missing: {rel}")
            print(f"[FAIL] {rel} missing")
            continue

        age_sec = now - p.stat().st_mtime
        age_min = age_sec / 60.0
        status = "PASS" if age_sec <= max_age_sec else "FAIL"
        print(f"[{status}] {rel} age_minutes={age_min:.1f}")
        if age_sec > max_age_sec:
            failed.append(f"stale: {rel} age_minutes={age_min:.1f}")

    if failed:
        print("status=FAIL")
        for idx, item in enumerate(failed, start=1):
            print(f"{idx}. {item}")
        return 1

    print("status=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
