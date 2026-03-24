#!/usr/bin/env python3
"""Flag unexpected jumps in LangGraph policy trend deltas."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

DELTA_FIELDS = (
    "delta_supported_true",
    "delta_supported_false",
    "delta_query_policy_ok_true",
    "delta_query_policy_ok_false",
    "delta_query_policy_ok_null",
)


def to_int(value: str) -> int:
    try:
        return int(value)
    except Exception:
        return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Check LangGraph policy trend for anomalous deltas")
    parser.add_argument(
        "--csv",
        default="docs/logs/langgraph_policy_summary_history/latest_trend.csv",
        help="Trend CSV path",
    )
    parser.add_argument(
        "--max-abs-delta",
        type=int,
        default=5,
        help="Maximum allowed absolute delta for monitored counters",
    )
    args = parser.parse_args()

    path = Path(args.csv)
    if not path.exists():
        print(f"FAIL: trend csv missing: {path}")
        return 1

    rows: list[dict[str, str]] = []
    with path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)

    print("=== LangGraph Policy Trend Anomaly Check ===")
    print(f"csv={path}")
    print(f"rows={len(rows)}")
    print(f"max_abs_delta={args.max_abs_delta}")

    if not rows:
        print("status=PASS")
        print("No rows found; nothing to evaluate.")
        return 0

    failures: list[str] = []
    for row in rows[1:]:
        file_name = row.get("file", "unknown")
        for field in DELTA_FIELDS:
            delta = to_int(row.get(field, "0"))
            if abs(delta) > args.max_abs_delta:
                failures.append(
                    f"file={file_name} field={field} delta={delta} exceeds threshold {args.max_abs_delta}"
                )

    if failures:
        print("status=FAIL")
        for idx, msg in enumerate(failures, start=1):
            print(f"{idx}. {msg}")
        return 1

    print("status=PASS")
    print("No anomalous deltas detected.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

