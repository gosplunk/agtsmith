#!/usr/bin/env python3
"""Summarize regression history and print per-intent row-count deltas.

Reads timestamped JSON snapshots from docs/logs/template_regression_history.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any


def load_report(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def intent_rows(report: dict[str, Any]) -> dict[str, int]:
    rows: dict[str, int] = {}
    for item in report.get("intent_results", []):
        if not isinstance(item, dict):
            continue
        intent = item.get("intent")
        value = item.get("rows_returned")
        if isinstance(intent, str) and isinstance(value, int):
            rows[intent] = value
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description="Summarize template regression trends")
    parser.add_argument(
        "--history-dir",
        default="docs/logs/template_regression_history",
        help="Directory containing timestamped regression JSON snapshots",
    )
    parser.add_argument(
        "--max-abs-delta",
        type=int,
        default=None,
        help="Fail (exit 1) if absolute delta for any intent exceeds this value",
    )
    parser.add_argument(
        "--csv-out",
        default=None,
        help="Optional path to write per-intent trend rows as CSV",
    )
    parser.add_argument(
        "--csv-meta-out",
        default=None,
        help="Optional path to write summary metadata as CSV key/value rows",
    )
    args = parser.parse_args()

    history_dir = Path(args.history_dir)
    if not history_dir.exists():
        print(f"FAIL: history dir not found: {history_dir}")
        return 1

    files = sorted(history_dir.glob("template_regression_*.json"))
    if not files:
        print(f"FAIL: no history files found in {history_dir}")
        return 1

    latest_path = files[-1]
    latest = load_report(latest_path)
    latest_status = latest.get("status")
    latest_timestamp = latest.get("timestamp_utc")

    print("=== Regression Trend Summary ===")
    print(f"history_files={len(files)}")
    print(f"latest_file={latest_path}")
    print(f"latest_status={latest_status}")
    print(f"latest_timestamp_utc={latest_timestamp}")

    latest_rows = intent_rows(latest)
    print("\nLatest rows by intent:")
    for intent in sorted(latest_rows.keys()):
        print(f"- {intent}: {latest_rows[intent]}")

    if len(files) < 2:
        print("\nNo previous snapshot available for delta comparison.")
        return 0

    prev_path = files[-2]
    prev = load_report(prev_path)
    prev_rows = intent_rows(prev)
    prev_timestamp = prev.get("timestamp_utc")

    intents = sorted(set(latest_rows.keys()) | set(prev_rows.keys()))
    csv_rows: list[dict[str, object]] = []
    print("\nDelta vs previous snapshot:")
    print(f"previous_file={prev_path}")
    breaches: list[str] = []
    for intent in intents:
        old = prev_rows.get(intent, 0)
        new = latest_rows.get(intent, 0)
        delta = new - old
        sign = "+" if delta >= 0 else ""
        print(f"- {intent}: prev={old} latest={new} delta={sign}{delta}")
        csv_rows.append(
            {
                "intent": intent,
                "previous_rows": old,
                "latest_rows": new,
                "delta": delta,
            }
        )
        if args.max_abs_delta is not None and abs(delta) > args.max_abs_delta:
            breaches.append(
                f"{intent} delta {delta} exceeds max_abs_delta={args.max_abs_delta}"
            )

    if args.csv_out:
        csv_path = Path(args.csv_out)
        csv_path.parent.mkdir(parents=True, exist_ok=True)
        with csv_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=["intent", "previous_rows", "latest_rows", "delta"],
            )
            writer.writeheader()
            writer.writerows(csv_rows)
        print(f"csv={csv_path}")

    if args.csv_meta_out:
        meta_path = Path(args.csv_meta_out)
        meta_path.parent.mkdir(parents=True, exist_ok=True)
        meta_rows = [
            {"key": "latest_file", "value": str(latest_path)},
            {"key": "latest_status", "value": str(latest_status)},
            {"key": "latest_timestamp_utc", "value": str(latest_timestamp)},
            {"key": "previous_file", "value": str(prev_path)},
            {"key": "previous_timestamp_utc", "value": str(prev_timestamp)},
            {"key": "history_files", "value": str(len(files))},
        ]
        with meta_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["key", "value"])
            writer.writeheader()
            writer.writerows(meta_rows)
        print(f"csv_meta={meta_path}")

    if args.max_abs_delta is not None:
        if breaches:
            print("\nstatus=FAIL")
            for idx, breach in enumerate(breaches, start=1):
                print(f"{idx}. {breach}")
            return 1
        print("\nstatus=PASS")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
