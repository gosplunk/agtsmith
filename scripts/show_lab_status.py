#!/usr/bin/env python3
"""Show compact lab status from existing regression artifacts.

This script does not execute Splunk/Ollama calls. It only reads files in docs/logs.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any

LATEST_PATH = Path("docs/logs/template_regression_latest.json")
HISTORY_DIR = Path("docs/logs/template_regression_history")


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def rows_by_intent(report: dict[str, Any]) -> dict[str, int]:
    out: dict[str, int] = {}
    for item in report.get("intent_results", []):
        if not isinstance(item, dict):
            continue
        intent = item.get("intent")
        rows = item.get("rows_returned")
        if isinstance(intent, str) and isinstance(rows, int):
            out[intent] = rows
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="Show compact lab status from artifacts")
    parser.add_argument(
        "--csv-out",
        default=None,
        help="Optional path to write latest per-intent rows as CSV",
    )
    parser.add_argument(
        "--csv-meta-out",
        default=None,
        help="Optional path to write summary metadata as CSV key/value rows",
    )
    parser.add_argument(
        "--json-out",
        default=None,
        help="Optional path to write aggregate status JSON",
    )
    args = parser.parse_args()

    print("=== Lab Status Dashboard ===")

    if not LATEST_PATH.exists():
        print(f"status=FAIL latest_report_missing path={LATEST_PATH}")
        return 1

    latest = load_json(LATEST_PATH)
    latest_status = latest.get("status", "UNKNOWN")
    latest_ts = latest.get("timestamp_utc", "unknown")

    print(f"latest_report={LATEST_PATH}")
    print(f"latest_status={latest_status}")
    print(f"latest_timestamp_utc={latest_ts}")

    latest_rows = rows_by_intent(latest)
    print("rows_by_intent:")
    for intent in sorted(latest_rows):
        print(f"- {intent}: {latest_rows[intent]}")
    if args.csv_out:
        csv_path = Path(args.csv_out)
        csv_path.parent.mkdir(parents=True, exist_ok=True)
        with csv_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["intent", "rows_returned"])
            writer.writeheader()
            for intent in sorted(latest_rows):
                writer.writerow({"intent": intent, "rows_returned": latest_rows[intent]})
        print(f"csv={csv_path}")

    history_files = sorted(HISTORY_DIR.glob("template_regression_*.json")) if HISTORY_DIR.exists() else []
    print(f"history_count={len(history_files)}")

    if len(history_files) >= 2:
        prev = load_json(history_files[-2])
        prev_rows = rows_by_intent(prev)
        delta_map: dict[str, int] = {}
        print("delta_vs_previous:")
        intents = sorted(set(latest_rows) | set(prev_rows))
        for intent in intents:
            old = prev_rows.get(intent, 0)
            new = latest_rows.get(intent, 0)
            delta = new - old
            delta_map[intent] = delta
            sign = "+" if delta >= 0 else ""
            print(f"- {intent}: {sign}{delta}")
    else:
        delta_map = {}
        print("delta_vs_previous: unavailable (need >=2 history snapshots)")

    overall = "PASS" if str(latest_status).upper() == "PASS" else "FAIL"
    if args.csv_meta_out:
        meta_path = Path(args.csv_meta_out)
        meta_path.parent.mkdir(parents=True, exist_ok=True)
        meta_rows = [
            {"key": "latest_report", "value": str(LATEST_PATH)},
            {"key": "latest_status", "value": str(latest_status)},
            {"key": "latest_timestamp_utc", "value": str(latest_ts)},
            {"key": "history_count", "value": str(len(history_files))},
            {"key": "overall", "value": overall},
        ]
        with meta_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["key", "value"])
            writer.writeheader()
            writer.writerows(meta_rows)
        print(f"csv_meta={meta_path}")
    if args.json_out:
        json_path = Path(args.json_out)
        json_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "latest_report": str(LATEST_PATH),
            "latest_status": latest_status,
            "latest_timestamp_utc": latest_ts,
            "history_count": len(history_files),
            "rows_by_intent": latest_rows,
            "delta_vs_previous": delta_map,
            "overall": overall,
        }
        json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"json={json_path}")
    print(f"overall={overall}")
    return 0 if overall == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
