#!/usr/bin/env python3
"""Summarize LangGraph policy summary history snapshots and show deltas."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any


def load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def get_summary_counts(doc: dict[str, Any]) -> dict[str, int]:
    summary = doc.get("summary", {}) if isinstance(doc, dict) else {}
    # Snapshot payload stores "summary" object from latest_policy_summary.json,
    # which itself contains a nested "summary" block with numeric counters.
    nested = summary.get("summary", {}) if isinstance(summary, dict) else {}
    out: dict[str, int] = {}
    for k in (
        "total_runs",
        "supported_true",
        "supported_false",
        "query_policy_ok_true",
        "query_policy_ok_false",
        "query_policy_ok_null",
    ):
        v = nested.get(k)
        out[k] = int(v) if isinstance(v, int) else 0
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="Summarize LangGraph policy history snapshots")
    parser.add_argument(
        "--dir",
        default="docs/logs/langgraph_policy_summary_history",
        help="History directory",
    )
    parser.add_argument("--limit", type=int, default=10, help="Show latest N snapshots")
    parser.add_argument("--csv-out", default=None, help="Optional path to write trend rows as CSV")
    args = parser.parse_args()

    d = Path(args.dir)
    if not d.exists():
        print(f"FAIL: history dir not found: {d}")
        return 1

    files = sorted(d.glob("langgraph_policy_summary_*.json"))
    if not files:
        print(f"No policy history snapshots found in {d}")
        return 0

    selected = files[-args.limit :]
    print("=== LangGraph Policy History Trend ===")
    print(f"dir={d}")
    print(f"total_files={len(files)}")
    print(f"showing={len(selected)}")

    prev_counts: dict[str, int] | None = None
    csv_rows: list[dict[str, Any]] = []

    for p in selected:
        doc = load(p)
        ts = doc.get("timestamp_utc")
        counts = get_summary_counts(doc)
        print(f"\n- file={p.name} ts={ts}")
        print(
            "  counts: "
            f"total={counts['total_runs']} "
            f"supported_true={counts['supported_true']} "
            f"supported_false={counts['supported_false']} "
            f"policy_ok_true={counts['query_policy_ok_true']} "
            f"policy_ok_false={counts['query_policy_ok_false']} "
            f"policy_ok_null={counts['query_policy_ok_null']}"
        )

        if prev_counts is not None:
            delta_total = counts["total_runs"] - prev_counts["total_runs"]
            delta_st = counts["supported_true"] - prev_counts["supported_true"]
            delta_sf = counts["supported_false"] - prev_counts["supported_false"]
            delta_pt = counts["query_policy_ok_true"] - prev_counts["query_policy_ok_true"]
            delta_pf = counts["query_policy_ok_false"] - prev_counts["query_policy_ok_false"]
            delta_pn = counts["query_policy_ok_null"] - prev_counts["query_policy_ok_null"]
            print(
                "  delta: "
                f"total={delta_total:+d} "
                f"supported_true={delta_st:+d} "
                f"supported_false={delta_sf:+d} "
                f"policy_ok_true={delta_pt:+d} "
                f"policy_ok_false={delta_pf:+d} "
                f"policy_ok_null={delta_pn:+d}"
            )
        else:
            delta_total = delta_st = delta_sf = delta_pt = delta_pf = delta_pn = 0

        csv_rows.append(
            {
                "file": p.name,
                "timestamp_utc": ts,
                "total_runs": counts["total_runs"],
                "supported_true": counts["supported_true"],
                "supported_false": counts["supported_false"],
                "query_policy_ok_true": counts["query_policy_ok_true"],
                "query_policy_ok_false": counts["query_policy_ok_false"],
                "query_policy_ok_null": counts["query_policy_ok_null"],
                "delta_total_runs": delta_total,
                "delta_supported_true": delta_st,
                "delta_supported_false": delta_sf,
                "delta_query_policy_ok_true": delta_pt,
                "delta_query_policy_ok_false": delta_pf,
                "delta_query_policy_ok_null": delta_pn,
            }
        )

        prev_counts = counts

    if args.csv_out:
        out = Path(args.csv_out)
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=[
                    "file",
                    "timestamp_utc",
                    "total_runs",
                    "supported_true",
                    "supported_false",
                    "query_policy_ok_true",
                    "query_policy_ok_false",
                    "query_policy_ok_null",
                    "delta_total_runs",
                    "delta_supported_true",
                    "delta_supported_false",
                    "delta_query_policy_ok_true",
                    "delta_query_policy_ok_false",
                    "delta_query_policy_ok_null",
                ],
            )
            writer.writeheader()
            writer.writerows(csv_rows)
        print(f"csv={out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

