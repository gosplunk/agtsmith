#!/usr/bin/env python3
"""Summarize prune summary history snapshots and show deltas."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any


def load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def get_counts(doc: dict[str, Any]) -> dict[str, int]:
    summary = doc.get("summary", {}) if isinstance(doc, dict) else {}
    counts = summary.get("counts", {}) if isinstance(summary, dict) else {}
    out: dict[str, int] = {}
    for k in ("template_regression_history", "operator_snapshot_history", "langgraph_runs"):
        v = counts.get(k)
        out[k] = int(v) if isinstance(v, int) else 0
    return out


def get_candidates(doc: dict[str, Any]) -> dict[str, int]:
    summary = doc.get("summary", {}) if isinstance(doc, dict) else {}
    c = summary.get("candidates_estimate", {}) if isinstance(summary, dict) else {}
    out: dict[str, int] = {}
    for k in ("template_regression_history", "operator_snapshot_history", "langgraph_runs"):
        v = c.get(k)
        out[k] = int(v) if isinstance(v, int) else 0
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="Summarize prune history snapshots")
    parser.add_argument("--dir", default="docs/logs/prune_summary_history", help="History directory")
    parser.add_argument("--limit", type=int, default=10, help="Show latest N snapshots")
    parser.add_argument("--csv-out", default=None, help="Optional path to write trend rows as CSV")
    args = parser.parse_args()

    d = Path(args.dir)
    if not d.exists():
        print(f"FAIL: history dir not found: {d}")
        return 1

    files = sorted(d.glob("prune_summary_*.json"))
    if not files:
        print(f"No prune history snapshots found in {d}")
        return 0

    selected = files[-args.limit :]
    print("=== Prune History Trend ===")
    print(f"dir={d}")
    print(f"total_files={len(files)}")
    print(f"showing={len(selected)}")

    csv_rows: list[dict[str, Any]] = []
    prev_counts: dict[str, int] | None = None
    prev_candidates: dict[str, int] | None = None
    for p in selected:
        doc = load(p)
        ts = doc.get("timestamp_utc")
        counts = get_counts(doc)
        cand = get_candidates(doc)

        print(f"\n- file={p.name} ts={ts}")
        print(
            "  counts: "
            f"reg={counts['template_regression_history']} "
            f"snap={counts['operator_snapshot_history']} "
            f"lg={counts['langgraph_runs']}"
        )
        print(
            "  candidates: "
            f"reg={cand['template_regression_history']} "
            f"snap={cand['operator_snapshot_history']} "
            f"lg={cand['langgraph_runs']}"
        )

        if prev_counts is not None and prev_candidates is not None:
            dc_reg = counts["template_regression_history"] - prev_counts["template_regression_history"]
            dc_snap = counts["operator_snapshot_history"] - prev_counts["operator_snapshot_history"]
            dc_lg = counts["langgraph_runs"] - prev_counts["langgraph_runs"]
            dd_reg = cand["template_regression_history"] - prev_candidates["template_regression_history"]
            dd_snap = cand["operator_snapshot_history"] - prev_candidates["operator_snapshot_history"]
            dd_lg = cand["langgraph_runs"] - prev_candidates["langgraph_runs"]
            print(
                "  delta_counts: "
                f"reg={dc_reg:+d} snap={dc_snap:+d} lg={dc_lg:+d}"
            )
            print(
                "  delta_candidates: "
                f"reg={dd_reg:+d} snap={dd_snap:+d} lg={dd_lg:+d}"
            )
        else:
            dc_reg = dc_snap = dc_lg = 0
            dd_reg = dd_snap = dd_lg = 0

        csv_rows.append(
            {
                "file": p.name,
                "timestamp_utc": ts,
                "count_regression": counts["template_regression_history"],
                "count_snapshots": counts["operator_snapshot_history"],
                "count_langgraph": counts["langgraph_runs"],
                "cand_regression": cand["template_regression_history"],
                "cand_snapshots": cand["operator_snapshot_history"],
                "cand_langgraph": cand["langgraph_runs"],
                "delta_count_regression": dc_reg,
                "delta_count_snapshots": dc_snap,
                "delta_count_langgraph": dc_lg,
                "delta_cand_regression": dd_reg,
                "delta_cand_snapshots": dd_snap,
                "delta_cand_langgraph": dd_lg,
            }
        )

        prev_counts = counts
        prev_candidates = cand

    if args.csv_out:
        out = Path(args.csv_out)
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=[
                    "file",
                    "timestamp_utc",
                    "count_regression",
                    "count_snapshots",
                    "count_langgraph",
                    "cand_regression",
                    "cand_snapshots",
                    "cand_langgraph",
                    "delta_count_regression",
                    "delta_count_snapshots",
                    "delta_count_langgraph",
                    "delta_cand_regression",
                    "delta_cand_snapshots",
                    "delta_cand_langgraph",
                ],
            )
            writer.writeheader()
            writer.writerows(csv_rows)
        print(f"csv={out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
