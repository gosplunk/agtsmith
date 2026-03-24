#!/usr/bin/env python3
"""Summarize latest LangGraph run artifacts.

Reads JSON files from docs/logs/langgraph_runs and prints a compact index.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any


def load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description="Summarize LangGraph run artifacts")
    parser.add_argument(
        "--dir",
        default="artifacts/runs/langgraph",
        help="Directory containing langgraph_run_*.json files",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=10,
        help="Max number of latest runs to display",
    )
    parser.add_argument(
        "--csv-out",
        default=None,
        help="Optional path to write run index rows as CSV",
    )
    args = parser.parse_args()

    run_dir = Path(args.dir)
    if not run_dir.exists():
        print(f"FAIL: run dir not found: {run_dir}")
        return 1

    files = sorted(run_dir.glob("langgraph_run_*.json"))
    if not files:
        print(f"No run artifacts found in {run_dir}")
        return 0

    selected = files[-args.limit :]

    print("=== LangGraph Run Index ===")
    print(f"dir={run_dir}")
    print(f"total_files={len(files)}")
    print(f"showing={len(selected)}")

    csv_rows: list[dict[str, Any]] = []
    for path in selected:
        data = load(path)
        ts = data.get("timestamp_utc")
        result = data.get("result", {}) if isinstance(data, dict) else {}
        intent = result.get("intent") if isinstance(result, dict) else None
        supported = result.get("supported") if isinstance(result, dict) else None
        selected_tool = result.get("selected_tool") if isinstance(result, dict) else None
        rows = result.get("rows_returned") if isinstance(result, dict) else None
        question = result.get("question") if isinstance(result, dict) else None
        print(
            f"- file={path.name} ts={ts} intent={intent} tool={selected_tool} "
            f"supported={supported} rows={rows} question={question!r}"
        )
        csv_rows.append(
            {
                "file": path.name,
                "timestamp_utc": ts,
                "intent": intent,
                "selected_tool": selected_tool,
                "supported": supported,
                "rows_returned": rows,
                "question": question,
            }
        )

    if args.csv_out:
        csv_path = Path(args.csv_out)
        csv_path.parent.mkdir(parents=True, exist_ok=True)
        with csv_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=[
                    "file",
                    "timestamp_utc",
                    "intent",
                    "selected_tool",
                    "supported",
                    "rows_returned",
                    "question",
                ],
            )
            writer.writeheader()
            writer.writerows(csv_rows)
        print(f"csv={csv_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
