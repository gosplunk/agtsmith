#!/usr/bin/env python3
"""Summarize latest agentic run artifacts."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path


def load_rows(path: Path) -> list[dict]:
    files = sorted(path.glob("agentic_run_*.json"))
    rows: list[dict] = []
    for f in files[-200:]:
        try:
            payload = json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            continue
        result = payload.get("result", {}) if isinstance(payload, dict) else {}
        trajectory = result.get("trajectory", []) if isinstance(result, dict) else []
        last_tool = ""
        if isinstance(trajectory, list) and trajectory:
            last_tool = str(trajectory[-1].get("tool", ""))
        rows.append(
            {
                "file": f.name,
                "timestamp_utc": payload.get("timestamp_utc"),
                "question": result.get("question"),
                "supported": result.get("supported"),
                "steps_executed": result.get("steps_executed"),
                "done_reason": result.get("done_reason"),
                "last_tool": last_tool,
                "summary_fallback_used": result.get("summary_fallback_used"),
                "tdir_severity": (result.get("tdir_case", {}) or {}).get("severity"),
                "tdir_risk_score": (result.get("tdir_case", {}) or {}).get("risk_score"),
            }
        )
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description="Summarize agentic run artifacts")
    parser.add_argument("--dir", default="artifacts/runs/agentic")
    parser.add_argument("--limit", type=int, default=10)
    parser.add_argument("--csv-out", default="")
    args = parser.parse_args()

    run_dir = Path(args.dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    rows = load_rows(run_dir)
    show = rows[-args.limit :]

    print("=== Agentic Run Index ===")
    print(f"dir={run_dir}")
    print(f"total_files={len(rows)}")
    print(f"showing={len(show)}")
    for row in show:
        print(
            "- "
            f"file={row['file']} "
            f"ts={row['timestamp_utc']} "
            f"supported={row['supported']} "
            f"steps={row['steps_executed']} "
            f"done_reason={row['done_reason']} "
            f"last_tool={row['last_tool']} "
            f"tdir_severity={row['tdir_severity']} "
            f"tdir_risk={row['tdir_risk_score']} "
            f"fallback={row['summary_fallback_used']} "
            f"question={row['question']!r}"
        )

    if args.csv_out:
        out = Path(args.csv_out)
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=[
                    "file",
                    "timestamp_utc",
                    "question",
                    "supported",
                    "steps_executed",
                    "done_reason",
                    "last_tool",
                    "tdir_severity",
                    "tdir_risk_score",
                    "summary_fallback_used",
                ],
            )
            writer.writeheader()
            writer.writerows(show)
        print(f"csv={out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
