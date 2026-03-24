#!/usr/bin/env python3
"""Summarize latest multi-model run artifacts."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path


def load_rows(path: Path) -> list[dict]:
    files = sorted(path.glob("multi_model_run_*.json"))
    rows: list[dict] = []
    for f in files[-300:]:
        try:
            payload = json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            continue
        result = payload.get("result", {}) if isinstance(payload, dict) else {}
        rows.append(
            {
                "file": f.name,
                "timestamp_utc": payload.get("timestamp_utc"),
                "question": result.get("question"),
                "supported": result.get("supported"),
                "intent": result.get("intent"),
                "selected_tool": result.get("selected_tool"),
                "rows_returned": result.get("rows_returned"),
                "final_confidence": result.get("final_confidence"),
                "validation_reason": result.get("validation_reason"),
                "tdir_severity": (result.get("tdir_case", {}) or {}).get("severity"),
                "tdir_risk_score": (result.get("tdir_case", {}) or {}).get("risk_score"),
                "winner": (result.get("peer_reviewer_decision", {}) or {}).get("winner"),
                "winner_2": (result.get("peer_reviewer_2_decision", {}) or {}).get("winner"),
                "query_writer_model": (result.get("planner", {}) or {}).get("model"),
                "security_reviewer_model": (result.get("security_reviewer", {}) or {}).get("model"),
                "peer_reviewer_model": (result.get("peer_reviewer", {}) or {}).get("model"),
                "peer_reviewer_2_model": (result.get("peer_reviewer_2", {}) or {}).get("model"),
            }
        )
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description="Summarize multi-model run artifacts")
    parser.add_argument("--dir", default="artifacts/runs/multi_model")
    parser.add_argument("--limit", type=int, default=10)
    parser.add_argument("--csv-out", default="")
    args = parser.parse_args()

    run_dir = Path(args.dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    rows = load_rows(run_dir)
    show = rows[-args.limit :]

    print("=== Multi-Model Run Index ===")
    print(f"dir={run_dir}")
    print(f"total_files={len(rows)}")
    print(f"showing={len(show)}")
    for row in show:
        print(
            "- "
            f"file={row['file']} "
            f"ts={row['timestamp_utc']} "
            f"supported={row['supported']} "
            f"intent={row['intent']} "
            f"tool={row['selected_tool']} "
            f"rows={row['rows_returned']} "
            f"confidence={row['final_confidence']} "
            f"tdir_severity={row['tdir_severity']} "
            f"tdir_risk={row['tdir_risk_score']} "
            f"winner={row['winner']} "
            f"validation_reason={row['validation_reason']} "
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
                    "intent",
                    "selected_tool",
                    "rows_returned",
                    "final_confidence",
                    "tdir_severity",
                    "tdir_risk_score",
                    "winner",
                    "winner_2",
                    "validation_reason",
                    "query_writer_model",
                    "security_reviewer_model",
                    "peer_reviewer_model",
                    "peer_reviewer_2_model",
                ],
            )
            writer.writeheader()
            writer.writerows(show)
        print(f"csv={out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
