#!/usr/bin/env python3
"""Summarize LangGraph policy outcomes from run artifacts."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path
from typing import Any


def load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description="Summarize LangGraph policy outcomes")
    parser.add_argument(
        "--dir",
        default="artifacts/runs/langgraph",
        help="Directory containing langgraph_run_*.json files",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Number of latest runs to analyze",
    )
    parser.add_argument(
        "--csv-out",
        default=None,
        help="Optional CSV output path for per-run policy rows",
    )
    parser.add_argument(
        "--json-out",
        default=None,
        help="Optional JSON output path for aggregate summary",
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
    rows: list[dict[str, Any]] = []
    policy_reason_counts: Counter[str] = Counter()
    guardrail_reason_counts: Counter[str] = Counter()
    summary = {
        "total_runs": len(selected),
        "supported_true": 0,
        "supported_false": 0,
        "query_policy_ok_true": 0,
        "query_policy_ok_false": 0,
        "query_policy_ok_null": 0,
    }

    for path in selected:
        data = load(path)
        result = data.get("result", {}) if isinstance(data, dict) else {}
        if not isinstance(result, dict):
            result = {}
        supported = result.get("supported")
        query_policy_ok = result.get("query_policy_ok")
        query_policy_reason = result.get("query_policy_reason")
        guardrail_reason = result.get("guardrail_reason")
        question = result.get("question")
        intent = result.get("intent")
        ts = data.get("timestamp_utc")

        if supported is True:
            summary["supported_true"] += 1
        else:
            summary["supported_false"] += 1

        if query_policy_ok is True:
            summary["query_policy_ok_true"] += 1
        elif query_policy_ok is False:
            summary["query_policy_ok_false"] += 1
        else:
            summary["query_policy_ok_null"] += 1

        if query_policy_reason:
            policy_reason_counts[str(query_policy_reason)] += 1
        if guardrail_reason:
            guardrail_reason_counts[str(guardrail_reason)] += 1

        rows.append(
            {
                "file": path.name,
                "timestamp_utc": ts,
                "intent": intent,
                "supported": supported,
                "query_policy_ok": query_policy_ok,
                "query_policy_reason": query_policy_reason,
                "guardrail_reason": guardrail_reason,
                "question": question,
            }
        )

    print("=== LangGraph Policy Summary ===")
    print(f"dir={run_dir}")
    print(f"total_files={len(files)}")
    print(f"analyzed={len(selected)}")
    print(f"supported_true={summary['supported_true']}")
    print(f"supported_false={summary['supported_false']}")
    print(f"query_policy_ok_true={summary['query_policy_ok_true']}")
    print(f"query_policy_ok_false={summary['query_policy_ok_false']}")
    print(f"query_policy_ok_null={summary['query_policy_ok_null']}")

    print("policy_reason_counts:")
    for reason, count in sorted(policy_reason_counts.items()):
        print(f"- {reason}: {count}")

    print("guardrail_reason_counts:")
    for reason, count in sorted(guardrail_reason_counts.items()):
        print(f"- {reason}: {count}")

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
                    "supported",
                    "query_policy_ok",
                    "query_policy_reason",
                    "guardrail_reason",
                    "question",
                ],
            )
            writer.writeheader()
            writer.writerows(rows)
        print(f"csv={csv_path}")

    if args.json_out:
        json_path = Path(args.json_out)
        json_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "summary": summary,
            "policy_reason_counts": dict(policy_reason_counts),
            "guardrail_reason_counts": dict(guardrail_reason_counts),
        }
        json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"json={json_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
