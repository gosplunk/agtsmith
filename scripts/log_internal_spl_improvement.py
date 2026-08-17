#!/usr/bin/env python3
"""Append an improvement experiment result to the internal SPL improvement log."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_LOG = PROJECT_ROOT / "artifacts" / "spl_autonomy" / "internal_benchmark" / "improvement_log.json"
DEFAULT_REPORT = PROJECT_ROOT / "artifacts" / "spl_autonomy" / "internal_benchmark" / "latest.json"


def main() -> int:
    parser = argparse.ArgumentParser(description="Log internal SPL improvement experiment")
    parser.add_argument("--idea-id", required=True)
    parser.add_argument("--title", required=True)
    parser.add_argument("--status", choices=("kept", "reverted", "no_change", "failed"), required=True)
    parser.add_argument("--reason", default="")
    parser.add_argument("--report", default=str(DEFAULT_REPORT))
    parser.add_argument("--log", default=str(DEFAULT_LOG))
    args = parser.parse_args()

    report_path = Path(args.report)
    log_path = Path(args.log)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    payload: dict = {"program": "internal_spl_llm_improvement", "ideas": []}
    if log_path.is_file():
        try:
            payload = json.loads(log_path.read_text(encoding="utf-8"))
        except Exception:
            payload = {"program": "internal_spl_llm_improvement", "ideas": []}
    if not isinstance(payload.get("ideas"), list):
        payload["ideas"] = []

    report: dict = {}
    if report_path.is_file():
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
        except Exception:
            report = {}

    payload["ideas"].append(
        {
            "id": args.idea_id,
            "title": args.title,
            "status": args.status,
            "reason": str(args.reason or "").strip(),
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "passed_count": report.get("passed_count"),
            "case_count": report.get("case_count"),
            "pass_rate_pct": report.get("pass_rate_pct"),
            "multi_model": report.get("multi_model"),
            "failure_taxonomy": report.get("failure_taxonomy"),
        }
    )
    log_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"log": str(log_path), "idea": args.idea_id, "status": args.status}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
