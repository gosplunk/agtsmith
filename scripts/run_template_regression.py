#!/usr/bin/env python3
"""Run lightweight regression checks for template-driven query flow.

Checks performed:
1) Template definition self-check
2) One retrieval smoke check per template intent

This is intentionally minimal and read-only.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
import sys

from check_query_templates import main as run_template_check
from minimal_question_to_answer import run_splunk_query
from query_templates import TEMPLATES

QUESTION_BY_INTENT = {
    "internal_sourcetypes": "What sourcetypes generated the most _internal events in the last 24 hours?",
    "top_indexes": "Which indexes had the most events in the last 24 hours?",
    "failed_login_activity": "Show failed login activity in the last 24 hours",
    "linux_auth_failures": "Show linux failed login activity in the last 24 hours",
    "linux_privilege_escalation": "Show failed sudo activity on linux in the last 24 hours",
    "apache_access_top_ips": "Show top client IPs in apache access logs (access_combined) in the last 24 hours",
    "apache_404_spike": "Show 404 spike behavior in apache access_combined logs in the last 24 hours",
    "apache_suspicious_user_agents": "Show suspicious user agents in apache access_combined logs in the last 24 hours",
}


def main() -> int:
    parser = argparse.ArgumentParser(description="Run template regression checks")
    parser.add_argument(
        "--report",
        default="docs/logs/template_regression_latest.json",
        help="Path to write JSON regression report",
    )
    parser.add_argument(
        "--snapshot-dir",
        default="docs/logs/template_regression_history",
        help="Directory to write timestamped JSON snapshots",
    )
    args = parser.parse_args()

    report_path = Path(args.report)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    snapshot_dir = Path(args.snapshot_dir)
    snapshot_dir.mkdir(parents=True, exist_ok=True)

    print("=== Template Regression Runner ===")
    report: dict[str, object] = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "template_count": len(TEMPLATES),
        "template_check_passed": False,
        "intent_results": [],
        "status": "FAIL",
    }
    snapshot_stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    snapshot_path = snapshot_dir / f"template_regression_{snapshot_stamp}.json"

    print("\n[1/2] Running template self-check...")
    check_code = run_template_check()
    if check_code != 0:
        print("FAIL: template self-check failed.")
        report["template_check_passed"] = False
        report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        snapshot_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"report={report_path}")
        print(f"snapshot={snapshot_path}")
        return 1
    report["template_check_passed"] = True

    print("\n[2/2] Running one smoke retrieval per template...")
    failures = []
    intent_results: list[dict[str, object]] = []
    for template in TEMPLATES:
        question = QUESTION_BY_INTENT.get(template.intent)
        if not question:
            failures.append(f"No regression question configured for intent '{template.intent}'")
            intent_results.append(
                {
                    "intent": template.intent,
                    "ok": False,
                    "error": "missing regression question",
                }
            )
            continue

        try:
            data = run_splunk_query(question)
            structured = data.get("structured", {})
            rows = structured.get("results", []) if isinstance(structured, dict) else []
            total_rows = structured.get("total_rows") if isinstance(structured, dict) else None
            row_count = len(rows) if isinstance(rows, list) else -1

            print(
                f"- intent={template.intent} rows_returned={row_count} total_rows={total_rows}"
            )
            intent_results.append(
                {
                    "intent": template.intent,
                    "ok": True,
                    "rows_returned": row_count,
                    "total_rows": total_rows,
                }
            )

            if row_count < 0:
                failures.append(f"Intent '{template.intent}' returned invalid results shape")
        except Exception as exc:
            failures.append(f"Intent '{template.intent}' failed: {exc}")
            intent_results.append(
                {
                    "intent": template.intent,
                    "ok": False,
                    "error": str(exc),
                }
            )

    report["intent_results"] = intent_results

    if failures:
        print("\nstatus=FAIL")
        report["status"] = "FAIL"
        for idx, failure in enumerate(failures, start=1):
            print(f"{idx}. {failure}")
        report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        snapshot_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"report={report_path}")
        print(f"snapshot={snapshot_path}")
        return 1

    print("\nstatus=PASS")
    report["status"] = "PASS"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    snapshot_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"report={report_path}")
    print(f"snapshot={snapshot_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
