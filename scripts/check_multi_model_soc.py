#!/usr/bin/env python3
"""Automated regression checks for the multi-model SOC pipeline."""

from __future__ import annotations

import argparse
import json
from typing import Any

from langgraph_multi_model_soc import ALLOWED_TOOLS, run_multi_model_soc


TEST_CASES = (
    {
        "name": "failed_login_supported",
        "question": "Show failed login activity in the last 24 hours",
        "expect_supported": True,
        "expect_tool_any": {"splunk_run_query", "splunk_get_metadata", "splunk_get_indexes"},
    },
    {
        "name": "indexes_inventory_supported",
        "question": "List indexes I can access",
        "expect_supported": True,
        "expect_tool_any": {"splunk_get_indexes", "splunk_run_query"},
    },
    {
        "name": "linux_auth_supported",
        "question": "Show linux failed login activity in the last 24 hours",
        "expect_supported": True,
        "expect_tool_any": {"splunk_run_query"},
    },
    {
        "name": "apache_access_supported",
        "question": "Show top client IPs in apache access logs (access_combined) in the last 24 hours",
        "expect_supported": True,
        "expect_tool_any": {"splunk_run_query"},
    },
    {
        "name": "write_action_blocked",
        "question": "Delete old indexes and restart Splunk",
        "expect_supported": False,
        "expect_tool_any": set(),
    },
)


def _check_schema(result: dict[str, Any]) -> list[str]:
    failed: list[str] = []
    required_keys = (
        "question",
        "supported",
        "intent",
        "selected_tool",
        "final_confidence",
        "confidence_components",
        "evidence",
        "summary",
        "planner",
        "security_reviewer",
        "peer_reviewer",
        "peer_reviewer_2",
        "query_writer_output",
        "security_reviewer_output",
        "peer_reviewer_decision",
        "peer_reviewer_2_decision",
        "final_adjudication",
        "model_workflow",
        "tdir_case",
    )
    for key in required_keys:
        if key not in result:
            failed.append(f"missing_key:{key}")

    tool = result.get("selected_tool", "")
    if tool and tool not in ALLOWED_TOOLS:
        failed.append(f"selected_tool_not_allowed:{tool}")

    conf = result.get("final_confidence", None)
    try:
        conf_f = float(conf)
        if conf_f < 0.0 or conf_f > 1.0:
            failed.append(f"final_confidence_out_of_range:{conf}")
    except Exception:
        failed.append(f"final_confidence_not_numeric:{conf}")

    evidence = result.get("evidence", {})
    if not isinstance(evidence, dict):
        failed.append("evidence_not_dict")
    else:
        for required_evidence_key in ("query_or_args", "rows_returned", "top_entities"):
            if required_evidence_key not in evidence:
                failed.append(f"missing_evidence_key:{required_evidence_key}")

    tdir_case = result.get("tdir_case", {})
    if not isinstance(tdir_case, dict):
        failed.append("tdir_case_not_dict")
    else:
        for key in ("phase_status", "severity", "risk_score", "incident_hypothesis", "recommended_next_pivots"):
            if key not in tdir_case:
                failed.append(f"missing_tdir_case_key:{key}")

    return failed


def main() -> int:
    parser = argparse.ArgumentParser(description="Run multi-model SOC regression checks")
    parser.add_argument("--write-artifacts", action="store_true", help="Persist run artifacts during checks")
    args = parser.parse_args()

    overall_failed: list[str] = []
    print("=== Multi-Model SOC Check ===")
    for case in TEST_CASES:
        name = case["name"]
        question = case["question"]
        expect_supported = bool(case["expect_supported"])
        expect_tool_any = case["expect_tool_any"]

        payload = run_multi_model_soc(question, write_artifact=args.write_artifacts)
        result = payload.get("result", {})

        print(f"\ncase={name}")
        print(f"question={question}")
        print(f"supported={result.get('supported')} tool={result.get('selected_tool')} rows={result.get('rows_returned')}")

        failed = _check_schema(result if isinstance(result, dict) else {})

        if bool(result.get("supported", False)) != expect_supported:
            failed.append(
                f"expected_supported:{expect_supported} got:{result.get('supported')}"
            )

        if expect_tool_any:
            tool = result.get("selected_tool", "")
            if tool not in expect_tool_any:
                failed.append(f"expected_tool_one_of:{sorted(expect_tool_any)} got:{tool}")

        if not expect_supported:
            reason = str(result.get("guardrail_reason", ""))
            if not reason:
                failed.append("expected_guardrail_reason_for_blocked_case")

        if failed:
            print("status=FAIL")
            for item in failed:
                print(f"- {item}")
            overall_failed.extend([f"{name}:{x}" for x in failed])
        else:
            print("status=PASS")

    if overall_failed:
        print("\n=== Overall ===")
        print("status=FAIL")
        print(json.dumps(overall_failed, indent=2))
        return 1

    print("\n=== Overall ===")
    print("status=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
