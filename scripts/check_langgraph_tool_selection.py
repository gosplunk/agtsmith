#!/usr/bin/env python3
"""Regression checks for LangGraph tool-selection helper."""

from __future__ import annotations

from langgraph_minimal_flow import determine_splunk_tool


def main() -> int:
    cases = [
        ("List indexes I can access", "top_indexes", "splunk_get_indexes", {}, ""),
        ("Show indexes available", "top_indexes", "splunk_get_indexes", {}, ""),
        ("Which indexes had the most events in 24h", "top_indexes", "splunk_run_query", {}, ""),
        ("Show failed login activity", "failed_login_activity", "splunk_run_query", {}, ""),
        ("List hosts metadata for the last day", "internal_sourcetypes", "splunk_get_metadata", {"type": "hosts"}, ""),
        ("Show Splunk version details", "internal_sourcetypes", "splunk_get_info", {}, ""),
        (
            "Investigate top index with metadata drilldown",
            "top_indexes",
            "splunk_get_indexes",
            {},
            "indexes_to_metadata_sourcetypes",
        ),
    ]

    print("=== LangGraph Tool Selection Check ===")
    failed: list[str] = []
    for question, intent, expected_tool, metadata_expect, expected_chain_mode in cases:
        tool, reason, metadata_args, chain_mode = determine_splunk_tool(question, intent)
        metadata_type = metadata_args.get("type") if isinstance(metadata_args, dict) else None
        expected_metadata_type = metadata_expect.get("type")
        if tool != expected_tool:
            failed.append(
                f"expected={expected_tool} got={tool} question={question!r} intent={intent!r} reason={reason}"
            )
            print(f"[FAIL] question={question!r} expected={expected_tool} got={tool} reason={reason}")
        elif expected_metadata_type is not None and metadata_type != expected_metadata_type:
            failed.append(
                "expected_metadata_type="
                f"{expected_metadata_type} got={metadata_type} question={question!r} intent={intent!r}"
            )
            print(
                f"[FAIL] question={question!r} tool={tool} expected_metadata_type="
                f"{expected_metadata_type} got={metadata_type} reason={reason}"
            )
        elif expected_chain_mode != chain_mode:
            failed.append(
                f"expected_chain_mode={expected_chain_mode!r} got={chain_mode!r} "
                f"question={question!r} intent={intent!r}"
            )
            print(
                f"[FAIL] question={question!r} tool={tool} "
                f"expected_chain_mode={expected_chain_mode!r} got={chain_mode!r} reason={reason}"
            )
        else:
            print(
                f"[PASS] question={question!r} tool={tool} reason={reason} "
                f"metadata_type={metadata_type} chain_mode={chain_mode!r}"
            )

    if failed:
        print("status=FAIL")
        for i, line in enumerate(failed, start=1):
            print(f"{i}. {line}")
        return 1

    print("status=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
