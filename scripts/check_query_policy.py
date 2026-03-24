#!/usr/bin/env python3
"""Regression checks for lab query policy validation behavior."""

from __future__ import annotations

import sys

from query_policy import validate_query_args


def run_case(name: str, query_args: dict, expected_ok: bool, expected_reason_prefix: str, question: str = "") -> str | None:
    ok, reason = validate_query_args(query_args, question=question)
    if ok != expected_ok:
        return f"{name}: expected ok={expected_ok}, got ok={ok} (reason={reason})"
    if not reason.startswith(expected_reason_prefix):
        return (
            f"{name}: expected reason prefix '{expected_reason_prefix}', "
            f"got '{reason}'"
        )
    return None


def main() -> int:
    cases = [
        (
            "pass_read_only_search",
            {
                "query": "search index=_internal | stats count by sourcetype | sort - count",
                "earliest_time": "-24h",
                "latest_time": "now",
                "row_limit": 10,
            },
            False,
            "internal_index_requires_explicit_question_context",
        ),
        (
            "pass_internal_when_explicit",
            {
                "query": "search index=_internal | stats count by sourcetype | sort - count",
                "earliest_time": "-24h",
                "latest_time": "now",
                "row_limit": 10,
            },
            True,
            "query_policy_ok",
            "Show internal Splunk sourcetypes in _internal",
        ),
        (
            "fail_non_search_prefix",
            {
                "query": "| tstats count where index=_internal by sourcetype",
                "earliest_time": "-24h",
                "latest_time": "now",
                "row_limit": 10,
            },
            False,
            "query_must_start_with_search",
        ),
        (
            "fail_forbidden_term_outputlookup",
            {
                "query": "search index=_internal | outputlookup dangerous.csv",
                "earliest_time": "-24h",
                "latest_time": "now",
                "row_limit": 10,
            },
            False,
            "forbidden_query_term:",
        ),
        (
            "fail_missing_time_bounds",
            {
                "query": "search index=_internal | head 10",
                "earliest_time": "",
                "latest_time": "now",
                "row_limit": 10,
            },
            False,
            "missing_time_bounds",
        ),
        (
            "fail_row_limit_over_max",
            {
                "query": "search index=_internal | head 1000",
                "earliest_time": "-24h",
                "latest_time": "now",
                "row_limit": 500,
            },
            False,
            "row_limit_exceeds_max:",
        ),
        (
            "fail_inline_transport_controls_in_query",
            {
                "query": (
                    "search index=linux sourcetype=auth.log sudo "
                    "earliest_time=-7d latest_time=now | stats count by host row_limit=200"
                ),
                "earliest_time": "-7d",
                "latest_time": "now",
                "row_limit": 50,
            },
            False,
            "query_contains_inline_control:",
        ),
    ]

    errors: list[str] = []
    print("=== Query Policy Regression Check ===")
    print(f"cases={len(cases)}")
    for case in cases:
        name, query_args, expected_ok, expected_reason_prefix, *rest = case
        question = str(rest[0]) if rest else ""
        maybe_error = run_case(name, query_args, expected_ok, expected_reason_prefix, question)
        if maybe_error:
            errors.append(maybe_error)
            print(f"[FAIL] {name}")
        else:
            print(f"[PASS] {name}")

    if errors:
        print("status=FAIL")
        for idx, err in enumerate(errors, start=1):
            print(f"{idx}. {err}")
        return 1

    print("status=PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
