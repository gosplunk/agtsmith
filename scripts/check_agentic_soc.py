#!/usr/bin/env python3
"""Deterministic checks for agentic SOC planning heuristics."""

from __future__ import annotations

from langgraph_agentic_soc import (
    _build_loop_control,
    _fallback_continuation_review,
    _normalize_case_state,
    _pivot_signature,
    initial_action_from_question,
    propose_next_action,
)


def main() -> int:
    failed: list[str] = []
    print("=== Agentic SOC Planning Check ===")

    # Initial routing sanity
    tool, _args, _reason = initial_action_from_question("Show Splunk version details")
    if tool != "splunk_get_info":
        failed.append(f"expected initial splunk_get_info got {tool}")

    tool, _args, _reason = initial_action_from_question("Investigate top index with metadata drilldown")
    if tool != "splunk_get_indexes":
        failed.append(f"expected initial splunk_get_indexes got {tool}")

    # Pivot: indexes -> metadata
    done, reason, next_tool, next_args = propose_next_action(
        question="Investigate top index with metadata drilldown",
        step_index=1,
        max_steps=3,
        trajectory=[{"step": 1, "tool": "splunk_get_indexes"}],
        last_result={
            "selected_tool": "splunk_get_indexes",
            "structured": {"results": [{"title": "_audit"}], "total_rows": 1},
            "mapped_query": {},
        },
    )
    if done or next_tool != "splunk_get_metadata" or next_args.get("index") != "_audit":
        failed.append(
            "expected pivot to splunk_get_metadata index=_audit "
            f"got done={done} tool={next_tool} args={next_args} reason={reason}"
        )

    # Regression guard: failed-login intent must not drift to generic host->sourcetype query.
    done, reason, next_tool, next_args = propose_next_action(
        question="Show failed login activity in the last 24 hours",
        step_index=2,
        max_steps=4,
        trajectory=[
            {"step": 1, "tool": "splunk_run_query"},
            {"step": 2, "tool": "splunk_get_metadata"},
        ],
        last_result={
            "selected_tool": "splunk_get_metadata",
            "structured": {"results": [{"host": "JUPITER"}], "total_rows": 1},
            "mapped_query": {"type": "hosts", "index": "*"},
        },
    )
    query = str(next_args.get("query", ""))
    if done or next_tool != "splunk_run_query":
        failed.append(
            "expected failed-login metadata pivot to splunk_run_query "
            f"got done={done} tool={next_tool} reason={reason}"
        )
    if "stats count by sourcetype" in query.lower():
        failed.append(f"unexpected generic sourcetype distribution query for failed-login intent: {query}")
    if "failure" not in query.lower() and "failed_login" not in query.lower():
        failed.append(f"failed-login pivot query missing auth-failure semantics: {query}")

    # Max-step stop
    done, reason, next_tool, _next_args = propose_next_action(
        question="Anything",
        step_index=3,
        max_steps=3,
        trajectory=[],
        last_result={"selected_tool": "splunk_run_query", "structured": {"results": []}, "mapped_query": {}},
    )
    if not done or reason != "max_steps_reached" or next_tool:
        failed.append(f"expected max_steps_reached stop, got done={done} reason={reason} tool={next_tool}")

    continuation = _fallback_continuation_review(
        question="Show failed login activity in the last 24 hours",
        trajectory=[
            {"step": 1, "tool": "splunk_run_query"},
            {"step": 2, "tool": "splunk_get_metadata"},
            {"step": 3, "tool": "splunk_run_query"},
        ],
        last_result={
            "selected_tool": "splunk_run_query",
            "mapped_query": {"query": 'search index=_audit info=failed | stats count by user src | sort - count'},
            "structured": {
                "results": [{"user": "alice", "src": "10.0.0.5", "count": 42}],
                "total_rows": 1,
            },
        },
        evidence_review={"evidence_quality": "low"},
        max_steps=3,
    )
    if not continuation.get("should_continue", False):
        failed.append(f"expected continuation fallback to request another bounded pivot, got {continuation}")
    if not str(continuation.get("next_best_question", "")).strip():
        failed.append(f"expected continuation fallback to produce next_best_question, got {continuation}")

    case_state = _normalize_case_state({}, "Show failed login activity in the last 24 hours")
    loop = _build_loop_control(
        output={"continuation_reviewer_output": continuation},
        case_state=case_state,
        approved_deeper_investigation=False,
    )
    if not loop.get("auto_followup_allowed", False):
        failed.append(f"expected first continuation to allow one automatic deeper pass, got {loop}")

    sig = _pivot_signature(
        str(continuation.get("next_best_question", "")),
        str(continuation.get("next_best_spl_or_tool", "")),
    )
    duplicate_state = _normalize_case_state(
        {
            "root_question": "Show failed login activity in the last 24 hours",
            "pivot_signatures": [sig],
            "current_depth": 1,
        },
        "Show failed login activity in the last 24 hours",
    )
    duplicate_loop = _build_loop_control(
        output={"continuation_reviewer_output": continuation},
        case_state=duplicate_state,
        approved_deeper_investigation=False,
    )
    if duplicate_loop.get("auto_followup_allowed", False) or duplicate_loop.get("human_approval_required", False):
        failed.append(f"expected duplicate pivot to be blocked, got {duplicate_loop}")

    if failed:
        print("status=FAIL")
        for i, item in enumerate(failed, start=1):
            print(f"{i}. {item}")
        return 1

    print("status=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
