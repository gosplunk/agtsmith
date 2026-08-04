#!/usr/bin/env python3
"""Post-execution diagnostics and evidence-gated extraction fallback retry."""

from __future__ import annotations

import os
import re
import time
from typing import Any

AUTH_DIAGNOSTIC_INTENTS = frozenset(
    {
        "failed_login_activity",
        "successful_login_activity",
        "linux_auth_failures",
        "windows_auth_failures",
    }
)


def _row_count(splunk_data: dict[str, Any]) -> int:
    if not isinstance(splunk_data, dict):
        return 0
    structured = splunk_data.get("structured", {})
    if isinstance(structured, dict):
        total = structured.get("total_rows")
        if isinstance(total, int):
            return total
        rows = structured.get("results", [])
        if isinstance(rows, list):
            return len(rows)
    return 0


def _extract_linux_branch(query: str) -> str:
    append_idx = query.lower().find("| append [")
    branch = query[:append_idx].strip() if append_idx > 0 else query.strip()
    if not branch.lower().startswith("search "):
        branch = f"search {branch}"
    return re.sub(r"\|\s*(stats|table|timechart)\b.*$", "", branch, flags=re.IGNORECASE).strip()


def _extract_windows_append(query: str) -> str:
    m = re.search(r"\|\s*append\s*\[\s*search\s+(.*?)\s*\]", query, flags=re.IGNORECASE | re.DOTALL)
    if not m:
        return ""
    inner = m.group(1).strip()
    if not inner.lower().startswith("search "):
        inner = f"search {inner}"
    return inner


def _base_search(query: str) -> str:
    """Return the event-producing search before transforming commands."""
    base = str(query or "").split("|", 1)[0].strip()
    if base and not base.lower().startswith("search "):
        base = f"search {base}"
    return base


def _safe_field_reference(field: str) -> str:
    value = str(field or "").strip()
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.:-]*", value):
        return ""
    return f"'{value}'" if any(char in value for char in ".:-") else value


def _required_native_predicate(field_strategy: dict[str, Any]) -> tuple[str, list[str]]:
    """Require at least one trusted native value for every resolved role."""
    roles = field_strategy.get("roles", {}) if isinstance(field_strategy.get("roles"), dict) else {}
    role_predicates: list[str] = []
    role_names: list[str] = []
    for role, data in roles.items():
        if not isinstance(data, dict):
            continue
        fields = [
            ref
            for ref in (_safe_field_reference(item) for item in data.get("trusted_fields", []))
            if ref
        ]
        if not fields:
            continue
        value_checks = [
            f"(isnotnull({field}) AND len(trim(tostring({field})))>0)"
            for field in fields
        ]
        role_predicates.append(f"({' OR '.join(value_checks)})")
        role_names.append(str(role))
    return " AND ".join(role_predicates), role_names


def _query_with_fallback_extractions(query: str, extractions: list[str]) -> str:
    """Insert trusted template extraction stages immediately after base search."""
    rendered = str(query or "").strip()
    base = _base_search(rendered)
    if not base:
        return rendered
    stages = [
        str(stage).strip().lstrip("|").strip()
        for stage in extractions
        if re.match(r"^(?:rex|spath)\b", str(stage).strip().lstrip("|").strip(), flags=re.IGNORECASE)
    ]
    existing = rendered.lower()
    missing = [stage for stage in stages if f"| {stage.lower()}" not in existing]
    if not missing:
        return rendered
    remainder = rendered[len(base) :].strip()
    prefix = " | ".join([base, *missing])
    return f"{prefix} {remainder}".strip() if remainder else prefix


def _run_diag_query(
    query: str,
    *,
    tool_args: dict[str, Any],
    label: str,
    query_budget: dict[str, Any] | None = None,
) -> dict[str, Any]:
    from minimal_question_to_answer import run_splunk_query_args
    from semantic_candidate_select import reserve_query

    args = {
        "query": query,
        "earliest_time": str(tool_args.get("earliest_time", "-7d")),
        "latest_time": str(tool_args.get("latest_time", "now")),
        "row_limit": min(int(tool_args.get("row_limit", 20) or 20), 50),
    }
    reserved, updated_budget = reserve_query(
        query_budget,
        purpose=f"post_execution:{label}",
    )
    if not reserved:
        return {
            "label": label,
            "query": query,
            "rows_returned": 0,
            "ok": False,
            "duration_ms": 0,
            "error": "global_query_budget_exhausted",
            "query_budget": updated_budget,
            "_splunk_data": {},
        }
    started = time.time()
    try:
        data = run_splunk_query_args(
            args,
            intent=f"post_exec_diag:{label}",
            summary_hint="diagnostic",
            timeout_seconds=15.0,
            max_attempts=1,
        )
        rows = _row_count(data)
        return {
            "label": label,
            "query": query,
            "rows_returned": rows,
            "ok": rows > 0,
            "duration_ms": int((time.time() - started) * 1000),
            "error": "",
            "query_budget": updated_budget,
            "_splunk_data": data,
        }
    except Exception as exc:
        return {
            "label": label,
            "query": query,
            "rows_returned": 0,
            "ok": False,
            "duration_ms": int((time.time() - started) * 1000),
            "error": f"{type(exc).__name__}:{exc}",
            "query_budget": updated_budget,
            "_splunk_data": {},
        }


def run_post_execution_diagnostics(
    *,
    question: str,
    plan: dict[str, Any],
    splunk_data: dict[str, Any],
    field_strategy: dict[str, Any] | None = None,
    coverage_report: dict[str, Any] | None = None,
    query_budget: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Classify evidence and retry extraction only under bounded semantic rules."""
    from semantic_candidate_select import new_query_budget, score_live_evidence

    budget = dict(query_budget) if isinstance(query_budget, dict) else new_query_budget()
    live_evidence = score_live_evidence(coverage_report, splunk_data)
    if os.getenv("AGTSMITH_POST_EXEC_DIAG", "1").strip().lower() in {"0", "false", "no"}:
        return {
            "skipped": True,
            "reason": "disabled",
            "live_evidence": live_evidence,
            "query_budget": budget,
        }

    tool = str(plan.get("selected_tool", "")).strip()
    if tool != "splunk_run_query":
        return {
            "skipped": True,
            "reason": "non_query_tool",
            "live_evidence": live_evidence,
            "query_budget": budget,
        }

    rows = _row_count(splunk_data)
    if rows > 0:
        return {
            "skipped": True,
            "reason": "rows_present",
            "rows_returned": rows,
            "live_evidence": live_evidence,
            "query_budget": budget,
        }

    intent = str(plan.get("intent", "")).strip()
    tool_args = plan.get("tool_args", {}) if isinstance(plan.get("tool_args"), dict) else {}
    query = str(tool_args.get("query", "")).strip()
    strategy = field_strategy if isinstance(field_strategy, dict) else {}
    diagnostics: list[dict[str, Any]] = []

    bounded_graph_budget = isinstance(query_budget, dict)
    if intent in AUTH_DIAGNOSTIC_INTENTS and query and not bounded_graph_budget:
        linux_q = _extract_linux_branch(query)
        if linux_q:
            diag = _run_diag_query(
                linux_q,
                tool_args=tool_args,
                label="linux_branch",
                query_budget=budget,
            )
            budget = diag.get("query_budget", budget)
            diag.pop("_splunk_data", None)
            diagnostics.append(diag)
        win_q = _extract_windows_append(query)
        if win_q:
            diag = _run_diag_query(
                win_q,
                tool_args=tool_args,
                label="windows_append",
                query_budget=budget,
            )
            budget = diag.get("query_budget", budget)
            diag.pop("_splunk_data", None)
            diagnostics.append(diag)

    base_query = _base_search(query)
    if not base_query:
        return {
            "skipped": True,
            "reason": "base_search_missing",
            "rows_returned": rows,
            "intent": intent,
            "diagnostics": diagnostics,
            "live_evidence": live_evidence,
            "query_budget": budget,
        }
    base_diag = _run_diag_query(
        f"{base_query} | head 1",
        tool_args=tool_args,
        label="base_events",
        query_budget=budget,
    )
    budget = base_diag.get("query_budget", budget)
    base_diag.pop("_splunk_data", None)
    diagnostics.append(base_diag)

    retry_applied = False
    retry_data: dict[str, Any] = {}
    retry_plan: dict[str, Any] = {}
    retry_reason = ""

    if os.getenv("AGTSMITH_POST_EXEC_RETRY", "1").strip().lower() not in {"0", "false", "no"}:
        if not base_diag.get("ok"):
            retry_reason = "base_events_empty"
            live_evidence = {
                **live_evidence,
                "status": "no_base_data",
                "score": 0.0,
                "accepted": False,
                "rejected": False,
                "reason": "base_search_returned_zero_rows",
            }
        elif strategy.get("raw_parse_required"):
            retry_reason = "raw_parse_already_required"
        else:
            predicate, required_roles = _required_native_predicate(strategy)
            fallback_extractions = [
                str(item)
                for item in strategy.get("fallback_extractions", [])
                if str(item).strip()
            ]
            if not predicate:
                retry_reason = "trusted_native_fields_unavailable"
            elif not fallback_extractions:
                retry_reason = "extraction_fallback_unavailable"
            else:
                if bounded_graph_budget:
                    native_diag = {
                        "label": "required_native_fields",
                        "ok": False,
                        "skipped": True,
                        "reason": "reserved_budget_for_extraction_retry",
                        "required_roles": required_roles,
                    }
                else:
                    native_probe = f"{base_query} | where {predicate} | head 1"
                    native_diag = _run_diag_query(
                        native_probe,
                        tool_args=tool_args,
                        label="required_native_fields",
                        query_budget=budget,
                    )
                    budget = native_diag.get("query_budget", budget)
                    native_diag["required_roles"] = required_roles
                    native_diag.pop("_splunk_data", None)
                    diagnostics.append(native_diag)
                if native_diag.get("ok"):
                    retry_reason = "required_native_fields_populated"
                else:
                    fallback_query = _query_with_fallback_extractions(query, fallback_extractions)
                    if not fallback_query or fallback_query == query:
                        retry_reason = "fallback_already_present"
                    else:
                        fallback_args = dict(tool_args)
                        fallback_args["query"] = fallback_query
                        diag = _run_diag_query(
                            fallback_query,
                            tool_args=fallback_args,
                            label="extraction_fallback_probe",
                            query_budget=budget,
                        )
                        budget = diag.get("query_budget", budget)
                        if diag.get("ok"):
                            retry_plan = {
                                "selected_tool": "splunk_run_query",
                                "intent": intent,
                                "tool_args": fallback_args,
                                "confidence": 0.72,
                                "reason": "post_exec_extraction_retry",
                                "source": "post_execution_retry",
                            }
                            retry_data = (
                                diag.get("_splunk_data", {})
                                if isinstance(diag.get("_splunk_data"), dict)
                                else {}
                            )
                            retry_applied = _row_count(retry_data) > 0
                            retry_reason = "extraction_fallback_succeeded" if retry_applied else "extraction_fallback_empty"
                        else:
                            retry_reason = "extraction_fallback_empty"
                        diag.pop("_splunk_data", None)
                        diagnostics.append(diag)
    else:
        retry_reason = "retry_disabled"

    if retry_applied:
        live_evidence = score_live_evidence(coverage_report, retry_data)
    elif live_evidence.get("status") == "zero_result_unclassified" and base_diag.get("ok"):
        live_evidence = {
            **live_evidence,
            "status": "valid_zero_result",
            "score": 0.5,
            "accepted": True,
            "rejected": False,
            "reason": retry_reason or "base_data_exists_but_analysis_returned_zero_rows",
        }

    return {
        "skipped": False,
        "rows_returned": rows,
        "intent": intent,
        "diagnostics": diagnostics,
        "retry_applied": retry_applied,
        "retry_reason": retry_reason,
        "retry_plan": retry_plan if retry_applied else {},
        "retry_rows_returned": _row_count(retry_data) if retry_applied else 0,
        "retry_splunk_data": retry_data if retry_applied else {},
        "live_evidence": live_evidence,
        "query_budget": budget,
    }
