#!/usr/bin/env python3
"""Two-model LangGraph SOC pipeline (lab).

Workflow:
1) Planner model interprets analyst intent and produces a structured search plan.
2) Writer model turns that plan into read-only Splunk SPL or a bounded MCP tool call.
3) Security reviewer critiques the generated SPL against the plan.
4) Peer reviewer 1 adjudicates writer vs reviewer candidate.
5) Peer reviewer 2 validates or overrides peer reviewer 1 decision.
6) Deterministic policy / environment validation runs before Splunk execution.
7) Deterministic tool execution runs the approved read-only plan.
8) Evidence review and final summary turn execution results into analyst-facing output.

This is lab-only and intentionally fail-closed on unsafe plans.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from collections.abc import Callable
from typing import Any, TypedDict

from investigation_progress import (
    MULTI_MODEL_NODE_PROGRESS,
    POST_GRAPH_PROGRESS_NODES,
    classify_review_profile,
    journey_node_for_graph_node,
    progress_for_multi_model_node,
    progress_for_stage_log,
    requires_security_review,
    skipped_nodes_for_profile,
    SECURITY_REVIEW_SKIP_INTENTS,
)

import httpx
from langgraph.graph import END, START, StateGraph

from langgraph_minimal_flow import determine_splunk_tool
from minimal_question_to_answer import (
    OLLAMA_HOST,
    OLLAMA_MODEL,
    OLLAMA_REASONING_MODEL,
    map_question_to_template,
    run_splunk_get_info,
    run_splunk_get_indexes,
    run_splunk_get_metadata,
    run_splunk_query_args,
    summarize_with_ollama_model,
    template_to_query_args,
)
from botsv3_catalog import extract_explicit_botsv3_sourcetype
from question_intelligence import (
    apply_question_time_window,
    build_question_profile_text,
    describe_supported_time_windows,
    domain_oracle_threshold_for_question,
    extract_explicit_sourcetype,
    infer_analytical_shape_hints,
    query_conflicts_with_explicit_sourcetype,
    question_has_index_token,
    question_requests_all_time,
    question_requests_privilege_first_seen,
    APACHE_WEB_INTENTS,
)
from query_templates import TEMPLATES, QueryTemplate
from query_policy import validate_query_args
from spl_rag_context import build_resolved_domain_hints, build_spl_rag_context
from windows_event_code_catalog import build_event_code_reviewer_context
from spl_query_repair import attempt_query_repair_once
from tdir_core import build_tdir_case
from environment_profile import (
    apply_environment_query_constraints,
    load_environment_profile,
    normalize_query_index_aliases,
    profile_inventory_structured_results,
    validate_query_against_environment,
)
from intent_field_contracts import validate_query_for_intent, validate_platform_sourcetype_coherence, validate_intent_platform_scope
from local_learning import ranked_approved_learning_records
from saved_query_library import retrieve_saved_query_shortcut
from runtime_config import (
    DEFAULT_MODEL_ANALYST_REVIEWER,
    DEFAULT_MODEL_EVIDENCE_REVIEWER,
    DEFAULT_MODEL_FINAL_SUMMARY,
    DEFAULT_MODEL_PEER_REVIEWER,
    DEFAULT_MODEL_PEER_REVIEWER_2,
    DEFAULT_MODEL_QUERY_PLANNER,
    DEFAULT_MODEL_QUERY_PLANNER_FALLBACK,
    DEFAULT_MODEL_QUERY_REPAIR,
    DEFAULT_MODEL_QUERY_WRITER,
    DEFAULT_MODEL_SECURITY_REVIEWER,
    get_model_assignment,
)
from ollama_client import call_ollama_json, extract_json_object

# Per-role model selection (env or saved runtime config driven for easy lab switching)
MODEL_QUERY_PLANNER = get_model_assignment(
    "OLLAMA_MODEL_QUERY_PLANNER",
    os.getenv("OLLAMA_MODEL_PLANNER", os.getenv("OLLAMA_MODEL_PRIMARY", DEFAULT_MODEL_QUERY_PLANNER)),
)
MODEL_QUERY_WRITER = get_model_assignment("OLLAMA_MODEL_QUERY_WRITER", DEFAULT_MODEL_QUERY_WRITER)
MODEL_SECURITY_REVIEWER = get_model_assignment("OLLAMA_MODEL_SECURITY_REVIEWER", DEFAULT_MODEL_SECURITY_REVIEWER)
# Operational SPL validation + evidence review (defaults to QUERY_PLANNER / ministral stack).
MODEL_ANALYST_REVIEWER = get_model_assignment(
    "OLLAMA_MODEL_ANALYST_REVIEWER",
    os.getenv("OLLAMA_MODEL_QUERY_PLANNER", DEFAULT_MODEL_ANALYST_REVIEWER),
)
MODEL_EVIDENCE_REVIEWER = get_model_assignment("OLLAMA_MODEL_EVIDENCE_REVIEWER", DEFAULT_MODEL_EVIDENCE_REVIEWER)
MODEL_PEER_REVIEWER = get_model_assignment("OLLAMA_MODEL_PEER_REVIEWER", DEFAULT_MODEL_PEER_REVIEWER)
MODEL_PEER_REVIEWER_2 = get_model_assignment("OLLAMA_MODEL_PEER_REVIEWER_2", DEFAULT_MODEL_PEER_REVIEWER_2)
MODEL_FINAL_SUMMARY = get_model_assignment("OLLAMA_MODEL_FINAL_SUMMARY", DEFAULT_MODEL_FINAL_SUMMARY)
MODEL_QUERY_REPAIR = get_model_assignment("OLLAMA_MODEL_QUERY_REPAIR", DEFAULT_MODEL_QUERY_REPAIR)
MODEL_QUERY_PLANNER_FALLBACK = get_model_assignment(
    "OLLAMA_MODEL_QUERY_PLANNER_FALLBACK",
    DEFAULT_MODEL_QUERY_PLANNER_FALLBACK,
)
RAG_ENABLED = str(os.getenv("OLLAMA_RAG_ENABLED", "1")).strip().lower() not in {"0", "false", "no", "off"}
RAG_MAX_CHARS = int(os.getenv("OLLAMA_RAG_MAX_CHARS", "1600"))

BLOCKED_TERMS = ("delete", "drop", "remove", "shutdown", "restart", "write", "modify")
ALLOWED_TOOLS = {"splunk_run_query", "splunk_get_indexes", "splunk_get_metadata", "splunk_get_info"}


def _display_spl_for_plan(plan: dict[str, Any]) -> str:
    """Human-readable SPL/tool representation for UI and artifacts."""
    tool = str(plan.get("selected_tool", "")).strip()
    args = plan.get("tool_args", {}) if isinstance(plan.get("tool_args", {}), dict) else {}
    query = str(args.get("query", "")).strip()
    if query:
        return query
    if tool == "splunk_get_indexes":
        return (
            "| rest splunk_server=local /services/data/indexes "
            "| table title disabled currentDBSizeMB totalEventCount splunk_server"
        )
    if tool == "splunk_get_info":
        return "| rest splunk_server=local /services/server/info | table version build"
    if tool == "splunk_get_metadata":
        meta_type = str(args.get("type", "hosts")).strip() or "hosts"
        index = str(args.get("index", "*")).strip() or "*"
        earliest = str(args.get("earliest_time", "-7d")).strip() or "-7d"
        latest = str(args.get("latest_time", "now")).strip() or "now"
        return f"| metadata type={meta_type} index={index} earliest={earliest} latest={latest}"
    return ""


FORCE_QUERY_INTENTS = {
    "windows_auth_failures",
    "windows_successful_logons",
    "windows_process_activity",
    "windows_sysmon_network_activity",
    "windows_sysmon_dns_activity",
    "windows_credential_access_activity",
    "windows_process_audit_activity",
    "windows_privilege_assigned_activity",
    "linux_auth_failures",
    "linux_successful_logins",
    "successful_login_activity",
    "linux_session_activity",
    "linux_privilege_escalation",
    "linux_privilege_escalation_activity",
    "linux_audit_activity",
}

LINUX_STYLE_INTENTS = {
    "failed_login_activity",
    "successful_login_activity",
    "linux_auth_failures",
    "linux_successful_logins",
    "linux_session_activity",
    "linux_privilege_escalation",
    "linux_privilege_escalation_activity",
    "linux_privilege_escalation_first_seen",
    "linux_audit_activity",
}
WINDOWS_STYLE_INTENTS = {
    "windows_auth_failures",
    "windows_successful_logons",
    "windows_process_activity",
    "windows_sysmon_network_activity",
    "windows_sysmon_dns_activity",
    "windows_credential_access_activity",
    "windows_process_audit_activity",
    "windows_privilege_assigned_activity",
}
WEB_STYLE_INTENTS = {"apache_access_top_ips", "apache_404_spike"}
AUTH_FAMILY_INTENTS = {
    "failed_login_activity",
    "successful_login_activity",
    "linux_auth_failures",
    "windows_auth_failures",
    "linux_successful_logins",
    "windows_successful_logons",
}

DETERMINISTIC_RUN_QUERY_INTENTS = {
    "failed_login_activity",
    "successful_login_activity",
    "linux_auth_failures",
    "linux_successful_logins",
    "windows_successful_logons",
    "windows_auth_failures",
    "windows_process_activity",
    "osquery_process_activity",
    "windows_sysmon_network_activity",
    "windows_sysmon_dns_activity",
    "windows_credential_access_activity",
    "windows_process_audit_activity",
    "windows_privilege_assigned_activity",
    "linux_privilege_escalation",
    "linux_privilege_escalation_activity",
    "linux_privilege_escalation_first_seen",
    "linux_session_activity",
    "linux_audit_activity",
    "apache_access_top_ips",
    "apache_404_spike",
    "apache_suspicious_user_agents",
    "stream_http_activity",
    "botsv3_named_sourcetype_overview",
    "top_indexes",
    "metadata_inventory",
    "index_sourcetype_volume",
    "host_activity_summary",
    "index_staleness",
    "internal_auth_failures",
    "internal_sourcetypes",
    "splunk_internal_health",
    "splunk_license_usage",
    "forwarder_connectivity",
    "web_traffic_summary",
    "network_flow_summary",
    "app_error_spike",
    "aws_vpc_flow_activity",
    "aad_signin_activity",
    "stream_dns_activity",
    "o365_management_activity",
}


def _template_override_mode() -> str:
    mode = str(os.getenv("AGTSMITH_TEMPLATE_OVERRIDE", "fallback")).strip().lower()
    if mode in {"always", "fallback", "never"}:
        return mode
    return "fallback"


def _canonical_query_for_intent(intent: str) -> str:
    for template in TEMPLATES:
        if template.intent == intent:
            return template.query
    raise KeyError(f"missing_query_template:{intent}")


def _build_template_aligned_plan(question: str, mapped_template: QueryTemplate) -> dict[str, Any]:
    return {
        "selected_tool": "splunk_run_query",
        "tool_args": template_to_query_args(mapped_template, question),
        "intent": mapped_template.intent,
        "reason": f"question_alignment_override:template:{mapped_template.intent}",
    }


def _merge_fields_preserving_order(existing: list[str], additions: list[str]) -> list[str]:
    out: list[str] = []
    for item in [*existing, *additions]:
        text = str(item).strip()
        if text and text not in out:
            out.append(text)
    return out


def _parse_pipe_fields(query: str, command: str) -> tuple[list[str], re.Match[str] | None]:
    match = re.search(rf"\|\s*{command}\s+(.+?)(?:\s*\|\s*|$)", str(query or ""), flags=re.IGNORECASE)
    if not match:
        return [], None
    segment = match.group(1).strip()
    if command.lower() == "table":
        return [tok for tok in re.split(r"\s+", segment) if tok], match
    by_match = re.search(r"\bby\s+(.+)$", segment, flags=re.IGNORECASE)
    if not by_match:
        return [], match
    return [tok.strip().strip(",") for tok in by_match.group(1).split() if tok.strip().strip(",")], match


def _inject_sources_into_query(query: str, sources: list[str]) -> str:
    clean_sources = [str(item).strip() for item in sources if str(item).strip()]
    if not clean_sources or re.search(r"\bsource=", str(query or ""), flags=re.IGNORECASE):
        return query
    source_clause = "(" + " OR ".join(f"source={json.dumps(item)}" for item in clean_sources) + ")"
    return re.sub(r"^search\s+([^\|]+?)\b", lambda m: f"search {m.group(1).strip()} {source_clause} ", str(query or ""), count=1, flags=re.IGNORECASE).strip()


def _writer_saved_query_suggestion_patch(shortcut: dict[str, Any]) -> dict[str, Any]:
    if str(shortcut.get("mode", "")).strip().lower() != "suggest":
        return {}
    record = shortcut.get("record") if isinstance(shortcut.get("record"), dict) else {}
    supporting_question = str(record.get("supporting_question", "")).strip()
    return {
        "saved_query_suggestion": {
            "record_id": str(shortcut.get("record_id", "")).strip(),
            "score": float(shortcut.get("score", 0.0) or 0.0),
            "query": str(shortcut.get("query", "")).strip(),
            "supporting_question": supporting_question,
            "intent": str(shortcut.get("intent", "")).strip(),
            "reason": str(shortcut.get("reason", "")).strip(),
        }
    }


def _writer_output_from_saved_query_shortcut(
    state: MultiModelState,
    question: str,
    shortcut: dict[str, Any],
    *,
    planner_intent: str,
    started: float,
) -> dict[str, Any] | None:
    query = str(shortcut.get("query", "")).strip()
    if str(shortcut.get("mode", "")).strip().lower() != "auto" or not query:
        return None
    planner_output = state.get("planner_output", {}) or {}
    planner_args = planner_output.get("tool_args", {}) if isinstance(planner_output.get("tool_args"), dict) else {}
    from minimal_question_to_answer import infer_time_window
    from question_intelligence import apply_question_time_window

    inferred_e, inferred_l = infer_time_window(question)
    tool_args = {
        "query": query,
        "earliest_time": str(planner_args.get("earliest_time") or inferred_e or "-7d"),
        "latest_time": str(planner_args.get("latest_time") or inferred_l or "now"),
        "row_limit": int(planner_args.get("row_limit", 50) or 50),
    }
    apply_question_time_window(question, tool_args)
    intent = str(shortcut.get("intent", "")).strip() or planner_intent or "investigation_saved"
    writer_output = _normalize_candidate(
        {
            "selected_tool": "splunk_run_query",
            "tool_args": tool_args,
            "intent": intent,
            "confidence": min(0.95, max(0.75, float(shortcut.get("score", 0.92) or 0.92))),
            "reason": f"saved_query_library:{shortcut.get('reason', 'match')}",
            "source": "saved_query_library",
        },
        question,
        fallback_reason="saved_query_library_shortcut",
    )
    routing = _writer_post_routing(state, writer_output)
    duration_ms = int((time.monotonic() - started) * 1000)
    return {
        "planner_output": planner_output,
        "writer_output": writer_output,
        **routing,
        "writer_duration_ms": duration_ms,
        "stage_logs": _append_stage_log(
            state,
            stage="writer",
            title="Writer reused saved query library match",
            details=[
                f"record_id={shortcut.get('record_id', '')}",
                f"score={shortcut.get('score', 0.0)}",
                f"query={query[:220]}",
            ],
            model="saved_query_library",
            duration_ms=duration_ms,
        ),
    }


def _apply_learning_assets(question: str, plan: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(plan, dict) or str(plan.get("selected_tool", "")).strip() != "splunk_run_query":
        return plan
    intent = str(plan.get("intent", "")).strip()
    if not intent:
        return plan
    args = plan.get("tool_args", {}) if isinstance(plan.get("tool_args", {}), dict) else {}
    query = str(args.get("query", "")).strip()
    if not query:
        return plan
    updated = dict(plan)
    updated_args = dict(args)
    learned_reasons: list[str] = []
    for row in ranked_approved_learning_records(question, intent, max_records=4):
        kind = str(row.get("kind", "")).strip()
        proposal = row.get("proposal", {}) if isinstance(row.get("proposal", {}), dict) else {}
        if kind == "preferred_sources":
            preferred_sources = proposal.get("preferred_sources", [])
            if isinstance(preferred_sources, list):
                new_query = _inject_sources_into_query(query, [str(item) for item in preferred_sources])
                if new_query != query:
                    query = new_query
                    learned_reasons.append("learning:preferred_sources")
        elif kind == "preferred_fields":
            preferred_fields = [str(item).strip() for item in proposal.get("preferred_fields", []) if str(item).strip()]
            if preferred_fields:
                fields, match = _parse_pipe_fields(query, "table")
                if match:
                    merged = _merge_fields_preserving_order(fields, preferred_fields)
                    query = query[:match.start()] + f"| table {' '.join(merged)}" + query[match.end():]
                    learned_reasons.append("learning:preferred_fields_table")
                else:
                    fields, match = _parse_pipe_fields(query, "stats")
                    if match and fields:
                        merged = _merge_fields_preserving_order(fields, preferred_fields)
                        replacement = re.sub(r"\bby\s+(.+)$", f"by {' '.join(merged)}", match.group(0), flags=re.IGNORECASE)
                        query = query[:match.start()] + replacement + query[match.end():]
                        learned_reasons.append("learning:preferred_fields_stats")
        elif kind == "spl_pattern_asset":
            if intent in AUTH_FAMILY_INTENTS:
                continue
            required_sources = [str(item).strip() for item in proposal.get("required_sources", []) if str(item).strip()]
            required_sourcetypes = [str(item).strip() for item in proposal.get("required_sourcetypes", []) if str(item).strip()]
            template = str(proposal.get("query_template", "")).strip()
            if template and template.lower().startswith("search "):
                if not query or (required_sources and not any(f"source={json.dumps(src)}" in query for src in required_sources)) or (
                    required_sourcetypes and not any(f"sourcetype={st}" in query for st in required_sourcetypes)
                ):
                    query = template
                    learned_reasons.append("learning:spl_pattern_asset")
    if learned_reasons:
        updated_args["query"] = query
        updated["tool_args"] = updated_args
        prior_reason = str(updated.get("reason", "")).strip()
        updated["reason"] = "; ".join([part for part in [prior_reason, *learned_reasons] if part])
    return updated


def _apply_environment_constraints_to_query(
    question: str,
    intent: str,
    query: str,
    *,
    args: dict[str, Any] | None = None,
) -> str:
    if isinstance(args, dict) and args.get("_env_constraints_applied"):
        return query
    return apply_environment_query_constraints(question, intent, query)


def _env_flag(name: str, default: bool) -> bool:
    raw = str(os.getenv(name, "1" if default else "0")).strip().lower()
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    return default


def _topology_settings() -> dict[str, bool]:
    return {
        "security_review": _env_flag("LANGGRAPH_ENABLE_SECURITY_REVIEW", True),
        "peer_review": _env_flag("LANGGRAPH_ENABLE_PEER_REVIEW", True),
        "evidence_review": _env_flag("LANGGRAPH_ENABLE_EVIDENCE_REVIEW", True),
        "final_summary": _env_flag("LANGGRAPH_ENABLE_FINAL_SUMMARY", True),
        "query_repair": _env_flag("LANGGRAPH_ENABLE_QUERY_REPAIR", True),
    }


class MultiModelState(TypedDict, total=False):
    question: str
    session_id: str
    review_profile: str
    supported: bool
    guardrail_reason: str
    planner_output: dict
    field_bind_output: dict
    field_discovery_output: dict
    field_strategy_output: dict
    field_policy_output: dict
    semantic_coverage_output: dict
    semantic_candidate_output: dict
    query_budget_output: dict
    confidence_cap: float
    domain_knowledge_output: dict
    writer_output: dict
    reviewer_output: dict
    judge_output: dict
    judge2_output: dict
    final_plan: dict
    validation_ok: bool
    validation_reason: str
    splunk_data: dict
    evidence_review_output: dict
    summary: str
    output: dict
    guardrail_duration_ms: int
    planner_duration_ms: int
    field_bind_duration_ms: int
    field_discovery_duration_ms: int
    field_strategy_duration_ms: int
    field_policy_duration_ms: int
    semantic_gate_duration_ms: int
    semantic_candidate_duration_ms: int
    domain_knowledge_duration_ms: int
    security_review_duration_ms: int
    peer_review_duration_ms: int
    peer_review_2_duration_ms: int
    validation_duration_ms: int
    run_tool_duration_ms: int
    post_execution_output: dict
    post_execution_duration_ms: int
    evidence_review_duration_ms: int
    summarize_duration_ms: int
    query_repair: dict[str, Any]
    stage_logs: list[dict[str, Any]]
    writer_duration_ms: int
    spl_validate_duration_ms: int
    skipped_nodes: list[str]
    force_saved_query_id: str
    saved_query_suggestion: dict[str, Any]


def _review_profile_for_state(state: MultiModelState, *, planner_intent: str = "") -> str:
    question = str(state.get("question", "")).strip()
    existing = str(state.get("review_profile", "")).strip()
    mapped_template = map_question_to_template(question)
    profile = classify_review_profile(
        question,
        template_intent=mapped_template.intent,
        planner_intent=planner_intent or str((state.get("planner_output", {}) or {}).get("intent", "")).strip(),
    )
    return profile or existing or "operational"


def _metadata_profile_for_state(state: MultiModelState, *, plan: dict[str, Any] | None = None) -> bool:
    return _review_profile_for_state(state) == "metadata"


def _inventory_skip_for_state(state: MultiModelState, *, plan: dict[str, Any] | None = None) -> bool:
    """Back-compat helper: metadata profile skips Foundation-Sec review stages."""
    return _metadata_profile_for_state(state, plan=plan)


def _merge_skipped_nodes(state: MultiModelState, *nodes: str) -> list[str]:
    merged = [str(item).strip() for item in (state.get("skipped_nodes") or []) if str(item).strip()]
    for node in nodes:
        key = str(node or "").strip()
        if key and key not in merged:
            merged.append(key)
    return merged


def _float01(value: Any, default: float = 0.5) -> float:
    try:
        f = float(value)
    except Exception:
        return default
    return max(0.0, min(1.0, round(f, 3)))


def _planner_model_candidates() -> list[str]:
    ordered = [MODEL_QUERY_PLANNER]
    for tag in str(MODEL_QUERY_PLANNER_FALLBACK or "").split(","):
        tag = tag.strip()
        if tag:
            ordered.append(tag)
    seen: set[str] = set()
    out: list[str] = []
    for tag in ordered:
        if tag not in seen:
            seen.add(tag)
            out.append(tag)
    return out


def _call_ollama_json(
    *,
    model: str,
    system_prompt: str,
    user_payload: dict[str, Any],
    timeout: float | None = None,
) -> dict[str, Any]:
    return call_ollama_json(model=model, system_prompt=system_prompt, user_payload=user_payload, timeout=timeout)


def _extract_json_object(text: str) -> dict[str, Any]:
    return extract_json_object(text)


def _default_plan_from_template(question: str) -> dict[str, Any]:
    selected_tool, tool_reason, metadata_args, _chain_mode = determine_splunk_tool(question, "")
    if selected_tool == "splunk_get_indexes":
        return {
            "selected_tool": "splunk_get_indexes",
            "tool_args": {},
            "intent": "top_indexes",
            "confidence": 0.75,
            "reason": f"deterministic_fallback:{tool_reason}",
            "source": "fallback",
        }
    if selected_tool == "splunk_get_info":
        return {
            "selected_tool": "splunk_get_info",
            "tool_args": {},
            "intent": "splunk_info",
            "confidence": 0.75,
            "reason": f"deterministic_fallback:{tool_reason}",
            "source": "fallback",
        }
    if selected_tool == "splunk_get_metadata":
        return {
            "selected_tool": "splunk_get_metadata",
            "tool_args": metadata_args,
            "intent": "metadata_inventory",
            "confidence": 0.75,
            "reason": f"deterministic_fallback:{tool_reason}",
            "source": "fallback",
        }

    template = map_question_to_template(question)
    args = template_to_query_args(template, question)
    if isinstance(args, dict) and str(args.get("query", "")).strip():
        args = dict(args)
        args["_env_constraints_applied"] = True
    return {
        "selected_tool": "splunk_run_query",
        "tool_args": args,
        "intent": template.intent,
        "confidence": 0.7,
        "reason": "deterministic_template_fallback",
        "source": "fallback",
    }


def _append_stage_log(state: MultiModelState, *, stage: str, title: str, details: list[str], model: str = "", duration_ms: int = 0) -> list[dict[str, Any]]:
    logs = list(state.get("stage_logs", []) or [])
    logs.append(
        {
            "stage": stage,
            "title": title,
            "details": [str(item) for item in details if str(item).strip()],
            "model": model,
            "duration_ms": int(duration_ms or 0),
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }
    )
    return logs


def _plans_equivalent(left: dict[str, Any], right: dict[str, Any]) -> bool:
    if not isinstance(left, dict) or not isinstance(right, dict):
        return False
    if str(left.get("selected_tool", "")).strip() != str(right.get("selected_tool", "")).strip():
        return False
    left_args = left.get("tool_args", {}) if isinstance(left.get("tool_args", {}), dict) else {}
    right_args = right.get("tool_args", {}) if isinstance(right.get("tool_args", {}), dict) else {}
    keys = {"query", "earliest_time", "latest_time", "row_limit", "type"}
    for key in keys:
        if str(left_args.get(key, "")).strip() != str(right_args.get(key, "")).strip():
            return False
    return True


def _normalize_planner_plan(candidate: dict[str, Any], question: str, *, fallback_reason: str) -> dict[str, Any]:
    mapped_template = map_question_to_template(question)
    if not isinstance(candidate, dict):
        fallback = _default_plan_from_template(question)
        return {
            "selected_tool": fallback.get("selected_tool", "splunk_run_query"),
            "intent": mapped_template.intent,
            "intent_summary": question.strip() or "read-only investigation",
            "search_strategy_summary": "Use the deterministic template fallback for this question.",
            "likely_indexes": [],
            "likely_sourcetypes": [],
            "likely_fields": [],
            "constraints": ["read_only_only", "row_limit<=200"],
            "tool_args": fallback.get("tool_args", {}),
            "confidence": float(fallback.get("confidence", 0.5)),
            "reason": fallback_reason,
            "caveats": [],
            "source": "planner_fallback",
        }

    tool = str(candidate.get("selected_tool", "splunk_run_query")).strip() or "splunk_run_query"
    if tool not in ALLOWED_TOOLS:
        tool = "splunk_run_query"
    raw_intent = str(candidate.get("intent", "unknown")).strip() or "unknown"
    known_intents = {tpl.intent for tpl in TEMPLATES}
    if raw_intent not in known_intents:
        raw_intent = mapped_template.intent
    if mapped_template.intent in SECURITY_REVIEW_SKIP_INTENTS:
        raw_intent = mapped_template.intent
    q_lower = question.lower()
    if mapped_template.intent == "botsv3_named_sourcetype_overview" or (
        "botsv3" in q_lower and "overview of sourcetype" in q_lower
    ):
        tool = "splunk_run_query"
        raw_intent = "botsv3_named_sourcetype_overview"
    if raw_intent in FORCE_QUERY_INTENTS and mapped_template.intent == raw_intent:
        tool = "splunk_run_query"
    out = {
        "selected_tool": tool,
        "intent": raw_intent,
        "intent_summary": str(candidate.get("intent_summary", candidate.get("reason", question))).strip() or question.strip(),
        "search_strategy_summary": str(candidate.get("search_strategy_summary", candidate.get("strategy", ""))).strip(),
        "likely_indexes": candidate.get("likely_indexes", []),
        "likely_sourcetypes": candidate.get("likely_sourcetypes", []),
        "likely_fields": candidate.get("likely_fields", []),
        "constraints": candidate.get("constraints", []),
        "tool_args": candidate.get("tool_args", {}) if isinstance(candidate.get("tool_args", {}), dict) else {},
        "confidence": _float01(candidate.get("confidence", 0.5), default=0.5),
        "reason": str(candidate.get("reason", "")).strip() or fallback_reason,
        "caveats": candidate.get("caveats", []),
        "source": str(candidate.get("source", "planner_model")).strip() or "planner_model",
    }
    for key in ("likely_indexes", "likely_sourcetypes", "likely_fields", "constraints", "caveats"):
        value = out.get(key, [])
        if not isinstance(value, list):
            value = [str(value)]
        out[key] = [str(item).strip() for item in value if str(item).strip()]
    if not out["search_strategy_summary"]:
        out["search_strategy_summary"] = "Build a read-only bounded query using the likely indexes, sourcetypes, and fields."
    if tool == "splunk_run_query":
        canonical_args = template_to_query_args(mapped_template, question)
        out["tool_args"].setdefault("earliest_time", str(canonical_args.get("earliest_time", mapped_template.earliest_time)))
        out["tool_args"].setdefault("latest_time", str(canonical_args.get("latest_time", mapped_template.latest_time)))
        out["tool_args"].setdefault("row_limit", mapped_template.row_limit)
        apply_question_time_window(question, out["tool_args"], default_earliest=mapped_template.earliest_time, default_latest=mapped_template.latest_time)
        canonical_query = template_to_query_args(mapped_template, question).get("query", "")
        out["canonical_template_query"] = _apply_environment_constraints_to_query(question, raw_intent, canonical_query)
    else:
        out["canonical_template_query"] = ""
    if "analytical_plan" in candidate:
        raw_analytical_plan = candidate.get("analytical_plan")
        out["analytical_plan"] = (
            dict(raw_analytical_plan)
            if isinstance(raw_analytical_plan, dict)
            else raw_analytical_plan
        )
    if tool in {"splunk_get_indexes", "splunk_get_info"}:
        out["tool_args"] = {}
    return out


def _normalize_candidate(candidate: dict[str, Any], question: str, *, fallback_reason: str) -> dict[str, Any]:
    if not isinstance(candidate, dict):
        out = _default_plan_from_template(question)
        out["reason"] = fallback_reason
        return out

    tool = str(candidate.get("selected_tool", "")).strip()
    args = candidate.get("tool_args", {})
    if not isinstance(args, dict):
        args = {}
    intent = str(candidate.get("intent", "unknown")).strip() or "unknown"
    intent_aliases = {
        "linux_audit_activity_summary": "linux_audit_activity",
        "investigate_linux_audit_activity": "linux_audit_activity",
        "windows_process_activity_summary": "windows_process_activity",
        "windows_sysmon_network_summary": "windows_sysmon_network_activity",
        "windows_sysmon_network_connections": "windows_sysmon_network_activity",
        "windows_sysmon_network_connections_summary": "windows_sysmon_network_activity",
        "windows_sysmon_dns_summary": "windows_sysmon_dns_activity",
        "windows_sysmon_dns_activity_summary": "windows_sysmon_dns_activity",
        "windows_dns_activity_summary": "windows_sysmon_dns_activity",
        "windows_credential_access_summary": "windows_credential_access_activity",
        "linux_session_activity_summary": "linux_session_activity",
    }
    intent = intent_aliases.get(intent, intent)
    q_lower = question.lower()
    first_seen_priv_esc = question_requests_privilege_first_seen(question)
    failed_priv_esc = any(
        tok in q_lower
        for tok in (
            "failed sudo",
            "sudo failure",
            "failed privilege escalation",
            "failed su",
            "privilege escalation attempts",
        )
    )
    if first_seen_priv_esc:
        intent = "linux_privilege_escalation_first_seen"
    elif intent == "linux_privilege_escalation_activity" and failed_priv_esc:
        intent = "linux_privilege_escalation"
    confidence = _float01(candidate.get("confidence", 0.5), default=0.5)
    reason = str(candidate.get("reason") or candidate.get("rationale") or "")

    normalized = {
        "selected_tool": tool,
        "tool_args": args,
        "intent": intent,
        "confidence": confidence,
        "reason": reason,
        "source": str(candidate.get("source", "model")),
    }

    if tool not in ALLOWED_TOOLS:
        out = _default_plan_from_template(question)
        out["reason"] = f"{fallback_reason}:tool_not_allowed:{tool}"
        return out

    if tool == "splunk_run_query":
        if not str(args.get("query", args.get("search", ""))).strip():
            mapped_template = map_question_to_template(question)
            fallback_args = template_to_query_args(mapped_template, question)
            for key in ("earliest_time", "latest_time", "row_limit"):
                if str(args.get(key, "")).strip():
                    fallback_args[key] = args[key]
            args = fallback_args
            normalized["tool_args"] = args
            normalized["intent"] = mapped_template.intent
            normalized["source"] = "deterministic_missing_query_fallback"
            normalized["reason"] = (
                f"{reason};{fallback_reason}:missing_query_template_fallback"
            ).strip(";")
        if "query" not in args and "search" in args:
            args["query"] = str(args.get("search", "")).strip()
            args.pop("search", None)
        if "query" in args:
            q = str(args.get("query", "")).strip()
            if q and not q.lower().startswith("search ") and not q.startswith("|"):
                args["query"] = f"search {q}"
            # Remove inline time modifiers from SPL. Time belongs in tool args.
            args["query"] = re.sub(r"\s+(earliest(?:_time)?|latest(?:_time)?)\s*=\s*([^\s|]+)", "", args["query"], flags=re.IGNORECASE)
            args["query"] = re.sub(r"\s{2,}", " ", str(args["query"]).strip())
        apply_question_time_window(question, args)
        if str(args.get("latest_time", "")).strip().lower() == "now()":
            args["latest_time"] = "now"
        try:
            rl = int(args.get("row_limit", 10))
        except Exception:
            rl = 10
        args["row_limit"] = max(1, min(200, rl))

        # Question-aware query cleanup for common planner mistakes on benchmark-only BOTSv3 families.
        if "botsv3" in q_lower:
            if "query" not in args:
                out = _default_plan_from_template(question)
                out["reason"] = f"{fallback_reason}:missing_query_for_run_query"
                return out
            explicit_sourcetype = extract_explicit_sourcetype(question)
            botsv3_family_rewrite_blocked = explicit_sourcetype == "access_combined"
            explicit_botsv3_sourcetype = extract_explicit_botsv3_sourcetype(question)
            generic_botsv3_overview = explicit_botsv3_sourcetype and (
                "overview of sourcetype" in q_lower or "show an overview of sourcetype" in q_lower
            )
            args["query"] = re.sub(r"index=BOTSv3", "index=botsv3", str(args["query"]), flags=re.IGNORECASE)
            args["earliest_time"] = "0" if question_requests_all_time(question) else args["earliest_time"]
            if generic_botsv3_overview:
                args["query"] = (
                    f"search index=botsv3 sourcetype={explicit_botsv3_sourcetype} "
                    "| stats count by host source sourcetype "
                    "| sort - count | head 20"
                )
                normalized["intent"] = "botsv3_named_sourcetype_overview"
            if any(tok in q_lower for tok in ("cloudtrail", "aws cloudtrail", "aws api", "eventname", "eventsource")):
                args["query"] = re.sub(r"sourcetype=cloudtrail\b", "sourcetype=aws:cloudtrail", str(args["query"]), flags=re.IGNORECASE)
                args["query"] = re.sub(r"\bindex=aws\b", "index=botsv3", str(args["query"]), flags=re.IGNORECASE)
                args["query"] = re.sub(r"\bsource_ip\b", "sourceIPAddress", str(args["query"]))
                if "sourcetype=aws:cloudtrail" not in str(args["query"]):
                    args["query"] = re.sub(r"^search\s+", "search index=botsv3 sourcetype=aws:cloudtrail ", str(args["query"]), count=1, flags=re.IGNORECASE)
                # Upgrade shallow CloudTrail summaries into richer evidence views.
                if re.search(r"\|\s*stats\s+count\s+by\s+sourceIPAddress\s*$", str(args["query"]), flags=re.IGNORECASE):
                    args["query"] = (
                        "search index=botsv3 sourcetype=aws:cloudtrail "
                        "| eval principal=coalesce('userIdentity.arn','userIdentity.principalId','userIdentity.type') "
                        "| eval error_state=coalesce(errorCode,errorMessage,\"success\") "
                        "| stats count by eventSource eventName sourceIPAddress principal userAgent error_state "
                        "| sort - count | head 20"
                    )
            if any(tok in q_lower for tok in ("cisco asa", "asa firewall", "blocked flows", "firewall flows", "blocked traffic")):
                args["query"] = re.sub(r"sourcetype=firewall_cisco_asa\b", "sourcetype=cisco:asa", str(args["query"]), flags=re.IGNORECASE)
                args["query"] = re.sub(r"index=\*", "index=botsv3", str(args["query"]), flags=re.IGNORECASE)
                if "sourcetype=cisco:asa" not in str(args["query"]):
                    args["query"] = re.sub(r"^search\s+", "search index=botsv3 sourcetype=cisco:asa ", str(args["query"]), count=1, flags=re.IGNORECASE)
                # Upgrade overly shallow ASA summaries to include actual flow context.
                if re.search(r"\|\s*stats\s+count\s+by\s+action(\s+\|\s*sort\s+-\s*count)?\s*$", str(args["query"]), flags=re.IGNORECASE):
                    args["query"] = (
                        "search index=botsv3 sourcetype=cisco:asa "
                        "| stats count by action src_ip dest_ip dest_port transport "
                        "| sort - count | head 20"
                    )
            if not botsv3_family_rewrite_blocked and any(tok in q_lower for tok in ("stream:http", "stream http", "http methods", "destination sites")):
                args["query"] = re.sub(r"sourcetype=access_combined\b", "sourcetype=stream:http", str(args["query"]), flags=re.IGNORECASE)
                args["query"] = re.sub(r"\bindex=linux\b", "index=botsv3", str(args["query"]), flags=re.IGNORECASE)
                args["query"] = re.sub(r"\bclientip\b", "src_ip", str(args["query"]))
                if "sourcetype=stream:http" not in str(args["query"]) or "spath" not in str(args["query"]).lower():
                    args["query"] = (
                        "search index=botsv3 sourcetype=stream:http "
                        "| spath input=_raw path=http_method output=http_method "
                        "| spath input=_raw path=status output=status "
                        "| spath input=_raw path=site output=site "
                        "| spath input=_raw path=src_ip output=src_ip "
                        "| stats count by http_method status site src_ip "
                        "| sort - count | head 20"
                    )
            if not botsv3_family_rewrite_blocked and any(tok in q_lower for tok in ("osquery", "process monitoring", "added processes")):
                args["query"] = re.sub(r"sourcetype=osquery:processes\b", "sourcetype=osquery:results", str(args["query"]), flags=re.IGNORECASE)
                args["query"] = re.sub(r"\bindex=\w+\b", "index=botsv3", str(args["query"]), count=1, flags=re.IGNORECASE)
                if "sourcetype=osquery:results" not in str(args["query"]) or "spath" not in str(args["query"]).lower():
                    args["query"] = (
                        "search index=botsv3 sourcetype=osquery:results "
                        "| spath input=_raw path=name output=query_name "
                        "| spath input=_raw path=action output=action "
                        "| spath input=_raw path=hostIdentifier output=hostIdentifier "
                        "| spath input=_raw path=columns.path output=path "
                        "| spath input=_raw path=columns.cmdline output=cmdline "
                        "| stats count by hostIdentifier action path cmdline "
                        "| sort - count | head 20"
                    )
            if any(tok in q_lower for tok in ("vpc flow", "vpc flows", "accepted and rejected flows", "cloudwatchlogs:vpcflow")):
                # Canonicalize VPC flow queries to a known-good raw-line parser.
                args["query"] = (
                    "search index=botsv3 sourcetype=aws:cloudwatchlogs:vpcflow "
                    "| rex field=_raw \"^\\S+\\s+\\S+\\s+\\S+\\s+(?<src_ip>\\S+)\\s+(?<dest_ip>\\S+)\\s+\\S+\\s+(?<dest_port>\\S+)\\s+(?<protocol_num>\\S+)\\s+\\S+\\s+\\S+\\s+\\S+\\s+\\S+\\s+(?<action>\\S+)\\s+\\S+$\" "
                    "| eval transport=case(protocol_num=\"6\",\"tcp\",protocol_num=\"17\",\"udp\",protocol_num=\"1\",\"icmp\",true(),protocol_num) "
                    "| stats count by action src_ip dest_ip dest_port transport "
                    "| sort - count | head 20"
                )
            if any(tok in q_lower for tok in ("azure ad", "aad sign-in", "aad signin", "login status")):
                args["query"] = re.sub(r"sourcetype=azure:ad:signins\b", "sourcetype=ms:aad:signin", str(args["query"]), flags=re.IGNORECASE)
                args["query"] = re.sub(r"\bindex=\w+\b", "index=botsv3", str(args["query"]), count=1, flags=re.IGNORECASE)
                if "sourcetype=ms:aad:signin" not in str(args["query"]) or "spath" not in str(args["query"]).lower():
                    args["query"] = (
                        "search index=botsv3 sourcetype=ms:aad:signin "
                        "| spath input=_raw path=userPrincipalName output=userPrincipalName "
                        "| spath input=_raw path=ipAddress output=ipAddress "
                        "| spath input=_raw path=appDisplayName output=appDisplayName "
                        "| spath input=_raw path=loginStatus output=loginStatus "
                        "| stats count by userPrincipalName ipAddress appDisplayName loginStatus "
                        "| sort - count | head 20"
                    )
            if any(tok in q_lower for tok in ("stream:dns", "stream dns", "dns activity", "reply code", "dns query")):
                args["query"] = re.sub(r"\bindex=\w+\b", "index=botsv3", str(args["query"]), count=1, flags=re.IGNORECASE)
                if "sourcetype=stream:dns" not in str(args["query"]) or "spath" not in str(args["query"]).lower():
                    args["query"] = (
                        "search index=botsv3 sourcetype=stream:dns "
                        "| spath input=_raw path=query{} output=query_name "
                        "| mvexpand query_name "
                        "| stats count by query_name reply_code src_ip dest_ip "
                        "| sort - count | head 20"
                    )
            if any(tok in q_lower for tok in ("office 365 management", "o365 management", "sharepoint activity", "onedrive activity", "ms:o365:management")):
                args["query"] = re.sub(r"sourcetype=ms:aad:signin\b", "sourcetype=ms:o365:management", str(args["query"]), flags=re.IGNORECASE)
                args["query"] = re.sub(r"\bindex=\w+\b", "index=botsv3", str(args["query"]), count=1, flags=re.IGNORECASE)
                if "sourcetype=ms:o365:management" not in str(args["query"]) or "spath" not in str(args["query"]).lower():
                    args["query"] = (
                        "search index=botsv3 sourcetype=ms:o365:management "
                        "| spath input=_raw path=UserId output=UserId "
                        "| spath input=_raw path=Operation output=Operation "
                        "| spath input=_raw path=Workload output=Workload "
                        "| spath input=_raw path=ClientIP output=ClientIP "
                        "| stats count by UserId Operation Workload ClientIP "
                        "| sort - count | head 20"
                    )
            args["query"] = re.sub(r"\s{2,}", " ", str(args["query"]).strip())

        if any(tok in q_lower for tok in ("process creation", "process activity", "sysmon process", "new processes")):
            args["query"] = _canonical_query_for_intent("windows_process_activity")
            normalized["intent"] = "windows_process_activity"
        # Cross-platform failed-login shaping defers to query_templates.failed_login_activity
        # via map_question_to_template + template_to_query_args (env rewriter applies per-branch).
        if first_seen_priv_esc:
            args["query"] = (
                "search index=linux (source=\"/var/log/auth.log\" OR source=\"/var/log/secure\") "
                "(\"session opened for user root by\" OR \"COMMAND=\" OR \"pam_unix(sudo:session)\" OR "
                "\"pam_unix(su:session)\" OR \"sudo:\" OR \"su:\") "
                "| eval user_name=coalesce(user, account, uid, user_name) "
                "| eval src_ip=coalesce(rhost, src, src_ip, ip) "
                "| stats earliest(_time) as first_seen latest(_time) as last_seen count by host user_name tty src_ip "
                "| convert ctime(first_seen) ctime(last_seen) "
                "| sort 0 first_seen"
            )
            normalized["intent"] = "linux_privilege_escalation_first_seen"
        if any(tok in q_lower for tok in ("sysmon network", "network connections", "event id 3", "sysmon event 3")):
            args["query"] = _canonical_query_for_intent(
                "windows_sysmon_network_activity"
            )
            normalized["intent"] = "windows_sysmon_network_activity"
        if any(tok in q_lower for tok in ("sysmon dns", "dns queries", "event id 22", "sysmon event 22")):
            args["query"] = _canonical_query_for_intent(
                "windows_sysmon_dns_activity"
            )
            normalized["intent"] = "windows_sysmon_dns_activity"
        if any(tok in q_lower for tok in ("credential access", "credential manager", "stored credentials", "event 5379")):
            args["query"] = _canonical_query_for_intent(
                "windows_credential_access_activity"
            )
            normalized["intent"] = "windows_credential_access_activity"
        if any(tok in q_lower for tok in ("linux session activity", "session opened", "session closed", "cron session", "pam_unix session")):
            args["query"] = (
                "search index=linux (source=\"/var/log/auth.log\" OR source=\"/var/log/secure\") "
                "(\"session opened for user\" OR \"session closed for user\" OR \"pam_unix(cron:session)\") "
                "| rex field=_raw \"(?i)session (?<session_state>opened|closed) for user (?<session_user>[A-Za-z0-9_.-]+)\" "
                "| rex field=_raw \"(?i)tty=(?<tty>[^\\s;]+)\" "
                "| rex field=_raw \"(?i)rhost=(?<src_ip>[^\\s;]+)\" "
                "| eval actor=session_user "
                "| eval src_ip=if(isnull(src_ip) OR len(trim(src_ip))=0, \"local\", src_ip) "
                "| table _time host sourcetype session_state actor tty src_ip _raw "
                "| head 20"
            )
            normalized["intent"] = "linux_session_activity"
        if any(tok in q_lower for tok in ("failed sudo", "sudo attempts", "sudo failure", "failed privilege escalation", "failed su", "su failed")):
            query = (
                "search index=linux (source=\"/var/log/auth.log\" OR source=\"/var/log/secure\") "
                "((\"pam_unix(sudo:auth): authentication failure\" OR \"pam_unix(su:auth): authentication failure\" OR \"conversation failed\") "
                "OR ((\"sudo:\" OR \"su:\") (\"authentication failure\" OR \"incorrect password\" OR \"incorrect password attempts\" OR \"failed\"))) "
                "| rex field=_raw \"\\s(?<process_name>sudo|su)(?:\\[[^\\]]+\\])?:\" "
                "| rex field=_raw \"(?i)sudo:\\s+(?<sudo_actor>[A-Za-z0-9_.-]+)\\s+:\" "
                "| rex field=_raw \"(?i)logname=(?<logname_user>[^\\s;]+)\" "
                "| rex field=_raw \"(?i)ruser=(?<ruser>[^\\s;]+)\" "
                "| rex field=_raw \"(?i)\\buser=(?<auth_user>[^\\s;]+)\" "
                "| rex field=_raw \"(?i)tty=(?<tty_value>[^\\s;]+)\" "
                "| rex field=_raw \"(?i)rhost=(?<src_ip>[^\\s;]+)\" "
                "| eval actor=coalesce(sudo_actor,logname_user,ruser,auth_user,user,account,uid,user_name) "
                "| eval tty=coalesce(tty_value,tty) "
                "| eval src_ip=if(isnull(src_ip) OR len(trim(src_ip))=0, \"local\", src_ip) "
                "| stats count by host process_name actor tty src_ip sourcetype "
                "| sort - count | head 20"
            )
            if re.search(r"\bfailed sudo\b", q_lower):
                query = query.replace(
                    "((\"pam_unix(sudo:auth): authentication failure\" OR \"pam_unix(su:auth): authentication failure\" OR \"conversation failed\") OR ((\"sudo:\" OR \"su:\") (\"authentication failure\" OR \"incorrect password\" OR \"incorrect password attempts\" OR \"failed\")))",
                    "((\"pam_unix(sudo:auth): authentication failure\" OR \"conversation failed\") OR (\"sudo:\" (\"authentication failure\" OR \"incorrect password\" OR \"incorrect password attempts\" OR \"failed\")))",
                )
            elif re.search(r"\bfailed su\b", q_lower):
                query = query.replace(
                    "((\"pam_unix(sudo:auth): authentication failure\" OR \"pam_unix(su:auth): authentication failure\" OR \"conversation failed\") OR ((\"sudo:\" OR \"su:\") (\"authentication failure\" OR \"incorrect password\" OR \"incorrect password attempts\" OR \"failed\")))",
                    "(\"pam_unix(su:auth): authentication failure\" OR (\"su:\" (\"authentication failure\" OR \"incorrect password\" OR \"incorrect password attempts\" OR \"failed\")))",
                )
            args["query"] = query
            normalized["intent"] = "linux_privilege_escalation"
        if (not first_seen_priv_esc) and (not failed_priv_esc) and any(tok in q_lower for tok in ("sudo behavior", "sudo activity", "su behavior", "su activity", "root session", "sudo sessions")):
            args["query"] = _canonical_query_for_intent(
                "linux_privilege_escalation_activity"
            )
            normalized["intent"] = "linux_privilege_escalation_activity"
        if any(tok in q_lower for tok in ("linux audit", "auditd", "linux_audit", "audit operations")):
            target_index = "index=botsv3" if "botsv3" in q_lower else "index=linux"
            args["query"] = (
                f"search {target_index} sourcetype=linux_audit "
                "| rex field=_raw \"type=(?<audit_type>[^ ]+)\" "
                "| rex field=_raw \"\\bop=(?<audit_op>[^ ]+)\" "
                "| rex field=_raw \"\\bres=(?<audit_res>[^ ]+)\" "
                "| stats count by host audit_type audit_op audit_res "
                "| sort - count | head 20"
            )
            normalized["intent"] = "linux_audit_activity"
        if "query" in args and str(args.get("query", "")).strip():
            if not args.get("_env_constraints_applied"):
                args["query"] = _apply_environment_constraints_to_query(
                    question,
                    normalized["intent"],
                    str(args.get("query", "")).strip(),
                    args=args,
                )
                args["_env_constraints_applied"] = True
            args["query"] = re.sub(r"\s{2,}", " ", str(args["query"]).strip())

    if tool == "splunk_run_query" and "row_limit" not in args:
        args["row_limit"] = 10
    return normalized


def _validate_metadata_args(args: dict[str, Any]) -> tuple[bool, str]:
    metadata_type = args.get("type")
    if metadata_type not in {"hosts", "sources", "sourcetypes"}:
        return False, "metadata_type_invalid"
    row_limit = args.get("row_limit")
    if not isinstance(row_limit, int):
        return False, "metadata_row_limit_not_int"
    if row_limit < 1:
        return False, "metadata_row_limit_below_min"
    if row_limit > 200:
        return False, "metadata_row_limit_exceeds_max:200"
    for time_key in ("earliest_time", "latest_time"):
        if not args.get(time_key):
            return False, f"metadata_missing_{time_key}"
    return True, "metadata_args_allowed"


def _enforce_question_alignment(question: str, plan: dict[str, Any]) -> dict[str, Any]:
    q = question.lower()
    aligned = dict(plan)
    mapped_template = map_question_to_template(question)

    # A question that names a time window, a data-volume comparison, or any other
    # signal requiring a real event search must never be force-routed to a
    # metadata-only tool (splunk_get_indexes has no time filter and cannot answer
    # "in the last hour" style questions). Check this before the typo-tolerant
    # index-inventory override below so wording like "which indexes have data in
    # the last hour" falls through to the time-aware run_query branch instead.
    from mcp_deterministic_routing import question_disqualified_for_deterministic

    needs_time_scoped_search = bool(question_disqualified_for_deterministic(question))

    # Typo-tolerant index inventory detection: catch common misspellings ("idexes",
    # "indexs", "indeces") paired with an inventory-style verb or "access" phrasing,
    # so e.g. "which idexes do I have access to?" still routes to index inventory
    # instead of falling through to a generic/security template.
    has_index_like_token = question_has_index_token(q)
    has_inventory_verb = any(v in q for v in ("which", "what", "list", "show", "available"))
    has_access_phrase = "access to" in q or "can access" in q or "have access" in q
    if not needs_time_scoped_search and (
        "list indexes" in q
        or "show indexes" in q
        or "what indexes" in q
        or "indexes i can access" in q
        or re.search(r"\b(how many|number of|count of)\s+indexes?\b", q)
        or (has_index_like_token and (has_inventory_verb or has_access_phrase))
    ):
        aligned["selected_tool"] = "splunk_get_indexes"
        aligned["tool_args"] = {}
        aligned["intent"] = "top_indexes"
        aligned["reason"] = "question_alignment_override:index_inventory"
        return aligned

    if mapped_template.intent == "top_indexes":
        selected_tool, _reason, _metadata_args, _mode = determine_splunk_tool(question, mapped_template.intent)
        if selected_tool == "splunk_run_query":
            aligned.update(_build_template_aligned_plan(question, mapped_template))
            aligned["reason"] = "question_alignment_override:top_indexes_run_query"
            return aligned

    time_bounded_inventory_intents = {
        "index_sourcetype_volume",
        "internal_sourcetypes",
        "linux_sourcetypes",
        "linux_host_activity",
        "host_activity_summary",
        "splunk_internal_health",
        "internal_auth_failures",
        "forwarder_connectivity",
        "splunk_license_usage",
    }
    if mapped_template.intent in time_bounded_inventory_intents and needs_time_scoped_search:
        aligned.update(_build_template_aligned_plan(question, mapped_template))
        aligned["reason"] = f"question_alignment_override:{mapped_template.intent}_run_query"
        return aligned

    if "splunk version" in q or "splunk info" in q or "server info" in q or "instance info" in q:
        aligned["selected_tool"] = "splunk_get_info"
        aligned["tool_args"] = {}
        aligned["intent"] = "splunk_info"
        aligned["reason"] = "question_alignment_override:splunk_info"
        return aligned

    if mapped_template.intent == "botsv3_named_sourcetype_overview":
        aligned.update(_build_template_aligned_plan(question, mapped_template))
        aligned["reason"] = "question_alignment_override:botsv3_sourcetype_overview"
        return aligned

    explicit_sourcetype = extract_explicit_sourcetype(question)
    if explicit_sourcetype == "access_combined" and mapped_template.intent in APACHE_WEB_INTENTS:
        aligned.update(_build_template_aligned_plan(question, mapped_template))
        aligned["reason"] = "question_alignment_override:explicit_access_combined"
        return aligned

    if "metadata" in q and any(x in q for x in ("host", "hosts", "source", "sources", "sourcetype", "sourcetypes")):
        selected_tool, _reason, metadata_args, _mode = determine_splunk_tool(question, "")
        if selected_tool == "splunk_get_metadata":
            aligned["selected_tool"] = "splunk_get_metadata"
            aligned["tool_args"] = metadata_args
            aligned["intent"] = "metadata_inventory"
            aligned["reason"] = "question_alignment_override:metadata_inventory"
        return aligned

    deterministic_run_query_intents = DETERMINISTIC_RUN_QUERY_INTENTS
    if _template_override_mode() == "always" and mapped_template.intent in deterministic_run_query_intents:
        aligned.update(_build_template_aligned_plan(question, mapped_template))
        return aligned

    return aligned


def ingest_question(state: MultiModelState) -> MultiModelState:
    question = str(state.get("question", "")).strip()
    if not question:
        raise ValueError("question is required")
    mapped_template = map_question_to_template(question)
    review_profile = classify_review_profile(question, template_intent=mapped_template.intent)
    return {
        "question": question,
        "session_id": str(state.get("session_id", "")).strip(),
        "review_profile": review_profile,
        "skipped_nodes": skipped_nodes_for_profile(review_profile),
    }


def guardrail_check(state: MultiModelState) -> MultiModelState:
    started = time.monotonic()
    question = state["question"].lower()
    if any(term in question for term in BLOCKED_TERMS):
        return {
            "supported": False,
            "guardrail_reason": (
                "Question appears to request non-read-only action. "
                "This lab flow supports read-only analysis questions only."
            ),
            "validation_ok": False,
            "validation_reason": "guardrail_blocked",
            "guardrail_duration_ms": int((time.monotonic() - started) * 1000),
            "stage_logs": _append_stage_log(
                state,
                stage="guardrail",
                title="Guardrail blocked the request before planning",
                details=["The question appeared to ask for a non-read-only action."],
                duration_ms=int((time.monotonic() - started) * 1000),
            ),
        }
    return {
        "supported": True,
        "guardrail_reason": "",
        "guardrail_duration_ms": int((time.monotonic() - started) * 1000),
        "stage_logs": _append_stage_log(
            state,
            stage="guardrail",
            title="Guardrail allowed the request to proceed",
            details=["The question stayed within read-only investigation scope."],
            duration_ms=int((time.monotonic() - started) * 1000),
        ),
    }


def _process_planner_analytical_plan(
    question: str,
    normalized: dict[str, Any],
    *,
    planner_model: str,
) -> dict[str, Any]:
    """Validate an optional typed plan and perform at most one structured repair."""
    from spl_plan_migration import analytical_planner_mode, validate_planner_analytical_plan
    from spl_writer_prompt import build_analytical_plan_repair_system_prompt

    output = dict(normalized)
    raw_plan = output.get("analytical_plan")
    status = validate_planner_analytical_plan(question, raw_plan)
    status["mode"] = analytical_planner_mode()
    status["repair_attempted"] = False
    status["repair_succeeded"] = False
    if status["valid"]:
        output["analytical_plan"] = status["plan"]
        output["analytical_plan_status"] = status
        return output

    status["repair_attempted"] = True
    repair_payload = {
        "question": question,
        "question_shape_hints": infer_analytical_shape_hints(question),
        "dataset_locks": status["dataset_locks"],
        "validation_errors": status["errors"],
        "invalid_analytical_plan": raw_plan,
    }
    try:
        repaired = _call_ollama_json(
            model=planner_model,
            system_prompt=build_analytical_plan_repair_system_prompt(),
            user_payload=repair_payload,
        )
        repaired_plan = repaired.get("analytical_plan") if isinstance(repaired, dict) else None
        repaired_status = validate_planner_analytical_plan(
            question,
            repaired_plan,
            enforce_dataset_locks=True,
        )
        status["repair_errors"] = repaired_status["errors"]
        if repaired_status["valid"]:
            output["analytical_plan"] = repaired_status["plan"]
            status["valid"] = True
            status["errors"] = []
            status["plan"] = repaired_status["plan"]
            status["repair_succeeded"] = True
        else:
            output["analytical_plan_proposal"] = raw_plan
            output.pop("analytical_plan", None)
    except Exception as exc:
        status["repair_errors"] = [f"repair_exception:{type(exc).__name__}:{exc}"]
        output["analytical_plan_proposal"] = raw_plan
        output.pop("analytical_plan", None)
    output["analytical_plan_status"] = status
    return output


def planner_node(state: MultiModelState) -> MultiModelState:
    started = time.monotonic()
    question = state["question"]
    rag_context = build_spl_rag_context(question, max_chars=RAG_MAX_CHARS) if RAG_ENABLED else ""
    question_profile = build_question_profile_text(question)
    system = (
        "You are the planning model in a guarded Splunk workflow. "
        "Do not write final SPL unless the selected tool is metadata/get-info/get-indexes. "
        "Your job is to interpret analyst intent and emit a structured read-only search plan. "
        "Allowed tools: splunk_run_query, splunk_get_indexes, splunk_get_metadata, splunk_get_info. "
        "Never invent indexes, sourcetypes, or fields. Use exact names present in supplied context. "
        "When the question explicitly says BOTSv3, scope thinking to index=botsv3. "
        "When the question requests all available history (all time, at any point ever, ever in/on, were there any without a recent window), set earliest_time=0 and latest_time=now in tool_args. "
        f"{describe_supported_time_windows()} "
        "Return strict JSON keys: intent, intent_summary, selected_tool, search_strategy_summary, likely_indexes, likely_sourcetypes, likely_fields, constraints, tool_args, confidence, reason, caveats. "
        "If selected_tool is splunk_run_query, tool_args may only include earliest_time, latest_time, and row_limit. Do not include query text."
    )
    from spl_writer_prompt import build_analytical_planner_system_prompt

    system = build_analytical_planner_system_prompt(system)
    payload = {
        "question": question,
        "question_profile": question_profile,
        "question_shape_hints": infer_analytical_shape_hints(question),
        "constraints": {
            "read_only": True,
            "max_row_limit": 200,
            "metadata_types": ["hosts", "sources", "sourcetypes"],
        },
        "rag_context": rag_context,
    }
    planner_output: dict[str, Any]
    planner_model_used = ""
    planner_errors: list[str] = []
    for candidate_model in _planner_model_candidates():
        try:
            planner_output = _call_ollama_json(model=candidate_model, system_prompt=system, user_payload=payload)
            planner_output["source"] = "planner_model"
            planner_output["planner_model_used"] = candidate_model
            planner_model_used = candidate_model
            break
        except Exception as exc:
            planner_errors.append(f"{candidate_model}:{type(exc).__name__}:{exc}")
    else:
        template_fallback = _default_plan_from_template(question)
        planner_output = {
            "selected_tool": template_fallback.get("selected_tool", "splunk_run_query"),
            "intent": template_fallback.get("intent", "unknown"),
            "intent_summary": question,
            "search_strategy_summary": "Use the deterministic template fallback for this question.",
            "likely_indexes": [],
            "likely_sourcetypes": [],
            "likely_fields": [],
            "constraints": ["read_only_only", "row_limit<=200"],
            "tool_args": {
                key: value
                for key, value in (template_fallback.get("tool_args", {}) or {}).items()
                if key in {"earliest_time", "latest_time", "row_limit", "type"}
            },
            "confidence": 0.5,
            "reason": f"planner_exception:{'|'.join(planner_errors[-3:])}",
            "caveats": ["planner_fallback_used"],
            "source": "planner_fallback",
        }

    normalized = _normalize_planner_plan(planner_output, question, fallback_reason="planner_normalization_fallback")
    if planner_model_used and normalized.get("source") == "planner_model":
        normalized["planner_model_used"] = planner_model_used
    normalized = _process_planner_analytical_plan(
        question,
        normalized,
        planner_model=planner_model_used or MODEL_QUERY_PLANNER,
    )
    review_profile = _review_profile_for_state(state, planner_intent=str(normalized.get("intent", "")).strip())
    return {
        "planner_output": normalized,
        "review_profile": review_profile,
        "skipped_nodes": skipped_nodes_for_profile(review_profile),
        "planner_duration_ms": int((time.monotonic() - started) * 1000),
        "stage_logs": _append_stage_log(
            state,
            stage="planner",
            title="Planner interpreted the analyst request",
            details=[
                f"intent={normalized.get('intent', 'unknown')}",
                f"selected_tool={normalized.get('selected_tool', '')}",
                f"strategy={normalized.get('search_strategy_summary', '')}",
                f"analytical_plan={str((normalized.get('analytical_plan_status') or {}).get('valid', False)).lower()}",
                "Typed plans are compiled and scored in observe mode, then selected only in prefer mode.",
            ],
            model=planner_model_used or MODEL_QUERY_PLANNER,
            duration_ms=int((time.monotonic() - started) * 1000),
        ),
    }


def _writer_post_routing(state: MultiModelState, normalized: dict[str, Any]) -> dict[str, Any]:
    """Set final_plan for metadata profile and persist profile-derived skipped nodes."""
    review_profile = _review_profile_for_state(
        state,
        planner_intent=str(normalized.get("intent", "")).strip(),
    )
    skip_security = not requires_security_review(review_profile)
    return {
        "review_profile": review_profile,
        "final_plan": normalized if skip_security else state.get("final_plan", {}),
        "skipped_nodes": skipped_nodes_for_profile(review_profile),
    }


def _writer_bypass_for_template_override(question: str, mapped_template: QueryTemplate) -> dict[str, Any] | None:
    """Skip the writer LLM when template override mode supplies deterministic SPL."""
    mode = _template_override_mode()
    if mode == "never":
        return None
    if mapped_template.intent not in DETERMINISTIC_RUN_QUERY_INTENTS:
        return None
    if mode == "always" or mode == "fallback":
        return _normalize_candidate(
            {
                **_build_template_aligned_plan(question, mapped_template),
                "confidence": 0.95,
                "reason": f"writer_bypass_template_override_{mode}:{mapped_template.intent}",
                "source": "writer_template_bypass",
                "canonical_template_query": template_to_query_args(mapped_template, question).get("query", ""),
            },
            question,
            fallback_reason="writer_template_bypass_fallback",
        )
    return None


def _revise_writer_if_invalid(question: str, normalized: dict[str, Any]) -> dict[str, Any]:
    """One-shot in-writer repair when the model draft fails policy/intent/environment checks."""
    if str(normalized.get("selected_tool", "")).strip() != "splunk_run_query":
        return normalized
    if os.getenv("AGTSMITH_WRITER_REVISE", "1").strip().lower() in {"0", "false", "no"}:
        return normalized
    args = normalized.get("tool_args", {})
    if not isinstance(args, dict) or not str(args.get("query", "")).strip():
        return normalized
    intent = str(normalized.get("intent", "")).strip()
    ok, reason = validate_query_args(args, question=question)
    if ok and intent:
        contract_ok, contract_reason = validate_query_for_intent(intent, args, question=question)
        if contract_ok:
            env_ok, env_reason = validate_query_against_environment(args)
            if env_ok:
                return normalized
            reason = f"environment:{env_reason}"
        else:
            reason = f"intent:{contract_reason}"
    elif not ok:
        reason = f"policy:{reason}"
    repair = attempt_query_repair_once(
        question=question,
        failed_query_args=args,
        failure_reason=reason,
        model=MODEL_QUERY_WRITER,
        intent=intent,
    )
    if not repair.get("ok"):
        return normalized
    revised = dict(normalized)
    revised["tool_args"] = repair["args"]
    revised["source"] = "writer_model_revised"
    revised["reason"] = f"{normalized.get('reason', '')};writer_revised:{repair.get('repair_reason', '')}".strip(";")
    return revised


def field_bind_node(state: MultiModelState) -> MultiModelState:
    started = time.monotonic()
    question = state["question"]
    planner_output = state.get("planner_output", {}) or {}
    from spl_field_binding import bind_fields_for_plan

    allow_mcp = str(os.getenv("SPL_FIELD_BIND_MCP_FALLBACK", "0")).strip().lower() in {"1", "true", "yes"}
    bound = bind_fields_for_plan(question, planner_output, allow_mcp_fallback=allow_mcp)
    duration_ms = int((time.monotonic() - started) * 1000)
    return {
        "field_bind_output": bound,
        "field_bind_duration_ms": duration_ms,
        "stage_logs": _append_stage_log(
            state,
            stage="field_bind",
            title="Field binding applied environment oracle hints",
            details=[
                f"sourcetype={bound.get('sourcetype', '')}",
                f"index_expr={bound.get('index_expr', '')}",
                f"source={bound.get('source', '')}",
            ],
            duration_ms=duration_ms,
        ),
    }


def field_discovery_node(state: MultiModelState) -> MultiModelState:
    started = time.monotonic()
    question = state["question"]
    planner_output = state.get("planner_output", {}) or {}
    bound = dict(state.get("field_bind_output", {}) or {})
    from spl_field_discovery import discover_fields_for_plan, enrich_field_bind_with_discovery, should_run_field_discovery
    from spl_plan_migration import analytical_planner_mode

    run, reason = should_run_field_discovery(bound)
    discovery: dict[str, Any] = {"skipped": True, "reason": reason}
    planner_status = planner_output.get("analytical_plan_status", {})
    typed_observe = (
        analytical_planner_mode() == "observe"
        and isinstance(planner_status, dict)
        and bool(planner_status.get("valid"))
    )
    if run:
        discovery = discover_fields_for_plan(
            question,
            planner_output,
            bound=bound,
            live_probe=True,
            include_raw_sample=not typed_observe,
        )
        bound = enrich_field_bind_with_discovery(bound, discovery)
        discovery["skipped"] = False
        discovery["trigger_reason"] = reason

    duration_ms = int((time.monotonic() - started) * 1000)
    details = [
        f"ran={not discovery.get('skipped', True)}",
        f"reason={reason}",
        f"field_count={discovery.get('field_count', 0)}",
        f"raw_sample={'disabled_typed_observe' if typed_observe else 'enabled'}",
    ]
    return {
        "field_bind_output": bound,
        "field_discovery_output": discovery,
        "field_discovery_duration_ms": duration_ms,
        "stage_logs": _append_stage_log(
            state,
            stage="field_discovery",
            title="Field discovery probe completed" if run else "Field discovery skipped",
            details=details,
            duration_ms=duration_ms,
        ),
    }


def field_strategy_node(state: MultiModelState) -> MultiModelState:
    """Resolve trusted native fields before any writer path generates SPL."""
    started = time.monotonic()
    from spl_field_strategy import resolve_field_strategy

    strategy = resolve_field_strategy(
        str(state.get("question", "")),
        state.get("planner_output", {}) or {},
        field_bind_output=state.get("field_bind_output", {}) or {},
        field_discovery_output=state.get("field_discovery_output", {}) or {},
    )
    duration_ms = int((time.monotonic() - started) * 1000)
    roles = strategy.get("roles", {}) if isinstance(strategy.get("roles"), dict) else {}
    classifications: dict[str, int] = {}
    for data in roles.values():
        if isinstance(data, dict):
            name = str(data.get("classification", "unresolved"))
            classifications[name] = classifications.get(name, 0) + 1
    return {
        "field_strategy_output": strategy,
        "field_strategy_duration_ms": duration_ms,
        "stage_logs": _append_stage_log(
            state,
            stage="field_strategy",
            title="Field strategy resolved trusted extraction capabilities",
            details=[
                f"domains={len(strategy.get('domain_verifications', []))}",
                f"trusted_fields={len(strategy.get('trusted_fields', []))}",
                f"classifications={classifications}",
            ],
            duration_ms=duration_ms,
        ),
    }


def domain_resolve_node(state: MultiModelState) -> MultiModelState:
    started = time.monotonic()
    question = state["question"]
    planner_output = state.get("planner_output", {}) or {}
    from spl_domain_knowledge import bind_domain_knowledge_for_plan

    bound = bind_domain_knowledge_for_plan(question, planner_output)
    duration_ms = int((time.monotonic() - started) * 1000)
    details = [f"matched={bool(bound.get('matched'))}"]
    if bound.get("pattern_id"):
        details.append(f"pattern_id={bound.get('pattern_id')}")
        details.append(f"preferred_tool={bound.get('preferred_tool')}")
    return {
        "domain_knowledge_output": bound,
        "domain_knowledge_duration_ms": duration_ms,
        "stage_logs": _append_stage_log(
            state,
            stage="domain_knowledge",
            title="SPL domain oracle resolved question shape",
            details=details,
            duration_ms=duration_ms,
        ),
    }


def _preferred_analytical_candidate(
    state: MultiModelState,
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    """Compile and statically score the typed candidate before rollout selection."""
    from spl_plan_migration import (
        analytical_planner_mode,
        compile_bound_analytical_plan,
        validate_planner_analytical_plan,
    )
    from spl_semantic_coverage import evaluate_semantic_coverage
    from spl_writer_prompt import build_analytical_plan_repair_system_prompt

    mode = analytical_planner_mode()
    planner_output = state.get("planner_output", {}) or {}
    status = planner_output.get("analytical_plan_status", {})
    diagnostics: dict[str, Any] = {
        "mode": mode,
        "selected": False,
        "observed": False,
        "errors": [],
        "repair_attempted": False,
        "repair_succeeded": False,
    }
    if not isinstance(status, dict) or not status.get("valid"):
        diagnostics["fallback_reason"] = "analytical_plan_missing_or_invalid"
        diagnostics["errors"] = list(status.get("errors", [])) if isinstance(status, dict) else []
        return None, diagnostics
    raw_plan = planner_output.get("analytical_plan")

    def compile_and_score(plan_payload: Any) -> tuple[dict[str, Any], dict[str, Any]]:
        candidate = compile_bound_analytical_plan(
            str(state.get("question", "")),
            plan_payload,
            intent=str(planner_output.get("intent", "")).strip(),
            field_bind=state.get("field_bind_output", {}) or {},
            field_strategy=state.get("field_strategy_output", {}) or {},
        )
        args = candidate.get("tool_args", {})
        policy_ok, policy_reason = validate_query_args(
            args,
            question=str(state.get("question", "")),
        )
        if not policy_ok and mode in {"prefer", "enforce"}:
            raise ValueError(f"query_policy:{policy_reason}")
        environment_ok, environment_reason = validate_query_against_environment(args)
        if not environment_ok and mode in {"prefer", "enforce"}:
            raise ValueError(f"environment:{environment_reason}")
        safety_ok = bool(policy_ok and environment_ok)
        safety_reason = (
            "query_policy_and_environment_passed"
            if safety_ok
            else (
                f"query_policy:{policy_reason}"
                if not policy_ok
                else f"environment:{environment_reason}"
            )
        )
        report = evaluate_semantic_coverage(
            question=str(state.get("question", "")),
            analytical_plan=candidate.get("analytical_plan", plan_payload),
            query_args=args if isinstance(args, dict) else {},
            field_strategy=state.get("field_strategy_output", {}) or {},
            safety_ok=safety_ok,
            safety_reason=safety_reason,
        )
        candidate["semantic_coverage"] = report
        return candidate, report

    try:
        candidate, report = compile_and_score(raw_plan)
    except Exception as exc:
        diagnostics["fallback_reason"] = "analytical_plan_bind_or_compile_failed"
        diagnostics["errors"] = [f"{type(exc).__name__}:{exc}"]
        return None, diagnostics
    diagnostics["observed"] = True
    diagnostics["semantic_coverage"] = report
    diagnostics["observed_candidate"] = candidate

    if (
        not report.get("passed", False)
        and mode in {"prefer", "enforce"}
        and not status.get("repair_attempted")
    ):
        diagnostics["repair_attempted"] = True
        repair_payload = {
            "question": str(state.get("question", "")),
            "question_shape_hints": infer_analytical_shape_hints(str(state.get("question", ""))),
            "dataset_locks": status.get("dataset_locks", {}),
            "semantic_repair_feedback": report.get("repair_feedback", {}),
            "invalid_analytical_plan": raw_plan,
        }
        try:
            repaired = _call_ollama_json(
                model=str(planner_output.get("planner_model_used", "")).strip() or MODEL_QUERY_PLANNER,
                system_prompt=build_analytical_plan_repair_system_prompt(),
                user_payload=repair_payload,
            )
            repaired_plan = repaired.get("analytical_plan") if isinstance(repaired, dict) else None
            repaired_status = validate_planner_analytical_plan(
                str(state.get("question", "")),
                repaired_plan,
                enforce_dataset_locks=True,
            )
            diagnostics["repair_validation_errors"] = repaired_status.get("errors", [])
            if repaired_status.get("valid"):
                repaired_candidate, repaired_report = compile_and_score(repaired_status["plan"])
                diagnostics["semantic_coverage"] = repaired_report
                if repaired_report.get("passed", False):
                    candidate = repaired_candidate
                    report = repaired_report
                    diagnostics["repair_succeeded"] = True
                    diagnostics["repaired_plan"] = repaired_status["plan"]
        except Exception as exc:
            diagnostics["repair_errors"] = [f"{type(exc).__name__}:{exc}"]

    if mode == "observe":
        diagnostics["fallback_reason"] = "observe_mode_legacy_execution"
        return None, diagnostics
    if not report.get("passed", False):
        diagnostics["fallback_reason"] = "semantic_coverage_failed"
        diagnostics["errors"] = list(report.get("hard_failures", []))
        return None, diagnostics
    candidate["confidence"] = _float01(planner_output.get("confidence", 0.8), default=0.8)
    candidate["analytical_plan_status"] = status
    diagnostics["selected"] = True
    diagnostics["source"] = "validated_bound_analytical_plan"
    return candidate, diagnostics


def writer_node(state: MultiModelState) -> MultiModelState:
    started = time.monotonic()
    question = state["question"]
    planner_output = state.get("planner_output", {}) or {}
    planner_intent = str(planner_output.get("intent", "")).strip()
    mapped_template = map_question_to_template(question)
    force_saved_query_id = str(state.get("force_saved_query_id", "")).strip()
    shortcut = retrieve_saved_query_shortcut(
        question,
        planner_intent,
        force_saved_query_id=force_saved_query_id,
    )
    suggestion_patch = _writer_saved_query_suggestion_patch(shortcut)
    shortcut_writer = _writer_output_from_saved_query_shortcut(
        state,
        question,
        shortcut,
        planner_intent=planner_intent,
        started=started,
    )
    if shortcut_writer is not None:
        return {**shortcut_writer, **suggestion_patch}
    template_override_mode = _template_override_mode()
    if (
        template_override_mode != "never"
        and mapped_template.intent in DETERMINISTIC_RUN_QUERY_INTENTS
    ):
        bypass_output = _writer_bypass_for_template_override(question, mapped_template)
        if bypass_output is not None:
            routing = _writer_post_routing(state, bypass_output)
            return {
                "writer_output": bypass_output,
                **routing,
                "writer_duration_ms": int((time.monotonic() - started) * 1000),
                "stage_logs": _append_stage_log(
                    state,
                    stage="writer",
                    title=f"Writer bypassed LLM (AGTSMITH_TEMPLATE_OVERRIDE={template_override_mode})",
                    details=[
                        f"intent={mapped_template.intent}",
                        "Deterministic template SPL used before analytical plan for benchmark-stable platform intent.",
                    ],
                    model=MODEL_QUERY_WRITER,
                    duration_ms=int((time.monotonic() - started) * 1000),
                ),
            }
    analytical_candidate, analytical_diagnostics = _preferred_analytical_candidate(state)
    planner_output["analytical_plan_execution"] = analytical_diagnostics
    if analytical_candidate is not None:
        routing = _writer_post_routing(state, analytical_candidate)
        duration_ms = int((time.monotonic() - started) * 1000)
        return {
            "planner_output": planner_output,
            "writer_output": analytical_candidate,
            **routing,
            "writer_duration_ms": duration_ms,
            "stage_logs": _append_stage_log(
                state,
                stage="writer",
                title="Writer compiled the validated analytical plan",
                details=[
                    f"intent={analytical_candidate.get('intent', 'unknown')}",
                    f"mode={analytical_diagnostics.get('mode', '')}",
                    f"query={str((analytical_candidate.get('tool_args', {}) or {}).get('query', ''))[:220]}",
                ],
                model="deterministic_spl_plan_compiler",
                duration_ms=duration_ms,
            ),
        }
    domain_knowledge = state.get("domain_knowledge_output", {}) or {}
    domain_confidence = float(domain_knowledge.get("confidence", 0) or 0)
    oracle_threshold = domain_oracle_threshold_for_question(
        question,
        domain_intent=str(domain_knowledge.get("intent", "")),
        mapped_intent=mapped_template.intent,
    )
    if domain_knowledge.get("matched") and domain_confidence >= oracle_threshold:
        preferred_tool = str(domain_knowledge.get("preferred_tool", "")).strip()
        if preferred_tool == "splunk_get_indexes":
            writer_output = _normalize_candidate(
                {
                    "selected_tool": "splunk_get_indexes",
                    "tool_args": {},
                    "intent": str(domain_knowledge.get("intent", mapped_template.intent)),
                    "confidence": domain_confidence,
                    "reason": f"domain_oracle:{domain_knowledge.get('pattern_id', '')}",
                    "source": "domain_knowledge",
                },
                question,
                fallback_reason="domain_knowledge_indexes",
            )
            routing = _writer_post_routing(state, writer_output)
            duration_ms = int((time.monotonic() - started) * 1000)
            return {
                "writer_output": writer_output,
                **routing,
                "writer_duration_ms": duration_ms,
                "stage_logs": _append_stage_log(
                    state,
                    stage="writer",
                    title="Writer used domain oracle for index inventory",
                    details=[f"pattern_id={domain_knowledge.get('pattern_id', '')}"],
                    model=MODEL_QUERY_WRITER,
                    duration_ms=duration_ms,
                ),
            }
        if preferred_tool == "splunk_run_query" and str(domain_knowledge.get("query", "")).strip():
            tool_args = dict(domain_knowledge.get("tool_args") or {})
            if not tool_args.get("query"):
                tool_args["query"] = str(domain_knowledge.get("query", "")).strip()
            planner_args = planner_output.get("tool_args", {}) if isinstance(planner_output.get("tool_args"), dict) else {}
            from minimal_question_to_answer import infer_time_window
            from question_intelligence import apply_question_time_window

            inferred_e, inferred_l = infer_time_window(question)
            tool_args.setdefault("earliest_time", str(planner_args.get("earliest_time") or inferred_e or "-7d"))
            tool_args.setdefault("latest_time", str(planner_args.get("latest_time") or inferred_l or "now"))
            apply_question_time_window(question, tool_args)
            tool_args.setdefault("row_limit", int(planner_args.get("row_limit", 50) or 50))
            writer_output = _normalize_candidate(
                {
                    "selected_tool": "splunk_run_query",
                    "tool_args": tool_args,
                    "intent": str(domain_knowledge.get("intent", mapped_template.intent)),
                    "confidence": domain_confidence,
                    "reason": f"domain_oracle:{domain_knowledge.get('pattern_id', '')}",
                    "source": "domain_knowledge",
                },
                question,
                fallback_reason="domain_knowledge_query",
            )
            routing = _writer_post_routing(state, writer_output)
            duration_ms = int((time.monotonic() - started) * 1000)
            return {
                "writer_output": writer_output,
                **routing,
                "writer_duration_ms": duration_ms,
                "stage_logs": _append_stage_log(
                    state,
                    stage="writer",
                    title="Writer used domain oracle for canonical SPL",
                    details=[f"pattern_id={domain_knowledge.get('pattern_id', '')}"],
                    model=MODEL_QUERY_WRITER,
                    duration_ms=duration_ms,
                ),
            }
    rag_context = (
        build_spl_rag_context(question, intent=planner_intent, max_chars=RAG_MAX_CHARS)
        if RAG_ENABLED
        else ""
    )
    resolved_domain_hints = build_resolved_domain_hints(question, intent=planner_intent)
    if str(planner_output.get("selected_tool", "")) != "splunk_run_query":
        if (
            mapped_template.intent in DETERMINISTIC_RUN_QUERY_INTENTS
            and _template_override_mode() != "never"
        ):
            writer_output = _normalize_candidate(
                {
                    **_build_template_aligned_plan(question, mapped_template),
                    "confidence": 0.9,
                    "reason": "writer_template_fallback_non_query_planner",
                    "source": "writer_template_fallback",
                },
                question,
                fallback_reason="writer_template_fallback",
            )
            writer_output = _revise_writer_if_invalid(question, writer_output)
            routing = _writer_post_routing(state, writer_output)
            duration_ms = int((time.monotonic() - started) * 1000)
            return {
                "writer_output": writer_output,
                **routing,
                "writer_duration_ms": duration_ms,
                "stage_logs": _append_stage_log(
                    state,
                    stage="writer",
                    title="Writer replaced non-query planner tool with template SPL",
                    details=[
                        f"planner_tool={planner_output.get('selected_tool', '')}",
                        f"template_intent={mapped_template.intent}",
                        "Deterministic template SPL used because this intent requires searchable results.",
                    ],
                    model=MODEL_QUERY_WRITER,
                    duration_ms=duration_ms,
                ),
            }
        writer_output = _normalize_candidate(
            {
                "selected_tool": planner_output.get("selected_tool", ""),
                "tool_args": planner_output.get("tool_args", {}),
                "intent": planner_output.get("intent", "unknown"),
                "confidence": planner_output.get("confidence", 0.7),
                "reason": "writer_bypass_non_query_tool",
                "source": "writer_bypass",
            },
            question,
            fallback_reason="writer_bypass_fallback",
        )
        routing = _writer_post_routing(state, writer_output)
        stage_logs = _append_stage_log(
            state,
            stage="writer",
            title="Writer preserved the bounded non-query tool choice",
            details=[
                f"selected_tool={writer_output.get('selected_tool', '')}",
                "No SPL generation was needed because the planner chose a metadata/info tool.",
            ],
            model=MODEL_QUERY_WRITER,
            duration_ms=int((time.monotonic() - started) * 1000),
        )
        if "security_review" in routing.get("skipped_nodes", []):
            stage_logs = _append_stage_log(
                {"stage_logs": stage_logs},
                stage="reviewer",
                title="Security review skipped",
                details=["Non-SPL inventory tool; security review was not required."],
                duration_ms=0,
            )
        return {
            "writer_output": writer_output,
            **routing,
            "writer_duration_ms": int((time.monotonic() - started) * 1000),
            "stage_logs": stage_logs,
        }

    from spl_writer_prompt import build_writer_system_prompt, build_writer_user_payload

    canonical_query = str(planner_output.get("canonical_template_query", "")).strip()
    if not canonical_query:
        canonical_query = str(template_to_query_args(mapped_template, question).get("query", ""))
    if domain_knowledge.get("matched") and str(domain_knowledge.get("query", "")).strip():
        canonical_query = str(domain_knowledge.get("query", "")).strip()
    system = build_writer_system_prompt(intent=planner_intent or mapped_template.intent)
    payload = build_writer_user_payload(
        question=question,
        planner_output=planner_output,
        canonical_template_query=canonical_query,
        resolved_domain_hints=resolved_domain_hints,
        rag_context=rag_context,
        field_bind_output=state.get("field_bind_output", {}) or {},
        field_strategy_output=state.get("field_strategy_output", {}) or {},
        domain_knowledge_output=domain_knowledge if domain_knowledge.get("matched") else None,
    )

    writer_output: dict[str, Any]
    try:
        writer_output = _call_ollama_json(model=MODEL_QUERY_WRITER, system_prompt=system, user_payload=payload)
        writer_output["source"] = "writer_model"
        from spl_query_schema import (
            constrained_mode_enabled,
            parse_write_plan,
            validate_write_plan,
            write_plan_to_tool_args,
        )

        if constrained_mode_enabled():
            plan = parse_write_plan(writer_output)
            if plan is not None:
                field_bind = state.get("field_bind_output", {}) or {}
                if field_bind.get("index_expr") and plan.index_expr in {"", "index=* NOT index=_*"}:
                    plan.index_expr = str(field_bind.get("index_expr"))
                if field_bind.get("sourcetype") and not plan.sourcetype:
                    plan.sourcetype = str(field_bind.get("sourcetype"))
                from spl_write_plan_slots import apply_field_bind_slots, group_by_from_role_mappings

                field_strategy = state.get("field_strategy_output", {}) or {}
                if not plan.group_by:
                    plan.group_by = group_by_from_role_mappings(
                        field_bind,
                        intent=planner_intent or mapped_template.intent,
                        field_strategy=field_strategy,
                    )
                plan = apply_field_bind_slots(
                    plan,
                    field_bind,
                    intent=planner_intent or mapped_template.intent,
                    field_strategy=field_strategy,
                )
                ok, plan_reason = validate_write_plan(plan)
                if ok:
                    tool_plan = write_plan_to_tool_args(plan, intent=planner_intent or mapped_template.intent)
                    writer_output = {**writer_output, **tool_plan, "source": "writer_constrained"}
                else:
                    writer_output["write_plan_error"] = plan_reason
    except Exception as exc:
        writer_output = {
            **_default_plan_from_template(question),
            "confidence": 0.5,
            "reason": f"writer_exception:{type(exc).__name__}:{exc}",
            "caveats": ["writer_fallback_used"],
            "source": "writer_fallback",
        }

    candidate = {
        "selected_tool": writer_output.get("selected_tool", planner_output.get("selected_tool", "")),
        "tool_args": writer_output.get("tool_args", planner_output.get("tool_args", {})),
        "intent": planner_output.get("intent", "unknown"),
        "confidence": writer_output.get("confidence", 0.5),
        "reason": writer_output.get("reason", ""),
        "source": writer_output.get("source", "writer_model"),
    }
    normalized = _normalize_candidate(candidate, question, fallback_reason="writer_normalization_fallback")
    normalized = _revise_writer_if_invalid(question, normalized)
    normalized = _enforce_question_alignment(question, normalized)
    tool_args = normalized.get("tool_args", {})
    if isinstance(tool_args, dict):
        query_text = str(tool_args.get("query", "")).strip()
        if query_text and query_conflicts_with_explicit_sourcetype(question, query_text):
            normalized.update(_build_template_aligned_plan(question, mapped_template))
            normalized["reason"] = (
                f"{normalized.get('reason', '')};writer_explicit_sourcetype_realigned"
            ).strip(";")
            normalized["source"] = "writer_explicit_sourcetype_guard"
    normalized = _normalize_candidate(normalized, question, fallback_reason="writer_post_alignment_normalization")
    tool_args = normalized.get("tool_args", {})
    if isinstance(tool_args, dict) and str(tool_args.get("query", "")).strip():
        from spl_query_normalize import normalize_writer_query

        query = normalize_writer_query(str(tool_args.get("query", "")))
        query = normalize_query_index_aliases(query, load_environment_profile())
        if domain_knowledge.get("matched"):
            from spl_domain_knowledge import apply_domain_postprocess

            query = apply_domain_postprocess(
                query,
                question=question,
                intent=str(domain_knowledge.get("intent", "")),
                bound=domain_knowledge,
            )
        tool_args = dict(tool_args)
        tool_args["query"] = query
        normalized["tool_args"] = tool_args
    routing = _writer_post_routing(state, normalized)
    stage_logs = _append_stage_log(
        state,
        stage="writer",
        title="Writer generated the bounded SPL candidate",
        details=[
            f"selected_tool={normalized.get('selected_tool', '')}",
            f"intent={normalized.get('intent', 'unknown')}",
            f"query={str((normalized.get('tool_args', {}) or {}).get('query', ''))[:220]}",
        ],
        model=MODEL_QUERY_WRITER,
        duration_ms=int((time.monotonic() - started) * 1000),
    )
    if "security_review" in routing.get("skipped_nodes", []):
        stage_logs = _append_stage_log(
            {"stage_logs": stage_logs},
            stage="reviewer",
            title="Security review skipped",
            details=["Inventory or non-security intent; deterministic plan passed through."],
            duration_ms=0,
        )
    return {
        "writer_output": normalized,
        **routing,
        "writer_duration_ms": int((time.monotonic() - started) * 1000),
        "stage_logs": stage_logs,
        **suggestion_patch,
    }


def spl_validate_node(state: MultiModelState) -> MultiModelState:
    """Operational-profile SPL validation using the analyst/ministral model."""
    started = time.monotonic()
    question = state["question"]
    writer_output = state.get("writer_output", {}) or {}
    planner_output = state.get("planner_output", {}) or {}
    selected_tool = str(writer_output.get("selected_tool", "")).strip()

    if selected_tool != "splunk_run_query":
        final_plan = _normalize_candidate(writer_output, question, fallback_reason="spl_validate_non_query_passthrough")
        return {
            "final_plan": final_plan,
            "spl_validate_duration_ms": int((time.monotonic() - started) * 1000),
            "stage_logs": _append_stage_log(
                state,
                stage="spl_validate",
                title="Analyst SPL validation skipped for non-query tool",
                details=[f"selected_tool={selected_tool}"],
                duration_ms=int((time.monotonic() - started) * 1000),
            ),
        }

    system = (
        "You are the operational SPL validator in a guarded Splunk workflow. "
        "Review the writer SPL for syntactic correctness, read-only scope, and alignment with the planner intent. "
        "Return strict JSON keys: approved, confidence, issues, revised_tool_args, rationale, caveats. "
        "Only propose read-only actions and bounded row limits."
    )
    payload = {
        "question": question,
        "planner_output": planner_output,
        "writer_output": writer_output,
    }
    validate_output: dict[str, Any]
    try:
        validate_output = _call_ollama_json(model=MODEL_ANALYST_REVIEWER, system_prompt=system, user_payload=payload)
        validate_output["source"] = "analyst_spl_validator_model"
    except Exception as exc:
        validate_output = {
            "approved": True,
            "confidence": 0.5,
            "issues": [f"spl_validate_exception:{type(exc).__name__}:{exc}"],
            "revised_tool_args": writer_output.get("tool_args", {}),
            "rationale": "spl_validate_fallback_pass_through",
            "caveats": ["spl_validate_fallback_used"],
            "source": "spl_validate_fallback",
        }

    writer_tool_args = writer_output.get("tool_args", {})
    if not isinstance(writer_tool_args, dict):
        writer_tool_args = {}
    revised_tool_args = validate_output.get("revised_tool_args", writer_tool_args)
    if not isinstance(revised_tool_args, dict):
        revised_tool_args = writer_tool_args
    merged_tool_args = {**writer_tool_args, **revised_tool_args}
    candidate = {
        "selected_tool": writer_output.get("selected_tool", ""),
        "tool_args": merged_tool_args,
        "intent": writer_output.get("intent", planner_output.get("intent", "unknown")),
        "confidence": validate_output.get("confidence", writer_output.get("confidence", 0.5)),
        "reason": validate_output.get("rationale", writer_output.get("reason", "")),
        "source": validate_output.get("source", "analyst_spl_validator_model"),
    }
    final_plan = _normalize_candidate(candidate, question, fallback_reason="spl_validate_normalization_fallback")
    return {
        "final_plan": final_plan,
        "spl_validate_duration_ms": int((time.monotonic() - started) * 1000),
        "stage_logs": _append_stage_log(
            state,
            stage="spl_validate",
            title="Analyst model validated the operational SPL candidate",
            details=[
                f"approved={validate_output.get('approved', True)}",
                f"issues={len(validate_output.get('issues', []) if isinstance(validate_output.get('issues'), list) else [])}",
                str(validate_output.get("rationale", ""))[:220],
            ],
            model=MODEL_ANALYST_REVIEWER,
            duration_ms=int((time.monotonic() - started) * 1000),
        ),
    }


def security_review_node(state: MultiModelState) -> MultiModelState:
    started = time.monotonic()
    if not requires_security_review(_review_profile_for_state(state)):
        writer_output = state.get("writer_output", {}) or {}
        return {
            "reviewer_output": {
                "approved": True,
                "confidence": 1.0,
                "issues": [],
                "improvements": [],
                "revised_selected_tool": writer_output.get("selected_tool", ""),
                "revised_tool_args": writer_output.get("tool_args", {}),
                "rationale": "non_security_profile_bypass",
                "caveats": [],
                "source": "security_review_skipped",
            },
            "final_plan": state.get("final_plan", {}) or writer_output,
            "security_review_duration_ms": 0,
            "skipped_nodes": _merge_skipped_nodes(state, "security_review"),
            "stage_logs": _append_stage_log(
                state,
                stage="reviewer",
                title="Security review skipped",
                details=["Review profile does not require Foundation-Sec security review."],
                duration_ms=0,
            ),
        }
    question = state["question"]
    rag_context = build_spl_rag_context(question, max_chars=RAG_MAX_CHARS) if RAG_ENABLED else ""
    planner_output = state.get("planner_output", {}) or {}
    writer_output = state.get("writer_output", {}) or {}
    planner_intent = str(planner_output.get("intent", "")).strip()
    writer_query = str((writer_output.get("tool_args", {}) or {}).get("query", ""))
    system = (
        "You are the reviewer / critic in a guarded Splunk workflow. "
        "Review the generated SPL against the planner intent and strategy. "
        "Prefer the canonical template/query shape when it is already environment-aligned and safer than the writer candidate. "
        "Be conservative. Do not propose cosmetic rewrites or generic safety edits when the query already scopes to explicit non-internal indexes and passes the stated intent. "
        "Return JSON keys: approved, confidence, issues, improvements, revised_selected_tool, revised_tool_args, rationale, caveats. "
        "Only propose read-only actions and bounded row limits."
    )
    payload = {
        "question": question,
        "planner_output": planner_output,
        "writer_output": writer_output,
        "canonical_template_query": str(planner_output.get("canonical_template_query", "")),
        "review_goals": [
            "check that the SPL matches the user goal",
            "identify bad assumptions or field mistakes",
            "identify anti-patterns and missing filters",
            "propose a safer or more informative read-only rewrite when needed",
        ],
        "rag_context": rag_context,
        "windows_event_code_context": build_event_code_reviewer_context(
            question=question,
            intent=planner_intent,
            query=writer_query,
        ),
    }

    reviewer_output: dict[str, Any]
    try:
        reviewer_output = _call_ollama_json(model=MODEL_SECURITY_REVIEWER, system_prompt=system, user_payload=payload)
        reviewer_output["source"] = "security_reviewer_model"
    except Exception as exc:
        reviewer_output = {
            "approved": True,
            "confidence": 0.5,
            "issues": [f"reviewer_exception:{type(exc).__name__}:{exc}"],
            "improvements": [],
            "revised_selected_tool": writer_output.get("selected_tool", ""),
            "revised_tool_args": writer_output.get("tool_args", {}),
            "rationale": "reviewer_fallback_pass_through",
            "caveats": ["reviewer_fallback_used"],
            "source": "reviewer_fallback",
        }

    revised_tool_args = reviewer_output.get("revised_tool_args", writer_output.get("tool_args", {}))
    if not isinstance(revised_tool_args, dict):
        revised_tool_args = {}
    writer_tool_args = writer_output.get("tool_args", {})
    if not isinstance(writer_tool_args, dict):
        writer_tool_args = {}
    merged_tool_args = {**writer_tool_args, **revised_tool_args}
    candidate = {
        "selected_tool": reviewer_output.get("revised_selected_tool", writer_output.get("selected_tool", "")),
        "tool_args": merged_tool_args,
        "intent": planner_output.get("intent", "unknown"),
        "confidence": reviewer_output.get("confidence", 0.5),
        "reason": reviewer_output.get("rationale", ""),
        "source": reviewer_output.get("source", "security_reviewer_model"),
    }
    normalized = _normalize_candidate(candidate, question, fallback_reason="reviewer_normalization_fallback")
    reviewer_output["normalized_candidate"] = normalized
    reviewer_approved = bool(reviewer_output.get("approved", False))
    reviewer_issues = reviewer_output.get("issues", [])
    reviewer_issue_count = len(reviewer_issues) if isinstance(reviewer_issues, list) else 0
    skip_peer_review = reviewer_approved and reviewer_issue_count == 0
    peer_review_enabled = _topology_settings().get("peer_review", True)
    return {
        "reviewer_output": reviewer_output,
        "final_plan": normalized if (skip_peer_review or not peer_review_enabled) else state.get("final_plan", {}),
        "security_review_duration_ms": int((time.monotonic() - started) * 1000),
        "stage_logs": _append_stage_log(
            state,
            stage="reviewer",
            title="Reviewer critiqued the writer output",
            details=[
                f"approved={reviewer_output.get('approved', True)}",
                f"issues={reviewer_issue_count}",
                f"skip_peer_review={skip_peer_review}",
                str(reviewer_output.get("rationale", ""))[:220],
            ],
            model=MODEL_SECURITY_REVIEWER,
            duration_ms=int((time.monotonic() - started) * 1000),
        ),
    }


def peer_review_node(state: MultiModelState) -> MultiModelState:
    started = time.monotonic()
    question = state["question"]
    writer_output = state.get("writer_output", {}) or {}
    reviewer_output = state.get("reviewer_output", {}) or {}
    reviewer_candidate = reviewer_output.get("normalized_candidate", {})

    system = (
        "You are a peer-review SOC judge. Choose the better candidate between the writer and reviewer candidates. "
        "Prefer safer read-only and higher investigative value. "
        "Return JSON keys: winner (writer|reviewer), confidence, rationale, concerns."
    )
    payload = {
        "question": question,
        "writer_candidate": writer_output,
        "reviewer_candidate": reviewer_candidate,
    }

    judge_output: dict[str, Any]
    try:
        judge_output = _call_ollama_json(model=MODEL_PEER_REVIEWER, system_prompt=system, user_payload=payload)
        judge_output["source"] = "peer_reviewer_model"
    except Exception as exc:
        judge_output = {
            "winner": "reviewer",
            "confidence": 0.5,
            "rationale": f"judge_exception:{type(exc).__name__}:{exc}; default reviewer",
            "concerns": ["judge_fallback_triggered"],
            "source": "judge_fallback",
        }

    winner = str(judge_output.get("winner", "reviewer")).strip().lower()
    selected_candidate = reviewer_candidate if winner == "reviewer" else writer_output
    final_plan = _normalize_candidate(selected_candidate, question, fallback_reason="judge_selection_fallback")

    return {
        "judge_output": judge_output,
        "final_plan": final_plan,
        "peer_review_duration_ms": int((time.monotonic() - started) * 1000),
        "stage_logs": _append_stage_log(
            state,
            stage="peer_review_1",
            title="Peer reviewer 1 adjudicated writer vs reviewer",
            details=[
                f"winner={winner}",
                str(judge_output.get("rationale", ""))[:220],
            ],
            model=MODEL_PEER_REVIEWER,
            duration_ms=int((time.monotonic() - started) * 1000),
        ),
    }


def peer_review_2_node(state: MultiModelState) -> MultiModelState:
    started = time.monotonic()
    question = state["question"]
    writer_output = state.get("writer_output", {}) or {}
    reviewer_output = state.get("reviewer_output", {}) or {}
    reviewer_candidate = reviewer_output.get("normalized_candidate", {})
    judge1_output = state.get("judge_output", {}) or {}
    judge1_winner = str(judge1_output.get("winner", "reviewer")).strip().lower()
    judge1_winner = "reviewer" if judge1_winner not in {"writer", "reviewer"} else judge1_winner

    system = (
        "You are peer-review SOC judge #2. Verify or override peer reviewer #1 decision. "
        "Choose winner among writer and reviewer candidates using only read-only and investigative-value criteria. "
        "Return JSON keys: winner (writer|reviewer), confidence, rationale, concerns, agrees_with_peer1 (true|false)."
    )
    payload = {
        "question": question,
        "writer_candidate": writer_output,
        "reviewer_candidate": reviewer_candidate,
        "peer1_decision": judge1_output,
    }

    judge2_output: dict[str, Any]
    try:
        judge2_output = _call_ollama_json(model=MODEL_PEER_REVIEWER_2, system_prompt=system, user_payload=payload)
        judge2_output["source"] = "peer_reviewer_2_model"
    except Exception as exc:
        judge2_output = {
            "winner": judge1_winner,
            "confidence": 0.5,
            "rationale": f"peer2_exception:{type(exc).__name__}:{exc}; default peer1 winner",
            "concerns": ["peer2_fallback_triggered"],
            "agrees_with_peer1": True,
            "source": "peer2_fallback",
        }

    winner = str(judge2_output.get("winner", judge1_winner)).strip().lower()
    winner = "reviewer" if winner not in {"writer", "reviewer"} else winner
    selected_candidate = reviewer_candidate if winner == "reviewer" else writer_output
    final_plan = _normalize_candidate(selected_candidate, question, fallback_reason="peer2_selection_fallback")

    return {
        "judge2_output": judge2_output,
        "final_plan": final_plan,
        "peer_review_2_duration_ms": int((time.monotonic() - started) * 1000),
        "stage_logs": _append_stage_log(
            state,
            stage="peer_review_2",
            title="Peer reviewer 2 verified or overrode the first adjudication",
            details=[
                f"winner={winner}",
                f"agrees_with_peer1={judge2_output.get('agrees_with_peer1', True)}",
                str(judge2_output.get("rationale", ""))[:220],
            ],
            model=MODEL_PEER_REVIEWER_2,
            duration_ms=int((time.monotonic() - started) * 1000),
        ),
    }


def validate_final_plan_node(state: MultiModelState) -> MultiModelState:
    started = time.monotonic()
    if not state.get("supported", False):
        return {
            "validation_ok": False,
            "validation_reason": state.get("validation_reason", "unsupported"),
            "validation_duration_ms": int((time.monotonic() - started) * 1000),
        }

    question = state["question"]
    analytical_execution = (
        (state.get("planner_output", {}) or {}).get("analytical_plan_execution", {})
    )
    analytical_preferred = bool(
        isinstance(analytical_execution, dict)
        and analytical_execution.get("selected")
        and str((state.get("writer_output", {}) or {}).get("source", ""))
        == "analytical_plan_compiler"
    )
    if analytical_preferred:
        plan = dict(state.get("writer_output", {}) or {})
    else:
        plan = state.get("final_plan", {}) or state.get("writer_output", {}) or {}
        plan = _normalize_candidate(plan, question, fallback_reason="final_plan_normalization_fallback")
        plan = _enforce_question_alignment(question, plan)
        plan = _normalize_candidate(plan, question, fallback_reason="post_alignment_normalization_fallback")
        plan = _apply_learning_assets(question, plan)
        plan = _normalize_candidate(plan, question, fallback_reason="post_learning_assets_normalization_fallback")

    tool = plan.get("selected_tool", "")
    args = plan.get("tool_args", {})
    if tool not in ALLOWED_TOOLS:
        return {
            "supported": False,
            "guardrail_reason": f"Selected tool blocked by allowlist: {tool}",
            "validation_ok": False,
            "validation_reason": f"tool_not_allowed:{tool}",
            "final_plan": plan,
            "validation_duration_ms": int((time.monotonic() - started) * 1000),
        }

    if tool == "splunk_run_query":
        args_current = args if isinstance(args, dict) else {}
        repair_meta: dict[str, Any] = {}
        intent_name = str(plan.get("intent", "")).strip()
        for attempt_idx in range(3):
            validation_passes = 2 if attempt_idx == 0 else 1
            for validation_pass in range(validation_passes):
                ok, reason = validate_query_args(args_current, question=question)
                if not ok:
                    failure_reason = f"policy:{reason}"
                else:
                    contract_ok, contract_reason = validate_query_for_intent(
                        intent_name,
                        args_current,
                        question=str(state.get("question", "")),
                    )
                    if not contract_ok:
                        failure_reason = f"intent_contract:{contract_reason}"
                    else:
                        query_text = str(args_current.get("query", "")).strip()
                        _profile_for_norm = load_environment_profile()
                        query_text = normalize_query_index_aliases(query_text, _profile_for_norm)
                        if query_text and not re.search(r"\|\s*append\s*\[", query_text, flags=re.IGNORECASE):
                            from spl_query_normalize import drop_invented_sourcetypes

                            # Applies to every query source (writer-model AND canonical
                            # templates): if a sourcetype OR list has at least one known
                            # alternative, drop only the unknown member(s) instead of
                            # letting validate_structure hard-block the whole query.
                            query_text = drop_invented_sourcetypes(query_text, profile=_profile_for_norm)
                        if query_text:
                            args_current = dict(args_current)
                            args_current["query"] = query_text
                        from spl_structure_validate import validate_structure

                        structure_ok, structure_reason = validate_structure(
                            query_text,
                            intent=intent_name,
                            question=question,
                        )
                        if not structure_ok:
                            failure_reason = f"structure:{structure_reason}"
                        else:
                            coherence_ok, coherence_reason = validate_platform_sourcetype_coherence(query_text, intent_name)
                            if not coherence_ok:
                                failure_reason = f"platform_coherence:{coherence_reason}"
                            else:
                                scope_ok, scope_reason = validate_intent_platform_scope(
                                    query_text,
                                    intent_name,
                                    question=question,
                                )
                                if not scope_ok:
                                    failure_reason = f"platform_scope:{scope_reason}"
                                else:
                                    from spl_domain_knowledge import validate_query_against_domain_knowledge

                                    domain_ok, domain_reason = validate_query_against_domain_knowledge(
                                        query_text,
                                        question=question,
                                        intent=intent_name,
                                    )
                                    if not domain_ok:
                                        failure_reason = f"domain:{domain_reason}"
                                    else:
                                        env_ok, env_reason = validate_query_against_environment(args_current)
                                        if not env_ok:
                                            failure_reason = f"environment:{env_reason}"
                                        else:
                                            if isinstance(args_current, dict):
                                                args_current.pop("_env_constraints_applied", None)
                                            plan["tool_args"] = args_current
                                            result_payload: dict[str, Any] = {
                                                "final_plan": plan,
                                                "validation_ok": True,
                                                "validation_reason": "plan_valid",
                                                "validation_duration_ms": int((time.monotonic() - started) * 1000),
                                                "stage_logs": _append_stage_log(
                                                    state,
                                                    stage="validation",
                                                    title="Deterministic validation approved the plan",
                                                    details=[
                                                        f"intent={intent_name}",
                                                        f"selected_tool={plan.get('selected_tool', '')}",
                                                        "Policy, intent contract, platform coherence, and environment checks passed.",
                                                    ],
                                                    duration_ms=int((time.monotonic() - started) * 1000),
                                                ),
                                            }
                                            if repair_meta:
                                                result_payload["query_repair"] = repair_meta
                                                result_payload["validation_reason"] = "plan_valid_after_auto_repair"
                                            return result_payload

                if (
                    attempt_idx == 0
                    and validation_pass == 0
                    and failure_reason.startswith("intent_contract:")
                ):
                    from spl_domain_knowledge import bind_domain_knowledge_for_plan

                    bound = bind_domain_knowledge_for_plan(question, {"intent": intent_name, "tool_args": args_current})
                    if bound.get("matched") and str(bound.get("query", "")).strip():
                        args_current = dict(bound.get("tool_args") or {})
                        args_current["query"] = str(bound.get("query", "")).strip()
                        plan = dict(plan)
                        plan["tool_args"] = args_current
                        plan["intent"] = str(bound.get("intent", intent_name))
                        plan["source"] = "domain_knowledge_contract_repair"
                        intent_name = str(plan.get("intent", intent_name)).strip()
                        repair_meta = {**(repair_meta or {}), "domain_contract_repair": True}
                        continue

                break

            if analytical_preferred:
                failed_reason = failure_reason
                plan = _default_plan_from_template(question)
                args_current = (
                    plan.get("tool_args", {})
                    if isinstance(plan.get("tool_args", {}), dict)
                    else {}
                )
                intent_name = str(plan.get("intent", "")).strip()
                analytical_preferred = False
                repair_meta = {
                    "analytical_plan_fallback_applied": True,
                    "analytical_plan_failure_reason": failed_reason,
                    "legacy_source": plan.get("source", "fallback"),
                }
                continue

            if attempt_idx == 1 and _template_override_mode() != "never":
                mapped_template = map_question_to_template(question)
                plan = _build_template_aligned_plan(question, mapped_template)
                args_current = plan.get("tool_args", {}) if isinstance(plan.get("tool_args", {}), dict) else {}
                intent_name = str(plan.get("intent", "")).strip()
                repair_meta = {
                    **(repair_meta or {}),
                    "template_fallback_applied": True,
                    "template_intent": mapped_template.intent,
                }
                continue

            if attempt_idx >= 2:
                human_reason = failure_reason
                if human_reason.startswith("intent_contract:"):
                    human_reason = f"Final query blocked by intent contract: {human_reason.split(':', 1)[1]}"
                elif human_reason.startswith("platform_coherence:"):
                    human_reason = f"Final query blocked by platform/sourcetype coherence: {human_reason.split(':', 1)[1]}"
                elif human_reason.startswith("environment:"):
                    human_reason = f"Final query blocked by environment profile: {human_reason.split(':', 1)[1]}"
                elif human_reason.startswith("policy:"):
                    human_reason = f"Final query blocked by policy: {human_reason.split(':', 1)[1]}"
                else:
                    human_reason = f"Final query blocked: {human_reason}"
                return {
                    "supported": False,
                    "guardrail_reason": human_reason,
                    "validation_ok": False,
                    "validation_reason": failure_reason,
                    "query_repair": repair_meta,
                    "final_plan": plan,
                    "validation_duration_ms": int((time.monotonic() - started) * 1000),
                    "stage_logs": _append_stage_log(
                        state,
                        stage="validation",
                        title="Deterministic validation blocked the plan",
                        details=[human_reason],
                        duration_ms=int((time.monotonic() - started) * 1000),
                    ),
                }

            if not _topology_settings().get("query_repair", True):
                return {
                    "supported": False,
                    "guardrail_reason": f"Final query blocked with query repair disabled: {failure_reason}",
                    "validation_ok": False,
                    "validation_reason": failure_reason,
                    "query_repair": {"ok": False, "disabled": True, "failure_reason": failure_reason},
                    "final_plan": plan,
                    "validation_duration_ms": int((time.monotonic() - started) * 1000),
                    "stage_logs": _append_stage_log(
                        state,
                        stage="validation",
                        title="Deterministic validation blocked the plan with repair disabled",
                        details=[f"failure_reason={failure_reason}"],
                        duration_ms=int((time.monotonic() - started) * 1000),
                    ),
                }

            repair = attempt_query_repair_once(
                question=question,
                failed_query_args=args_current,
                failure_reason=failure_reason,
                model=MODEL_QUERY_REPAIR,
                intent=str(plan.get("intent", "")).strip(),
                rag_max_chars=RAG_MAX_CHARS,
            )
            repair_meta = repair if isinstance(repair, dict) else {}
            if repair_meta.get("ok", False):
                repaired_args = repair_meta.get("args", {})
                if isinstance(repaired_args, dict):
                    args_current = repaired_args
                    plan["reason"] = f"{plan.get('reason', '')};auto_repair:{repair_meta.get('repair_reason', '')}".strip(";")
                    continue
            if _template_override_mode() != "never":
                mapped_template = map_question_to_template(question)
                plan = _build_template_aligned_plan(question, mapped_template)
                args_current = plan.get("tool_args", {}) if isinstance(plan.get("tool_args", {}), dict) else {}
                intent_name = str(plan.get("intent", "")).strip()
                repair_meta = {
                    **(repair_meta or {}),
                    "template_fallback_applied": True,
                    "template_intent": mapped_template.intent,
                }
                continue
            return {
                "supported": False,
                "guardrail_reason": f"Final query blocked after repair attempt: {failure_reason}",
                "validation_ok": False,
                "validation_reason": failure_reason,
                "query_repair": repair_meta,
                "final_plan": plan,
                "validation_duration_ms": int((time.monotonic() - started) * 1000),
                "stage_logs": _append_stage_log(
                    state,
                    stage="validation",
                    title="Deterministic validation blocked the plan after repair",
                    details=[f"failure_reason={failure_reason}"],
                    duration_ms=int((time.monotonic() - started) * 1000),
                ),
            }

    if tool == "splunk_get_metadata":
        ok, reason = _validate_metadata_args(args if isinstance(args, dict) else {})
        if not ok:
            return {
                "supported": False,
                "guardrail_reason": f"Final metadata args blocked by policy: {reason}",
                "validation_ok": False,
                "validation_reason": reason,
                "final_plan": plan,
                "validation_duration_ms": int((time.monotonic() - started) * 1000),
            }

    return {
        "final_plan": plan,
        "validation_ok": True,
        "validation_reason": "plan_valid",
        "validation_duration_ms": int((time.monotonic() - started) * 1000),
        "stage_logs": _append_stage_log(
            state,
            stage="validation",
            title="Deterministic validation approved the non-query tool plan",
            details=[f"selected_tool={plan.get('selected_tool', '')}"],
            duration_ms=int((time.monotonic() - started) * 1000),
        ),
    }


def _validate_field_policy_plan(
    plan: dict[str, Any],
    *,
    question: str,
    field_strategy: dict[str, Any] | None = None,
) -> tuple[bool, str]:
    """Re-run every deterministic pre-execution gate after field rewriting."""
    if str(plan.get("selected_tool", "")).strip() != "splunk_run_query":
        return True, "field_policy_non_query_passthrough"
    args = plan.get("tool_args", {}) if isinstance(plan.get("tool_args"), dict) else {}
    intent = str(plan.get("intent", "")).strip()
    ok, reason = validate_query_args(args, question=question)
    if not ok:
        return False, f"policy:{reason}"
    ok, reason = validate_query_for_intent(
        intent,
        args,
        field_strategy=field_strategy,
        question=question,
    )
    if not ok:
        return False, f"intent_contract:{reason}"
    query = str(args.get("query", "")).strip()
    if query:
        from spl_query_normalize import drop_invented_sourcetypes

        query = drop_invented_sourcetypes(query, profile=load_environment_profile())
        args = dict(args)
        args["query"] = query
    from spl_structure_validate import validate_structure

    ok, reason = validate_structure(query, intent=intent, question=question)
    if not ok:
        return False, f"structure:{reason}"
    ok, reason = validate_platform_sourcetype_coherence(query, intent)
    if not ok:
        return False, f"platform_coherence:{reason}"
    ok, reason = validate_intent_platform_scope(query, intent, question=question)
    if not ok:
        return False, f"platform_scope:{reason}"
    from spl_domain_knowledge import validate_query_against_domain_knowledge

    ok, reason = validate_query_against_domain_knowledge(query, question=question, intent=intent)
    if not ok:
        return False, f"domain:{reason}"
    ok, reason = validate_query_against_environment(args)
    if not ok:
        return False, f"environment:{reason}"
    return True, "field_policy_valid"


def field_policy_node(state: MultiModelState) -> MultiModelState:
    """Apply one shared fields-first rewrite after all candidate/repair paths."""
    started = time.monotonic()
    plan = state.get("final_plan", {}) or {}
    from spl_field_strategy import apply_field_policy_to_plan

    rewritten, policy = apply_field_policy_to_plan(
        plan,
        state.get("field_strategy_output", {}) or {},
    )
    ok, reason = _validate_field_policy_plan(
        rewritten,
        question=str(state.get("question", "")),
        field_strategy=state.get("field_strategy_output", {}) or {},
    )
    duration_ms = int((time.monotonic() - started) * 1000)
    policy = {**policy, "validation_ok": ok, "validation_reason": reason}
    return {
        "final_plan": rewritten,
        "field_policy_output": policy,
        "field_policy_duration_ms": duration_ms,
        "validation_ok": ok,
        "validation_reason": reason,
        "supported": bool(state.get("supported", True)) and ok,
        "guardrail_reason": (
            str(state.get("guardrail_reason", ""))
            if ok
            else f"Final query blocked after fields-first rewrite: {reason}"
        ),
        "stage_logs": _append_stage_log(
            state,
            stage="field_policy",
            title="Fields-first policy approved the final SPL" if ok else "Fields-first policy blocked the final SPL",
            details=[
                f"changed={bool(policy.get('changed'))}",
                f"actions={policy.get('actions', [])}",
                f"validation={reason}",
            ],
            duration_ms=duration_ms,
        ),
    }


def semantic_gate_node(state: MultiModelState) -> MultiModelState:
    """Score final rewritten SPL; observe logs, prefer fails closed on typed semantics."""
    started = time.monotonic()
    from spl_plan_migration import analytical_planner_mode
    from spl_semantic_coverage import evaluate_semantic_coverage

    mode = analytical_planner_mode()
    plan = state.get("final_plan", {}) or {}
    planner_output = state.get("planner_output", {}) or {}
    selected_tool = str(plan.get("selected_tool", "")).strip()
    raw_plan = plan.get("analytical_plan")
    if raw_plan is None:
        status = planner_output.get("analytical_plan_status", {})
        if isinstance(status, dict) and status.get("valid"):
            raw_plan = planner_output.get("analytical_plan")

    duration_ms = int((time.monotonic() - started) * 1000)
    if selected_tool != "splunk_run_query" or raw_plan is None:
        reason = (
            "semantic_gate_non_query_passthrough"
            if selected_tool != "splunk_run_query"
            else "semantic_gate_no_valid_typed_plan_compatibility"
        )
        report = {
            "mode": mode,
            "enforced": False,
            "decision": "compatibility_passthrough",
            "passed": True,
            "skipped": True,
            "reason": reason,
            "live_evidence": {
                "status": "pending_candidate_probe",
                "score": None,
                "reason": "scored_by_semantic_candidate_selector",
            },
        }
        return {
            "semantic_coverage_output": report,
            "semantic_gate_duration_ms": duration_ms,
            "stage_logs": _append_stage_log(
                state,
                stage="semantic_gate",
                title="Semantic coverage gate used compatibility passthrough",
                details=[f"mode={mode}", f"reason={reason}"],
                duration_ms=duration_ms,
            ),
        }

    args = plan.get("tool_args", {}) if isinstance(plan.get("tool_args"), dict) else {}
    report = evaluate_semantic_coverage(
        question=str(state.get("question", "")),
        analytical_plan=raw_plan,
        query_args=args,
        field_strategy=state.get("field_strategy_output", {}) or {},
        safety_ok=bool(state.get("validation_ok", False)),
        safety_reason=str(state.get("validation_reason", "pre_execution_validation_failed")),
    )
    report["mode"] = mode
    report["skipped"] = False
    if mode == "observe":
        report["enforced"] = False
        report["decision"] = "observe_only"
        validation_ok = bool(state.get("validation_ok", False))
        validation_reason = str(state.get("validation_reason", ""))
        supported = bool(state.get("supported", True))
        guardrail_reason = str(state.get("guardrail_reason", ""))
    else:
        report["enforced"] = True
        validation_ok = bool(state.get("validation_ok", False)) and bool(report.get("passed", False))
        report["decision"] = "approved" if validation_ok else "blocked"
        validation_reason = (
            str(state.get("validation_reason", ""))
            if validation_ok
            else "semantic_coverage_failed"
        )
        supported = bool(state.get("supported", True)) and validation_ok
        guardrail_reason = (
            str(state.get("guardrail_reason", ""))
            if validation_ok
            else "Final query blocked by deterministic semantic coverage: "
            + ";".join(str(item) for item in report.get("hard_failures", [])[:6])
        )
    duration_ms = int((time.monotonic() - started) * 1000)
    return {
        "semantic_coverage_output": report,
        "semantic_gate_duration_ms": duration_ms,
        "validation_ok": validation_ok,
        "validation_reason": validation_reason,
        "supported": supported,
        "guardrail_reason": guardrail_reason,
        "query_repair": {
            **(state.get("query_repair", {}) or {}),
            "semantic_plan_repair_feedback": report.get("repair_feedback", {}),
        },
        "stage_logs": _append_stage_log(
            state,
            stage="semantic_gate",
            title=(
                "Semantic coverage gate observed the final SPL"
                if mode == "observe"
                else (
                    "Semantic coverage gate approved the final SPL"
                    if validation_ok
                    else "Semantic coverage gate blocked the final SPL"
                )
            ),
            details=[
                f"mode={mode}",
                f"enforced={report.get('enforced', False)}",
                f"static_score={report.get('static_score', 0.0)}",
                f"plan_score={(report.get('plan', {}) or {}).get('score', 0.0)}",
                f"spl_score={(report.get('spl', {}) or {}).get('score', 0.0)}",
                f"output_schema_score={(report.get('output_schema', {}) or {}).get('score', 0.0)}",
                f"hard_failures={len(report.get('hard_failures', []))}",
                "live_evidence=pending_candidate_probe",
            ],
            model="deterministic_semantic_coverage",
            duration_ms=duration_ms,
        ),
    }


def _score_candidate_for_selection(
    state: MultiModelState,
    candidate: dict[str, Any],
    *,
    canonical_plan: Any,
    candidate_source: str,
) -> dict[str, Any] | None:
    """Apply final deterministic rewrites and static coverage to one candidate."""
    from spl_field_strategy import apply_field_policy_to_plan
    from spl_semantic_coverage import evaluate_semantic_coverage

    rewritten, _ = apply_field_policy_to_plan(
        candidate,
        state.get("field_strategy_output", {}) or {},
    )
    ok, reason = _validate_field_policy_plan(
        rewritten,
        question=str(state.get("question", "")),
        field_strategy=state.get("field_strategy_output", {}) or {},
    )
    raw_plan = rewritten.get("analytical_plan") or canonical_plan
    if raw_plan is None:
        report = {
            "passed": ok,
            "static_score": 0.5 if ok else 0.0,
            "hard_failures": [] if ok else [f"safety:{reason}"],
            "spec": {},
            "compatibility_candidate": True,
        }
    else:
        try:
            report = evaluate_semantic_coverage(
                question=str(state.get("question", "")),
                analytical_plan=raw_plan,
                query_args=rewritten.get("tool_args", {})
                if isinstance(rewritten.get("tool_args"), dict)
                else {},
                field_strategy=state.get("field_strategy_output", {}) or {},
                safety_ok=ok,
                safety_reason=reason,
            )
        except Exception:
            return None
    rewritten["semantic_coverage"] = report
    rewritten["candidate_source"] = candidate_source
    return rewritten


def _collect_semantic_candidates(state: MultiModelState) -> list[dict[str, Any]]:
    """Collect primary, structured-repair, and fallback candidates for ranking."""
    from spl_plan_migration import compile_bound_analytical_plan

    question = str(state.get("question", ""))
    planner_output = state.get("planner_output", {}) or {}
    final_plan = state.get("final_plan", {}) or {}
    canonical_plan = final_plan.get("analytical_plan")
    if canonical_plan is None:
        status = planner_output.get("analytical_plan_status", {})
        if isinstance(status, dict) and status.get("valid"):
            canonical_plan = planner_output.get("analytical_plan")

    candidates: list[dict[str, Any]] = []
    final_candidate = _score_candidate_for_selection(
        state,
        final_plan,
        canonical_plan=canonical_plan,
        candidate_source=str(final_plan.get("source", "primary_final")) or "primary_final",
    )
    if final_candidate is not None:
        candidates.append(final_candidate)

    execution = planner_output.get("analytical_plan_execution", {})
    execution = execution if isinstance(execution, dict) else {}
    plan_payloads: list[tuple[str, Any]] = []
    if execution.get("repair_succeeded") and execution.get("repaired_plan") is not None:
        plan_payloads.append(("structured_plan_repair", execution.get("repaired_plan")))
    raw_plan = planner_output.get("analytical_plan")
    if raw_plan is not None and not plan_payloads:
        plan_payloads.append(("primary_typed_plan", raw_plan))
    for source, payload in plan_payloads:
        try:
            compiled = compile_bound_analytical_plan(
                question,
                payload,
                intent=str(planner_output.get("intent", "")).strip(),
                field_bind=state.get("field_bind_output", {}) or {},
                field_strategy=state.get("field_strategy_output", {}) or {},
            )
        except Exception:
            continue
        scored = _score_candidate_for_selection(
            state,
            compiled,
            canonical_plan=payload,
            candidate_source=source,
        )
        if scored is not None:
            candidates.append(scored)

    fallback = _default_plan_from_template(question)
    fallback_scored = _score_candidate_for_selection(
        state,
        fallback,
        canonical_plan=canonical_plan,
        candidate_source="compiled_template_fallback",
    )
    if fallback_scored is not None:
        candidates.append(fallback_scored)
    return candidates


def semantic_candidate_select_node(state: MultiModelState) -> MultiModelState:
    """Probe and rank a bounded candidate set before the full tool execution."""
    started = time.monotonic()
    from semantic_candidate_select import new_query_budget, select_semantic_candidate
    from spl_plan_migration import analytical_planner_mode

    mode = analytical_planner_mode()
    candidates = _collect_semantic_candidates(state)

    def probe_runner(args: dict[str, Any], timeout_seconds: float) -> dict[str, Any]:
        return run_splunk_query_args(
            args,
            intent="semantic_candidate_probe",
            summary_hint="bounded semantic evidence probe",
            timeout_seconds=timeout_seconds,
            max_attempts=1,
        )

    result = select_semantic_candidate(
        candidates=candidates,
        mode=mode,
        probe_runner=probe_runner,
        query_budget=state.get("query_budget_output") or new_query_budget(),
    )
    selected = result.get("selected_candidate", {})
    blocked = bool(result.get("blocked"))
    duration_ms = int((time.monotonic() - started) * 1000)
    payload: dict[str, Any] = {
        "semantic_candidate_output": result,
        "semantic_candidate_duration_ms": duration_ms,
        "query_budget_output": result.get("query_budget", {}),
        "confidence_cap": float(result.get("confidence_cap", 0.6) or 0.6),
        "validation_ok": bool(state.get("validation_ok", False)) and not blocked,
        "validation_reason": (
            "semantic_candidate_evidence_failed"
            if blocked
            else str(state.get("validation_reason", ""))
        ),
        "supported": bool(state.get("supported", True)) and not blocked,
        "guardrail_reason": (
            "No candidate satisfied enforced static and live evidence constraints."
            if blocked
            else str(state.get("guardrail_reason", ""))
        ),
        "stage_logs": _append_stage_log(
            state,
            stage="semantic_candidate_select",
            title=(
                "Semantic candidate selector blocked execution"
                if blocked
                else "Semantic candidate selector ranked bounded probes"
            ),
            details=[
                f"mode={mode}",
                f"candidates={result.get('candidate_count', 0)}",
                f"probes={result.get('probes_used', 0)}",
                f"selected={result.get('selected_candidate_id', '')}",
                f"query_budget_used={(result.get('query_budget', {}) or {}).get('used', 0)}",
            ],
            model="deterministic_candidate_evidence",
            duration_ms=duration_ms,
        ),
    }
    if isinstance(selected, dict) and selected and not blocked:
        selected.pop("live_evidence", None)
        selected.pop("candidate_id", None)
        payload["final_plan"] = selected
    return payload


def run_tool_node(state: MultiModelState) -> MultiModelState:
    started = time.monotonic()
    if not state.get("validation_ok", False):
        return {
            "splunk_data": {},
            "run_tool_duration_ms": int((time.monotonic() - started) * 1000),
        }

    plan = state.get("final_plan", {}) or {}
    tool = str(plan.get("selected_tool", ""))
    args = plan.get("tool_args", {}) if isinstance(plan.get("tool_args", {}), dict) else {}
    query_budget = state.get("query_budget_output", {}) or {}
    started = time.monotonic()
    profile_structured = None
    if tool == "splunk_run_query" and str(plan.get("intent", "")).strip() == "top_indexes":
        profile_structured = profile_inventory_structured_results(str(state.get("question", "")))

    if profile_structured is not None:
        data = {
            "structured": profile_structured,
            "source": "environment_profile_index_activity",
            "profile_first": True,
        }
    elif tool == "splunk_get_indexes":
        data = run_splunk_get_indexes()
    elif tool == "splunk_get_info":
        data = run_splunk_get_info()
    elif tool == "splunk_get_metadata":
        data = run_splunk_get_metadata(args)
    else:
        from semantic_candidate_select import reserve_query

        reserved, query_budget = reserve_query(
            query_budget,
            purpose="selected_candidate_execution",
            candidate_id=str(
                (state.get("semantic_candidate_output", {}) or {}).get(
                    "selected_candidate_id",
                    "",
                )
            ),
        )
        if not reserved:
            return {
                "splunk_data": {},
                "query_budget_output": query_budget,
                "validation_ok": False,
                "validation_reason": "global_query_budget_exhausted",
                "supported": False,
                "guardrail_reason": "The bounded live-query budget was exhausted before execution.",
                "run_tool_duration_ms": int((time.monotonic() - started) * 1000),
            }
        data = run_splunk_query_args(
            args,
            intent=str(plan.get("intent", "multi_model_query")),
            summary_hint="Summarize evidence, suspicious patterns, and next investigation action.",
        )

    data["execution_ms"] = int((time.monotonic() - started) * 1000)
    data["selected_tool"] = tool
    data["mapped_query"] = args
    return {
        "splunk_data": data,
        "query_budget_output": query_budget,
        "run_tool_duration_ms": int((time.monotonic() - started) * 1000),
        "stage_logs": _append_stage_log(
            state,
            stage="execution",
            title="Splunk tool execution completed",
            details=[
                f"selected_tool={tool}",
                f"source={data.get('source', 'splunk_mcp')}",
                f"execution_ms={data.get('execution_ms', 0)}",
                f"rows_returned={((data.get('structured', {}) or {}).get('total_rows', 0) if isinstance(data, dict) else 0)}",
            ],
            duration_ms=int((time.monotonic() - started) * 1000),
        ),
    }


def post_execution_node(state: MultiModelState) -> MultiModelState:
    started = time.monotonic()
    plan = state.get("final_plan", {}) or {}
    splunk_data = state.get("splunk_data", {}) or {}
    semantic_report = state.get("semantic_coverage_output", {}) or {}
    candidate_output = state.get("semantic_candidate_output", {}) or {}
    query_budget = state.get("query_budget_output", {}) or {}
    from semantic_candidate_select import (
        confidence_cap_for_evidence,
        reserve_query,
        score_live_evidence,
    )
    from spl_plan_migration import analytical_planner_mode
    from post_execution_diagnostics import run_post_execution_diagnostics

    semantic_retry: dict[str, Any] = {
        "attempted": False,
        "applied": False,
        "reason": "",
    }
    initial_evidence = score_live_evidence(semantic_report, splunk_data)
    if initial_evidence.get("rejected") and analytical_planner_mode() in {"prefer", "enforce"}:
        selected_id = str(candidate_output.get("selected_candidate_id", ""))
        alternates = candidate_output.get("ranked_candidates", [])
        alternates = alternates if isinstance(alternates, list) else []
        alternate = next(
            (
                item
                for item in alternates
                if isinstance(item, dict)
                and str(item.get("candidate_id", "")) != selected_id
                and bool((item.get("live_evidence", {}) or {}).get("accepted"))
                and not bool((item.get("live_evidence", {}) or {}).get("rejected"))
            ),
            None,
        )
        if alternate is not None:
            semantic_retry["attempted"] = True
            reserved, query_budget = reserve_query(
                query_budget,
                purpose="post_execution_semantic_retry",
                candidate_id=str(alternate.get("candidate_id", "")),
            )
            if reserved:
                alternate_args = (
                    alternate.get("tool_args", {})
                    if isinstance(alternate.get("tool_args"), dict)
                    else {}
                )
                try:
                    retry_data = run_splunk_query_args(
                        alternate_args,
                        intent=str(alternate.get("intent", "semantic_retry")),
                        summary_hint="post-execution semantic candidate retry",
                    )
                    retry_evidence = score_live_evidence(
                        alternate.get("semantic_coverage", semantic_report),
                        retry_data,
                    )
                    semantic_retry.update(
                        {
                            "candidate_id": str(alternate.get("candidate_id", "")),
                            "reason": initial_evidence.get("status", ""),
                            "live_evidence": retry_evidence,
                            "applied": not bool(retry_evidence.get("rejected")),
                        }
                    )
                    if semantic_retry["applied"]:
                        splunk_data = retry_data
                        semantic_report = alternate.get("semantic_coverage", semantic_report)
                        plan = dict(alternate)
                        for key in ("candidate_id", "candidate_source", "live_evidence"):
                            plan.pop(key, None)
                except Exception as exc:
                    semantic_retry["reason"] = f"{type(exc).__name__}:{exc}"
            else:
                semantic_retry["reason"] = "global_query_budget_exhausted"

    result = run_post_execution_diagnostics(
        question=str(state.get("question", "")),
        plan=plan,
        splunk_data=splunk_data if isinstance(splunk_data, dict) else {},
        field_strategy=state.get("field_strategy_output", {}) or {},
        coverage_report=semantic_report,
        query_budget=query_budget,
    )
    query_budget = result.get("query_budget", query_budget)
    live_evidence = result.get("live_evidence", initial_evidence)
    live_evidence = live_evidence if isinstance(live_evidence, dict) else initial_evidence
    semantic_report = dict(semantic_report)
    semantic_report["live_evidence"] = live_evidence
    semantic_report["post_execution_semantic_retry"] = semantic_retry
    mode = analytical_planner_mode()
    rejected = bool(live_evidence.get("rejected"))
    validation_ok = bool(state.get("validation_ok", False))
    supported = bool(state.get("supported", True))
    validation_reason = str(state.get("validation_reason", ""))
    guardrail_reason = str(state.get("guardrail_reason", ""))
    if rejected and mode in {"prefer", "enforce"}:
        validation_ok = False
        supported = False
        validation_reason = f"post_execution_evidence_rejected:{live_evidence.get('status', 'unknown')}"
        guardrail_reason = (
            "Returned rows were rejected because their schema did not satisfy the "
            "requested analytical evidence contract."
        )
    duration_ms = int((time.monotonic() - started) * 1000)
    payload: dict[str, Any] = {
        "post_execution_output": result,
        "semantic_coverage_output": semantic_report,
        "query_budget_output": query_budget,
        "confidence_cap": confidence_cap_for_evidence(live_evidence),
        "validation_ok": validation_ok,
        "validation_reason": validation_reason,
        "supported": supported,
        "guardrail_reason": guardrail_reason,
        "post_execution_duration_ms": duration_ms,
        "stage_logs": _append_stage_log(
            state,
            stage="post_execution",
            title="Post-execution diagnostics completed",
            details=[
                f"skipped={bool(result.get('skipped'))}",
                f"retry_applied={bool(result.get('retry_applied'))}",
                f"semantic_retry_applied={bool(semantic_retry.get('applied'))}",
                f"evidence_status={live_evidence.get('status', 'not_scored')}",
                f"evidence_score={live_evidence.get('score', 0.0)}",
                f"diagnostics={len(result.get('diagnostics', []) if isinstance(result.get('diagnostics'), list) else [])}",
                f"query_budget_used={query_budget.get('used', 0)}",
            ],
            duration_ms=duration_ms,
        ),
    }
    if semantic_retry.get("applied"):
        payload["splunk_data"] = splunk_data
        payload["final_plan"] = plan
    if result.get("retry_applied") and isinstance(result.get("retry_splunk_data"), dict):
        payload["splunk_data"] = result["retry_splunk_data"]
        if isinstance(result.get("retry_plan"), dict) and result["retry_plan"]:
            payload["final_plan"] = result["retry_plan"]
    return payload


def _evidence_review_blocked(state: MultiModelState) -> dict[str, Any] | None:
    started = time.monotonic()
    if not _topology_settings().get("evidence_review", True):
        return {
            "evidence_review_output": {
                "confidence": 0.0,
                "evidence_quality": "skipped",
                "key_findings": [],
                "anomalies": [],
                "gaps": ["evidence_review_disabled_by_topology"],
                "recommendation": "Evidence review disabled for this experiment topology.",
                "source": "evidence_review_disabled",
            },
            "evidence_review_duration_ms": int((time.monotonic() - started) * 1000),
            "stage_logs": _append_stage_log(
                state,
                stage="evidence_review",
                title="Evidence review skipped by topology setting",
                details=["LANGGRAPH_ENABLE_EVIDENCE_REVIEW=0"],
                duration_ms=int((time.monotonic() - started) * 1000),
            ),
        }
    if not state.get("validation_ok", False):
        return {
            "evidence_review_output": {
                "confidence": 0.0,
                "evidence_quality": "not_run",
                "key_findings": [],
                "anomalies": [],
                "gaps": ["validation_failed_pre_execution"],
                "recommendation": "No evidence review because query execution was blocked.",
                "source": "evidence_review_skipped",
            },
            "evidence_review_duration_ms": int((time.monotonic() - started) * 1000),
        }
    return None


def _evidence_context_from_state(state: MultiModelState) -> dict[str, Any]:
    plan = state.get("final_plan", {}) or {}
    splunk_data = state.get("splunk_data", {}) or {}
    structured = splunk_data.get("structured", {}) if isinstance(splunk_data, dict) else {}
    rows = structured.get("results", []) if isinstance(structured, dict) else []
    total_rows = structured.get("total_rows") if isinstance(structured, dict) else None
    platform_coverage = _derive_platform_coverage(plan, rows if isinstance(rows, list) else [])
    return {
        "plan": plan,
        "rows": rows if isinstance(rows, list) else [],
        "total_rows": total_rows,
        "platform_coverage": platform_coverage,
    }


def deterministic_evidence_pack_node(state: MultiModelState) -> MultiModelState:
    started = time.monotonic()
    blocked = _evidence_review_blocked(state)
    if blocked:
        return blocked
    ctx = _evidence_context_from_state(state)
    plan = ctx["plan"]
    rows = ctx["rows"]
    row_count = len(rows)
    review = {
        "confidence": 0.85 if row_count else 0.6,
        "evidence_quality": "deterministic_inventory",
        "key_findings": [
            f"rows_returned={row_count}",
            f"selected_tool={plan.get('selected_tool', '')}",
        ],
        "anomalies": [],
        "gaps": [] if row_count else ["inventory_query_returned_zero_rows"],
        "recommendation": "Inventory results are returned directly; no LLM evidence critique was required.",
        "source": "deterministic_evidence_pack",
    }
    return {
        "evidence_review_output": review,
        "evidence_review_duration_ms": int((time.monotonic() - started) * 1000),
        "stage_logs": _append_stage_log(
            state,
            stage="evidence_review",
            title="Deterministic evidence pack assembled for metadata question",
            details=[
                "Metadata profile; no LLM evidence critique.",
                f"rows_returned={row_count}",
            ],
            duration_ms=int((time.monotonic() - started) * 1000),
        ),
    }


def _llm_evidence_review_node(
    state: MultiModelState,
    *,
    model: str,
    source_label: str,
    stage_title: str,
    stage: str = "evidence_review",
) -> MultiModelState:
    started = time.monotonic()
    blocked = _evidence_review_blocked(state)
    if blocked:
        return blocked
    ctx = _evidence_context_from_state(state)
    plan = ctx["plan"]
    rows = ctx["rows"]
    total_rows = ctx["total_rows"]
    platform_coverage = ctx["platform_coverage"]
    system = (
        "You are an SOC evidence reviewer. Review executed query evidence only. "
        "Return strict JSON keys: confidence, evidence_quality, key_findings, anomalies, gaps, recommendation. "
        "Do not fabricate facts not present in evidence."
    )
    payload = {
        "question": state.get("question", ""),
        "intent": plan.get("intent", ""),
        "selected_tool": plan.get("selected_tool", ""),
        "query_args": plan.get("tool_args", {}),
        "platform_coverage": platform_coverage,
        "rows_returned": len(rows),
        "total_rows": total_rows,
        "sample_rows": rows[:25],
        "windows_event_code_context": build_event_code_reviewer_context(
            question=str(state.get("question", "")),
            intent=str(plan.get("intent", "")),
            query=str((plan.get("tool_args", {}) or {}).get("query", "")),
        ),
    }
    review: dict[str, Any]
    try:
        review = _call_ollama_json(model=model, system_prompt=system, user_payload=payload)
        review["source"] = source_label
    except Exception as exc:
        review = {
            "confidence": 0.6,
            "evidence_quality": "fallback",
            "key_findings": [
                f"rows_returned={len(rows)}",
                f"selected_tool={plan.get('selected_tool', '')}",
            ],
            "anomalies": [],
            "gaps": [f"evidence_reviewer_exception:{type(exc).__name__}:{exc}"],
            "recommendation": "Use deterministic row/entity pivots and re-run with narrower time scope if needed.",
            "source": f"{source_label}_fallback",
        }
    return {
        "evidence_review_output": review,
        "evidence_review_duration_ms": int((time.monotonic() - started) * 1000),
        "stage_logs": _append_stage_log(
            state,
            stage=stage,
            title=stage_title,
            details=[
                f"evidence_quality={review.get('evidence_quality', 'unknown')}",
                f"confidence={review.get('confidence', 0)}",
                str(review.get("recommendation", ""))[:220],
            ],
            model=model,
            duration_ms=int((time.monotonic() - started) * 1000),
        ),
    }


def analyst_evidence_review_node(state: MultiModelState) -> MultiModelState:
    return _llm_evidence_review_node(
        state,
        model=MODEL_ANALYST_REVIEWER,
        source_label="analyst_evidence_reviewer_model",
        stage_title="Analyst reviewer assessed the returned rows",
        stage="analyst_evidence_review",
    )


def security_evidence_review_node(state: MultiModelState) -> MultiModelState:
    return _llm_evidence_review_node(
        state,
        model=MODEL_SECURITY_REVIEWER,
        source_label="security_evidence_reviewer_model",
        stage_title="Security reviewer assessed the returned rows",
        stage="security_evidence_review",
    )


def evidence_review_node(state: MultiModelState) -> MultiModelState:
    """Legacy alias — routes by review_profile when invoked directly."""
    profile = _review_profile_for_state(state)
    if profile == "metadata":
        return deterministic_evidence_pack_node(state)
    if profile == "security":
        return security_evidence_review_node(state)
    return analyst_evidence_review_node(state)


def _deterministic_summary(output: dict[str, Any]) -> str:
    if not output.get("supported", False):
        return f"Guardrail blocked request: {output.get('guardrail_reason', 'unsupported request')}"

    intent = str(output.get("intent", "")).strip()
    tool = str(output.get("selected_tool", "")).strip()
    query_args = output.get("query_args", {}) if isinstance(output.get("query_args", {}), dict) else {}
    earliest = str(query_args.get("earliest_time", "") or "unknown")
    latest = str(query_args.get("latest_time", "") or "now")
    rows = int(output.get("rows_returned", 0) or 0)
    total_rows = output.get("total_rows")
    confidence = output.get("final_confidence", 0.0)
    search_strategy = str(output.get("search_strategy_summary", "")).strip()
    reviewer_notes = output.get("reviewer_notes", []) if isinstance(output.get("reviewer_notes", []), list) else []
    spl_results = output.get("spl_results_preview", []) if isinstance(output.get("spl_results_preview", []), list) else []
    top_row = spl_results[0] if spl_results and isinstance(spl_results[0], dict) else {}

    def _pick(*keys: str) -> str:
        for key in keys:
            value = str(top_row.get(key, "")).strip()
            if value and value.lower() not in {"unknown", "none", "null"}:
                return value
        return ""

    def _format_entities(*keys: str, limit: int = 3) -> str:
        values: list[str] = []
        for row in spl_results:
            if not isinstance(row, dict):
                continue
            for key in keys:
                value = str(row.get(key, "")).strip()
                if not value or value.lower() in {"unknown", "none", "null"}:
                    continue
                if value not in values:
                    values.append(value)
                if len(values) >= limit:
                    return ", ".join(values)
        return ", ".join(values)

    intent_labels = {
        "o365_management_activity": "Office 365 management activity",
        "aws_cloudtrail_activity": "AWS CloudTrail activity",
        "apache_404_spike": "Apache 404 activity",
        "apache_suspicious_user_agents": "Apache user-agent activity",
        "apache_access_top_ips": "Apache access activity",
        "linux_session_activity": "Linux session activity",
        "failed_login_activity": "failed login activity",
        "successful_login_activity": "successful login activity",
        "linux_successful_logins": "successful Linux login activity",
        "windows_successful_logons": "successful Windows logon activity",
    }
    label = intent_labels.get(intent, intent.replace("_", " ").strip() or "activity")

    summary_lines = [
        f"- **What was queried**: {label.capitalize()} using `{tool}` over `{earliest}` to `{latest}`.",
    ]
    if search_strategy:
        summary_lines.append(f"- **Search path**: {search_strategy}")

    if rows <= 0:
        summary_lines.append("- **Top findings**: No matching rows were returned in this time window.")
        summary_lines.append(f"- **Confidence rationale**: Confidence remains {confidence:.2f}; the query executed, but the current dataset did not surface supporting evidence.")
        summary_lines.append("- **Concrete next check**: Expand the time range or pivot to adjacent entities and related telemetry to test whether the activity appears elsewhere.")
        return "\n".join(summary_lines)

    if intent == "o365_management_activity":
        user = _pick("UserId", "user", "userid")
        operation = _pick("Operation", "operation")
        workload = _pick("Workload", "workload")
        client_ip = _pick("ClientIP", "clientip", "src_ip", "src")
        parts = []
        if user:
            parts.append(f"user `{user}`")
        if operation:
            parts.append(f"operation `{operation}`")
        if workload:
            parts.append(f"workload `{workload}`")
        if client_ip:
            parts.append(f"client IP `{client_ip}`")
        finding = ", ".join(parts) if parts else "returned Office 365 audit rows"
        summary_lines.append(f"- **Top findings**: The strongest returned result involved {finding}.")
        summary_lines.append("- **Interpretation**: This is activity visibility, not proof of malicious behavior by itself. Review the operation type, workload, and client IP concentration before treating it as suspicious.")
        summary_lines.append(f"- **Confidence rationale**: Confidence is {confidence:.2f} because the query returned structured management events, but intent still depends on the operation mix and actor context.")
        summary_lines.append("- **Concrete next check**: Pivot on the top user or client IP and compare operation diversity, workload spread, and any unusual admin-style actions.")
        return "\n".join(summary_lines)

    if intent == "linux_session_activity":
        actor = _format_entities("actor", "session_user", limit=3) or _pick("actor", "session_user", "user")
        host = _pick("host")
        session_state = _pick("session_state")
        details = []
        if actor:
            details.append(f"user(s) `{actor}`")
        if host:
            details.append(f"host `{host}`")
        if session_state:
            details.append(f"session state `{session_state}`")
        summary_lines.append(f"- **Top findings**: Session events were returned for {', '.join(details) if details else 'the Linux auth dataset'}.")
        summary_lines.append("- **Interpretation**: Session-open and session-close records are useful for context and scoping, but they are not malicious by default.")
        summary_lines.append(f"- **Confidence rationale**: Confidence is {confidence:.2f}; the query is aligned to Linux auth/session telemetry and returned usable context.")
        summary_lines.append("- **Concrete next check**: Pivot on the actor or host and compare session activity with failed logons, sudo usage, or other auth anomalies in the same period.")
        return "\n".join(summary_lines)

    if intent in {"apache_404_spike", "apache_suspicious_user_agents", "apache_access_top_ips"}:
        client = _pick("clientip", "src_ip")
        host = _pick("host")
        useragent = _pick("useragent", "http_user_agent")
        bits = []
        if client:
            bits.append(f"client `{client}`")
        if host:
            bits.append(f"host `{host}`")
        if useragent and intent == "apache_suspicious_user_agents":
            bits.append(f"user agent `{useragent}`")
        summary_lines.append(f"- **Top findings**: The returned web rows surfaced {', '.join(bits) if bits else 'Apache access patterns'} with `{total_rows if total_rows is not None else rows}` total matching records.")
        summary_lines.append("- **Interpretation**: Treat this as web activity triage. Repetition, concentration, or scanner-like user agents may be suspicious, but the result alone is not a compromise finding.")
        summary_lines.append(f"- **Confidence rationale**: Confidence is {confidence:.2f}; the query is mapped to the local Apache domain and returned scoped web evidence.")
        summary_lines.append("- **Concrete next check**: Pivot on the top client IP or user agent and inspect request paths, status distribution, and repetition over a narrower time range.")
        return "\n".join(summary_lines)

    entity_hint = _format_entities("user", "user_name", "host", "src_ip", "clientip")
    if entity_hint:
        summary_lines.append(f"- **Top findings**: Returned evidence surfaced these primary entities: {entity_hint}.")
    else:
        summary_lines.append(f"- **Top findings**: The query returned `{total_rows if total_rows is not None else rows}` matching rows for this investigation.")
    summary_lines.append(f"- **Confidence rationale**: Confidence is {confidence:.2f}; the query executed successfully and returned usable evidence.")
    if reviewer_notes:
        summary_lines.append(f"- **Review caveat**: {str(reviewer_notes[0])}")
    summary_lines.append("- **Concrete next check**: Pivot on the strongest returned entity and compare it against adjacent telemetry or a narrower time scope.")
    return "\n".join(summary_lines)


def _clean_summary_text(text: str) -> str:
    cleaned = text.replace("\r", "\n")
    cleaned = re.sub(r"<think>.*?</think>", "", cleaned, flags=re.IGNORECASE | re.DOTALL)
    cleaned = cleaned.replace("<think>", "").replace("</think>", "")
    cleaned = re.sub(r"[ \t]+\n", "\n", cleaned)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    return cleaned.strip()


def _derive_platform_coverage(plan: dict[str, Any], rows: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    tool_args = plan.get("tool_args", {}) if isinstance(plan.get("tool_args", {}), dict) else {}
    query = str(tool_args.get("query", "")).lower()
    rows_list = rows if isinstance(rows, list) else []
    row_platforms = {
        str(row.get("platform", "")).strip().lower()
        for row in rows_list
        if isinstance(row, dict) and str(row.get("platform", "")).strip()
    }
    query_platforms: set[str] = set()
    branch_status: list[dict[str, Any]] = []
    segments = _subsearch_segments_for_coverage(query)
    for segment in segments:
        platform = "unknown"
        if 'eval platform="linux"' in segment or "index=linux" in segment or 'source="/var/log/auth.log"' in segment or "linux_secure" in segment:
            platform = "linux"
            query_platforms.add("linux")
        if 'eval platform="windows"' in segment or "index=windows" in segment or "index=windows_sysmon" in segment or "eventcode=4625" in segment or "xmlwineventlog" in segment:
            platform = "windows" if platform == "unknown" else platform
            query_platforms.add("windows")
        branch_rows = sum(
            1
            for row in rows_list
            if isinstance(row, dict) and str(row.get("platform", "")).strip().lower() == platform
        ) if platform != "unknown" else 0
        branch_status.append({"platform": platform, "queried": platform != "unknown", "rows_returned": branch_rows})
    if 'eval platform="linux"' in query or "index=linux" in query or 'source="/var/log/auth.log"' in query or 'source="/var/log/secure"' in query:
        query_platforms.add("linux")
    if 'eval platform="windows"' in query or "index=windows" in query or "index=windows_sysmon" in query or "eventcode=4625" in query:
        query_platforms.add("windows")
    total_rows = len(rows_list)
    return {
        "query_platforms": sorted(query_platforms),
        "row_platforms": sorted(row_platforms),
        "platforms": sorted(query_platforms | row_platforms),
        "cross_platform_query": len(query_platforms) > 1,
        "cross_platform_results": len(row_platforms) > 1,
        "branch_status": branch_status,
        "zero_row_warning": total_rows == 0 and bool(query_platforms),
    }


def _subsearch_segments_for_coverage(query: str) -> list[str]:
    import re

    parts = re.split(r"\|\s*append\s*\[\s*search\s+", query, flags=re.IGNORECASE)
    segments = [parts[0].strip()]
    for part in parts[1:]:
        branch = part.rsplit("]", 1)[0] if "]" in part else part
        segments.append(f"search {branch}".strip())
    return [segment for segment in segments if segment]


def _enforce_platform_coverage_in_summary(summary: str, coverage: dict[str, Any]) -> str:
    text = summary.strip()
    query_platforms = set(coverage.get("query_platforms", []) if isinstance(coverage, dict) else [])
    row_platforms = set(coverage.get("row_platforms", []) if isinstance(coverage, dict) else [])
    lower = text.lower()
    if {"linux", "windows"}.issubset(query_platforms) and ("linux" not in lower or "windows" not in lower):
        lines = text.splitlines()
        insert_line = "- **What was queried**: A cross-platform failed-login search across both Linux authentication logs and Windows Security logon-failure events in the last 24 hours."
        if lines and "what was queried" in lines[0].lower():
            lines[0] = insert_line
        else:
            lines.insert(0, insert_line)
        text = "\n".join(lines).strip()
    if {"linux", "windows"}.issubset(query_platforms) and row_platforms == {"linux"} and "windows was queried but returned no matching" not in lower:
        lines = text.splitlines()
        note = "- **Coverage note**: Windows Security logon failures were queried as part of the cross-platform search, but no matching Windows failed-logon rows were returned in this time window."
        insert_at = 1 if lines else 0
        lines.insert(insert_at, note)
        text = "\n".join(lines).strip()
    if {"linux", "windows"}.issubset(query_platforms) and row_platforms == {"windows"} and "linux was queried but returned no matching" not in lower:
        lines = text.splitlines()
        note = "- **Coverage note**: Linux authentication logs were queried as part of the cross-platform search, but no matching Linux failed-login rows were returned in this time window."
        insert_at = 1 if lines else 0
        lines.insert(insert_at, note)
        text = "\n".join(lines).strip()
    return text


def _summarize_with_timeout(*, prompt: str, model: str, think: bool) -> str:
    from runtime_config import get_ollama_keep_alive

    with httpx.Client(timeout=SUMMARY_TIMEOUT_SECONDS) as client:
        resp = client.post(
            f"{OLLAMA_HOST}/api/generate",
            json={
                "model": model,
                "prompt": prompt,
                "stream": False,
                "think": think,
                "keep_alive": get_ollama_keep_alive(),
            },
        )
        resp.raise_for_status()
        body = resp.json()
    text = (body.get("response") or "").strip()
    if not text:
        raise RuntimeError("summary_empty")
    return text


def _compact_summary_context(output: dict[str, Any]) -> dict[str, Any]:
    evidence = output.get("evidence", {}) if isinstance(output.get("evidence"), dict) else {}
    top_entities = evidence.get("top_entities", []) if isinstance(evidence.get("top_entities"), list) else []
    reviewer_caveats = output.get("reviewer_caveats", [])
    return {
        "question": output.get("question"),
        "intent": output.get("intent"),
        "selected_tool": output.get("selected_tool"),
        "generated_spl": output.get("generated_spl"),
        "rows_returned": output.get("rows_returned"),
        "total_rows": output.get("total_rows"),
        "final_confidence": output.get("final_confidence"),
        "platform_coverage": output.get("platform_coverage"),
        "intent_summary": output.get("intent_summary"),
        "search_strategy_summary": output.get("search_strategy_summary"),
        "top_entities": top_entities[:5],
        "reviewer_caveats": reviewer_caveats[:3] if isinstance(reviewer_caveats, list) else [],
    }


def _is_summary_quality_ok(summary: str) -> tuple[bool, str]:
    text = summary.strip()
    lower = text.lower()
    if len(text) < 80:
        return False, "summary_too_short"
    if len(text) > 2400:
        return False, "summary_too_long"
    if "my task is" in lower or "i need to" in lower:
        return False, "reasoning_trace_leakage"
    if "<think>" in lower or "</think>" in lower:
        return False, "think_tag_leakage"
    bullet_count = sum(1 for line in text.splitlines() if line.strip().startswith(("-", "*")))
    if bullet_count < 3:
        return False, "summary_too_few_bullets"
    return True, "summary_quality_ok"


SUMMARY_TIMEOUT_SECONDS = float(os.getenv("OLLAMA_SUMMARY_TIMEOUT_SEC", "25"))


def summarize_node(state: MultiModelState) -> MultiModelState:
    started = time.monotonic()
    question = state["question"]
    plan = state.get("final_plan", {}) or state.get("writer_output", {}) or {}
    review_profile = _review_profile_for_state(state)
    metadata_profile = review_profile == "metadata"
    security_profile = review_profile == "security"
    operational_profile = review_profile == "operational"
    splunk_data = state.get("splunk_data", {}) or {}

    rows = splunk_data.get("structured", {}).get("results", []) if isinstance(splunk_data, dict) else []
    total_rows = splunk_data.get("structured", {}).get("total_rows") if isinstance(splunk_data, dict) else None
    platform_coverage = _derive_platform_coverage(plan, rows if isinstance(rows, list) else [])

    reviewer_conf = _float01((state.get("reviewer_output", {}) or {}).get("confidence", 0.5), default=0.5)
    evidence_conf = _float01((state.get("evidence_review_output", {}) or {}).get("confidence", 0.5), default=0.5)
    judge_conf = _float01((state.get("judge_output", {}) or {}).get("confidence", 0.5), default=0.5)
    judge2_conf = _float01((state.get("judge2_output", {}) or {}).get("confidence", 0.5), default=0.5)
    plan_conf = _float01(plan.get("confidence", 0.5), default=0.5)
    final_conf = round((plan_conf + reviewer_conf + evidence_conf + judge_conf + judge2_conf) / 5.0, 3)
    rows_returned = len(rows) if isinstance(rows, list) else 0
    intent_name = str(plan.get("intent", "")).strip()
    if rows_returned == 0 and intent_name in AUTH_FAMILY_INTENTS:
        query_platforms = set(platform_coverage.get("query_platforms", []) if isinstance(platform_coverage, dict) else [])
        row_platforms = set(platform_coverage.get("row_platforms", []) if isinstance(platform_coverage, dict) else [])
        if platform_coverage.get("cross_platform_query") and not row_platforms:
            final_conf = min(final_conf, 0.45)
        elif query_platforms and not row_platforms:
            final_conf = min(final_conf, 0.55)
        else:
            final_conf = min(final_conf, 0.50)
    elif rows_returned == 0 and str(plan.get("selected_tool", "")).strip() == "splunk_run_query":
        final_conf = min(final_conf, 0.55)
    final_conf = min(
        final_conf,
        _float01(state.get("confidence_cap", 1.0), default=1.0),
    )

    evidence = {
        "query_or_args": plan.get("tool_args", {}),
        "platform_coverage": platform_coverage,
        "time_window": {
            "earliest_time": (plan.get("tool_args", {}) or {}).get("earliest_time"),
            "latest_time": (plan.get("tool_args", {}) or {}).get("latest_time"),
        },
        "rows_returned": len(rows) if isinstance(rows, list) else 0,
        "total_rows": total_rows,
        "top_entities": rows[:25] if isinstance(rows, list) else [],
    }

    final_stage_logs = list(state.get("stage_logs", []) or [])
    output = {
        "question": question,
        "supported": bool(state.get("supported", False)) and bool(state.get("validation_ok", False)),
        "guardrail_reason": state.get("guardrail_reason", ""),
        "validation_reason": state.get("validation_reason", ""),
        "intent_summary": str((state.get("planner_output", {}) or {}).get("intent_summary", "")),
        "search_strategy_summary": str((state.get("planner_output", {}) or {}).get("search_strategy_summary", "")),
        "rag_enabled": RAG_ENABLED,
        "rag_max_chars": RAG_MAX_CHARS,
        "intent": plan.get("intent", "unknown"),
        "selected_tool": plan.get("selected_tool", ""),
        "query_args": plan.get("tool_args", {}),
        "planner_model": MODEL_QUERY_PLANNER,
        "query_writer_model": MODEL_QUERY_WRITER,
        "security_reviewer_model": MODEL_SECURITY_REVIEWER,
        "peer_reviewer_model": MODEL_PEER_REVIEWER,
        "peer_reviewer_2_model": MODEL_PEER_REVIEWER_2,
        "evidence_reviewer_model": MODEL_SECURITY_REVIEWER if security_profile else MODEL_ANALYST_REVIEWER,
        "analyst_reviewer_model": MODEL_ANALYST_REVIEWER,
        "final_summary_model": MODEL_FINAL_SUMMARY if security_profile else MODEL_ANALYST_REVIEWER,
        "review_profile": review_profile,
        "planner": {
            "model": MODEL_QUERY_PLANNER,
            "output": state.get("planner_output", {}),
        },
        "writer": {
            "model": MODEL_QUERY_WRITER,
            "output": state.get("writer_output", {}),
        },
        "security_reviewer": {
            "model": MODEL_SECURITY_REVIEWER,
            "output": state.get("reviewer_output", {}),
        },
        "evidence_reviewer": {
            "model": MODEL_SECURITY_REVIEWER if security_profile else MODEL_ANALYST_REVIEWER,
            "output": state.get("evidence_review_output", {}),
        },
        "peer_reviewer": {
            "model": MODEL_PEER_REVIEWER,
            "output": state.get("judge_output", {}),
        },
        "peer_reviewer_2": {
            "model": MODEL_PEER_REVIEWER_2,
            "output": state.get("judge2_output", {}),
        },
        "query_writer_output": state.get("writer_output", {}),
        "security_reviewer_output": state.get("reviewer_output", {}),
        "evidence_reviewer_output": state.get("evidence_review_output", {}),
        "peer_reviewer_decision": state.get("judge_output", {}),
        "peer_reviewer_2_decision": state.get("judge2_output", {}),
        "final_adjudication": {
            "selected_tool": plan.get("selected_tool", ""),
            "selected_intent": plan.get("intent", "unknown"),
            "selected_args": plan.get("tool_args", {}),
            "validation_ok": bool(state.get("validation_ok", False)),
            "validation_reason": state.get("validation_reason", ""),
            "selected_confidence": _float01(plan.get("confidence", 0.5), default=0.5),
            "winner": str((state.get("judge2_output", {}) or {}).get("winner", (state.get("judge_output", {}) or {}).get("winner", "reviewer"))),
            "adjudication_reason": str((state.get("judge2_output", {}) or {}).get("rationale", (state.get("judge_output", {}) or {}).get("rationale", ""))),
        },
        "skip_peer_review": not any(
            str((entry or {}).get("stage", "")).strip() in {"peer_review_1", "peer_review_2"}
            for entry in final_stage_logs
            if isinstance(entry, dict)
        ),
        "skipped_nodes": [
            str(item).strip()
            for item in (state.get("skipped_nodes") or [])
            if str(item).strip()
        ],
        "query_repair": state.get("query_repair", {}),
        "semantic_coverage": state.get("semantic_coverage_output", {}),
        "semantic_candidates": state.get("semantic_candidate_output", {}),
        "query_budget": state.get("query_budget_output", {}),
        "confidence_cap": _float01(state.get("confidence_cap", 1.0), default=1.0),
        **(
            {"saved_query_suggestion": dict(state.get("saved_query_suggestion", {}))}
            if isinstance(state.get("saved_query_suggestion"), dict)
            and state.get("saved_query_suggestion")
            else {}
        ),
        "model_workflow": [
            {
                "stage": "planner",
                "model": MODEL_QUERY_PLANNER,
                "responsibility": "Interpret the analyst question and produce a structured search plan.",
            },
            {
                "stage": "query_writer",
                "model": MODEL_QUERY_WRITER,
                "responsibility": "Translate the structured plan into bounded read-only SPL or a bounded MCP tool call.",
            },
            *(
                [
                    {
                        "stage": "spl_validate",
                        "model": MODEL_ANALYST_REVIEWER,
                        "responsibility": "Operational SPL validation before deterministic policy gates.",
                    }
                ]
                if operational_profile
                else []
            ),
            *(
                []
                if metadata_profile or operational_profile
                else [
                    {
                        "stage": "security_reviewer",
                        "model": MODEL_SECURITY_REVIEWER,
                        "responsibility": "Critique the generated SPL against analyst intent, field assumptions, and safety constraints.",
                    }
                ]
            ),
            *(
                [
                    {
                        "stage": "peer_reviewer",
                        "model": MODEL_PEER_REVIEWER,
                        "responsibility": "Adjudicate writer vs reviewer candidate and choose winner.",
                    },
                    {
                        "stage": "peer_reviewer_2",
                        "model": MODEL_PEER_REVIEWER_2,
                        "responsibility": "Validate or override peer reviewer #1 winner before deterministic gates.",
                    },
                ]
                if (
                    security_profile
                    and not (
                        not any(
                            str((entry or {}).get("stage", "")).strip() in {"peer_review_1", "peer_review_2"}
                            for entry in final_stage_logs
                            if isinstance(entry, dict)
                        )
                    )
                )
                else []
            ),
            *(
                []
                if metadata_profile
                else [
                    {
                        "stage": "evidence_reviewer",
                        "model": MODEL_ANALYST_REVIEWER if operational_profile else MODEL_SECURITY_REVIEWER,
                        "responsibility": (
                            "Post-execution analyst evidence review on returned rows."
                            if operational_profile
                            else "Post-execution security evidence review on returned rows."
                        ),
                    },
                    *(
                        [
                            {
                                "stage": "final_summary",
                                "model": MODEL_FINAL_SUMMARY,
                                "responsibility": "Generate analyst-facing evidence-first narrative from validated results.",
                            }
                        ]
                        if security_profile
                        else [
                            {
                                "stage": "final_summary",
                                "model": MODEL_ANALYST_REVIEWER,
                                "responsibility": "Generate operational analyst summary from validated results.",
                            }
                        ]
                    ),
                ]
            ),
            {
                "stage": "query_repair",
                "model": MODEL_QUERY_REPAIR,
                "responsibility": "One-pass writer-side rewrite when validation fails, then deterministic re-validation.",
            },
        ],
        "rows_returned": len(rows) if isinstance(rows, list) else 0,
        "total_rows": total_rows,
        "final_confidence": final_conf,
        "platform_coverage": platform_coverage,
        "confidence_components": {
            "planner": plan_conf,
            "security_reviewer": reviewer_conf,
            "evidence_reviewer": evidence_conf,
            "peer_reviewer": judge_conf,
            "peer_reviewer_2": judge2_conf,
        },
        "evidence": evidence,
        "reviewer_notes": (state.get("reviewer_output", {}) or {}).get("issues", []),
        "reviewer_caveats": (state.get("reviewer_output", {}) or {}).get("caveats", []),
        "generated_spl": _display_spl_for_plan(plan),
        "stage_logs": final_stage_logs,
    }
    node_timings_ms = {
        "guardrail": int(state.get("guardrail_duration_ms", 0) or 0),
        "planner": int(state.get("planner_duration_ms", 0) or 0),
        "field_bind": int(state.get("field_bind_duration_ms", 0) or 0),
        "field_discovery": int(state.get("field_discovery_duration_ms", 0) or 0),
        "field_strategy": int(state.get("field_strategy_duration_ms", 0) or 0),
        "domain_knowledge": int(state.get("domain_knowledge_duration_ms", 0) or 0),
        "writer": int(state.get("writer_duration_ms", 0) or 0),
        "spl_validate": int(state.get("spl_validate_duration_ms", 0) or 0),
        "security_review": int(state.get("security_review_duration_ms", 0) or 0),
        "peer_review_1": int(state.get("peer_review_duration_ms", 0) or 0),
        "peer_review_2": int(state.get("peer_review_2_duration_ms", 0) or 0),
        "validation": int(state.get("validation_duration_ms", 0) or 0),
        "field_policy": int(state.get("field_policy_duration_ms", 0) or 0),
        "semantic_gate": int(state.get("semantic_gate_duration_ms", 0) or 0),
        "semantic_candidate_select": int(state.get("semantic_candidate_duration_ms", 0) or 0),
        "post_execution": int(state.get("post_execution_duration_ms", 0) or 0),
        "run_tool": int(state.get("run_tool_duration_ms", 0) or 0),
        "evidence_review": int(state.get("evidence_review_duration_ms", 0) or 0),
    }
    selected_spl_details: list[dict[str, Any]] = []
    selected_tool_name = str(output.get("selected_tool", ""))
    if selected_tool_name in ALLOWED_TOOLS:
        display_spl = _display_spl_for_plan(plan)
        selected_args = output.get("query_args", {}) if isinstance(output.get("query_args", {}), dict) else {}
        writer_model = MODEL_QUERY_WRITER
        plan_source = str(plan.get("source", "")).strip()
        if plan_source == "saved_query_library" or str(plan.get("reason", "")).startswith("saved_query_library"):
            writer_model = "saved_query_library"
        selected_spl_details.append(
            {
                "step": 1,
                "query": display_spl,
                "selected_tool": selected_tool_name,
                "writer_model": writer_model,
                "execution_ms": int(splunk_data.get("execution_ms", 0) or 0),
                "rows_returned": output.get("rows_returned"),
                "total_rows": output.get("total_rows"),
                "reason": str(plan.get("reason", "")),
            }
        )
    output["selected_spl_details"] = selected_spl_details
    output["spl_results_preview"] = rows[:50] if isinstance(rows, list) else []
    output["tdir_case"] = build_tdir_case(
        question=question,
        intent=str(output.get("intent", "unknown")),
        selected_tool=str(output.get("selected_tool", "")),
        query_args=output.get("query_args", {}) if isinstance(output.get("query_args", {}), dict) else {},
        structured=splunk_data.get("structured", {}) if isinstance(splunk_data, dict) else {},
        pipeline="multi_model_reviewer",
    )

    summary_error = ""
    summary_quality_reason = "summary_quality_ok"
    summary_model = MODEL_FINAL_SUMMARY if security_profile else MODEL_ANALYST_REVIEWER
    if metadata_profile:
        summary = _deterministic_summary(output)
        summary_quality_reason = "metadata_profile_deterministic_summary"
    elif not _topology_settings().get("final_summary", True):
        summary = _deterministic_summary(output)
        summary_quality_reason = "summary_model_disabled_fallback"
    elif output["supported"]:
        try:
            summary_context = _compact_summary_context(output)
            summary_prompt = (
                "You are a SOC analyst assistant in a lab. "
                "Produce analyst output in 5-7 bullets. Include: what was asked, what query/tool was executed, "
                "top findings, confidence rationale, and concrete next checks. "
                "If platform_coverage.query_platforms includes both linux and windows, explicitly say the executed "
                "search was cross-platform and mention both Linux and Windows in the first bullet.\n\n"
                f"INVESTIGATION:\n{json.dumps(summary_context, indent=2)}"
            )
            summary = _summarize_with_timeout(prompt=summary_prompt, model=summary_model, think=False)
            summary = _clean_summary_text(summary)
            summary = _enforce_platform_coverage_in_summary(summary, platform_coverage)
            ok, summary_quality_reason = _is_summary_quality_ok(summary)
            if not ok:
                raise RuntimeError(f"summary_quality_gate_failed:{summary_quality_reason}")
        except Exception as exc:
            summary = _deterministic_summary(output)
            summary_error = f"{type(exc).__name__}: {exc}"
            if summary_quality_reason == "summary_quality_ok":
                summary_quality_reason = "model_exception_fallback"
    else:
        summary = _deterministic_summary(output)
        summary_quality_reason = "unsupported_request_fallback"

    summarize_ms = int((time.monotonic() - started) * 1000)
    node_timings_ms["summarize"] = summarize_ms
    detect_ms = (
        node_timings_ms["guardrail"]
        + node_timings_ms["planner"]
        + node_timings_ms["field_bind"]
        + node_timings_ms["field_discovery"]
        + node_timings_ms["field_strategy"]
        + node_timings_ms["domain_knowledge"]
        + node_timings_ms["writer"]
        + node_timings_ms["spl_validate"]
        + node_timings_ms["security_review"]
        + node_timings_ms["peer_review_1"]
        + node_timings_ms["peer_review_2"]
        + node_timings_ms["validation"]
        + node_timings_ms["field_policy"]
        + node_timings_ms["semantic_gate"]
        + node_timings_ms["semantic_candidate_select"]
    )
    triage_ms = node_timings_ms["run_tool"] + node_timings_ms["post_execution"]
    investigate_ms = node_timings_ms["evidence_review"] + node_timings_ms["summarize"]
    stage_timings_ms = {
        "detect": detect_ms,
        "triage": triage_ms,
        "investigate": investigate_ms,
        "respond": 0,
        "recover": 0,
        "total": detect_ms + triage_ms + investigate_ms,
    }
    summary_stage_logs = _append_stage_log(
        state,
        stage="summary",
        title="Summary stage prepared the analyst-facing output",
        details=[
            f"supported={output.get('supported', False)}",
            f"rows_returned={output.get('rows_returned', 0)}",
            f"final_confidence={output.get('final_confidence', 0)}",
            f"summary_model_enabled={_topology_settings().get('final_summary', True)}",
            f"summary_fallback_used={bool(summary_error) or summary_quality_reason != 'summary_quality_ok'}",
            f"summary_quality_reason={summary_quality_reason}",
            f"summary_error={summary_error or 'none'}",
        ],
        model="" if metadata_profile else summary_model,
        duration_ms=summarize_ms,
    )
    output["summary"] = summary
    output["summary_fallback_used"] = bool(summary_error) or summary_quality_reason != "summary_quality_ok"
    output["summary_error"] = summary_error
    output["summary_quality_reason"] = summary_quality_reason
    output["node_timings_ms"] = node_timings_ms
    output["stage_timings_ms"] = stage_timings_ms
    output["stage_logs"] = summary_stage_logs
    output["topology_settings"] = _topology_settings()
    return {
        "summary": summary,
        "output": output,
        "summarize_duration_ms": summarize_ms,
        "stage_logs": summary_stage_logs,
    }


def finalize(state: MultiModelState) -> MultiModelState:
    return state


def route_after_guardrail(state: MultiModelState) -> str:
    return "planner" if state.get("supported", False) else "summarize"


def route_after_writer(state: MultiModelState) -> str:
    analytical_execution = (
        (state.get("planner_output", {}) or {}).get("analytical_plan_execution", {})
    )
    if isinstance(analytical_execution, dict) and analytical_execution.get("selected"):
        return "validate_final_plan"
    profile = _review_profile_for_state(state)
    if profile == "metadata":
        return "validate_final_plan"
    if profile == "operational":
        return "spl_validate"
    if not _topology_settings().get("security_review", True):
        return "validate_final_plan"
    return "security_review"


def route_after_spl_validate(state: MultiModelState) -> str:
    return "validate_final_plan"


def route_after_run_tool(state: MultiModelState) -> str:
    profile = _review_profile_for_state(state)
    if profile == "metadata":
        return "deterministic_evidence_pack"
    if profile == "security":
        return "security_evidence_review"
    return "analyst_evidence_review"


def route_after_security_review(state: MultiModelState) -> str:
    if not _topology_settings().get("peer_review", True):
        return "validate_final_plan"
    reviewer_output = state.get("reviewer_output", {}) or {}
    reviewer_approved = bool(reviewer_output.get("approved", False))
    reviewer_issues = reviewer_output.get("issues", [])
    reviewer_issue_count = len(reviewer_issues) if isinstance(reviewer_issues, list) else 0
    if reviewer_approved and reviewer_issue_count == 0:
        return "validate_final_plan"
    return "peer_review"


def route_after_validation(state: MultiModelState) -> str:
    return "field_policy" if state.get("validation_ok", False) else "summarize"


def route_after_field_policy(state: MultiModelState) -> str:
    return "semantic_gate" if state.get("validation_ok", False) else "summarize"


def route_after_semantic_gate(state: MultiModelState) -> str:
    return "semantic_candidate_select" if state.get("validation_ok", False) else "summarize"


def route_after_semantic_candidate(state: MultiModelState) -> str:
    return "run_tool" if state.get("validation_ok", False) else "summarize"


def describe_multi_model_graph(topology_settings: dict[str, bool] | None = None) -> dict[str, Any]:
    settings = dict(_topology_settings())
    if topology_settings:
        settings.update({str(k): bool(v) for k, v in topology_settings.items()})

    canonical_nodes = [
        {"id": "ingest_question", "label": "Ingest Question", "group": "controller"},
        {"id": "guardrail", "label": "Guardrail", "group": "controller"},
        {"id": "planner", "label": "Planner", "group": "primary_inference"},
        {"id": "field_bind", "label": "Field Binding", "group": "controller"},
        {"id": "field_discovery", "label": "Field Discovery", "group": "data_plane"},
        {"id": "field_strategy", "label": "Field Strategy", "group": "controller"},
        {"id": "domain_knowledge", "label": "Domain Knowledge", "group": "controller"},
        {"id": "writer", "label": "SPL Writer", "group": "primary_inference"},
        {"id": "security_review", "label": "Security Reviewer", "group": "primary_inference"},
        {"id": "peer_review", "label": "Peer Review 1", "group": "primary_inference"},
        {"id": "peer_review_2", "label": "Peer Review 2", "group": "primary_inference"},
        {"id": "validate_final_plan", "label": "Deterministic Validation", "group": "controller"},
        {"id": "field_policy", "label": "Fields-First Policy", "group": "controller"},
        {"id": "semantic_gate", "label": "Semantic Coverage Gate", "group": "controller"},
        {"id": "semantic_candidate_select", "label": "Candidate Evidence", "group": "controller"},
        {"id": "run_tool", "label": "Splunk MCP Execution", "group": "data_plane"},
        {"id": "evidence_review", "label": "Evidence Review", "group": "primary_inference"},
        {"id": "summarize", "label": "Final Summary", "group": "primary_inference"},
        {"id": "finalize", "label": "Finalize", "group": "controller"},
    ]
    canonical_edges = [
        {"from": "ingest_question", "to": "guardrail", "kind": "direct", "label": ""},
        {"from": "guardrail", "to": "planner", "kind": "conditional", "label": "supported"},
        {"from": "guardrail", "to": "summarize", "kind": "conditional", "label": "blocked"},
        {"from": "planner", "to": "field_bind", "kind": "direct", "label": ""},
        {"from": "field_bind", "to": "field_discovery", "kind": "direct", "label": ""},
        {"from": "field_discovery", "to": "field_strategy", "kind": "direct", "label": ""},
        {"from": "field_strategy", "to": "domain_knowledge", "kind": "direct", "label": ""},
        {"from": "domain_knowledge", "to": "writer", "kind": "direct", "label": ""},
        {"from": "writer", "to": "security_review", "kind": "conditional", "label": "security review enabled"},
        {"from": "writer", "to": "validate_final_plan", "kind": "conditional", "label": "security review disabled"},
        {"from": "security_review", "to": "validate_final_plan", "kind": "conditional", "label": "clean approval"},
        {"from": "security_review", "to": "peer_review", "kind": "conditional", "label": "contested"},
        {"from": "peer_review", "to": "peer_review_2", "kind": "direct", "label": ""},
        {"from": "peer_review_2", "to": "validate_final_plan", "kind": "direct", "label": ""},
        {"from": "validate_final_plan", "to": "field_policy", "kind": "conditional", "label": "approved"},
        {"from": "validate_final_plan", "to": "summarize", "kind": "conditional", "label": "blocked"},
        {"from": "field_policy", "to": "semantic_gate", "kind": "conditional", "label": "approved"},
        {"from": "field_policy", "to": "summarize", "kind": "conditional", "label": "blocked"},
        {"from": "semantic_gate", "to": "semantic_candidate_select", "kind": "conditional", "label": "approved"},
        {"from": "semantic_gate", "to": "summarize", "kind": "conditional", "label": "blocked"},
        {"from": "semantic_candidate_select", "to": "run_tool", "kind": "conditional", "label": "selected"},
        {"from": "semantic_candidate_select", "to": "summarize", "kind": "conditional", "label": "blocked"},
        {"from": "run_tool", "to": "evidence_review", "kind": "direct", "label": ""},
        {"from": "evidence_review", "to": "summarize", "kind": "direct", "label": ""},
        {"from": "summarize", "to": "finalize", "kind": "direct", "label": ""},
    ]

    active_nodes = [
        {"id": "ingest_question", "label": "Ingest Question", "group": "controller"},
        {"id": "guardrail", "label": "Guardrail", "group": "controller"},
        {"id": "planner", "label": "Planner", "group": "primary_inference"},
        {"id": "field_bind", "label": "Field Binding", "group": "controller"},
        {"id": "field_discovery", "label": "Field Discovery", "group": "data_plane"},
        {"id": "field_strategy", "label": "Field Strategy", "group": "controller"},
        {"id": "domain_knowledge", "label": "Domain Knowledge", "group": "controller"},
        {"id": "writer", "label": "SPL Writer", "group": "primary_inference"},
    ]
    active_edges = [
        {"from": "ingest_question", "to": "guardrail", "kind": "direct", "label": ""},
        {"from": "guardrail", "to": "planner", "kind": "conditional", "label": "supported"},
        {"from": "guardrail", "to": "summarize", "kind": "conditional", "label": "blocked"},
        {"from": "planner", "to": "field_bind", "kind": "direct", "label": ""},
        {"from": "field_bind", "to": "field_discovery", "kind": "direct", "label": ""},
        {"from": "field_discovery", "to": "field_strategy", "kind": "direct", "label": ""},
        {"from": "field_strategy", "to": "domain_knowledge", "kind": "direct", "label": ""},
        {"from": "domain_knowledge", "to": "writer", "kind": "direct", "label": ""},
    ]

    if settings.get("security_review", True):
        active_nodes.append({"id": "security_review", "label": "Security Reviewer", "group": "primary_inference"})
        active_edges.append({"from": "writer", "to": "security_review", "kind": "direct", "label": ""})
        if settings.get("peer_review", True):
            active_nodes.extend(
                [
                    {"id": "peer_review", "label": "Peer Review 1", "group": "primary_inference"},
                    {"id": "peer_review_2", "label": "Peer Review 2", "group": "primary_inference"},
                ]
            )
            active_edges.extend(
                [
                    {"from": "security_review", "to": "validate_final_plan", "kind": "conditional", "label": "clean approval"},
                    {"from": "security_review", "to": "peer_review", "kind": "conditional", "label": "contested"},
                    {"from": "peer_review", "to": "peer_review_2", "kind": "direct", "label": ""},
                    {"from": "peer_review_2", "to": "validate_final_plan", "kind": "direct", "label": ""},
                ]
            )
        else:
            active_edges.append({"from": "security_review", "to": "validate_final_plan", "kind": "direct", "label": "peer review disabled"})
    else:
        active_edges.append({"from": "writer", "to": "validate_final_plan", "kind": "direct", "label": "security review disabled"})

    active_nodes.append({"id": "validate_final_plan", "label": "Deterministic Validation", "group": "controller"})
    active_nodes.append({"id": "field_policy", "label": "Fields-First Policy", "group": "controller"})
    active_nodes.append({"id": "semantic_gate", "label": "Semantic Coverage Gate", "group": "controller"})
    active_nodes.append({"id": "semantic_candidate_select", "label": "Candidate Evidence", "group": "controller"})
    active_nodes.append({"id": "run_tool", "label": "Splunk MCP Execution", "group": "data_plane"})
    active_edges.extend(
        [
            {"from": "validate_final_plan", "to": "field_policy", "kind": "conditional", "label": "approved"},
            {"from": "validate_final_plan", "to": "summarize", "kind": "conditional", "label": "blocked"},
            {"from": "field_policy", "to": "semantic_gate", "kind": "conditional", "label": "approved"},
            {"from": "field_policy", "to": "summarize", "kind": "conditional", "label": "blocked"},
            {"from": "semantic_gate", "to": "semantic_candidate_select", "kind": "conditional", "label": "approved"},
            {"from": "semantic_gate", "to": "summarize", "kind": "conditional", "label": "blocked"},
            {"from": "semantic_candidate_select", "to": "run_tool", "kind": "conditional", "label": "selected"},
            {"from": "semantic_candidate_select", "to": "summarize", "kind": "conditional", "label": "blocked"},
            {"from": "run_tool", "to": "evidence_review", "kind": "direct", "label": ""},
        ]
    )

    evidence_label = "Evidence Review" if settings.get("evidence_review", True) else "Evidence Review (deterministic only)"
    summary_label = "Final Summary" if settings.get("final_summary", True) else "Final Summary (deterministic only)"
    active_nodes.append({"id": "evidence_review", "label": evidence_label, "group": "primary_inference"})
    active_nodes.append({"id": "summarize", "label": summary_label, "group": "primary_inference"})
    active_nodes.append({"id": "finalize", "label": "Finalize", "group": "controller"})
    active_edges.extend(
        [
            {"from": "evidence_review", "to": "summarize", "kind": "direct", "label": ""},
            {"from": "summarize", "to": "finalize", "kind": "direct", "label": ""},
        ]
    )

    return {
        "topology_settings": settings,
        "canonical": {"nodes": canonical_nodes, "edges": canonical_edges},
        "active": {"nodes": active_nodes, "edges": active_edges},
        "notes": [
            "LangGraph runs on the Linux controller host and orchestrates all model calls.",
            "Only the controller can hand an approved plan to Splunk MCP.",
            "Query repair is a validation-time rewrite path, not a standalone graph node.",
            "The optional edge helper sits before the planner and is shown in the architecture diagram rather than the core LangGraph state graph.",
        ],
    }


def build_graph():
    graph = StateGraph(MultiModelState)
    graph.add_node("ingest_question", ingest_question)
    graph.add_node("guardrail", guardrail_check)
    graph.add_node("planner", planner_node)
    graph.add_node("field_bind", field_bind_node)
    graph.add_node("field_discovery", field_discovery_node)
    graph.add_node("field_strategy", field_strategy_node)
    graph.add_node("domain_knowledge", domain_resolve_node)
    graph.add_node("writer", writer_node)
    graph.add_node("spl_validate", spl_validate_node)
    graph.add_node("security_review", security_review_node)
    graph.add_node("peer_review", peer_review_node)
    graph.add_node("peer_review_2", peer_review_2_node)
    graph.add_node("validate_final_plan", validate_final_plan_node)
    graph.add_node("field_policy", field_policy_node)
    graph.add_node("semantic_gate", semantic_gate_node)
    graph.add_node("semantic_candidate_select", semantic_candidate_select_node)
    graph.add_node("run_tool", run_tool_node)
    graph.add_node("post_execution", post_execution_node)
    graph.add_node("deterministic_evidence_pack", deterministic_evidence_pack_node)
    graph.add_node("analyst_evidence_review", analyst_evidence_review_node)
    graph.add_node("security_evidence_review", security_evidence_review_node)
    graph.add_node("summarize", summarize_node)
    graph.add_node("finalize", finalize)

    graph.add_edge(START, "ingest_question")
    graph.add_edge("ingest_question", "guardrail")
    graph.add_conditional_edges("guardrail", route_after_guardrail)
    graph.add_edge("planner", "field_bind")
    graph.add_edge("field_bind", "field_discovery")
    graph.add_edge("field_discovery", "field_strategy")
    graph.add_edge("field_strategy", "domain_knowledge")
    graph.add_edge("domain_knowledge", "writer")
    graph.add_conditional_edges("writer", route_after_writer)
    graph.add_edge("spl_validate", "validate_final_plan")
    graph.add_conditional_edges("security_review", route_after_security_review)
    graph.add_edge("peer_review", "peer_review_2")
    graph.add_edge("peer_review_2", "validate_final_plan")
    graph.add_conditional_edges("validate_final_plan", route_after_validation)
    graph.add_conditional_edges("field_policy", route_after_field_policy)
    graph.add_conditional_edges("semantic_gate", route_after_semantic_gate)
    graph.add_conditional_edges("semantic_candidate_select", route_after_semantic_candidate)
    graph.add_edge("run_tool", "post_execution")
    graph.add_conditional_edges("post_execution", route_after_run_tool)
    graph.add_edge("deterministic_evidence_pack", "summarize")
    graph.add_edge("analyst_evidence_review", "summarize")
    graph.add_edge("security_evidence_review", "summarize")
    graph.add_edge("summarize", "finalize")
    graph.add_edge("finalize", END)
    return graph.compile()


ProgressCallback = Callable[..., None]


def _emit_multi_model_progress(
    progress_cb: ProgressCallback | None,
    *,
    node: str = "",
    stage: str = "",
    skipped: bool = False,
    phase: str = "enter",
    duration_ms: int | None = None,
) -> None:
    if progress_cb is None:
        return
    journey_node = journey_node_for_graph_node(node or stage)
    if not journey_node:
        return
    info = progress_for_multi_model_node(journey_node)
    pct = info.get("pct")
    if pct is None:
        info = progress_for_stage_log(stage or node)
        pct = info.get("pct")
    if pct is None:
        return
    label = "skipped" if skipped else str(info.get("label", ""))
    title = str(info.get("title", ""))
    normalized_phase = str(phase or "enter").strip().lower()
    if normalized_phase not in {"enter", "complete"}:
        normalized_phase = "enter"
    measured_ms = max(0, int(duration_ms or 0)) if duration_ms is not None else None
    args = (journey_node, int(pct), label, title, skipped, normalized_phase, measured_ms)
    try:
        progress_cb(*args)  # type: ignore[misc]
    except TypeError:
        try:
            progress_cb(journey_node, int(pct), label, title, skipped)  # type: ignore[misc]
        except TypeError:
            progress_cb(journey_node, int(pct), label, title)  # type: ignore[misc]


def _emit_skipped_journey_nodes(progress_cb: ProgressCallback | None, nodes: list[str]) -> None:
    for node in nodes:
        _emit_multi_model_progress(progress_cb, node=node, skipped=True, phase="complete", duration_ms=0)


def _next_multi_model_node(node_id: str, skipped_nodes: list[str] | None = None) -> str:
    keys = list(MULTI_MODEL_NODE_PROGRESS.keys())
    try:
        index = keys.index(str(node_id or "").strip())
    except ValueError:
        return ""
    skipped = {str(item).strip() for item in (skipped_nodes or []) if str(item).strip()}
    for offset in range(index + 1, len(keys)):
        candidate = keys[offset]
        if candidate in POST_GRAPH_PROGRESS_NODES:
            continue
        if candidate not in skipped:
            return candidate
    return ""


def _invoke_multi_model_graph(
    app: Any,
    initial: dict[str, Any],
    *,
    progress_cb: ProgressCallback | None = None,
) -> dict[str, Any]:
    if progress_cb is None:
        result = app.invoke(initial)
        return result if isinstance(result, dict) else {}

    result: dict[str, Any] | None = None
    seen_nodes: set[str] = set()
    seen_stage_keys: set[str] = set()
    _emit_multi_model_progress(progress_cb, node="guardrail", phase="enter")

    for mode, payload in app.stream(initial, stream_mode=["updates", "values"]):
        if mode == "updates" and isinstance(payload, dict):
            for node_name, node_delta in payload.items():
                node_key = str(node_name or "").strip()
                if node_key and node_key not in seen_nodes:
                    seen_nodes.add(node_key)
                    skipped_nodes: list[str] = []
                    if isinstance(node_delta, dict):
                        raw_skipped = node_delta.get("skipped_nodes") or []
                        if isinstance(raw_skipped, list):
                            skipped_nodes = [str(item).strip() for item in raw_skipped if str(item).strip()]
                    if skipped_nodes:
                        _emit_skipped_journey_nodes(progress_cb, skipped_nodes)
                    next_node = _next_multi_model_node(node_key, skipped_nodes)
                    if next_node:
                        _emit_multi_model_progress(progress_cb, node=next_node, phase="enter")
        elif mode == "values" and isinstance(payload, dict):
            result = payload
            for entry in payload.get("stage_logs") or []:
                if not isinstance(entry, dict):
                    continue
                stage_key = str(entry.get("stage") or "").strip()
                if not stage_key or stage_key in seen_stage_keys:
                    continue
                seen_stage_keys.add(stage_key)
                duration_ms = max(0, int(entry.get("duration_ms") or 0))
                _emit_multi_model_progress(
                    progress_cb,
                    stage=stage_key,
                    phase="complete",
                    duration_ms=duration_ms,
                )

    if isinstance(result, dict):
        return result
    fallback = app.invoke(initial)
    return fallback if isinstance(fallback, dict) else {}


def run_multi_model_soc(
    question: str,
    *,
    session_id: str = "",
    write_artifact: bool = False,
    artifact_dir: str = "artifacts/runs/multi_model",
    progress_cb: ProgressCallback | None = None,
    force_saved_query_id: str = "",
) -> dict[str, Any]:
    app = build_graph()
    initial: dict[str, Any] = {"question": question, "session_id": session_id}
    forced_id = str(force_saved_query_id or "").strip()
    if forced_id:
        initial["force_saved_query_id"] = forced_id
    result = _invoke_multi_model_graph(
        app,
        initial,
        progress_cb=progress_cb,
    )
    output = result.get("output", {}) if isinstance(result, dict) else {}
    if not isinstance(output, dict):
        output = {}

    output.setdefault("question", question)
    if "summary" not in output:
        output["summary"] = result.get("summary", "") if isinstance(result, dict) else ""

    meta: dict[str, Any] = {}
    if write_artifact:
        out_dir = Path(artifact_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        out_path = out_dir / f"multi_model_run_{stamp}.json"
        payload = {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "models": {
                "query_planner": MODEL_QUERY_PLANNER,
                "query_writer": MODEL_QUERY_WRITER,
                "security_reviewer": MODEL_SECURITY_REVIEWER,
                "peer_reviewer": MODEL_PEER_REVIEWER,
                "peer_reviewer_2": MODEL_PEER_REVIEWER_2,
                "final_summary": MODEL_FINAL_SUMMARY,
            },
            "result": output,
        }
        out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        meta["artifact"] = str(out_path)

    return {"result": output, "meta": meta}


def main() -> int:
    parser = argparse.ArgumentParser(description="Run multi-model SOC LangGraph pipeline")
    parser.add_argument("question", nargs="?", default="Show failed login activity in the last 24 hours")
    parser.add_argument("--session-id", default="")
    parser.add_argument("--write-artifact", action="store_true")
    parser.add_argument("--artifact-dir", default="artifacts/runs/multi_model")
    args = parser.parse_args()

    payload = run_multi_model_soc(
        args.question,
        session_id=args.session_id,
        write_artifact=args.write_artifact,
        artifact_dir=args.artifact_dir,
    )
    print("=== Multi-Model LangGraph Result ===")
    print(json.dumps(payload["result"], indent=2))
    meta = payload.get("meta", {})
    if isinstance(meta, dict) and "artifact" in meta:
        print(f"artifact={meta['artifact']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
