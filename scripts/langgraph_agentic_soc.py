#!/usr/bin/env python3
"""Agentic LangGraph SOC investigation loop (lab).

This script extends the minimal flow into a bounded iterative investigation:
- plans an initial read-only tool action
- executes tool steps
- evaluates outcomes and proposes safe pivots
- repeats up to max_steps
- summarizes the multi-step trajectory

Lab safety remains enforced via read-only/policy checks.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TypedDict

import httpx
from langgraph.graph import END, START, StateGraph

from langgraph_minimal_flow import determine_splunk_tool, load_session_context, persist_session_context
from minimal_question_to_answer import (
    OLLAMA_HOST,
    OLLAMA_REASONING_MODEL,
    map_question_to_template,
    run_splunk_get_info,
    run_splunk_get_indexes,
    run_splunk_get_metadata,
    run_splunk_query,
    run_splunk_query_args,
    summarize_with_ollama_model,
    summarize_with_ollama,
    template_to_query_args,
)
from query_policy import validate_query_args
from tdir_core import build_tdir_case
from environment_profile import validate_query_against_environment
from spl_query_repair import attempt_query_repair_once


class AgentState(TypedDict, total=False):
    question: str
    max_steps: int
    session_id: str
    session_context: dict
    supported: bool
    guardrail_reason: str
    step_index: int
    next_tool: str
    next_args: dict
    next_reason: str
    done: bool
    done_reason: str
    trajectory: list[dict]
    last_result: dict
    evidence_review_output: dict
    evidence_review_duration_ms: int
    continuation_review_output: dict
    continuation_review_duration_ms: int
    summary: str


BLOCKED_TERMS = ("delete", "drop", "remove", "shutdown", "restart", "write", "modify")
AGENTIC_SUMMARY_MODEL = os.getenv(
    "OLLAMA_MODEL_AGENTIC_SUMMARY",
    os.getenv("OLLAMA_MODEL_FINAL_SUMMARY", OLLAMA_REASONING_MODEL),
)
AGENTIC_EVIDENCE_REVIEWER_MODEL = os.getenv("OLLAMA_MODEL_EVIDENCE_REVIEWER", OLLAMA_REASONING_MODEL)
AGENTIC_QUERY_WRITER_MODEL = os.getenv("OLLAMA_MODEL_AGENTIC_QUERY_WRITER", "deterministic_template_router_v1")
AGENTIC_REVIEWER_MODEL = os.getenv("OLLAMA_MODEL_AGENTIC_REVIEWER", "deterministic_query_policy_guard_v1")
AGENTIC_PEER_REVIEWER_MODEL = os.getenv("OLLAMA_MODEL_AGENTIC_PEER_REVIEWER", "deterministic_intent_alignment_guard_v1")
AGENTIC_CONTROLLER_MODEL = os.getenv("OLLAMA_MODEL_AGENTIC_CONTROLLER", "deterministic_agentic_controller_v1")
AGENTIC_CONTINUATION_REVIEWER_MODEL = os.getenv(
    "OLLAMA_MODEL_AGENTIC_CONTINUATION_REVIEWER",
    OLLAMA_REASONING_MODEL,
)
AGENTIC_CONTINUATION_REVIEW_TIMEOUT_SEC = float(os.getenv("OLLAMA_AGENTIC_CONTINUATION_TIMEOUT_SEC", "180"))
AGENTIC_QUERY_REPAIR_MODEL = os.getenv("OLLAMA_MODEL_QUERY_REPAIR", "hf.co/MaziyarPanahi/Qwen3-30B-A3B-Instruct-2507-GGUF:Q4_K_M")
AGENTIC_AUTO_CONTINUE_LIMIT = int(os.getenv("OLLAMA_AGENTIC_AUTO_CONTINUE_LIMIT", "1"))
AGENTIC_MAX_INVESTIGATION_DEPTH = int(os.getenv("OLLAMA_AGENTIC_MAX_INVESTIGATION_DEPTH", "3"))
AGENTIC_CONTINUE_CONFIDENCE_THRESHOLD = float(os.getenv("OLLAMA_AGENTIC_CONTINUE_CONFIDENCE_THRESHOLD", "0.6"))


def _extract_json_object(text: str) -> dict[str, Any]:
    if not text:
        raise ValueError("empty_model_text")
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```[a-zA-Z]*\s*", "", cleaned)
        cleaned = re.sub(r"\s*```$", "", cleaned)
    try:
        obj = json.loads(cleaned)
        if isinstance(obj, dict):
            return obj
    except Exception:
        pass
    decoder = json.JSONDecoder()
    for match in re.finditer(r"\{", cleaned):
        start = match.start()
        try:
            obj, _end = decoder.raw_decode(cleaned[start:])
        except Exception:
            continue
        if isinstance(obj, dict):
            return obj
    raise ValueError("json_object_not_found")


def _call_ollama_json(*, model: str, system_prompt: str, user_payload: dict[str, Any], timeout: float = 180.0) -> dict[str, Any]:
    prompt = (
        f"{system_prompt}\n\n"
        "Return strict JSON only. No prose.\n\n"
        f"INPUT:\n{json.dumps(user_payload, indent=2)}"
    )
    payload = {"model": model, "prompt": prompt, "stream": False, "think": False}
    with httpx.Client(timeout=timeout) as client:
        resp = client.post(f"{OLLAMA_HOST}/api/generate", json=payload)
        resp.raise_for_status()
        body = resp.json()
    raw = str(body.get("response") or "").strip()
    parsed = _extract_json_object(raw)
    parsed["_raw_text_preview"] = raw[:1200]
    return parsed


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


def _escape_spl_value(value: Any) -> str:
    text = str(value)
    text = text.replace("\\", "\\\\")
    text = text.replace('"', '\\"')
    return text


def _clean_summary_text(summary: str) -> str:
    cleaned = summary.replace("\r", "\n")
    cleaned = re.sub(r"<think>.*?</think>", "", cleaned, flags=re.IGNORECASE | re.DOTALL)
    cleaned = cleaned.replace("</think>", "").replace("<think>", "")
    cleaned = re.sub(r"[ \t]+\n", "\n", cleaned)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    return cleaned.strip()


def _is_summary_quality_ok(summary: str) -> tuple[bool, str]:
    text = summary.strip()
    if len(text) < 80:
        return False, "summary_too_short"
    if len(text) > 5000:
        return False, "summary_too_long"
    bullet_count = sum(1 for line in text.splitlines() if line.strip().startswith("-"))
    if bullet_count < 3:
        return False, "summary_too_few_bullets"
    if text.endswith(("(", "[", "e.g", "eg")):
        return False, "summary_looks_truncated"
    return True, "summary_quality_ok"


def _deterministic_summary(question: str, trajectory: list[dict[str, Any]], done_reason: str) -> str:
    if not trajectory:
        return (
            f"- Question: {question}\n"
            "- No investigation steps were executed.\n"
            f"- Completion reason: {done_reason or 'no_steps'}\n"
            "- Suggested next check: run a read-only question that maps to an allowed tool path."
        )

    last = trajectory[-1]
    lines = [
        f"- Question: {question}",
        f"- Steps executed: {len(trajectory)}",
        f"- Last step tool: {last.get('tool')}",
        f"- Last step rows: {last.get('rows_returned')} (total_rows={last.get('total_rows')})",
    ]
    first = trajectory[0]
    lines.append(f"- Initial action: {first.get('tool')} ({first.get('reason', 'no_reason')})")
    lines.append(f"- Completion reason: {done_reason or 'completed'}")
    lines.append("- Suggested next check: narrow the next query around the top entity surfaced in the final step.")
    return "\n".join(lines)


def _extract_evidence_signals(rows: list[Any], args: dict[str, Any]) -> list[str]:
    signals: list[str] = []
    if not isinstance(rows, list):
        return ["rows_not_list"]
    signals.append(f"rows={len(rows)}")
    if rows and isinstance(rows[0], dict):
        keys = sorted(rows[0].keys())
        signals.append(f"sample_fields={','.join(keys[:6])}")
        top_row = rows[0]
        for field in ("count", "totalCount", "title", "host", "sourcetype", "user"):
            if field in top_row:
                signals.append(f"top_{field}={top_row.get(field)}")
    if isinstance(args, dict) and args:
        if "query" in args:
            query = str(args.get("query", ""))
            signals.append(f"query_prefix={query[:60]}")
        else:
            signals.append("args_keys=" + ",".join(sorted(str(k) for k in args.keys())[:6]))
    return signals[:8]


def _extract_top_entities(rows: list[Any]) -> dict[str, str]:
    keys = ("user", "src", "clientip", "host", "sourcetype")
    entities: dict[str, str] = {}
    for row in rows[:15]:
        if not isinstance(row, dict):
            continue
        for key in keys:
            if key in entities:
                continue
            value = str(row.get(key, "")).strip()
            if value:
                entities[key] = value
        if len(entities) == len(keys):
            break
    return entities


def _normalize_case_state(case_state: dict[str, Any] | None, root_question: str) -> dict[str, Any]:
    state = case_state if isinstance(case_state, dict) else {}
    asked_questions = state.get("asked_questions", [])
    if not isinstance(asked_questions, list):
        asked_questions = []
    pivot_signatures = state.get("pivot_signatures", [])
    if not isinstance(pivot_signatures, list):
        pivot_signatures = []
    rounds = state.get("rounds", [])
    if not isinstance(rounds, list):
        rounds = []
    return {
        "root_question": str(state.get("root_question", "")).strip() or root_question,
        "current_depth": int(state.get("current_depth", 0) or 0),
        "auto_continue_used": int(state.get("auto_continue_used", 0) or 0),
        "manual_continue_used": int(state.get("manual_continue_used", 0) or 0),
        "asked_questions": [str(item) for item in asked_questions if str(item).strip()],
        "pivot_signatures": [str(item) for item in pivot_signatures if str(item).strip()],
        "rounds": [item for item in rounds if isinstance(item, dict)],
        "max_depth": int(state.get("max_depth", AGENTIC_MAX_INVESTIGATION_DEPTH) or AGENTIC_MAX_INVESTIGATION_DEPTH),
    }


def _pivot_signature(question: str, next_best_spl_or_tool: str) -> str:
    q = re.sub(r"\s+", " ", str(question or "").strip().lower())
    n = re.sub(r"\s+", " ", str(next_best_spl_or_tool or "").strip().lower())
    return f"q={q}|n={n}"


def _condense_round(output: dict[str, Any]) -> dict[str, Any]:
    return {
        "question": str(output.get("question", "")),
        "summary": str(output.get("summary", ""))[:800],
        "done_reason": str(output.get("done_reason", "")),
        "selected_spl_details": output.get("selected_spl_details", []),
        "continuation_reviewer_output": output.get("continuation_reviewer_output", {}),
        "node_timings_ms": output.get("node_timings_ms", {}),
    }


def _coerce_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


def _build_loop_control(
    *,
    output: dict[str, Any],
    case_state: dict[str, Any],
    approved_deeper_investigation: bool,
) -> dict[str, Any]:
    continuation = output.get("continuation_reviewer_output", {})
    if not isinstance(continuation, dict):
        continuation = {}
    next_question = str(continuation.get("next_best_question", "")).strip()
    next_tool = str(continuation.get("next_best_spl_or_tool", "")).strip()
    should_continue = bool(continuation.get("should_continue", False))
    confidence = _coerce_float(continuation.get("confidence", 0.0), 0.0)
    current_depth = int(case_state.get("current_depth", 0) or 0)
    max_depth = max(1, int(case_state.get("max_depth", AGENTIC_MAX_INVESTIGATION_DEPTH) or AGENTIC_MAX_INVESTIGATION_DEPTH))
    auto_used = int(case_state.get("auto_continue_used", 0) or 0)
    manual_used = int(case_state.get("manual_continue_used", 0) or 0)
    signature = _pivot_signature(next_question, next_tool) if next_question else ""
    duplicate = bool(signature and signature in set(case_state.get("pivot_signatures", [])))
    confidence_ok = confidence >= AGENTIC_CONTINUE_CONFIDENCE_THRESHOLD
    can_continue = bool(should_continue and next_question)
    depth_remaining = current_depth < max_depth - 1
    auto_allowed = bool(can_continue and depth_remaining and not duplicate and confidence_ok and auto_used < AGENTIC_AUTO_CONTINUE_LIMIT)
    human_allowed = bool(can_continue and depth_remaining and not duplicate and confidence_ok)
    human_required = bool(human_allowed and (approved_deeper_investigation or auto_used >= AGENTIC_AUTO_CONTINUE_LIMIT))
    stop_reason = ""
    if not should_continue:
        stop_reason = "continuation_not_requested"
    elif not next_question:
        stop_reason = "continuation_missing_question"
    elif duplicate:
        stop_reason = "duplicate_pivot_blocked"
    elif not depth_remaining:
        stop_reason = "max_depth_reached"
    elif not confidence_ok:
        stop_reason = f"continuation_confidence_below_threshold:{AGENTIC_CONTINUE_CONFIDENCE_THRESHOLD}"
    elif approved_deeper_investigation:
        stop_reason = "human_approved_followup_ready"
    elif auto_allowed:
        stop_reason = "auto_followup_allowed"
    else:
        stop_reason = "human_approval_required"
    continuation_request = {
        "next_question": next_question,
        "next_best_spl_or_tool": next_tool,
        "signature": signature,
        "case_state": _normalize_case_state(case_state, str(case_state.get("root_question", output.get("question", "")))),
        "root_question": str(case_state.get("root_question", output.get("question", ""))),
    } if can_continue and signature else {}
    followup_routable = False
    followup_route_reason = ""
    if next_question:
        followup_routable, followup_route_reason = _followup_question_is_routable(next_question)
        if not followup_routable:
            auto_allowed = False
            human_allowed = False
            human_required = False
            continuation_request = {}
            stop_reason = f"followup_unroutable:{followup_route_reason}"
    return {
        "should_continue": should_continue,
        "current_depth": current_depth,
        "max_depth": max_depth,
        "auto_continue_limit": AGENTIC_AUTO_CONTINUE_LIMIT,
        "auto_continue_used": auto_used,
        "manual_continue_used": manual_used,
        "confidence": confidence,
        "confidence_threshold": AGENTIC_CONTINUE_CONFIDENCE_THRESHOLD,
        "duplicate_pivot_blocked": duplicate,
        "depth_remaining": depth_remaining,
        "auto_followup_allowed": auto_allowed,
        "human_approval_required": human_required and not approved_deeper_investigation,
        "approved_deeper_investigation": approved_deeper_investigation,
        "stop_reason": stop_reason,
        "recommended_followup_question": next_question,
        "recommended_followup_tool": next_tool,
        "followup_routable": followup_routable,
        "followup_route_reason": followup_route_reason,
        "continuation_request": continuation_request,
    }


def _fallback_continuation_review(
    *,
    question: str,
    trajectory: list[dict[str, Any]],
    last_result: dict[str, Any],
    evidence_review: dict[str, Any],
    max_steps: int,
) -> dict[str, Any]:
    structured = last_result.get("structured", {}) if isinstance(last_result, dict) else {}
    rows = structured.get("results", []) if isinstance(structured, dict) else []
    if not isinstance(rows, list):
        rows = []
    entities = _extract_top_entities(rows)
    tool = str(last_result.get("selected_tool", ""))
    args = last_result.get("mapped_query", {}) if isinstance(last_result.get("mapped_query", {}), dict) else {}
    query_text = str(args.get("query", "")).lower()
    question_text = str(question or "").lower()
    evidence_quality = str(evidence_review.get("evidence_quality", "")).strip().lower()
    steps_executed = len(trajectory)
    rows_returned = len(rows)
    should_continue = bool(rows_returned > 0 and (evidence_quality in {"low", "fallback", "uncertain", ""} or steps_executed >= max_steps))

    entity_question = "What host, user, or source IP is driving this activity most strongly?"
    if "failed" in query_text or "failure" in query_text or "failed login" in question_text or "authentication" in question_text:
        if entities.get("user"):
            entity_question = f"Show failed login activity for user {entities['user']} in the last 24 hours"
        elif entities.get("src"):
            entity_question = f"Show failed login activity from source IP {entities['src']} in the last 24 hours"
        elif entities.get("host"):
            entity_question = f"Show failed login activity on host {entities['host']} in the last 24 hours"
    elif "access_combined" in query_text or entities.get("clientip"):
        if entities.get("clientip"):
            entity_question = f"Show apache access activity from client IP {entities['clientip']} in the last 24 hours"
        elif entities.get("host"):
            entity_question = f"Show apache access activity on host {entities['host']} in the last 24 hours"
    elif "linux" in query_text or "sudo" in query_text or "auth" in query_text:
        if entities.get("user"):
            entity_question = f"Show linux authentication activity for user {entities['user']} in the last 24 hours"
        elif entities.get("host"):
            entity_question = f"Show linux authentication activity on host {entities['host']} in the last 24 hours"
    elif entities.get("host"):
        entity_question = f"Show suspicious activity on host {entities['host']} in the last 24 hours"

    next_suggestion = tool
    if tool == "splunk_run_query" and isinstance(args, dict) and args.get("query"):
        next_suggestion = str(args.get("query", ""))
    elif tool:
        next_suggestion = f"{tool} with narrower entity/time scope"

    why = "Evidence quality is not yet strong enough to declare the investigation complete."
    if not should_continue:
        why = "Current evidence is sufficient for a bounded analyst summary without forcing another pivot."

    return {
        "should_continue": should_continue,
        "why": why,
        "next_best_question": entity_question if should_continue else "",
        "next_best_spl_or_tool": next_suggestion if should_continue else "",
        "confidence": 0.72 if should_continue else 0.81,
        "expected_value_of_next_step": "medium" if should_continue else "low",
        "source": "agentic_continuation_reviewer_fallback",
    }


def _step_confidence(tool: str, rows: Any, total_rows: Any, reason: str) -> float:
    score = 0.5
    if isinstance(rows, list):
        if len(rows) > 0:
            score += 0.25
        if len(rows) >= 5:
            score += 0.1
    if isinstance(total_rows, int):
        if total_rows > 0:
            score += 0.1
        if total_rows > 20:
            score += 0.05
    if "blocked" in reason:
        score -= 0.25
    if tool in {"splunk_get_metadata", "splunk_run_query"}:
        score += 0.05
    return max(0.05, min(0.99, round(score, 2)))


def _query_aligned_with_intent(intent: str, query: str) -> tuple[bool, str]:
    intent_l = (intent or "").strip().lower()
    query_l = (query or "").strip().lower()
    if not query_l:
        return False, "query_empty"

    expected_tokens: dict[str, tuple[str, ...]] = {
        "failed_login_activity": (
            "info=failed",
            "action=failure",
            "failed_login",
            "failed password",
            "authentication failure",
        ),
        "linux_auth_failures": ("sourcetype=linux_secure", "failed password", "authentication failure"),
        "windows_auth_failures": ("sourcetype=xmlwineventlog", "eventcode=4625", "an account failed to log on"),
        "linux_privilege_escalation": ("sourcetype=linux_secure", "sudo", " su", "privilege"),
        "linux_privilege_escalation_first_seen": (
            "index=linux",
            "earliest(_time)",
            "first_seen",
            "session opened for user root by",
        ),
        "apache_access_top_ips": ("sourcetype=access_combined", "clientip"),
        "apache_404_spike": ("sourcetype=access_combined", "status=404"),
        "apache_suspicious_user_agents": ("sourcetype=access_combined", "useragent"),
    }
    disallowed_tokens: dict[str, tuple[str, ...]] = {
        "failed_login_activity": ("stats count by sourcetype",),
        "linux_auth_failures": ("stats count by sourcetype",),
        "windows_auth_failures": ("stats count by sourcetype",),
        "linux_privilege_escalation": ("stats count by sourcetype",),
        "linux_privilege_escalation_first_seen": ("earliest_time=", "latest_time=", "row_limit="),
    }

    tokens = expected_tokens.get(intent_l, ())
    if tokens and not any(tok in query_l for tok in tokens):
        return False, f"intent_query_mismatch:{intent_l}"

    blocked = disallowed_tokens.get(intent_l, ())
    if blocked and any(tok in query_l for tok in blocked):
        return False, f"intent_disallowed_pattern:{intent_l}"

    return True, "intent_query_aligned"


def _intent_locked_query_args(question: str) -> dict[str, Any]:
    template = map_question_to_template(question)
    return template_to_query_args(template, question)


def initial_action_from_question(question: str) -> tuple[str, dict[str, Any], str]:
    selected_tool, reason, metadata_args, _chain_mode = determine_splunk_tool(question, "")

    if selected_tool == "splunk_get_metadata":
        return selected_tool, metadata_args, reason
    if selected_tool == "splunk_get_info":
        return selected_tool, {}, reason
    if selected_tool == "splunk_get_indexes":
        return selected_tool, {}, reason

    template = map_question_to_template(question)
    query_args = template_to_query_args(template, question)
    ok, policy_reason = validate_query_args(query_args, question=question)
    if not ok:
        return "", {}, f"initial_query_blocked:{policy_reason}"
    env_ok, env_reason = validate_query_against_environment(query_args)
    if not env_ok:
        repair = attempt_query_repair_once(
            question=question,
            failed_query_args=query_args,
            failure_reason=env_reason,
            model=AGENTIC_QUERY_REPAIR_MODEL,
        )
        if repair.get("ok", False):
            repaired_args = repair.get("args", {})
            if isinstance(repaired_args, dict):
                return "splunk_run_query", repaired_args, f"{reason};auto_repair:{repair.get('repair_reason', '')}"
        return "", {}, f"initial_query_blocked:{env_reason};repair={repair.get('repair_reason', 'failed')}"
    return "splunk_run_query", query_args, reason


def _followup_question_is_routable(question: str) -> tuple[bool, str]:
    tool, _args, reason = initial_action_from_question(question)
    if not tool:
        return False, reason
    return True, reason


def execute_tool_action(tool: str, args: dict[str, Any], question: str) -> dict[str, Any]:
    started = time.monotonic()
    if tool == "splunk_get_indexes":
        data = run_splunk_get_indexes()
    elif tool == "splunk_get_info":
        data = run_splunk_get_info()
    elif tool == "splunk_get_metadata":
        data = run_splunk_get_metadata(args)
    elif tool == "splunk_run_query":
        if args:
            data = run_splunk_query_args(
                args,
                intent="agentic_pivot",
                summary_hint="Summarize pivot findings and suggest one next investigative step.",
            )
        else:
            data = run_splunk_query(question)
    else:
        raise RuntimeError(f"unsupported_tool:{tool}")

    elapsed_ms = int((time.monotonic() - started) * 1000)
    data["selected_tool"] = tool
    data["mapped_query"] = args
    data["execution_ms"] = elapsed_ms
    return data


def propose_next_action(
    *,
    question: str,
    step_index: int,
    max_steps: int,
    trajectory: list[dict[str, Any]],
    last_result: dict[str, Any],
) -> tuple[bool, str, str, dict[str, Any]]:
    if step_index >= max_steps:
        return True, "max_steps_reached", "", {}

    selected_tool = str(last_result.get("selected_tool", ""))
    mapped_query = last_result.get("mapped_query", {})
    structured = last_result.get("structured", {}) if isinstance(last_result, dict) else {}
    rows = structured.get("results", []) if isinstance(structured, dict) else []

    used_tools = {str(s.get("tool", "")) for s in trajectory if isinstance(s, dict)}
    base_template = map_question_to_template(question)
    base_intent = str(base_template.intent)

    if (not isinstance(rows, list) or not rows) and "splunk_get_indexes" not in used_tools:
        return False, "no_rows_pivot_to_index_inventory", "splunk_get_indexes", {}

    if selected_tool == "splunk_get_indexes":
        top_index = "_internal"
        if isinstance(rows, list) and rows and isinstance(rows[0], dict):
            top_index = str(rows[0].get("title", "")).strip() or "_internal"
        next_args = {
            "type": "sourcetypes",
            "index": top_index,
            "earliest_time": "-24h",
            "latest_time": "now",
            "row_limit": 20,
        }
        ok, reason = _validate_metadata_args(next_args)
        if not ok:
            return True, f"metadata_pivot_blocked:{reason}", "", {}
        return False, "pivot_to_sourcetypes_for_top_index", "splunk_get_metadata", next_args

    if selected_tool == "splunk_get_metadata":
        metadata_type = str(mapped_query.get("type", ""))
        index_name = str(mapped_query.get("index", "*") or "*")
        if isinstance(rows, list) and rows and isinstance(rows[0], dict):
            if metadata_type == "sourcetypes":
                top_sourcetype = str(rows[0].get("sourcetype", "")).strip()
                if top_sourcetype:
                    st_esc = _escape_spl_value(top_sourcetype)
                    idx_esc = _escape_spl_value(index_name)
                    query_args = {
                        "query": f'search index={idx_esc} sourcetype="{st_esc}" | stats count by host | sort - count',
                        "earliest_time": "-24h",
                        "latest_time": "now",
                        "row_limit": 10,
                    }
                    ok, reason = validate_query_args(query_args, question=question)
                    if not ok:
                        return True, f"metadata_to_query_blocked:{reason}", "", {}
                    env_ok, env_reason = validate_query_against_environment(query_args)
                    if not env_ok:
                        repair = attempt_query_repair_once(
                            question=question,
                            failed_query_args=query_args,
                            failure_reason=env_reason,
                            model=AGENTIC_QUERY_REPAIR_MODEL,
                        )
                        if repair.get("ok", False):
                            repaired_args = repair.get("args", {})
                            if isinstance(repaired_args, dict):
                                return False, f"auto_repair_after_metadata:{repair.get('repair_reason', '')}", "splunk_run_query", repaired_args
                        return True, f"metadata_to_query_blocked:{env_reason};repair={repair.get('repair_reason', 'failed')}", "", {}
                    return False, "pivot_to_top_sourcetype_host_distribution", "splunk_run_query", query_args
            if metadata_type == "hosts":
                top_host = str(rows[0].get("host", "")).strip()
                if top_host:
                    host_esc = _escape_spl_value(top_host)
                    query_args = _intent_locked_query_args(question)
                    if base_intent in {"top_indexes", "internal_sourcetypes"}:
                        query_args = {
                            "query": f'search index=* host="{host_esc}" | stats count by sourcetype | sort - count',
                            "earliest_time": "-24h",
                            "latest_time": "now",
                            "row_limit": 10,
                        }
                    elif base_intent != "failed_login_activity":
                        query_args["query"] = f'{query_args["query"]} | search host="{host_esc}"'
                    aligned, aligned_reason = _query_aligned_with_intent(base_intent, str(query_args.get("query", "")))
                    if not aligned:
                        fallback = _intent_locked_query_args(question)
                        f_ok, f_aligned_reason = _query_aligned_with_intent(base_intent, str(fallback.get("query", "")))
                        if f_ok:
                            query_args = fallback
                        else:
                            return True, f"metadata_to_query_blocked:{aligned_reason}:{f_aligned_reason}", "", {}
                    ok, reason = validate_query_args(query_args, question=question)
                    if not ok:
                        return True, f"metadata_to_query_blocked:{reason}", "", {}
                    env_ok, env_reason = validate_query_against_environment(query_args)
                    if not env_ok:
                        repair = attempt_query_repair_once(
                            question=question,
                            failed_query_args=query_args,
                            failure_reason=env_reason,
                            model=AGENTIC_QUERY_REPAIR_MODEL,
                        )
                        if repair.get("ok", False):
                            repaired_args = repair.get("args", {})
                            if isinstance(repaired_args, dict):
                                return False, f"auto_repair_after_metadata:{repair.get('repair_reason', '')}", "splunk_run_query", repaired_args
                        return True, f"metadata_to_query_blocked:{env_reason};repair={repair.get('repair_reason', 'failed')}", "", {}
                    return False, "pivot_to_intent_locked_host_drilldown", "splunk_run_query", query_args

    if selected_tool == "splunk_run_query":
        query_text = str(mapped_query.get("query", "")).lower()
        if ("failure" in query_text or "failed_login" in query_text) and "splunk_get_metadata" not in used_tools:
            next_args = {
                "type": "hosts",
                "index": "*",
                "earliest_time": "-24h",
                "latest_time": "now",
                "row_limit": 20,
            }
            ok, reason = _validate_metadata_args(next_args)
            if not ok:
                return True, f"failure_pivot_blocked:{reason}", "", {}
            return False, "pivot_failed_login_to_hosts_metadata", "splunk_get_metadata", next_args
        if "failure" in query_text or "failed_login" in query_text:
            return True, "completed_failed_login_metadata_pivot", "", {}

    return True, "no_additional_safe_pivot", "", {}


def ingest_question(state: AgentState) -> AgentState:
    question = str(state.get("question", "")).strip()
    if not question:
        raise ValueError("question is required")
    session_id = str(state.get("session_id", "")).strip()
    session_context = state.get("session_context", {})
    if not isinstance(session_context, dict):
        session_context = {}
    max_steps = state.get("max_steps", 3)
    if not isinstance(max_steps, int) or max_steps < 1:
        max_steps = 3
    return {
        "question": question,
        "max_steps": max_steps,
        "session_id": session_id,
        "session_context": session_context,
        "step_index": 0,
        "trajectory": [],
    }


def guardrail_check(state: AgentState) -> AgentState:
    question = state["question"].lower()
    if any(term in question for term in BLOCKED_TERMS):
        return {
            "supported": False,
            "guardrail_reason": (
                "Question appears to request non-read-only action. "
                "This lab flow currently supports read-only analysis questions."
            ),
            "done": True,
            "done_reason": "guardrail_blocked",
        }
    return {
        "supported": True,
        "guardrail_reason": "",
        "done": False,
        "done_reason": "",
    }


def initial_plan_node(state: AgentState) -> AgentState:
    tool, args, reason = initial_action_from_question(state["question"])
    if not tool:
        return {
            "supported": False,
            "guardrail_reason": f"Initial plan blocked: {reason}",
            "done": True,
            "done_reason": reason,
        }
    return {
        "next_tool": tool,
        "next_args": args,
        "next_reason": reason,
    }


def execute_step_node(state: AgentState) -> AgentState:
    tool = str(state.get("next_tool", "")).strip()
    args = state.get("next_args", {})
    if not isinstance(args, dict):
        args = {}

    result = execute_tool_action(tool, args, state["question"])
    rows = result.get("structured", {}).get("results", [])
    total_rows = result.get("structured", {}).get("total_rows")
    reason = str(state.get("next_reason", ""))
    confidence = _step_confidence(tool, rows, total_rows, reason)
    evidence_signals = _extract_evidence_signals(rows if isinstance(rows, list) else [], args)

    trajectory = list(state.get("trajectory", []))
    step_num = int(state.get("step_index", 0)) + 1
    trajectory.append(
        {
            "step": step_num,
            "tool": tool,
            "args": args,
            "reason": reason,
            "query_writer_model": AGENTIC_QUERY_WRITER_MODEL,
            "rows_returned": len(rows) if isinstance(rows, list) else None,
            "total_rows": total_rows,
            "execution_ms": int(result.get("execution_ms", 0) or 0),
            "confidence": confidence,
            "evidence_signals": evidence_signals,
            "sample_rows": rows[:25] if isinstance(rows, list) else [],
        }
    )

    return {
        "step_index": step_num,
        "trajectory": trajectory,
        "last_result": result,
    }


def evaluate_step_node(state: AgentState) -> AgentState:
    done, done_reason, next_tool, next_args = propose_next_action(
        question=state["question"],
        step_index=int(state.get("step_index", 0)),
        max_steps=int(state.get("max_steps", 3)),
        trajectory=list(state.get("trajectory", [])),
        last_result=state.get("last_result", {}) or {},
    )

    update: AgentState = {
        "done": done,
        "done_reason": done_reason,
        "next_tool": next_tool,
        "next_args": next_args,
        "next_reason": done_reason if not done else "",
    }
    return update


def evidence_review_node(state: AgentState) -> AgentState:
    started = time.monotonic()
    trajectory = list(state.get("trajectory", []))
    last_result = state.get("last_result", {}) or {}
    rows = last_result.get("structured", {}).get("results", []) if isinstance(last_result, dict) else []
    total_rows = last_result.get("structured", {}).get("total_rows") if isinstance(last_result, dict) else None
    tool = str(last_result.get("selected_tool", ""))
    args = last_result.get("mapped_query", {}) if isinstance(last_result.get("mapped_query", {}), dict) else {}

    system = (
        "You are an SOC evidence reviewer. Evaluate only observed Splunk evidence from executed agentic steps. "
        "Return strict JSON with keys: confidence, evidence_quality, key_findings, anomalies, gaps, recommendation."
    )
    payload = {
        "question": state.get("question", ""),
        "done_reason": state.get("done_reason", ""),
        "steps_executed": len(trajectory),
        "final_selected_tool": tool,
        "final_query_args": args,
        "rows_returned": len(rows) if isinstance(rows, list) else 0,
        "total_rows": total_rows,
        "sample_rows": rows[:25] if isinstance(rows, list) else [],
        "trajectory_preview": trajectory[-3:],
    }

    review: dict[str, Any]
    try:
        review = _call_ollama_json(
            model=AGENTIC_EVIDENCE_REVIEWER_MODEL,
            system_prompt=system,
            user_payload=payload,
        )
        review["source"] = "agentic_evidence_reviewer_model"
    except Exception as exc:
        review = {
            "confidence": 0.6,
            "evidence_quality": "fallback",
            "key_findings": [f"steps_executed={len(trajectory)}", f"rows_returned={len(rows) if isinstance(rows, list) else 0}"],
            "anomalies": [],
            "gaps": [f"evidence_reviewer_exception:{type(exc).__name__}:{exc}"],
            "recommendation": "Pivot by top entity and rerun with narrower scope/time window.",
            "source": "agentic_evidence_reviewer_fallback",
        }

    return {
        "evidence_review_output": review,
        "evidence_review_duration_ms": int((time.monotonic() - started) * 1000),
    }


def continuation_review_node(state: AgentState) -> AgentState:
    started = time.monotonic()
    trajectory = list(state.get("trajectory", []))
    last_result = state.get("last_result", {}) or {}
    evidence_review = state.get("evidence_review_output", {}) or {}
    max_steps = int(state.get("max_steps", 3) or 3)

    structured = last_result.get("structured", {}) if isinstance(last_result, dict) else {}
    rows = structured.get("results", []) if isinstance(structured, dict) else []
    if not isinstance(rows, list):
        rows = []

    system = (
        "You are an SOC continuation reviewer. Decide if the current investigation should continue or stop. "
        "You must stay read-only and propose only bounded investigative next steps. "
        "Return strict JSON with keys: should_continue, why, next_best_question, next_best_spl_or_tool, confidence, expected_value_of_next_step."
    )
    payload = {
        "question": state.get("question", ""),
        "done_reason": state.get("done_reason", ""),
        "max_steps": max_steps,
        "steps_executed": len(trajectory),
        "selected_tool": str(last_result.get("selected_tool", "")),
        "query_args": last_result.get("mapped_query", {}) if isinstance(last_result.get("mapped_query", {}), dict) else {},
        "rows_returned": len(rows),
        "sample_rows": rows[:20],
        "evidence_review": evidence_review if isinstance(evidence_review, dict) else {},
        "trajectory_preview": trajectory[-4:],
    }

    review: dict[str, Any]
    try:
        review = _call_ollama_json(
            model=AGENTIC_CONTINUATION_REVIEWER_MODEL,
            system_prompt=system,
            user_payload=payload,
            timeout=AGENTIC_CONTINUATION_REVIEW_TIMEOUT_SEC,
        )
        review["source"] = "agentic_continuation_reviewer_model"
    except Exception:
        review = _fallback_continuation_review(
            question=str(state.get("question", "")),
            trajectory=trajectory,
            last_result=last_result,
            evidence_review=evidence_review if isinstance(evidence_review, dict) else {},
            max_steps=max_steps,
        )

    review["should_continue"] = bool(review.get("should_continue", False))
    candidate_question = str(review.get("next_best_question", "")).strip()
    if review["should_continue"] and candidate_question:
        routable, route_reason = _followup_question_is_routable(candidate_question)
        if not routable:
            fallback_review = _fallback_continuation_review(
                question=str(state.get("question", "")),
                trajectory=trajectory,
                last_result=last_result,
                evidence_review=evidence_review if isinstance(evidence_review, dict) else {},
                max_steps=max_steps,
            )
            fallback_question = str(fallback_review.get("next_best_question", "")).strip()
            fallback_routable, fallback_reason = _followup_question_is_routable(fallback_question)
            if fallback_question and fallback_routable:
                review["next_best_question"] = fallback_question
                review["next_best_spl_or_tool"] = fallback_review.get(
                    "next_best_spl_or_tool",
                    review.get("next_best_spl_or_tool", ""),
                )
                review["source"] = f"{review.get('source', 'agentic_continuation_reviewer')}_routable_rewrite"
                review["rewrite_reason"] = f"replaced_unroutable_question:{route_reason}"
            else:
                review["rewrite_reason"] = (
                    f"question_unroutable:{route_reason};fallback_routable={fallback_routable}:{fallback_reason}"
                )
    return {
        "continuation_review_output": review,
        "continuation_review_duration_ms": int((time.monotonic() - started) * 1000),
    }


def summarize_node(state: AgentState) -> AgentState:
    started = time.monotonic()
    trajectory = list(state.get("trajectory", []))
    last_result = state.get("last_result", {}) or {}
    done_reason = str(state.get("done_reason", ""))
    summary_error = ""
    quality_reason = "summary_quality_ok"

    question_for_summary = state["question"]
    session_context = state.get("session_context", {})
    if isinstance(session_context, dict):
        last_questions = session_context.get("recent_questions", [])
        if isinstance(last_questions, list) and last_questions:
            prior = ", ".join(str(q) for q in last_questions[-3:])
            question_for_summary = f"Session prior questions: {prior}\nCurrent question: {state['question']}"

    trajectory_text = json.dumps(
        {
            "question": state["question"],
            "done_reason": done_reason,
            "steps": trajectory,
        },
        indent=2,
    )

    try:
        summary_prompt = f"Agentic investigation context:\n{trajectory_text}\n\nUser question:\n{question_for_summary}"
        summary = summarize_with_ollama_model(
            summary_prompt,
            last_result,
            model=AGENTIC_SUMMARY_MODEL,
            think=False,
        )
        if not summary.strip():
            summary = summarize_with_ollama(summary_prompt, last_result)
        summary = _clean_summary_text(summary)
        ok, quality_reason = _is_summary_quality_ok(summary)
        if not ok:
            summary = _deterministic_summary(state["question"], trajectory, done_reason)
    except Exception as exc:
        summary = _deterministic_summary(state["question"], trajectory, done_reason)
        summary_error = f"{type(exc).__name__}: {exc}"
        quality_reason = "model_exception_fallback"

    return {
        "summary": summary,
        "last_result": {
            **last_result,
            "agentic_trajectory": trajectory,
            "agentic_done_reason": done_reason,
            "evidence_review_output": state.get("evidence_review_output", {}),
            "evidence_review_duration_ms": int(state.get("evidence_review_duration_ms", 0) or 0),
            "summary_fallback_used": bool(summary_error) or quality_reason != "summary_quality_ok",
            "summary_error": summary_error,
            "summary_quality_reason": quality_reason,
            "summary_duration_ms": int((time.monotonic() - started) * 1000),
        },
    }


def finalize(state: AgentState) -> AgentState:
    return state


def route_after_guardrail(state: AgentState) -> str:
    return "initial_plan" if state.get("supported", False) else "finalize"


def route_after_evaluate(state: AgentState) -> str:
    return "evidence_review" if state.get("done", False) else "execute_step"


def build_graph():
    graph = StateGraph(AgentState)
    graph.add_node("ingest_question", ingest_question)
    graph.add_node("guardrail_check", guardrail_check)
    graph.add_node("initial_plan", initial_plan_node)
    graph.add_node("execute_step", execute_step_node)
    graph.add_node("evaluate_step", evaluate_step_node)
    graph.add_node("evidence_review", evidence_review_node)
    graph.add_node("continuation_review", continuation_review_node)
    graph.add_node("summarize", summarize_node)
    graph.add_node("finalize", finalize)

    graph.add_edge(START, "ingest_question")
    graph.add_edge("ingest_question", "guardrail_check")
    graph.add_conditional_edges("guardrail_check", route_after_guardrail)
    graph.add_edge("initial_plan", "execute_step")
    graph.add_edge("execute_step", "evaluate_step")
    graph.add_conditional_edges("evaluate_step", route_after_evaluate)
    graph.add_edge("evidence_review", "continuation_review")
    graph.add_edge("continuation_review", "summarize")
    graph.add_edge("summarize", "finalize")
    graph.add_edge("finalize", END)

    return graph.compile()


def _run_agentic_single_pass(
    question: str,
    *,
    max_steps: int = 3,
    session_id: str = "",
    session_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    run_started = time.monotonic()
    app = build_graph()
    session_id = str(session_id).strip()
    if isinstance(session_context, dict):
        effective_session_context = session_context
    else:
        effective_session_context = load_session_context(session_id) if session_id else {}

    invoke_state: AgentState = {
        "question": question,
        "max_steps": max_steps,
        "session_id": session_id,
        "session_context": effective_session_context,
    }
    result = app.invoke(invoke_state)

    supported = bool(result.get("supported", False))
    summary = str(result.get("summary", ""))
    if not supported:
        summary = f"Guardrail blocked request: {result.get('guardrail_reason', 'unsupported request')}"

    output = {
        "question": result.get("question"),
        "pipeline": "agentic_loop",
        "supported": supported,
        "guardrail_reason": result.get("guardrail_reason"),
        "max_steps": result.get("max_steps"),
        "steps_executed": result.get("step_index"),
        "done": result.get("done"),
        "done_reason": result.get("done_reason"),
        "trajectory": result.get("trajectory", []),
        "summary": summary,
        "summary_fallback_used": result.get("last_result", {}).get("summary_fallback_used"),
        "summary_error": result.get("last_result", {}).get("summary_error"),
        "summary_quality_reason": result.get("last_result", {}).get("summary_quality_reason"),
        "last_result": result.get("last_result", {}),
    }
    trajectory = output.get("trajectory", [])
    if not isinstance(trajectory, list):
        trajectory = []
    spl_steps: list[dict[str, Any]] = []
    for step in trajectory:
        if not isinstance(step, dict):
            continue
        if str(step.get("tool", "")) != "splunk_run_query":
            continue
        args = step.get("args", {}) if isinstance(step.get("args", {}), dict) else {}
        spl_steps.append(
            {
                "step": int(step.get("step", 0) or 0),
                "query": str(args.get("query", "")),
                "writer_model": str(step.get("query_writer_model", AGENTIC_QUERY_WRITER_MODEL)),
                "execution_ms": int(step.get("execution_ms", 0) or 0),
                "rows_returned": step.get("rows_returned"),
                "total_rows": step.get("total_rows"),
                "reason": str(step.get("reason", "")),
            }
        )
    output["selected_spl_details"] = spl_steps
    last_result = result.get("last_result", {}) if isinstance(result.get("last_result", {}), dict) else {}
    spl_results_preview: list[dict[str, Any]] = []
    for step in reversed(trajectory):
        if not isinstance(step, dict):
            continue
        if str(step.get("tool", "")) != "splunk_run_query":
            continue
        sample_rows = step.get("sample_rows", [])
        if isinstance(sample_rows, list):
            spl_results_preview = [r for r in sample_rows if isinstance(r, dict)][:50]
        if spl_results_preview:
            break
    if not spl_results_preview and isinstance(last_result, dict):
        last_structured = last_result.get("structured", {})
        if isinstance(last_structured, dict):
            rows = last_structured.get("results", [])
            if isinstance(rows, list):
                spl_results_preview = [r for r in rows if isinstance(r, dict)][:50]
    output["spl_results_preview"] = spl_results_preview

    final_selected_tool = ""
    if trajectory:
        final_selected_tool = str(trajectory[-1].get("tool", ""))
    output["model_workflow"] = [
        {
            "stage": "query_writer",
            "model": AGENTIC_QUERY_WRITER_MODEL,
            "responsibility": "intent mapping and read-only SPL drafting",
        },
        {
            "stage": "security_reviewer",
            "model": AGENTIC_REVIEWER_MODEL,
            "responsibility": "deterministic guardrail and query policy validation",
        },
        {
            "stage": "peer_reviewer_1",
            "model": AGENTIC_PEER_REVIEWER_MODEL,
            "responsibility": "intent-alignment checks during safe pivots",
        },
        {
            "stage": "evidence_reviewer",
            "model": AGENTIC_EVIDENCE_REVIEWER_MODEL,
            "responsibility": "evidence-based quality review of executed rows and findings",
        },
        {
            "stage": "continuation_reviewer",
            "model": AGENTIC_CONTINUATION_REVIEWER_MODEL,
            "responsibility": "decides whether investigation should continue and proposes the highest-value next pivot",
        },
        {
            "stage": "controller",
            "model": AGENTIC_CONTROLLER_MODEL,
            "responsibility": "bounded step orchestration and completion decision",
        },
        {
            "stage": "summary",
            "model": AGENTIC_SUMMARY_MODEL,
            "responsibility": "analyst-facing narrative generation",
        },
    ]
    output["planner"] = {
        "model": AGENTIC_QUERY_WRITER_MODEL,
        "output": {
            "selected_tool": str(trajectory[0].get("tool", "")) if trajectory else "",
            "intent": map_question_to_template(str(output.get("question", ""))).intent,
            "confidence": trajectory[0].get("confidence", 0.0) if trajectory else 0.0,
        },
    }
    output["security_reviewer"] = {
        "model": AGENTIC_REVIEWER_MODEL,
        "output": {
            "approved": supported,
            "confidence": 1.0 if supported else 0.0,
            "revised_selected_tool": final_selected_tool,
        },
    }
    output["peer_reviewer"] = {
        "model": AGENTIC_PEER_REVIEWER_MODEL,
        "output": {
            "winner": "intent_locked_plan" if supported else "blocked",
            "confidence": 0.95 if supported else 1.0,
        },
    }
    output["peer_reviewer_2"] = {
        "model": AGENTIC_CONTROLLER_MODEL,
        "output": {
            "winner": "controller_finalized_plan" if supported else "controller_blocked",
            "confidence": 0.95 if supported else 1.0,
            "agrees_with_peer1": supported,
        },
    }
    evidence_review_output = result.get("evidence_review_output", {})
    if not isinstance(evidence_review_output, dict):
        evidence_review_output = (
            (result.get("last_result", {}) or {}).get("evidence_review_output", {})
            if isinstance(result.get("last_result", {}), dict)
            else {}
        )
    evidence_review_duration_ms = result.get("evidence_review_duration_ms", 0)
    if not isinstance(evidence_review_duration_ms, int):
        evidence_review_duration_ms = int(
            ((result.get("last_result", {}) or {}).get("evidence_review_duration_ms", 0)
            if isinstance(result.get("last_result", {}), dict)
            else 0)
            or 0
        )
    output["evidence_reviewer"] = {
        "model": AGENTIC_EVIDENCE_REVIEWER_MODEL,
        "output": evidence_review_output if isinstance(evidence_review_output, dict) else {},
    }
    output["evidence_reviewer_output"] = evidence_review_output if isinstance(evidence_review_output, dict) else {}
    continuation_review_output = result.get("continuation_review_output", {})
    if not isinstance(continuation_review_output, dict):
        continuation_review_output = {}
    continuation_review_duration_ms = result.get("continuation_review_duration_ms", 0)
    if not isinstance(continuation_review_duration_ms, int):
        continuation_review_duration_ms = int(continuation_review_duration_ms or 0)
    output["continuation_reviewer"] = {
        "model": AGENTIC_CONTINUATION_REVIEWER_MODEL,
        "output": continuation_review_output,
    }
    output["continuation_reviewer_output"] = continuation_review_output
    output["final_adjudication"] = {
        "selected_tool": final_selected_tool,
        "selected_intent": map_question_to_template(str(output.get("question", ""))).intent,
        "validation_ok": supported,
        "validation_reason": str(output.get("done_reason", "")),
    }
    query_exec_ms = 0
    metadata_exec_ms = 0
    if trajectory:
        for i, step in enumerate(trajectory):
            if not isinstance(step, dict):
                continue
            step_ms = int(step.get("execution_ms", 0) or 0)
            tool = str(step.get("tool", ""))
            if i == 0:
                query_exec_ms += step_ms
                continue
            if tool == "splunk_run_query":
                query_exec_ms += step_ms
            else:
                metadata_exec_ms += step_ms
    summary_ms = int((result.get("last_result", {}) or {}).get("summary_duration_ms", 0) or 0)
    stage_timings_ms = {
        "detect": query_exec_ms,
        "triage": metadata_exec_ms,
        "investigate": evidence_review_duration_ms + continuation_review_duration_ms + summary_ms,
        "respond": 0,
        "recover": 0,
    }
    stage_timings_ms["total"] = (
        stage_timings_ms["detect"]
        + stage_timings_ms["triage"]
        + stage_timings_ms["investigate"]
    )
    output["stage_timings_ms"] = stage_timings_ms
    output["node_timings_ms"] = {
        "query_exec_total": query_exec_ms,
        "metadata_exec_total": metadata_exec_ms,
        "evidence_review": evidence_review_duration_ms,
        "continuation_review": continuation_review_duration_ms,
        "summarize": summary_ms,
        "pipeline_total": int((time.monotonic() - run_started) * 1000),
    }

    template = map_question_to_template(str(output.get("question", "")))
    output["tdir_case"] = build_tdir_case(
        question=str(output.get("question", "")),
        intent=str(template.intent),
        selected_tool=str(last_result.get("selected_tool", "")),
        query_args=last_result.get("mapped_query", {}) if isinstance(last_result.get("mapped_query", {}), dict) else {},
        structured=last_result.get("structured", {}) if isinstance(last_result.get("structured", {}), dict) else {},
        pipeline="agentic_loop",
        continuation_review=continuation_review_output,
        loop_control={},
    )
    output["node_timings_ms"]["pipeline_total"] = int((time.monotonic() - run_started) * 1000)
    return output


def run_agentic_investigation(
    question: str,
    *,
    max_steps: int = 3,
    session_id: str = "",
    write_artifact: bool = False,
    artifact_dir: str = "artifacts/runs/agentic",
    approved_deeper_investigation: bool = False,
    continuation_state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    meta: dict[str, Any] = {}
    session_id = str(session_id).strip()
    root_question = str(question).strip()
    case_state = _normalize_case_state(
        (continuation_state or {}).get("case_state", {}) if isinstance(continuation_state, dict) else {},
        root_question=root_question,
    )
    session_context = load_session_context(session_id) if session_id else {}

    if approved_deeper_investigation:
        if not isinstance(continuation_state, dict):
            raise ValueError("continuation_state is required for approved deeper investigation")
        requested_question = str(continuation_state.get("next_question", "")).strip()
        requested_signature = str(continuation_state.get("signature", "")).strip()
        if not requested_question or not requested_signature:
            raise ValueError("continuation_state must include next_question and signature")
        routable, route_reason = _followup_question_is_routable(requested_question)
        if not routable:
            raise ValueError(f"approved continuation question is not safely routable: {route_reason}")
        case_state["manual_continue_used"] = int(case_state.get("manual_continue_used", 0) or 0) + 1
        case_state["current_depth"] = int(case_state.get("current_depth", 0) or 0) + 1
        case_state.setdefault("asked_questions", []).append(requested_question)
        case_state.setdefault("pivot_signatures", []).append(requested_signature)
        active_question = requested_question
        root_question = str(continuation_state.get("root_question", root_question)).strip() or root_question
    else:
        active_question = root_question
        if active_question and active_question not in case_state["asked_questions"]:
            case_state["asked_questions"].append(active_question)

    primary_output = _run_agentic_single_pass(
        active_question,
        max_steps=max_steps,
        session_id=session_id,
        session_context=session_context,
    )
    primary_output["root_question"] = root_question
    primary_output["active_question"] = active_question
    case_state["rounds"].append(_condense_round(primary_output))
    primary_continuation = primary_output.get("continuation_reviewer_output", {})
    primary_loop_control = _build_loop_control(
        output=primary_output,
        case_state=case_state,
        approved_deeper_investigation=approved_deeper_investigation,
    )

    rounds: list[dict[str, Any]] = [primary_output]
    auto_followup_executed = False
    final_output = primary_output

    if primary_loop_control["auto_followup_allowed"] and not approved_deeper_investigation:
        followup_request = primary_loop_control.get("continuation_request", {})
        followup_question = str(followup_request.get("next_question", "")).strip()
        followup_signature = str(followup_request.get("signature", "")).strip()
        if followup_question and followup_signature:
            auto_followup_executed = True
            case_state["auto_continue_used"] = int(case_state.get("auto_continue_used", 0) or 0) + 1
            case_state["current_depth"] = int(case_state.get("current_depth", 0) or 0) + 1
            case_state.setdefault("asked_questions", []).append(followup_question)
            case_state.setdefault("pivot_signatures", []).append(followup_signature)
            followup_output = _run_agentic_single_pass(
                followup_question,
                max_steps=max(1, min(max_steps, 2)),
                session_id=session_id,
                session_context=session_context,
            )
            followup_output["root_question"] = root_question
            followup_output["active_question"] = followup_question
            case_state["rounds"].append(_condense_round(followup_output))
            rounds.append(followup_output)
            final_output = followup_output

    loop_control = _build_loop_control(
        output=final_output,
        case_state=case_state,
        approved_deeper_investigation=False,
    )
    loop_control["auto_followup_executed"] = auto_followup_executed
    loop_control["total_rounds"] = len(case_state.get("rounds", []))

    final_output["question"] = root_question
    final_output["root_question"] = root_question
    final_output["active_question"] = str(final_output.get("active_question", active_question))
    final_output["investigation_rounds"] = list(case_state.get("rounds", []))
    final_output["loop_control"] = loop_control
    final_output["case_state"] = case_state
    final_output["summary"] = (
        final_output.get("summary", "")
        + (
            f"\n\nAuto deeper investigation executed: {str(rounds[-1].get('active_question', ''))}"
            if auto_followup_executed
            else ""
        )
    ).strip()
    final_output["tdir_case"] = build_tdir_case(
        question=str(final_output.get("question", "")),
        intent=str(map_question_to_template(str(final_output.get("question", ""))).intent),
        selected_tool=str((final_output.get("trajectory", [])[-1].get("tool", "") if final_output.get("trajectory") else "")),
        query_args=(
            final_output.get("last_result", {}).get("mapped_query", {})
            if isinstance(final_output.get("last_result", {}), dict)
            else {}
        ),
        structured=(
            final_output.get("last_result", {}).get("structured", {})
            if isinstance(final_output.get("last_result", {}), dict)
            else {}
        ),
        pipeline="agentic_loop",
        continuation_review=final_output.get("continuation_reviewer_output", {}),
        loop_control=loop_control,
    )

    if session_id:
        selected_tool = ""
        trajectory = final_output.get("trajectory", [])
        if isinstance(trajectory, list) and trajectory:
            selected_tool = str(trajectory[-1].get("tool", ""))
        session_path = persist_session_context(
            session_id,
            question=str(final_output.get("question", "")),
            selected_tool=selected_tool,
            summary=str(final_output.get("summary", "")),
            rows_returned=final_output.get("tdir_case", {}).get("rows_returned"),
        )
        if session_path is not None:
            meta["session_context"] = str(session_path)

    if write_artifact:
        out_dir = Path(artifact_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        out_path = out_dir / f"agentic_run_{stamp}.json"
        payload = {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "result": final_output,
        }
        out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        meta["artifact"] = str(out_path)

    return {"result": final_output, "meta": meta}


def main() -> int:
    parser = argparse.ArgumentParser(description="Run agentic LangGraph SOC investigation loop")
    parser.add_argument("question", nargs="?", default="Investigate top index with metadata drilldown")
    parser.add_argument("--max-steps", type=int, default=3, help="Maximum investigation steps")
    parser.add_argument("--session-id", default="", help="Optional session id for lightweight memory")
    parser.add_argument("--write-artifact", action="store_true", help="Write JSON artifact to artifacts/runs/agentic")
    parser.add_argument("--artifact-dir", default="artifacts/runs/agentic", help="Artifact directory")
    args = parser.parse_args()

    payload = run_agentic_investigation(
        args.question,
        max_steps=args.max_steps,
        session_id=args.session_id,
        write_artifact=args.write_artifact,
        artifact_dir=args.artifact_dir,
    )
    print("=== Agentic LangGraph Result ===")
    print(json.dumps(payload["result"], indent=2))
    meta = payload.get("meta", {})
    if isinstance(meta, dict):
        if "session_context" in meta:
            print(f"session_context={meta['session_context']}")
        if "artifact" in meta:
            print(f"artifact={meta['artifact']}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
