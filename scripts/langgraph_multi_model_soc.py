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
from typing import Any, TypedDict

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
from question_intelligence import build_question_profile_text
from query_templates import TEMPLATES
from query_policy import validate_query_args
from spl_rag_context import build_spl_rag_context
from spl_query_repair import attempt_query_repair_once
from tdir_core import build_tdir_case
from environment_profile import validate_query_against_environment
from intent_field_contracts import validate_query_for_intent
from runtime_config import (
    DEFAULT_MODEL_EVIDENCE_REVIEWER,
    DEFAULT_MODEL_FINAL_SUMMARY,
    DEFAULT_MODEL_PEER_REVIEWER,
    DEFAULT_MODEL_PEER_REVIEWER_2,
    DEFAULT_MODEL_QUERY_PLANNER,
    DEFAULT_MODEL_QUERY_REPAIR,
    DEFAULT_MODEL_QUERY_WRITER,
    DEFAULT_MODEL_SECURITY_REVIEWER,
    get_model_assignment,
)

# Per-role model selection (env or saved runtime config driven for easy lab switching)
MODEL_QUERY_PLANNER = get_model_assignment(
    "OLLAMA_MODEL_QUERY_PLANNER",
    os.getenv("OLLAMA_MODEL_PLANNER", os.getenv("OLLAMA_MODEL_PRIMARY", DEFAULT_MODEL_QUERY_PLANNER)),
)
MODEL_QUERY_WRITER = get_model_assignment("OLLAMA_MODEL_QUERY_WRITER", DEFAULT_MODEL_QUERY_WRITER)
MODEL_SECURITY_REVIEWER = get_model_assignment("OLLAMA_MODEL_SECURITY_REVIEWER", DEFAULT_MODEL_SECURITY_REVIEWER)
MODEL_EVIDENCE_REVIEWER = get_model_assignment("OLLAMA_MODEL_EVIDENCE_REVIEWER", DEFAULT_MODEL_EVIDENCE_REVIEWER)
MODEL_PEER_REVIEWER = get_model_assignment("OLLAMA_MODEL_PEER_REVIEWER", DEFAULT_MODEL_PEER_REVIEWER)
MODEL_PEER_REVIEWER_2 = get_model_assignment("OLLAMA_MODEL_PEER_REVIEWER_2", DEFAULT_MODEL_PEER_REVIEWER_2)
MODEL_FINAL_SUMMARY = get_model_assignment("OLLAMA_MODEL_FINAL_SUMMARY", DEFAULT_MODEL_FINAL_SUMMARY)
MODEL_QUERY_REPAIR = get_model_assignment("OLLAMA_MODEL_QUERY_REPAIR", DEFAULT_MODEL_QUERY_REPAIR)
RAG_ENABLED = str(os.getenv("OLLAMA_RAG_ENABLED", "1")).strip().lower() not in {"0", "false", "no", "off"}
RAG_MAX_CHARS = int(os.getenv("OLLAMA_RAG_MAX_CHARS", "1600"))

BLOCKED_TERMS = ("delete", "drop", "remove", "shutdown", "restart", "write", "modify")
ALLOWED_TOOLS = {"splunk_run_query", "splunk_get_indexes", "splunk_get_metadata", "splunk_get_info"}
FORCE_QUERY_INTENTS = {
    "windows_auth_failures",
    "windows_process_activity",
    "windows_sysmon_network_activity",
    "windows_sysmon_dns_activity",
    "windows_credential_access_activity",
    "linux_auth_failures",
    "linux_session_activity",
    "linux_privilege_escalation",
    "linux_privilege_escalation_activity",
    "linux_audit_activity",
}


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
    supported: bool
    guardrail_reason: str
    planner_output: dict
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
    security_review_duration_ms: int
    peer_review_duration_ms: int
    peer_review_2_duration_ms: int
    validation_duration_ms: int
    run_tool_duration_ms: int
    evidence_review_duration_ms: int
    summarize_duration_ms: int
    query_repair: dict[str, Any]
    stage_logs: list[dict[str, Any]]
    writer_duration_ms: int


def _float01(value: Any, default: float = 0.5) -> float:
    try:
        f = float(value)
    except Exception:
        return default
    return max(0.0, min(1.0, round(f, 3)))


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

    # Robust fallback: locate first decodable JSON object among mixed text.
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
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "think": False,
    }
    with httpx.Client(timeout=timeout) as client:
        resp = client.post(f"{OLLAMA_HOST}/api/generate", json=payload)
        resp.raise_for_status()
        body = resp.json()

    raw = str(body.get("response") or "").strip()
    parsed = _extract_json_object(raw)
    parsed["_raw_text_preview"] = raw[:1200]
    return parsed


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
        out["tool_args"].setdefault("earliest_time", mapped_template.earliest_time)
        out["tool_args"].setdefault("latest_time", mapped_template.latest_time)
        out["tool_args"].setdefault("row_limit", mapped_template.row_limit)
        out["canonical_template_query"] = template_to_query_args(mapped_template, question).get("query", "")
    else:
        out["canonical_template_query"] = ""
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
        if "query" not in args and "search" in args:
            args["query"] = str(args.get("search", "")).strip()
            args.pop("search", None)
        if "query" in args:
            q = str(args.get("query", "")).strip()
            if q and not q.lower().startswith("search "):
                args["query"] = f"search {q}"
            # Remove inline time modifiers from SPL. Time belongs in tool args.
            args["query"] = re.sub(r"\s+(earliest(?:_time)?|latest(?:_time)?)\s*=\s*([^\s|]+)", "", args["query"], flags=re.IGNORECASE)
            args["query"] = re.sub(r"\s{2,}", " ", str(args["query"]).strip())
        if not args.get("earliest_time"):
            args["earliest_time"] = "-24h"
        if not args.get("latest_time"):
            args["latest_time"] = "now"
        if str(args.get("latest_time", "")).strip().lower() == "now()":
            args["latest_time"] = "now"
        try:
            rl = int(args.get("row_limit", 10))
        except Exception:
            rl = 10
        args["row_limit"] = max(1, min(200, rl))

        # Question-aware query cleanup for common planner mistakes on benchmark-only BOTSv3 families.
        q_lower = question.lower()
        if "botsv3" in q_lower:
            if "query" not in args:
                out = _default_plan_from_template(question)
                out["reason"] = f"{fallback_reason}:missing_query_for_run_query"
                return out
            explicit_botsv3_sourcetype = extract_explicit_botsv3_sourcetype(question)
            generic_botsv3_overview = explicit_botsv3_sourcetype and (
                "overview of sourcetype" in q_lower or "show an overview of sourcetype" in q_lower
            )
            args["query"] = re.sub(r"index=BOTSv3", "index=botsv3", str(args["query"]), flags=re.IGNORECASE)
            args["earliest_time"] = "0" if any(tok in q_lower for tok in ("all time", "full botsv3 dataset", "entire botsv3 dataset")) else args["earliest_time"]
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
            if any(tok in q_lower for tok in ("stream:http", "stream http", "http methods", "destination sites")):
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
            if any(tok in q_lower for tok in ("osquery", "process monitoring", "added processes")):
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
                        "| spath input=_raw path=query{} output=query "
                        "| spath input=_raw path=reply_code output=reply_code "
                        "| spath input=_raw path=src_ip output=src_ip "
                        "| spath input=_raw path=dest_ip output=dest_ip "
                        "| mvexpand query "
                        "| stats count by query reply_code src_ip dest_ip "
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
            is_botsv3 = "botsv3" in q_lower
            target_index = "index=botsv3" if is_botsv3 else "(index=windows OR index=windows_sysmon)"
            args["query"] = (
                f"search {target_index} sourcetype=XmlWinEventLog \"<EventID>1</EventID>\" "
                "| rex field=_raw \"<Data Name='Image'>(?<Image>[^<]+)</Data>\" "
                "| rex field=_raw \"<Data Name='CommandLine'>(?<CommandLine>[^<]+)</Data>\" "
                "| rex field=_raw \"<Data Name='User'>(?<User>[^<]+)</Data>\" "
                "| rex field=_raw \"<Data Name='ParentImage'>(?<ParentImage>[^<]+)</Data>\" "
                "| rex field=_raw \"<Computer>(?<Computer>[^<]+)</Computer>\" "
                "| stats count by Computer Image CommandLine User ParentImage "
                "| sort - count | head 20"
            )
            normalized["intent"] = "windows_process_activity"
        if (
            any(tok in q_lower for tok in ("failed login", "failed authentication", "authentication failure", "password spray", "brute force", "failed logon"))
            and "windows" in q_lower
            and "linux" in q_lower
        ):
            args["query"] = (
                "search index=linux (source=\"/var/log/auth.log\" OR source=\"/var/log/secure\") "
                "(\"Failed password\" OR \"authentication failure\" OR \"Invalid user\" OR \"Connection closed by invalid user\" OR \"FAILED SU\") "
                "| eval platform=\"linux\" "
                "| rex field=_raw \"(?i)Failed password for (?:invalid user )?(?<failed_user>[^ ]+)\" "
                "| rex field=_raw \"(?i)user=(?<pam_user>[^\\s;]+)\" "
                "| rex field=_raw \"(?i)from (?<failed_src_ip>\\d{1,3}(?:\\.\\d{1,3}){3}) port (?<failed_port>\\d+)\" "
                "| rex field=_raw \"(?i)rhost=(?<failed_rhost>[^\\s;]+)\" "
                "| eval src_ip=coalesce(src_ip,failed_src_ip,failed_rhost,rhost,src,ip,\"local\") "
                "| eval user_name=coalesce(user,username,account,failed_user,pam_user) "
                "| eval auth_port=coalesce(port,lport) "
                "| append [ search index=windows sourcetype=XmlWinEventLog "
                "(Channel=Security OR source=\"XmlWinEventLog:Security\") "
                "(EventCode=4625 OR EventID=4625 OR \"An account failed to log on\") "
                "| eval platform=\"windows\" "
                "| eval src_ip=coalesce(Source_Network_Address,IpAddress,src,src_ip,clientip,ip) "
                "| eval user_name=coalesce(TargetUserName,SubjectUserName,Account_Name,Caller_User_Name,user,username,account) "
                "| eval auth_port=coalesce(DestinationPort,dest_port) ] "
                "| fillnull value=\"unknown\" src_ip user_name auth_port "
                "| stats count by platform index host user_name src_ip auth_port "
                "| sort - count"
            )
            normalized["intent"] = "failed_login_activity"
        first_seen_priv_esc = any(
            tok in q_lower
            for tok in (
                "first time sudo",
                "first seen sudo",
                "first time su",
                "first seen privilege escalation",
                "first privilege escalation",
                "newly observed sudo",
                "newly observed sudo or su",
                "first observed sudo",
            )
        )
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
            target_index = "index=botsv3" if "botsv3" in q_lower else "index=windows_sysmon"
            args["query"] = (
                f"search {target_index} sourcetype=XmlWinEventLog "
                "Channel=\"Microsoft-Windows-Sysmon/Operational\" "
                "(EventID=3 OR EventCode=3 OR DestinationIp=*) "
                "| table _time Computer Image SourceIp DestinationIp DestinationPort Protocol "
                "| head 20"
            )
            normalized["intent"] = "windows_sysmon_network_activity"
        if any(tok in q_lower for tok in ("sysmon dns", "dns queries", "event id 22", "sysmon event 22")):
            target_index = "index=botsv3" if "botsv3" in q_lower else "index=windows_sysmon"
            args["query"] = (
                f"search {target_index} sourcetype=XmlWinEventLog "
                "Channel=\"Microsoft-Windows-Sysmon/Operational\" "
                "(EventID=22 OR EventCode=22 OR QueryName=*) "
                "| table _time Computer Image QueryName QueryResults "
                "| head 20"
            )
            normalized["intent"] = "windows_sysmon_dns_activity"
        if any(tok in q_lower for tok in ("credential access", "credential manager", "stored credentials", "event 5379")):
            args["query"] = (
                "search index=windows sourcetype=XmlWinEventLog "
                "(EventID=5379 OR EventCode=5379 OR \"CountOfCredentialsReturned\") "
                "| rex field=_raw \"<Data Name='SubjectUserName'>(?<SubjectUserName>[^<]+)</Data>\" "
                "| rex field=_raw \"<Data Name='TargetName'>(?<TargetName>[^<]+)</Data>\" "
                "| rex field=_raw \"<Data Name='CountOfCredentialsReturned'>(?<CountOfCredentialsReturned>[^<]+)</Data>\" "
                "| rex field=_raw \"<Data Name='ClientProcessId'>(?<ClientProcessId>[^<]+)</Data>\" "
                "| rex field=_raw \"<Computer>(?<Computer>[^<]+)</Computer>\" "
                "| table _time Computer SubjectUserName TargetName CountOfCredentialsReturned ClientProcessId"
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
        if (not first_seen_priv_esc) and any(tok in q_lower for tok in ("sudo behavior", "sudo activity", "su behavior", "su activity", "root session", "sudo sessions")):
            args["query"] = (
                "search index=linux (source=\"/var/log/auth.log\" OR source=\"/var/log/secure\") "
                "(\"sudo:\" OR \"su:\" OR \"pam_unix(sudo:session)\" OR \"pam_unix(su:session)\" OR \"COMMAND=\" OR "
                "\"session opened for user root by\" OR \"incorrect password\" OR \"authentication failure\") "
                "| rex field=_raw \"\\s(?<process_name>sudo|su)(?:\\[[^\\]]+\\])?:\" "
                "| rex field=_raw \"(?i)sudo:\\s+(?<sudo_actor>[A-Za-z0-9_.-]+)\\s+:\" "
                "| rex field=_raw \"(?i)by\\s+(?<session_actor>[A-Za-z0-9_.-]+)\\(uid=\" "
                "| rex field=_raw \"(?i)\\(to\\s+(?<su_target>[A-Za-z0-9_.-]+)\\)\\s+(?<su_actor>[A-Za-z0-9_.-]+)\\s+on\\s+(?<su_tty>[^\\s;]+)\" "
                "| rex field=_raw \"(?i)for user\\s+(?<target_user>[A-Za-z0-9_.-]+)\" "
                "| rex field=_raw \"(?i)USER=(?<target_user_cmd>[A-Za-z0-9_.-]+)\" "
                "| rex field=_raw \"(?i)password changed for\\s+(?<passwd_target>[A-Za-z0-9_.-]+)\" "
                "| rex field=_raw \"(?i)new user:\\s+name=(?<new_user>[A-Za-z0-9_.-]+)\" "
                "| rex field=_raw \"(?i)delete user\\s+'(?<deleted_user>[A-Za-z0-9_.-]+)'\" "
                "| rex field=_raw \"(?i)COMMAND=(?<command>.+)$\" "
                "| eval target_user=coalesce(target_user,target_user_cmd,su_target,passwd_target,new_user,deleted_user) "
                "| eval outcome=case(match(_raw, \"(?i)incorrect password|failure|failed|not in sudoers|conversation failed|auth could not identify password\"), \"failure\", match(_raw, \"(?i)password changed for\"), \"password_changed\", match(_raw, \"(?i)new user:\"), \"user_created\", match(_raw, \"(?i)delete user\"), \"user_deleted\", match(_raw, \"(?i)session opened\"), \"session_opened\", match(_raw, \"(?i)session closed\"), \"session_closed\", match(_raw, \"(?i)COMMAND=\"), \"command\", true(), \"other\") "
                "| eval actor=coalesce(sudo_actor, su_actor, session_actor, user, account, uid, user_name) "
                "| eval src_ip=coalesce(rhost, src, src_ip, ip) "
                "| eval tty=coalesce(su_tty, tty) "
                "| table _time host sourcetype process_name outcome actor target_user command src_ip tty _raw"
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

    if "list indexes" in q or "show indexes" in q or "what indexes" in q or "indexes i can access" in q:
        aligned["selected_tool"] = "splunk_get_indexes"
        aligned["tool_args"] = {}
        aligned["intent"] = "top_indexes"
        aligned["reason"] = "question_alignment_override:index_inventory"
        return aligned

    if "splunk version" in q or "splunk info" in q or "server info" in q or "instance info" in q:
        aligned["selected_tool"] = "splunk_get_info"
        aligned["tool_args"] = {}
        aligned["intent"] = "splunk_info"
        aligned["reason"] = "question_alignment_override:splunk_info"
        return aligned

    if "metadata" in q and any(x in q for x in ("host", "hosts", "source", "sources", "sourcetype", "sourcetypes")):
        selected_tool, _reason, metadata_args, _mode = determine_splunk_tool(question, "")
        if selected_tool == "splunk_get_metadata":
            aligned["selected_tool"] = "splunk_get_metadata"
            aligned["tool_args"] = metadata_args
            aligned["intent"] = "metadata_inventory"
            aligned["reason"] = "question_alignment_override:metadata_inventory"
        return aligned

    deterministic_run_query_intents = {
        "failed_login_activity",
        "linux_auth_failures",
        "windows_auth_failures",
        "windows_process_activity",
        "osquery_process_activity",
        "windows_sysmon_network_activity",
        "windows_sysmon_dns_activity",
        "windows_credential_access_activity",
        "linux_privilege_escalation",
        "linux_privilege_escalation_first_seen",
        "linux_session_activity",
        "linux_audit_activity",
        "apache_access_top_ips",
        "apache_404_spike",
        "apache_suspicious_user_agents",
        "stream_http_activity",
        "botsv3_named_sourcetype_overview",
        "top_indexes",
        "aws_vpc_flow_activity",
        "aad_signin_activity",
        "stream_dns_activity",
        "o365_management_activity",
    }
    if mapped_template.intent in deterministic_run_query_intents:
        aligned["selected_tool"] = "splunk_run_query"
        aligned["tool_args"] = template_to_query_args(mapped_template, question)
        aligned["intent"] = mapped_template.intent
        aligned["reason"] = f"question_alignment_override:template:{mapped_template.intent}"
        return aligned

    return aligned


def ingest_question(state: MultiModelState) -> MultiModelState:
    question = str(state.get("question", "")).strip()
    if not question:
        raise ValueError("question is required")
    return {
        "question": question,
        "session_id": str(state.get("session_id", "")).strip(),
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
        "When the question explicitly says all time or full BOTSv3 dataset, set earliest_time=0 and latest_time=now in tool_args. "
        "Return strict JSON keys: intent, intent_summary, selected_tool, search_strategy_summary, likely_indexes, likely_sourcetypes, likely_fields, constraints, tool_args, confidence, reason, caveats. "
        "If selected_tool is splunk_run_query, tool_args may only include earliest_time, latest_time, and row_limit. Do not include query text."
    )
    payload = {
        "question": question,
        "question_profile": question_profile,
        "constraints": {
            "read_only": True,
            "max_row_limit": 200,
            "metadata_types": ["hosts", "sources", "sourcetypes"],
        },
        "rag_context": rag_context,
    }
    planner_output: dict[str, Any]
    try:
        planner_output = _call_ollama_json(model=MODEL_QUERY_PLANNER, system_prompt=system, user_payload=payload)
        planner_output["source"] = "planner_model"
    except Exception as exc:
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
            "reason": f"planner_exception:{type(exc).__name__}:{exc}",
            "caveats": ["planner_fallback_used"],
            "source": "planner_fallback",
        }

    normalized = _normalize_planner_plan(planner_output, question, fallback_reason="planner_normalization_fallback")
    return {
        "planner_output": normalized,
        "planner_duration_ms": int((time.monotonic() - started) * 1000),
        "stage_logs": _append_stage_log(
            state,
            stage="planner",
            title="Planner interpreted the analyst request",
            details=[
                f"intent={normalized.get('intent', 'unknown')}",
                f"selected_tool={normalized.get('selected_tool', '')}",
                f"strategy={normalized.get('search_strategy_summary', '')}",
                "This stage is planning only. Final SPL is generated by the writer model.",
            ],
            model=MODEL_QUERY_PLANNER,
            duration_ms=int((time.monotonic() - started) * 1000),
        ),
    }


def writer_node(state: MultiModelState) -> MultiModelState:
    started = time.monotonic()
    question = state["question"]
    rag_context = build_spl_rag_context(question, max_chars=RAG_MAX_CHARS) if RAG_ENABLED else ""
    planner_output = state.get("planner_output", {}) or {}
    if str(planner_output.get("selected_tool", "")) != "splunk_run_query":
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
        return {
            "writer_output": writer_output,
            "writer_duration_ms": int((time.monotonic() - started) * 1000),
            "stage_logs": _append_stage_log(
                state,
                stage="writer",
                title="Writer preserved the bounded non-query tool choice",
                details=[
                    f"selected_tool={writer_output.get('selected_tool', '')}",
                    "No SPL generation was needed because the planner chose a metadata/info tool.",
                ],
                model=MODEL_QUERY_WRITER,
                duration_ms=int((time.monotonic() - started) * 1000),
            ),
        }

    system = (
        "You are the SPL writer in a guarded Splunk workflow. "
        "Convert the structured search plan into executable read-only Splunk tool args. "
        "You are optimizing for syntactic correctness, clean command ordering, and practical SPL composition. "
        "When a canonical template query is supplied, treat it as the anchor shape to preserve unless you have a strong reason to improve it. "
        "Do not widen the scope beyond the canonical template. Do not invent alternate sourcetypes or indexes. "
        "If selected_tool is splunk_run_query, tool_args must include query, earliest_time, latest_time, row_limit. "
        "Place time bounds in tool_args, not inside query text. Query must start with 'search '. "
        "Do not invent indexes, sourcetypes, or fields. "
        "Return strict JSON only with keys: selected_tool, tool_args, confidence, reason, caveats."
    )
    payload = {
        "question": question,
        "planner_output": planner_output,
        "canonical_template_query": str(planner_output.get("canonical_template_query", "")),
        "rag_context": rag_context,
    }

    writer_output: dict[str, Any]
    try:
        writer_output = _call_ollama_json(model=MODEL_QUERY_WRITER, system_prompt=system, user_payload=payload)
        writer_output["source"] = "writer_model"
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
    return {
        "writer_output": normalized,
        "final_plan": normalized if not _topology_settings().get("security_review", True) else state.get("final_plan", {}),
        "writer_duration_ms": int((time.monotonic() - started) * 1000),
        "stage_logs": _append_stage_log(
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
        ),
    }


def security_review_node(state: MultiModelState) -> MultiModelState:
    started = time.monotonic()
    question = state["question"]
    rag_context = build_spl_rag_context(question, max_chars=RAG_MAX_CHARS) if RAG_ENABLED else ""
    planner_output = state.get("planner_output", {}) or {}
    writer_output = state.get("writer_output", {}) or {}
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

    plan = state.get("final_plan", {}) or state.get("writer_output", {}) or {}
    question = state["question"]
    plan = _normalize_candidate(plan, question, fallback_reason="final_plan_normalization_fallback")
    plan = _enforce_question_alignment(question, plan)
    plan = _normalize_candidate(plan, question, fallback_reason="post_alignment_normalization_fallback")

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
        for attempt_idx in range(2):
            ok, reason = validate_query_args(args_current, question=question)
            if not ok:
                failure_reason = f"policy:{reason}"
            else:
                contract_ok, contract_reason = validate_query_for_intent(intent_name, args_current)
                if not contract_ok:
                    failure_reason = f"intent_contract:{contract_reason}"
                else:
                    env_ok, env_reason = validate_query_against_environment(args_current)
                    if not env_ok:
                        failure_reason = f"environment:{env_reason}"
                    else:
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
                                    "Policy, intent contract, and environment checks passed.",
                                ],
                                duration_ms=int((time.monotonic() - started) * 1000),
                            ),
                        }
                        if repair_meta:
                            result_payload["query_repair"] = repair_meta
                            result_payload["validation_reason"] = "plan_valid_after_auto_repair"
                        return result_payload

            if attempt_idx == 1:
                human_reason = failure_reason
                if human_reason.startswith("intent_contract:"):
                    human_reason = f"Final query blocked by intent contract: {human_reason.split(':', 1)[1]}"
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
                rag_max_chars=RAG_MAX_CHARS,
            )
            repair_meta = repair if isinstance(repair, dict) else {}
            if repair_meta.get("ok", False):
                repaired_args = repair_meta.get("args", {})
                if isinstance(repaired_args, dict):
                    args_current = repaired_args
                    plan["reason"] = f"{plan.get('reason', '')};auto_repair:{repair_meta.get('repair_reason', '')}".strip(";")
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
    started = time.monotonic()

    if tool == "splunk_get_indexes":
        data = run_splunk_get_indexes()
    elif tool == "splunk_get_info":
        data = run_splunk_get_info()
    elif tool == "splunk_get_metadata":
        data = run_splunk_get_metadata(args)
    else:
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
        "run_tool_duration_ms": int((time.monotonic() - started) * 1000),
        "stage_logs": _append_stage_log(
            state,
            stage="execution",
            title="Splunk tool execution completed",
            details=[
                f"selected_tool={tool}",
                f"execution_ms={data.get('execution_ms', 0)}",
                f"rows_returned={((data.get('structured', {}) or {}).get('total_rows', 0) if isinstance(data, dict) else 0)}",
            ],
            duration_ms=int((time.monotonic() - started) * 1000),
        ),
    }


def evidence_review_node(state: MultiModelState) -> MultiModelState:
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

    plan = state.get("final_plan", {}) or {}
    splunk_data = state.get("splunk_data", {}) or {}
    structured = splunk_data.get("structured", {}) if isinstance(splunk_data, dict) else {}
    rows = structured.get("results", []) if isinstance(structured, dict) else []
    total_rows = structured.get("total_rows") if isinstance(structured, dict) else None
    platform_coverage = _derive_platform_coverage(plan, rows if isinstance(rows, list) else [])

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
        "rows_returned": len(rows) if isinstance(rows, list) else 0,
        "total_rows": total_rows,
        "sample_rows": rows[:25] if isinstance(rows, list) else [],
    }
    review: dict[str, Any]
    try:
        review = _call_ollama_json(model=MODEL_EVIDENCE_REVIEWER, system_prompt=system, user_payload=payload)
        review["source"] = "evidence_reviewer_model"
    except Exception as exc:
        review = {
            "confidence": 0.6,
            "evidence_quality": "fallback",
            "key_findings": [
                f"rows_returned={len(rows) if isinstance(rows, list) else 0}",
                f"selected_tool={plan.get('selected_tool', '')}",
            ],
            "anomalies": [],
            "gaps": [f"evidence_reviewer_exception:{type(exc).__name__}:{exc}"],
            "recommendation": "Use deterministic row/entity pivots and re-run with narrower time scope if needed.",
            "source": "evidence_reviewer_fallback",
        }

    return {
        "evidence_review_output": review,
        "evidence_review_duration_ms": int((time.monotonic() - started) * 1000),
        "stage_logs": _append_stage_log(
            state,
            stage="evidence_review",
            title="Evidence reviewer assessed the returned rows",
            details=[
                f"evidence_quality={review.get('evidence_quality', 'unknown')}",
                f"confidence={review.get('confidence', 0)}",
                str(review.get("recommendation", ""))[:220],
            ],
            model=MODEL_EVIDENCE_REVIEWER,
            duration_ms=int((time.monotonic() - started) * 1000),
        ),
    }


def _deterministic_summary(output: dict[str, Any]) -> str:
    if not output.get("supported", False):
        return f"Guardrail blocked request: {output.get('guardrail_reason', 'unsupported request')}"

    rows = output.get("rows_returned", 0)
    tool = output.get("selected_tool", "")
    confidence = output.get("final_confidence", 0.0)
    return (
        f"- Tool executed: {tool}\n"
        f"- Rows returned: {rows}\n"
        f"- Final confidence: {confidence}\n"
        "- Next action: pivot on top entity and re-run with narrower time scope if needed."
    )


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
    if 'eval platform="linux"' in query or "index=linux" in query or 'source="/var/log/auth.log"' in query or 'source="/var/log/secure"' in query:
        query_platforms.add("linux")
    if 'eval platform="windows"' in query or "index=windows" in query or "index=windows_sysmon" in query or "eventcode=4625" in query:
        query_platforms.add("windows")
    return {
        "query_platforms": sorted(query_platforms),
        "row_platforms": sorted(row_platforms),
        "platforms": sorted(query_platforms | row_platforms),
        "cross_platform_query": len(query_platforms) > 1,
        "cross_platform_results": len(row_platforms) > 1,
    }


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


def _summarize_with_timeout(question: str, splunk_data: dict[str, Any], *, model: str, think: bool) -> str:
    with httpx.Client(timeout=SUMMARY_TIMEOUT_SECONDS) as client:
        rows = splunk_data.get("structured", {}).get("results", [])
        total_rows = splunk_data.get("structured", {}).get("total_rows")
        context = {
            "question": question,
            "intent": splunk_data.get("intent"),
            "summary_hint": splunk_data.get("summary_hint"),
            "query_used": splunk_data.get("mapped_query", {}),
            "total_rows": total_rows,
            "rows": rows,
        }
        prompt = (
            "You are a SOC analyst assistant in a lab. "
            "Summarize the query result in plain English in 4-6 bullet points. "
            "Include: what was queried, top findings, and one suggested next check.\n\n"
            f"DATA:\n{json.dumps(context, indent=2)}"
        )
        resp = client.post(
            f"{OLLAMA_HOST}/api/generate",
            json={"model": model, "prompt": prompt, "stream": False, "think": think},
        )
        resp.raise_for_status()
        body = resp.json()
    text = (body.get("response") or "").strip()
    if not text:
        raise RuntimeError("summary_empty")
    return text


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
    plan = state.get("final_plan", {}) or {}
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

    evidence = {
        "query_or_args": plan.get("tool_args", {}),
        "platform_coverage": platform_coverage,
        "time_window": {
            "earliest_time": (plan.get("tool_args", {}) or {}).get("earliest_time"),
            "latest_time": (plan.get("tool_args", {}) or {}).get("latest_time"),
        },
        "rows_returned": len(rows) if isinstance(rows, list) else 0,
        "total_rows": total_rows,
        "top_entities": rows[:3] if isinstance(rows, list) else [],
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
        "evidence_reviewer_model": MODEL_EVIDENCE_REVIEWER,
        "final_summary_model": MODEL_FINAL_SUMMARY,
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
            "model": MODEL_EVIDENCE_REVIEWER,
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
        "query_repair": state.get("query_repair", {}),
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
            {
                "stage": "security_reviewer",
                "model": MODEL_SECURITY_REVIEWER,
                "responsibility": "Critique the generated SPL against analyst intent, field assumptions, and safety constraints.",
            },
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
                if not (
                    not any(
                        str((entry or {}).get("stage", "")).strip() in {"peer_review_1", "peer_review_2"}
                        for entry in final_stage_logs
                        if isinstance(entry, dict)
                    )
                )
                else []
            ),
            {
                "stage": "evidence_reviewer",
                "model": MODEL_EVIDENCE_REVIEWER,
                "responsibility": "Post-execution evidence quality review on actual returned rows.",
            },
            {
                "stage": "final_summary",
                "model": MODEL_FINAL_SUMMARY,
                "responsibility": "Generate analyst-facing evidence-first narrative from validated results.",
            },
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
        "generated_spl": str((plan.get("tool_args", {}) or {}).get("query", "")),
        "stage_logs": final_stage_logs,
    }
    node_timings_ms = {
        "guardrail": int(state.get("guardrail_duration_ms", 0) or 0),
        "planner": int(state.get("planner_duration_ms", 0) or 0),
        "writer": int(state.get("writer_duration_ms", 0) or 0),
        "security_review": int(state.get("security_review_duration_ms", 0) or 0),
        "peer_review_1": int(state.get("peer_review_duration_ms", 0) or 0),
        "peer_review_2": int(state.get("peer_review_2_duration_ms", 0) or 0),
        "validation": int(state.get("validation_duration_ms", 0) or 0),
        "run_tool": int(state.get("run_tool_duration_ms", 0) or 0),
        "evidence_review": int(state.get("evidence_review_duration_ms", 0) or 0),
    }
    selected_spl_details: list[dict[str, Any]] = []
    if str(output.get("selected_tool", "")) == "splunk_run_query":
        selected_args = output.get("query_args", {}) if isinstance(output.get("query_args", {}), dict) else {}
        selected_spl_details.append(
            {
                "step": 1,
                "query": str(selected_args.get("query", "")),
                "writer_model": MODEL_QUERY_WRITER,
                "execution_ms": int(splunk_data.get("execution_ms", 0) or 0),
                "rows_returned": output.get("rows_returned"),
                "total_rows": output.get("total_rows"),
                "reason": str(plan.get("reason", "")),
            }
        )
    output["selected_spl_details"] = selected_spl_details
    output["spl_results_preview"] = rows[:50] if (
        str(output.get("selected_tool", "")) == "splunk_run_query" and isinstance(rows, list)
    ) else []
    output["tdir_case"] = build_tdir_case(
        question=question,
        intent=str(output.get("intent", "unknown")),
        selected_tool=str(output.get("selected_tool", "")),
        query_args=output.get("query_args", {}) if isinstance(output.get("query_args", {}), dict) else {},
        structured=splunk_data.get("structured", {}) if isinstance(splunk_data, dict) else {},
        pipeline="multi_model_reviewer",
    )

    if not _topology_settings().get("final_summary", True):
        summary = _deterministic_summary(output)
    elif output["supported"]:
        try:
            summary_prompt = (
                "Produce SOC analyst output in 5-7 bullets. Include: what was asked, what query/tool was executed, "
                "top findings, confidence rationale, and concrete next checks. "
                "If platform_coverage.query_platforms includes both linux and windows, explicitly say the executed search was cross-platform and mention both Linux and Windows in the first bullet.\n"
                f"MODEL_PIPELINE_OUTPUT:\n{json.dumps(output, indent=2)}"
            )
            summary = _summarize_with_timeout(summary_prompt, splunk_data, model=MODEL_FINAL_SUMMARY, think=False)
            summary = _clean_summary_text(summary)
            summary = _enforce_platform_coverage_in_summary(summary, platform_coverage)
            ok, _reason = _is_summary_quality_ok(summary)
            if not ok:
                raise RuntimeError("summary_quality_gate_failed")
        except Exception:
            summary = _deterministic_summary(output)
    else:
        summary = _deterministic_summary(output)

    summarize_ms = int((time.monotonic() - started) * 1000)
    node_timings_ms["summarize"] = summarize_ms
    detect_ms = (
        node_timings_ms["guardrail"]
        + node_timings_ms["planner"]
        + node_timings_ms["writer"]
        + node_timings_ms["security_review"]
        + node_timings_ms["peer_review_1"]
        + node_timings_ms["peer_review_2"]
        + node_timings_ms["validation"]
    )
    triage_ms = node_timings_ms["run_tool"]
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
        ],
        model=MODEL_FINAL_SUMMARY,
        duration_ms=summarize_ms,
    )
    output["summary"] = summary
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
    if not _topology_settings().get("security_review", True):
        return "validate_final_plan"
    return "security_review"


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
    return "run_tool" if state.get("validation_ok", False) else "summarize"


def describe_multi_model_graph(topology_settings: dict[str, bool] | None = None) -> dict[str, Any]:
    settings = dict(_topology_settings())
    if topology_settings:
        settings.update({str(k): bool(v) for k, v in topology_settings.items()})

    canonical_nodes = [
        {"id": "ingest_question", "label": "Ingest Question", "group": "controller"},
        {"id": "guardrail", "label": "Guardrail", "group": "controller"},
        {"id": "planner", "label": "Planner", "group": "primary_inference"},
        {"id": "writer", "label": "SPL Writer", "group": "primary_inference"},
        {"id": "security_review", "label": "Security Reviewer", "group": "primary_inference"},
        {"id": "peer_review", "label": "Peer Review 1", "group": "primary_inference"},
        {"id": "peer_review_2", "label": "Peer Review 2", "group": "primary_inference"},
        {"id": "validate_final_plan", "label": "Deterministic Validation", "group": "controller"},
        {"id": "run_tool", "label": "Splunk MCP Execution", "group": "data_plane"},
        {"id": "evidence_review", "label": "Evidence Review", "group": "primary_inference"},
        {"id": "summarize", "label": "Final Summary", "group": "primary_inference"},
        {"id": "finalize", "label": "Finalize", "group": "controller"},
    ]
    canonical_edges = [
        {"from": "ingest_question", "to": "guardrail", "kind": "direct", "label": ""},
        {"from": "guardrail", "to": "planner", "kind": "conditional", "label": "supported"},
        {"from": "guardrail", "to": "summarize", "kind": "conditional", "label": "blocked"},
        {"from": "planner", "to": "writer", "kind": "direct", "label": ""},
        {"from": "writer", "to": "security_review", "kind": "conditional", "label": "security review enabled"},
        {"from": "writer", "to": "validate_final_plan", "kind": "conditional", "label": "security review disabled"},
        {"from": "security_review", "to": "validate_final_plan", "kind": "conditional", "label": "clean approval"},
        {"from": "security_review", "to": "peer_review", "kind": "conditional", "label": "contested"},
        {"from": "peer_review", "to": "peer_review_2", "kind": "direct", "label": ""},
        {"from": "peer_review_2", "to": "validate_final_plan", "kind": "direct", "label": ""},
        {"from": "validate_final_plan", "to": "run_tool", "kind": "conditional", "label": "approved"},
        {"from": "validate_final_plan", "to": "summarize", "kind": "conditional", "label": "blocked"},
        {"from": "run_tool", "to": "evidence_review", "kind": "direct", "label": ""},
        {"from": "evidence_review", "to": "summarize", "kind": "direct", "label": ""},
        {"from": "summarize", "to": "finalize", "kind": "direct", "label": ""},
    ]

    active_nodes = [
        {"id": "ingest_question", "label": "Ingest Question", "group": "controller"},
        {"id": "guardrail", "label": "Guardrail", "group": "controller"},
        {"id": "planner", "label": "Planner", "group": "primary_inference"},
        {"id": "writer", "label": "SPL Writer", "group": "primary_inference"},
    ]
    active_edges = [
        {"from": "ingest_question", "to": "guardrail", "kind": "direct", "label": ""},
        {"from": "guardrail", "to": "planner", "kind": "conditional", "label": "supported"},
        {"from": "guardrail", "to": "summarize", "kind": "conditional", "label": "blocked"},
        {"from": "planner", "to": "writer", "kind": "direct", "label": ""},
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
    active_nodes.append({"id": "run_tool", "label": "Splunk MCP Execution", "group": "data_plane"})
    active_edges.extend(
        [
            {"from": "validate_final_plan", "to": "run_tool", "kind": "conditional", "label": "approved"},
            {"from": "validate_final_plan", "to": "summarize", "kind": "conditional", "label": "blocked"},
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
    graph.add_node("writer", writer_node)
    graph.add_node("security_review", security_review_node)
    graph.add_node("peer_review", peer_review_node)
    graph.add_node("peer_review_2", peer_review_2_node)
    graph.add_node("validate_final_plan", validate_final_plan_node)
    graph.add_node("run_tool", run_tool_node)
    graph.add_node("evidence_review", evidence_review_node)
    graph.add_node("summarize", summarize_node)
    graph.add_node("finalize", finalize)

    graph.add_edge(START, "ingest_question")
    graph.add_edge("ingest_question", "guardrail")
    graph.add_conditional_edges("guardrail", route_after_guardrail)
    graph.add_edge("planner", "writer")
    graph.add_conditional_edges("writer", route_after_writer)
    graph.add_conditional_edges("security_review", route_after_security_review)
    graph.add_edge("peer_review", "peer_review_2")
    graph.add_edge("peer_review_2", "validate_final_plan")
    graph.add_conditional_edges("validate_final_plan", route_after_validation)
    graph.add_edge("run_tool", "evidence_review")
    graph.add_edge("evidence_review", "summarize")
    graph.add_edge("summarize", "finalize")
    graph.add_edge("finalize", END)
    return graph.compile()


def run_multi_model_soc(
    question: str,
    *,
    session_id: str = "",
    write_artifact: bool = False,
    artifact_dir: str = "artifacts/runs/multi_model",
) -> dict[str, Any]:
    app = build_graph()
    result = app.invoke({"question": question, "session_id": session_id})
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
