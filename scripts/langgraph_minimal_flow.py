#!/usr/bin/env python3
"""Minimal LangGraph SOC flow for the lab.

Graph nodes:
1) ingest_question
2) plan_query
3) run_splunk_query
4) summarize_results
5) finalize

This intentionally reuses existing validated functions from minimal_question_to_answer.py.
"""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import TypedDict

from langgraph.graph import END, START, StateGraph

from minimal_question_to_answer import (
    map_question_to_template,
    run_splunk_get_info,
    run_splunk_get_indexes,
    run_splunk_get_metadata,
    run_splunk_query,
    summarize_with_ollama,
)
from query_policy import validate_query_args


class SocState(TypedDict, total=False):
    question: str
    row_limit_override: int
    session_id: str
    session_context: dict
    intent: str
    intent_confidence: float
    planner_reason: str
    decision_log: list[dict]
    query_args: dict
    selected_tool: str
    selected_tool_allowed: bool
    selected_tool_reason: str
    metadata_args: dict
    tool_chain_mode: str
    chain_second_tool: str
    chain_second_tool_args: dict
    primary_splunk_data: dict
    query_policy_ok: bool
    query_policy_reason: str
    splunk_data: dict
    summary: str
    supported: bool
    guardrail_reason: str


def ingest_question(state: SocState) -> SocState:
    question = state.get("question", "").strip()
    if not question:
        raise ValueError("question is required")
    session_id = str(state.get("session_id", "")).strip()
    session_context = state.get("session_context", {})
    if not isinstance(session_context, dict):
        session_context = {}
    return {
        "question": question,
        "session_id": session_id,
        "session_context": session_context,
        "decision_log": [{"node": "ingest_question", "decision": "accepted_non_empty_question"}],
    }


def plan_query(state: SocState) -> SocState:
    question = state["question"]
    template = map_question_to_template(question)
    # Minimal explainable planner metadata for observability.
    confidence = 0.65
    reason = "fallback/default template match"
    lower = question.lower()
    if any(k in lower for k in template.keywords):
        confidence = 0.9
        reason = f"matched keywords for intent '{template.intent}'"
    log = list(state.get("decision_log", []))
    log.append(
        {
            "node": "plan_query",
            "intent": template.intent,
            "intent_confidence": confidence,
            "planner_reason": reason,
        }
    )
    query_args = {
        "query": template.query,
        "earliest_time": template.earliest_time,
        "latest_time": template.latest_time,
        "row_limit": template.row_limit,
    }
    if "row_limit_override" in state and state["row_limit_override"] is not None:
        query_args["row_limit"] = state["row_limit_override"]
        log.append(
            {
                "node": "plan_query",
                "override": "row_limit_override",
                "value": state["row_limit_override"],
            }
        )

    return {
        "intent": template.intent,
        "intent_confidence": confidence,
        "planner_reason": reason,
        "decision_log": log,
        "query_args": query_args,
    }


def guardrail_check(state: SocState) -> SocState:
    question = state["question"].lower()
    # Minimal starter guardrail: reject direct update/delete/control intent words.
    blocked_terms = ("delete", "drop", "remove", "shutdown", "restart", "write", "modify")
    log = list(state.get("decision_log", []))
    if any(term in question for term in blocked_terms):
        log.append(
            {
                "node": "guardrail_check",
                "supported": False,
                "reason": "blocked_non_read_only_intent_terms",
            }
        )
        return {
            "supported": False,
            "guardrail_reason": (
                "Question appears to request non-read-only action. "
                "This lab flow currently supports read-only analysis questions."
            ),
            "decision_log": log,
        }
    log.append({"node": "guardrail_check", "supported": True, "reason": "read_only_question"})
    return {"supported": True, "guardrail_reason": "", "decision_log": log}


def validate_query_policy_node(state: SocState) -> SocState:
    log = list(state.get("decision_log", []))
    ok, reason = validate_query_args(state.get("query_args", {}), question=state.get("question", ""))
    if not ok:
        log.append(
            {
                "node": "validate_query_policy",
                "supported": False,
                "reason": reason,
            }
        )
        return {
            "supported": False,
            "guardrail_reason": f"Planned query blocked by policy: {reason}",
            "query_policy_ok": False,
            "query_policy_reason": reason,
            "decision_log": log,
        }
    log.append({"node": "validate_query_policy", "supported": True, "reason": reason})
    return {
        "query_policy_ok": True,
        "query_policy_reason": reason,
        "decision_log": log,
    }


def select_splunk_tool_node(state: SocState) -> SocState:
    selected_tool, reason, metadata_args, tool_chain_mode = determine_splunk_tool(
        state.get("question", ""),
        state.get("intent", ""),
    )
    log = list(state.get("decision_log", []))
    log.append(
        {
            "node": "select_splunk_tool",
            "selected_tool": selected_tool,
            "reason": reason,
            "metadata_args": metadata_args,
            "tool_chain_mode": tool_chain_mode,
        }
    )
    return {
        "selected_tool": selected_tool,
        "metadata_args": metadata_args,
        "tool_chain_mode": tool_chain_mode,
        "decision_log": log,
    }


def _plan_metadata_args(question: str) -> dict:
    question_lower = question.lower()
    metadata_type = "sourcetypes"
    if "host" in question_lower or "hosts" in question_lower:
        metadata_type = "hosts"
    elif "source" in question_lower or "sources" in question_lower:
        metadata_type = "sources"
    return {
        "type": metadata_type,
        "index": "*",
        "earliest_time": "-24h",
        "latest_time": "now",
        "row_limit": 20,
    }


def determine_splunk_tool(question: str, intent: str) -> tuple[str, str, dict, str]:
    question_lower = question.lower()
    intent_lower = intent.lower()
    selected_tool = "splunk_run_query"
    reason = "read_only_query_pipeline"
    metadata_args: dict = {}
    tool_chain_mode = ""
    metadata_signal_terms = (
        "metadata",
        "list hosts",
        "show hosts",
        "which hosts",
        "what hosts",
        "list sources",
        "show sources",
        "which sources",
        "what sources",
        "list sourcetypes",
        "show sourcetypes",
        "which sourcetypes",
        "what sourcetypes",
    )
    info_signal_terms = (
        "splunk info",
        "splunk version",
        "server info",
        "instance info",
        "platform info",
    )
    if "list indexes" in question_lower or "show indexes" in question_lower or "what indexes" in question_lower:
        selected_tool = "splunk_get_indexes"
        reason = "question_requests_index_inventory"
    elif intent_lower == "top_indexes" and "most events" not in question_lower and "top" not in question_lower:
        selected_tool = "splunk_get_indexes"
        reason = "intent_top_indexes_with_inventory_wording"
    elif any(term in question_lower for term in info_signal_terms):
        selected_tool = "splunk_get_info"
        reason = "question_requests_splunk_instance_info"
    elif any(term in question_lower for term in metadata_signal_terms):
        selected_tool = "splunk_get_metadata"
        metadata_args = _plan_metadata_args(question)
        reason = "question_requests_metadata_inventory"
    if (
        "investigate top index" in question_lower
        or "drill down top index" in question_lower
        or "index drilldown" in question_lower
    ):
        selected_tool = "splunk_get_indexes"
        reason = "question_requests_index_to_metadata_chain"
        tool_chain_mode = "indexes_to_metadata_sourcetypes"
    return selected_tool, reason, metadata_args, tool_chain_mode


def plan_tool_chain_node(state: SocState) -> SocState:
    chain_mode = state.get("tool_chain_mode", "")
    log = list(state.get("decision_log", []))
    if chain_mode == "indexes_to_metadata_sourcetypes":
        second_args = {
            "type": "sourcetypes",
            "index": "__TOP_INDEX_FROM_PRIMARY__",
            "earliest_time": "-24h",
            "latest_time": "now",
            "row_limit": 20,
        }
        log.append(
            {
                "node": "plan_tool_chain",
                "chain_mode": chain_mode,
                "chain_second_tool": "splunk_get_metadata",
                "chain_second_tool_args": second_args,
            }
        )
        return {
            "chain_second_tool": "splunk_get_metadata",
            "chain_second_tool_args": second_args,
            "decision_log": log,
        }
    log.append({"node": "plan_tool_chain", "chain_mode": "", "chain_second_tool": ""})
    return {"chain_second_tool": "", "chain_second_tool_args": {}, "decision_log": log}


def validate_selected_tool_node(state: SocState) -> SocState:
    selected = state.get("selected_tool", "")
    allowed_tools = {"splunk_run_query", "splunk_get_indexes", "splunk_get_metadata", "splunk_get_info"}
    metadata_args = state.get("metadata_args", {}) or {}
    log = list(state.get("decision_log", []))

    def _validate_metadata_args(args: dict) -> tuple[bool, str]:
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

    if selected not in allowed_tools:
        reason = f"selected_tool_not_allowed:{selected}"
        log.append({"node": "validate_selected_tool", "allowed": False, "reason": reason})
        return {
            "supported": False,
            "guardrail_reason": f"Planned tool blocked by allowlist: {selected}",
            "selected_tool_allowed": False,
            "selected_tool_reason": reason,
            "decision_log": log,
        }
    if selected == "splunk_get_metadata":
        ok, reason = _validate_metadata_args(metadata_args if isinstance(metadata_args, dict) else {})
        if not ok:
            log.append({"node": "validate_selected_tool", "allowed": False, "reason": reason})
            return {
                "supported": False,
                "guardrail_reason": f"Planned metadata args blocked by policy: {reason}",
                "selected_tool_allowed": False,
                "selected_tool_reason": reason,
                "decision_log": log,
            }
    reason = "selected_tool_allowed"
    log.append({"node": "validate_selected_tool", "allowed": True, "reason": reason})
    return {
        "selected_tool_allowed": True,
        "selected_tool_reason": reason,
        "decision_log": log,
    }


def run_splunk_node(state: SocState) -> SocState:
    selected_tool = state.get("selected_tool", "splunk_run_query")
    if selected_tool == "splunk_get_indexes":
        splunk_data = run_splunk_get_indexes()
    elif selected_tool == "splunk_get_info":
        splunk_data = run_splunk_get_info()
    elif selected_tool == "splunk_get_metadata":
        metadata_args = state.get("metadata_args", {}) or {}
        if not isinstance(metadata_args, dict):
            metadata_args = {}
        splunk_data = run_splunk_get_metadata(metadata_args)
    else:
        splunk_data = run_splunk_query(state["question"])
    splunk_data["selected_tool"] = selected_tool
    rows = splunk_data.get("structured", {}).get("results", [])
    log = list(state.get("decision_log", []))
    log.append(
        {
            "node": "run_splunk_query",
            "selected_tool": selected_tool,
            "rows_returned": len(rows) if isinstance(rows, list) else None,
        }
    )
    return {"primary_splunk_data": splunk_data, "splunk_data": splunk_data, "decision_log": log}


def run_second_tool_node(state: SocState) -> SocState:
    second_tool = state.get("chain_second_tool", "")
    second_args = state.get("chain_second_tool_args", {}) or {}
    if not isinstance(second_args, dict):
        second_args = {}

    primary = state.get("primary_splunk_data", {}) or {}
    rows = primary.get("structured", {}).get("results", [])
    if second_args.get("index") == "__TOP_INDEX_FROM_PRIMARY__":
        if isinstance(rows, list) and rows and isinstance(rows[0], dict):
            second_args["index"] = str(rows[0].get("title", "")).strip() or "_internal"
        else:
            second_args["index"] = "_internal"

    if second_tool == "splunk_get_metadata":
        second_data = run_splunk_get_metadata(second_args)
    else:
        second_data = {"tool": second_tool, "structured": {"results": [], "total_rows": 0}}

    primary_rows = primary.get("structured", {}).get("results", [])
    second_rows = second_data.get("structured", {}).get("results", [])
    combined = {
        "tool": "tool_chain",
        "selected_tool": "tool_chain",
        "chain_mode": state.get("tool_chain_mode", ""),
        "chain_steps": [
            {
                "tool": primary.get("selected_tool"),
                "mapped_query": primary.get("mapped_query", {}),
                "rows_returned": len(primary_rows) if isinstance(primary_rows, list) else None,
                "total_rows": primary.get("structured", {}).get("total_rows"),
            },
            {
                "tool": second_tool,
                "mapped_query": second_args,
                "rows_returned": len(second_rows) if isinstance(second_rows, list) else None,
                "total_rows": second_data.get("structured", {}).get("total_rows"),
            },
        ],
        "structured": {
            "results": second_rows if isinstance(second_rows, list) else [],
            "total_rows": second_data.get("structured", {}).get("total_rows"),
            "chain_primary_rows": len(primary_rows) if isinstance(primary_rows, list) else None,
            "chain_primary_total_rows": primary.get("structured", {}).get("total_rows"),
            "chain_second_tool": second_tool,
            "chain_second_args": second_args,
            "chain_focus_index": second_args.get("index"),
        },
        "raw_result": {
            "primary": primary.get("raw_result", {}),
            "secondary": second_data.get("raw_result", {}),
        },
    }

    log = list(state.get("decision_log", []))
    log.append(
        {
            "node": "run_second_tool",
            "second_tool": second_tool,
            "second_args": second_args,
            "rows_returned": len(second_rows) if isinstance(second_rows, list) else None,
        }
    )
    return {"splunk_data": combined, "decision_log": log}


def _deterministic_summary_from_data(question: str, splunk_data: dict) -> str:
    selected_tool = splunk_data.get("selected_tool", "unknown")
    structured = splunk_data.get("structured", {}) if isinstance(splunk_data, dict) else {}
    rows = structured.get("results", []) if isinstance(structured, dict) else []
    total_rows = structured.get("total_rows") if isinstance(structured, dict) else None
    sample_keys: list[str] = []
    if isinstance(rows, list) and rows and isinstance(rows[0], dict):
        sample_keys = sorted(rows[0].keys())
    return (
        f"- Question: {question}\n"
        f"- Tool path: {selected_tool}\n"
        f"- Rows returned: {len(rows) if isinstance(rows, list) else 'n/a'} (total_rows={total_rows})\n"
        f"- Sample fields: {', '.join(sample_keys[:8]) if sample_keys else 'none'}\n"
        "- Suggested next check: run a narrower follow-up query on the top entity from these results."
    )


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
    if len(text) > 4000:
        return False, "summary_too_long"
    bullet_count = sum(1 for line in text.splitlines() if line.strip().startswith("-"))
    if bullet_count < 3:
        return False, "summary_too_few_bullets"
    if text.endswith(("(", "[", "e.g", "eg")):
        return False, "summary_looks_truncated"
    return True, "summary_quality_ok"


def summarize_node(state: SocState) -> SocState:
    def _fallback_summary() -> str:
        return _deterministic_summary_from_data(state["question"], state.get("splunk_data", {}))

    summary_error = ""
    summary_quality_reason = "summary_quality_ok"
    question_for_summary = state["question"]
    session_context = state.get("session_context", {})
    if isinstance(session_context, dict):
        last_questions = session_context.get("recent_questions", [])
        if isinstance(last_questions, list) and last_questions:
            prior = ", ".join(str(q) for q in last_questions[-3:])
            question_for_summary = f"Session prior questions: {prior}\nCurrent question: {state['question']}"

    try:
        summary = summarize_with_ollama(question_for_summary, state["splunk_data"])
        summary = _clean_summary_text(summary)
        summary_ok, summary_quality_reason = _is_summary_quality_ok(summary)
        if not summary_ok:
            summary = _fallback_summary()
    except Exception as exc:
        summary = _fallback_summary()
        summary_error = f"{type(exc).__name__}: {exc}"
        summary_quality_reason = "model_exception_fallback"
    log = list(state.get("decision_log", []))
    log.append(
        {
            "node": "summarize_results",
            "summary_generated": bool(summary.strip()),
            "summary_fallback_used": bool(summary_error) or summary_quality_reason != "summary_quality_ok",
            "summary_error": summary_error,
            "summary_quality_reason": summary_quality_reason,
        }
    )
    return {"summary": summary, "decision_log": log}


def finalize(state: SocState) -> SocState:
    # No-op terminal node for explicit workflow readability.
    return state


def route_after_guardrail(state: SocState) -> str:
    return "validate_query_policy" if state.get("supported", False) else "finalize"


def route_after_query_policy(state: SocState) -> str:
    return "select_splunk_tool" if state.get("supported", False) else "finalize"


def route_after_selected_tool(state: SocState) -> str:
    return "run_splunk_query" if state.get("supported", False) else "finalize"


def route_after_primary_tool(state: SocState) -> str:
    if not state.get("supported", False):
        return "finalize"
    return "run_second_tool" if state.get("chain_second_tool") else "summarize_results"


def build_graph():
    graph = StateGraph(SocState)
    graph.add_node("ingest_question", ingest_question)
    graph.add_node("plan_query", plan_query)
    graph.add_node("guardrail_check", guardrail_check)
    graph.add_node("validate_query_policy", validate_query_policy_node)
    graph.add_node("select_splunk_tool", select_splunk_tool_node)
    graph.add_node("plan_tool_chain", plan_tool_chain_node)
    graph.add_node("validate_selected_tool", validate_selected_tool_node)
    graph.add_node("run_splunk_query", run_splunk_node)
    graph.add_node("run_second_tool", run_second_tool_node)
    graph.add_node("summarize_results", summarize_node)
    graph.add_node("finalize", finalize)

    graph.add_edge(START, "ingest_question")
    graph.add_edge("ingest_question", "plan_query")
    graph.add_edge("plan_query", "guardrail_check")
    graph.add_conditional_edges("guardrail_check", route_after_guardrail)
    graph.add_conditional_edges("validate_query_policy", route_after_query_policy)
    graph.add_edge("select_splunk_tool", "plan_tool_chain")
    graph.add_edge("plan_tool_chain", "validate_selected_tool")
    graph.add_conditional_edges("validate_selected_tool", route_after_selected_tool)
    graph.add_conditional_edges("run_splunk_query", route_after_primary_tool)
    graph.add_edge("run_second_tool", "summarize_results")
    graph.add_edge("summarize_results", "finalize")
    graph.add_edge("finalize", END)

    return graph.compile()


def _session_file_path(session_id: str, base_dir: str = "artifacts/sessions") -> Path:
    return Path(base_dir) / f"session_{session_id}.json"


def load_session_context(session_id: str, *, base_dir: str = "artifacts/sessions") -> dict:
    session_id = session_id.strip()
    if not session_id:
        return {}
    path = _session_file_path(session_id, base_dir=base_dir)
    if not path.exists():
        return {"session_id": session_id, "recent_questions": [], "recent_tools": [], "last_updated_utc": ""}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"session_id": session_id, "recent_questions": [], "recent_tools": [], "last_updated_utc": ""}
    if not isinstance(payload, dict):
        return {"session_id": session_id, "recent_questions": [], "recent_tools": [], "last_updated_utc": ""}
    return payload


def persist_session_context(
    session_id: str,
    *,
    question: str,
    selected_tool: str,
    summary: str,
    rows_returned: int | None,
    base_dir: str = "artifacts/sessions",
) -> Path | None:
    session_id = session_id.strip()
    if not session_id:
        return None

    prior = load_session_context(session_id, base_dir=base_dir)
    questions = prior.get("recent_questions", []) if isinstance(prior, dict) else []
    tools = prior.get("recent_tools", []) if isinstance(prior, dict) else []
    if not isinstance(questions, list):
        questions = []
    if not isinstance(tools, list):
        tools = []
    questions = [str(x) for x in questions][-9:] + [question]
    tools = [str(x) for x in tools][-9:] + [selected_tool]

    payload = {
        "session_id": session_id,
        "last_updated_utc": datetime.now(timezone.utc).isoformat(),
        "recent_questions": questions,
        "recent_tools": tools,
        "last_rows_returned": rows_returned,
        "last_summary_preview": summary[:240],
    }

    out_path = _session_file_path(session_id, base_dir=base_dir)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return out_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Run minimal LangGraph SOC flow")
    parser.add_argument(
        "question",
        nargs="?",
        default="Show failed login activity in the last 24 hours",
        help="Natural-language SOC question",
    )
    parser.add_argument(
        "--write-artifact",
        action="store_true",
        help="Write run result JSON artifact to artifacts/runs/langgraph",
    )
    parser.add_argument(
        "--artifact-dir",
        default="artifacts/runs/langgraph",
        help="Directory for LangGraph run JSON artifacts",
    )
    parser.add_argument(
        "--row-limit-override",
        type=int,
        help="Optional lab override for planned query row_limit (used for policy-path testing)",
    )
    parser.add_argument(
        "--session-id",
        default="",
        help="Optional session id for lightweight lab memory across runs",
    )
    args = parser.parse_args()

    app = build_graph()
    session_id = str(args.session_id).strip()
    session_context = load_session_context(session_id) if session_id else {}
    invoke_state: SocState = {"question": args.question, "session_id": session_id, "session_context": session_context}
    if args.row_limit_override is not None:
        invoke_state["row_limit_override"] = args.row_limit_override
    result = app.invoke(invoke_state)
    supported = result.get("supported", False)
    summary = result.get("summary")
    if not supported:
        summary = f"Guardrail blocked request: {result.get('guardrail_reason', 'unsupported request')}"

    output = {
        "question": result.get("question"),
        "intent": result.get("intent"),
        "intent_confidence": result.get("intent_confidence"),
        "planner_reason": result.get("planner_reason"),
        "supported": supported,
        "guardrail_reason": result.get("guardrail_reason"),
        "query_args": result.get("query_args"),
        "selected_tool": result.get("selected_tool"),
        "selected_tool_allowed": result.get("selected_tool_allowed"),
        "selected_tool_reason": result.get("selected_tool_reason"),
        "tool_chain_mode": result.get("tool_chain_mode"),
        "chain_second_tool": result.get("chain_second_tool"),
        "chain_second_tool_args": result.get("chain_second_tool_args"),
        "metadata_args": result.get("metadata_args"),
        "query_policy_ok": result.get("query_policy_ok"),
        "query_policy_reason": result.get("query_policy_reason"),
        "rows_returned": len(result.get("splunk_data", {}).get("structured", {}).get("results", [])),
        "total_rows": result.get("splunk_data", {}).get("structured", {}).get("total_rows"),
        "summary": summary,
        "decision_log": result.get("decision_log", []),
    }

    print("=== LangGraph Result ===")
    print(json.dumps(output, indent=2))

    if session_id:
        session_path = persist_session_context(
            session_id,
            question=str(output.get("question", "")),
            selected_tool=str(output.get("selected_tool", "")),
            summary=str(output.get("summary", "")),
            rows_returned=output.get("rows_returned"),
        )
        if session_path is not None:
            print(f"session_context={session_path}")

    if args.write_artifact:
        out_dir = Path(args.artifact_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        out_path = out_dir / f"langgraph_run_{stamp}.json"
        payload = {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "result": output,
        }
        out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"artifact={out_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
