#!/usr/bin/env python3
"""Canonical graph case state shared across investigations and pivots."""

from __future__ import annotations

import time
from typing import Any, TypedDict


class GraphCaseState(TypedDict, total=False):
    case_id: str
    current_node_id: str
    parent_node_id: str
    session_id: str
    root_question: str
    current_question: str
    intent: str
    node_type: str
    selected_tool: str
    supported: bool
    time_range: dict[str, str]
    query_args: dict[str, Any]
    selected_spl_details: list[dict[str, Any]]
    rows_returned: int
    total_rows: int
    evidence_entities: dict[str, list[str]]
    ranked_entities: dict[str, list[dict[str, Any]]]
    pivot_candidates: list[dict[str, Any]]
    pivot_history: list[dict[str, Any]]
    pivot_signatures: list[str]
    investigation_depth: int
    playbook_id: str
    playbook_name: str
    playbook_stage: str
    matching_active_spl_assets: list[dict[str, Any]]
    summary: str
    updated_at: int


def bootstrap_graph_case_state(
    *,
    question: str,
    session_id: str = "",
    case_id: str = "",
    current_node_id: str = "",
    parent_node_id: str = "",
    root_question: str = "",
) -> GraphCaseState:
    now_ts = int(time.time())
    q = str(question or "").strip()
    root = str(root_question or "").strip() or q
    return GraphCaseState(
        case_id=str(case_id or "").strip(),
        current_node_id=str(current_node_id or "").strip(),
        parent_node_id=str(parent_node_id or "").strip(),
        session_id=str(session_id or "").strip(),
        root_question=root,
        current_question=q,
        intent="",
        node_type="investigation",
        selected_tool="",
        supported=True,
        time_range={},
        query_args={},
        selected_spl_details=[],
        rows_returned=0,
        total_rows=0,
        evidence_entities={},
        ranked_entities={},
        pivot_candidates=[],
        pivot_history=[],
        pivot_signatures=[],
        investigation_depth=0,
        playbook_id="",
        playbook_name="",
        playbook_stage="",
        matching_active_spl_assets=[],
        summary="",
        updated_at=now_ts,
    )


def snapshot_graph_case_state(
    *,
    previous: dict[str, Any] | None,
    question: str,
    result_body: dict[str, Any],
    case_id: str = "",
    current_node_id: str = "",
    parent_node_id: str = "",
    node_type: str = "investigation",
    evidence_entities: dict[str, list[str]] | None = None,
    ranked_entities: dict[str, list[dict[str, Any]]] | None = None,
    pivot_candidates: list[dict[str, Any]] | None = None,
) -> GraphCaseState:
    state = bootstrap_graph_case_state(
        question=question,
        session_id=str((previous or {}).get("session_id", "")).strip(),
        case_id=case_id or str((previous or {}).get("case_id", "")).strip(),
        current_node_id=current_node_id,
        parent_node_id=parent_node_id or str((previous or {}).get("current_node_id", "")).strip(),
        root_question=str((previous or {}).get("root_question", "")).strip() or str(result_body.get("root_question", "")).strip(),
    )
    query_args = result_body.get("query_args", {}) if isinstance(result_body.get("query_args"), dict) else {}
    time_range = {
        "earliest_time": str(query_args.get("earliest_time", "")).strip(),
        "latest_time": str(query_args.get("latest_time", "")).strip(),
    }
    if not any(time_range.values()):
        time_range = {}
    state.update(
        {
            "case_id": case_id or state.get("case_id", ""),
            "current_node_id": str(current_node_id or "").strip(),
            "parent_node_id": str(parent_node_id or state.get("parent_node_id", "")).strip(),
            "root_question": str(result_body.get("root_question", "")).strip() or state.get("root_question", str(question or "").strip()),
            "current_question": str(result_body.get("active_question", "")).strip() or str(question or "").strip(),
            "intent": str(result_body.get("intent", "")).strip(),
            "node_type": str(node_type or "investigation"),
            "selected_tool": str(result_body.get("selected_tool", "")).strip(),
            "supported": bool(result_body.get("supported", True)),
            "time_range": time_range,
            "query_args": query_args,
            "selected_spl_details": result_body.get("selected_spl_details", []) if isinstance(result_body.get("selected_spl_details"), list) else [],
            "rows_returned": int(result_body.get("rows_returned") or 0),
            "total_rows": int(result_body.get("total_rows") or 0),
            "evidence_entities": evidence_entities if isinstance(evidence_entities, dict) else {},
            "ranked_entities": ranked_entities if isinstance(ranked_entities, dict) else {},
            "pivot_candidates": pivot_candidates if isinstance(pivot_candidates, list) else [],
            "matching_active_spl_assets": result_body.get("matching_active_spl_assets", []) if isinstance(result_body.get("matching_active_spl_assets"), list) else [],
            "summary": str(result_body.get("summary", "")).strip(),
            "updated_at": int(time.time()),
        }
    )
    return state
