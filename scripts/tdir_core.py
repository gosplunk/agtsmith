#!/usr/bin/env python3
"""Deterministic core-TDIR enrichment helpers for the Splunk SOC lab.

This module intentionally avoids external calls. It derives:
- triage severity/risk labels
- concise incident hypothesis
- key entities from returned rows
- recommended read-only pivot actions
- explicit SOAR-next placeholder (not enabled yet)
"""

from __future__ import annotations

from typing import Any


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _normalize_intent(intent: str) -> str:
    return (intent or "").strip().lower()


def _first_entity(rows: list[dict[str, Any]], key: str) -> str:
    for row in rows:
        if not isinstance(row, dict):
            continue
        value = str(row.get(key, "")).strip()
        if value:
            return value
    return ""


def _extract_entities(rows: list[dict[str, Any]]) -> dict[str, list[str]]:
    entities: dict[str, list[str]] = {
        "users": [],
        "hosts": [],
        "source_ips": [],
        "client_ips": [],
        "sourcetypes": [],
    }
    for row in rows[:30]:
        if not isinstance(row, dict):
            continue
        mapping = {
            "users": ("user", "username"),
            "hosts": ("host",),
            "source_ips": ("src", "source", "sourceip"),
            "client_ips": ("clientip",),
            "sourcetypes": ("sourcetype",),
        }
        for out_key, candidates in mapping.items():
            for c in candidates:
                value = str(row.get(c, "")).strip()
                if value and value not in entities[out_key]:
                    entities[out_key].append(value)
    for k in entities:
        entities[k] = entities[k][:5]
    return entities


def _severity_and_risk(intent: str, rows_returned: int, top_count: int) -> tuple[str, int]:
    intent_l = _normalize_intent(intent)
    if rows_returned <= 0:
        return "info", 10

    if intent_l in {
        "failed_login_activity",
        "linux_auth_failures",
        "windows_auth_failures",
        "linux_privilege_escalation",
        "linux_privilege_escalation_first_seen",
    }:
        if top_count >= 500:
            return "high", 85
        if top_count >= 100:
            return "medium", 65
        return "medium", 55

    if intent_l in {"apache_404_spike", "apache_suspicious_user_agents"}:
        if top_count >= 400:
            return "high", 80
        if top_count >= 100:
            return "medium", 60
        return "low", 35

    if intent_l in {"apache_access_top_ips"}:
        if top_count >= 1000:
            return "medium", 60
        return "low", 30

    return "low", 25


def _hypothesis(question: str, intent: str, rows_returned: int, entities: dict[str, list[str]]) -> str:
    intent_l = _normalize_intent(intent)
    if rows_returned <= 0:
        return "No matching events in current window; broaden time range or pivot metadata."
    if intent_l in {"failed_login_activity", "linux_auth_failures", "windows_auth_failures"}:
        user = entities.get("users", [""])[0] if entities.get("users") else ""
        src = entities.get("source_ips", [""])[0] if entities.get("source_ips") else ""
        return (
            f"Repeated authentication failures suggest brute-force activity or service misconfiguration"
            f"{' for user ' + user if user else ''}{' from source ' + src if src else ''}."
        )
    if intent_l == "linux_privilege_escalation":
        return "Failed sudo/su attempts suggest possible privilege-escalation probing on Linux hosts."
    if intent_l == "linux_privilege_escalation_first_seen":
        return (
            "Newly observed successful sudo/su activity suggests privilege escalation behavior worth validating "
            "against expected administrative patterns on Linux hosts."
        )
    if intent_l in {"apache_access_top_ips", "apache_404_spike", "apache_suspicious_user_agents"}:
        ip = entities.get("client_ips", [""])[0] if entities.get("client_ips") else ""
        return (
            "Web-access concentration and error/user-agent patterns suggest scanning or scripted activity"
            f"{' from client ' + ip if ip else ''}."
        )
    return f"Investigation for question '{question}' surfaced events requiring deeper entity pivoting."


def _recommended_pivots(intent: str, entities: dict[str, list[str]]) -> list[str]:
    intent_l = _normalize_intent(intent)
    pivots: list[str] = []
    if intent_l in {
        "failed_login_activity",
        "linux_auth_failures",
        "windows_auth_failures",
        "linux_privilege_escalation",
        "linux_privilege_escalation_first_seen",
    }:
        pivots.extend(
            [
                "Pivot by host to identify concentration of auth failures.",
                "Pivot by source IP over narrower 1h windows to detect attack bursts.",
                "Pivot by username across sourcetypes for credential misuse patterns.",
            ]
        )
    if intent_l == "linux_privilege_escalation_first_seen":
        pivots = [
            "Pivot by host to validate whether the first-seen sudo/su activity is expected admin behavior.",
            "Pivot by username over the prior 30d to determine if the escalation pattern is genuinely new.",
            "Pivot by source IP or rhost to distinguish local admin activity from remote access.",
        ]
    elif intent_l in {"apache_access_top_ips", "apache_404_spike", "apache_suspicious_user_agents"}:
        pivots.extend(
            [
                "Pivot by client IP and user-agent pair across time windows.",
                "Pivot 404-heavy paths to detect web enumeration behavior.",
                "Pivot suspicious user-agents against Linux auth failures for correlation.",
            ]
        )
    else:
        pivots.extend(
            [
                "Pivot to index inventory for broader visibility.",
                "Pivot to sourcetype metadata before deeper search refinement.",
            ]
        )

    if entities.get("hosts"):
        pivots.append(f"Priority host pivot: {entities['hosts'][0]}")
    if entities.get("users"):
        pivots.append(f"Priority user pivot: {entities['users'][0]}")
    if entities.get("client_ips"):
        pivots.append(f"Priority client IP pivot: {entities['client_ips'][0]}")
    if entities.get("source_ips"):
        pivots.append(f"Priority source IP pivot: {entities['source_ips'][0]}")
    return pivots[:6]


def build_tdir_case(
    *,
    question: str,
    intent: str,
    selected_tool: str,
    query_args: dict[str, Any],
    structured: dict[str, Any] | None,
    pipeline: str,
    continuation_review: dict[str, Any] | None = None,
    loop_control: dict[str, Any] | None = None,
) -> dict[str, Any]:
    structured = structured or {}
    rows = structured.get("results", [])
    if not isinstance(rows, list):
        rows = []
    rows_dict = [r for r in rows if isinstance(r, dict)]
    rows_returned = len(rows_dict)

    top_count = 0
    if rows_dict:
        top_count = _to_int(rows_dict[0].get("count"), default=0)

    severity, risk_score = _severity_and_risk(intent, rows_returned, top_count)
    entities = _extract_entities(rows_dict)
    hypothesis = _hypothesis(question, intent, rows_returned, entities)
    continuation_review = continuation_review or {}
    loop_control = loop_control or {}
    should_continue = bool(continuation_review.get("should_continue", False))
    human_approval_required = bool(loop_control.get("human_approval_required", False))
    stop_reason = str(loop_control.get("stop_reason", "")).strip()
    investigate_status = "complete" if rows_returned > 0 else "queued"
    if human_approval_required:
        investigate_status = "awaiting_human_approval"
    elif should_continue:
        if stop_reason in {"duplicate_pivot_blocked", "max_depth_reached"}:
            investigate_status = "complete"
        elif stop_reason.startswith("continuation_confidence_below_threshold") or stop_reason.startswith("followup_unroutable"):
            investigate_status = "complete"
        else:
            investigate_status = "in_progress"
    recommended_pivots = _recommended_pivots(intent, entities)
    next_best_question = str(continuation_review.get("next_best_question", "")).strip()
    if next_best_question:
        recommended_pivots = [f"Continuation reviewer: {next_best_question}"] + recommended_pivots

    return {
        "pipeline": pipeline,
        "phase_status": {
            "detect": "complete" if rows_returned >= 0 else "unknown",
            "triage": "complete",
            "investigate": investigate_status,
            "respond": "planned",
            "recover": "planned",
            "soar_automation": "not_enabled_yet",
        },
        "question": question,
        "intent": intent,
        "selected_tool": selected_tool,
        "query_args": query_args,
        "rows_returned": rows_returned,
        "severity": severity,
        "risk_score": risk_score,
        "incident_hypothesis": hypothesis,
        "key_entities": entities,
        "recommended_next_pivots": recommended_pivots[:6],
        "continuation_review": continuation_review,
        "loop_control": loop_control,
        "investigation_stop_reason": stop_reason,
        "response_note": "SOAR is intentionally not integrated in this phase; manual response workflow only.",
    }
