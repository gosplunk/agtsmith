#!/usr/bin/env python3
"""Honest investigation progress mapping for LangGraph multi-model runs."""

from __future__ import annotations

import copy

from typing import Any, Literal

ReviewProfile = Literal["security", "operational", "metadata"]

# Post-graph UI stages (not LangGraph nodes) — never emit as graph "next step" previews.
POST_GRAPH_PROGRESS_NODES: frozenset[str] = frozenset({"package_response"})

# Weighted completion after each graph node finishes (never exceeds 98 until finalize).
MULTI_MODEL_NODE_PROGRESS: dict[str, dict[str, Any]] = {
    "ingest_question": {
        "pct": 5,
        "title": "Question intake",
        "label": "Receiving investigation question...",
        "note": "The controller is accepting the question and preparing the run context.",
    },
    "guardrail": {
        "pct": 12,
        "title": "Guardrails",
        "label": "Checking read-only scope...",
        "note": "Guardrails validate that the request stays inside read-only investigation scope.",
    },
    "planner": {
        "pct": 24,
        "title": "Planning",
        "label": "Planning investigation approach...",
        "note": "The planner is interpreting intent and building a bounded search plan.",
    },
    "field_bind": {
        "pct": 30,
        "title": "Field binding",
        "label": "Binding environment oracle hints...",
        "note": "Planner hints are bound to indexes, sourcetypes, and field contracts from the environment profile.",
    },
    "field_discovery": {
        "pct": 32,
        "title": "Field discovery",
        "label": "Discovering candidate fields...",
        "note": "A bounded read-only sample discovers candidate fields without treating hints as proof.",
    },
    "field_strategy": {
        "pct": 34,
        "title": "Field strategy",
        "label": "Verifying native fields...",
        "note": "Index-scoped live evidence determines whether native fields, spath, or rex should be used.",
    },
    "domain_knowledge": {
        "pct": 35,
        "title": "Domain knowledge",
        "label": "Resolving domain query shape...",
        "note": "The domain oracle binds the investigation to a known read-only query shape.",
    },
    "writer": {
        "pct": 36,
        "title": "SPL drafting",
        "label": "Drafting SPL query...",
        "note": "The writer is turning the plan into read-only Splunk SPL or MCP tool args.",
    },
    "spl_validate": {
        "pct": 42,
        "title": "SPL validation",
        "label": "Validating SPL with analyst model...",
        "note": "The operational analyst model checks SPL shape before deterministic policy gates.",
    },
    "security_review": {
        "pct": 48,
        "title": "Security review",
        "label": "Reviewing SPL safety...",
        "note": "The security reviewer is checking the generated SPL against policy and the plan.",
    },
    "peer_review": {
        "pct": 56,
        "title": "Peer review",
        "label": "Peer review round 1...",
        "note": "Peer reviewers are adjudicating contested planner/writer/security decisions.",
    },
    "peer_review_2": {
        "pct": 62,
        "title": "Peer review",
        "label": "Peer review round 2...",
        "note": "A second peer review pass is validating or overriding the first decision.",
    },
    "validate_final_plan": {
        "pct": 68,
        "title": "Plan validation",
        "label": "Validating approved plan...",
        "note": "Deterministic policy and environment validation runs before any Splunk call.",
    },
    "field_policy": {
        "pct": 73,
        "title": "Field policy",
        "label": "Enforcing fields-first SPL...",
        "note": "The final query is rewritten from trusted field evidence and all deterministic checks run again.",
    },
    "semantic_gate": {
        "pct": 76,
        "title": "Semantic coverage",
        "label": "Checking semantic coverage...",
        "note": "The typed plan, final SPL, and declared output schema are compared before any Splunk call.",
    },
    "run_tool": {
        "pct": 78,
        "title": "Splunk retrieval",
        "label": "Retrieving evidence from Splunk...",
        "note": "The approved read-only plan is executing against Splunk via MCP.",
    },
    "evidence_review": {
        "pct": 88,
        "title": "Evidence review",
        "label": "Reviewing evidence and pivots...",
        "note": "Returned evidence is being reviewed for analyst-facing pivots and ATT&CK context.",
    },
    "analyst_evidence_review": {
        "pct": 88,
        "title": "Analyst review",
        "label": "Analyst evidence review...",
        "note": "The operational analyst model reviews returned rows for pivots and next checks.",
    },
    "security_evidence_review": {
        "pct": 88,
        "title": "Security evidence",
        "label": "Security evidence review...",
        "note": "The security reviewer assesses evidence quality and ATT&CK-relevant pivots.",
    },
    "deterministic_evidence_pack": {
        "pct": 88,
        "title": "Evidence pack",
        "label": "Packaging inventory evidence...",
        "note": "Metadata questions receive a deterministic evidence pack without LLM critique.",
    },
    "summarize": {
        "pct": 94,
        "title": "Final summary",
        "label": "Writing analyst summary...",
        "note": "The final summary and decision support view are being assembled.",
    },
    "finalize": {
        "pct": 98,
        "title": "Graph finalize",
        "label": "Closing LangGraph run...",
        "note": "Instant graph checkpoint after summary; marks the LangGraph run complete before UI response assembly.",
    },
    "package_response": {
        "pct": 99,
        "title": "Packaging response",
        "label": "Assembling MCP chat response...",
        "note": "Sample rows, domain hints, and response metadata are assembled after the LangGraph run completes.",
    },
}

# stage_logs entries use slightly different stage ids than graph node names.
MULTI_MODEL_STAGE_LOG_PROGRESS: dict[str, dict[str, Any]] = {
    "guardrail": MULTI_MODEL_NODE_PROGRESS["guardrail"],
    "planner": MULTI_MODEL_NODE_PROGRESS["planner"],
    "field_bind": MULTI_MODEL_NODE_PROGRESS["field_bind"],
    "field_discovery": MULTI_MODEL_NODE_PROGRESS["field_discovery"],
    "field_strategy": MULTI_MODEL_NODE_PROGRESS["field_strategy"],
    "domain_knowledge": MULTI_MODEL_NODE_PROGRESS["domain_knowledge"],
    "writer": MULTI_MODEL_NODE_PROGRESS["writer"],
    "spl_validate": MULTI_MODEL_NODE_PROGRESS["spl_validate"],
    "reviewer": MULTI_MODEL_NODE_PROGRESS["security_review"],
    "peer_review_1": MULTI_MODEL_NODE_PROGRESS["peer_review"],
    "peer_review_2": MULTI_MODEL_NODE_PROGRESS["peer_review_2"],
    "validation": MULTI_MODEL_NODE_PROGRESS["validate_final_plan"],
    "field_policy": MULTI_MODEL_NODE_PROGRESS["field_policy"],
    "semantic_gate": MULTI_MODEL_NODE_PROGRESS["semantic_gate"],
    "execution": MULTI_MODEL_NODE_PROGRESS["run_tool"],
    "evidence_review": MULTI_MODEL_NODE_PROGRESS["evidence_review"],
    "analyst_evidence_review": MULTI_MODEL_NODE_PROGRESS["analyst_evidence_review"],
    "security_evidence_review": MULTI_MODEL_NODE_PROGRESS["security_evidence_review"],
    "deterministic_evidence_pack": MULTI_MODEL_NODE_PROGRESS["deterministic_evidence_pack"],
    "summary": MULTI_MODEL_NODE_PROGRESS["summarize"],
}

DEFAULT_WAITING_PROGRESS: dict[str, Any] = {
    "pct": 2,
    "title": "Starting investigation",
    "label": "Starting investigation...",
    "note": "Waiting for the investigation pipeline to begin.",
}

INDETERMINATE_WAITING_PROGRESS: dict[str, Any] = {
    "pct": None,
    "title": "Waiting on pipeline",
    "label": "Waiting on next pipeline stage...",
    "note": "The current stage is taking longer than expected. The bar stays indeterminate until the server reports the next completed stage.",
}


def _normalize_progress(entry: dict[str, Any] | None) -> dict[str, Any]:
    base = dict(DEFAULT_WAITING_PROGRESS)
    if isinstance(entry, dict):
        base.update(entry)
    pct = base.get("pct")
    if pct is not None:
        base["pct"] = max(0, min(100, int(pct)))
    return base


def progress_for_multi_model_node(node_id: str) -> dict[str, Any]:
    key = str(node_id or "").strip()
    return _normalize_progress(MULTI_MODEL_NODE_PROGRESS.get(key))


def progress_for_stage_log(stage: str) -> dict[str, Any]:
    key = str(stage or "").strip()
    entry = MULTI_MODEL_STAGE_LOG_PROGRESS.get(key)
    if entry is None:
        entry = MULTI_MODEL_NODE_PROGRESS.get(key)
    return _normalize_progress(entry)


# Condensed UI stepper shown in the investigation runtime rail.
# Template/intent layer — metadata profile (layer 1 classification).
METADATA_REVIEW_INTENTS: frozenset[str] = frozenset(
    {
        "top_indexes",
        "metadata_inventory",
        "index_sourcetype_volume",
        "host_activity_summary",
        "index_staleness",
        "splunk_info",
        "internal_sourcetypes",
    }
)

# Template/intent layer — security profile (layer 1 classification).
SECURITY_REVIEW_INTENTS: frozenset[str] = frozenset(
    {
        "failed_login_activity",
        "successful_login_activity",
        "linux_auth_failures",
        "linux_successful_logins",
        "linux_session_activity",
        "linux_privilege_escalation",
        "linux_privilege_escalation_activity",
        "linux_privilege_escalation_first_seen",
        "linux_audit_activity",
        "windows_auth_failures",
        "windows_successful_logons",
        "windows_process_activity",
        "windows_sysmon_network_activity",
        "windows_sysmon_dns_activity",
        "windows_credential_access_activity",
        "windows_process_audit_activity",
        "windows_privilege_assigned_activity",
        "osquery_process_activity",
        "apache_suspicious_user_agents",
        "aws_vpc_flow_activity",
        "aad_signin_activity",
        "stream_dns_activity",
        "o365_management_activity",
    }
)

# Back-compat alias for inventory skip helpers.
SECURITY_REVIEW_SKIP_INTENTS: frozenset[str] = METADATA_REVIEW_INTENTS
SECURITY_REVIEW_SKIP_TOOLS: frozenset[str] = frozenset(
    {
        "splunk_get_indexes",
        "splunk_get_metadata",
        "splunk_get_info",
    }
)

# Question wording that indicates index/metadata/inventory (even when tool is splunk_run_query).
_INVENTORY_INDEX_PHRASES: tuple[str, ...] = (
    "list indexes",
    "show indexes",
    "what indexes",
    "which indexes",
    "indexes i can access",
    "indexes available",
    "available indexes",
    "index inventory",
    "index list",
)
_INVENTORY_DATA_SIGNALS: tuple[str, ...] = (
    "have data",
    "has data",
    "with data",
    "contain data",
    "event count",
    "event volume",
    "eventcount",
    "most events",
    "events in",
)
_INVENTORY_VERBS: tuple[str, ...] = (
    "list",
    "show",
    "which",
    "what",
    "available",
    "accessible",
    "inventory",
)
_INVENTORY_ANALYTICS_SIGNALS: tuple[str, ...] = (
    "count",
    "counts",
    "top ",
    "spike",
    "activity",
    "trend",
    "volume",
    "events",
    "failed",
    "failure",
)
_METADATA_SIGNALS: tuple[str, ...] = (
    "metadata",
    "sourcetype",
    "sourcetypes",
)
_SPLUNK_INFO_PHRASES: tuple[str, ...] = (
    "splunk version",
    "splunk info",
    "server info",
    "instance info",
)

_SECURITY_QUESTION_PHRASES: tuple[str, ...] = (
    "failed login",
    "failed logon",
    "auth failure",
    "authentication failure",
    "brute force",
    "credential access",
    "privilege escalation",
    "lateral movement",
    "malware",
    "ransomware",
    "sysmon",
    "security event",
    "4625",
    "4624",
    "suspicious process",
    "powershell",
    "command line",
)


def is_inventory_question(question: str) -> bool:
    """Detect index/metadata/inventory questions from analyst wording alone."""
    q = str(question or "").strip().lower()
    if not q:
        return False
    if any(phrase in q for phrase in _INVENTORY_INDEX_PHRASES):
        return True
    has_index = "index" in q or "indexes" in q
    if has_index and any(term in q for term in _INVENTORY_DATA_SIGNALS):
        return True
    if has_index and any(term in q for term in _INVENTORY_ANALYTICS_SIGNALS):
        return False
    if has_index and any(phrase in q for phrase in _INVENTORY_INDEX_PHRASES):
        return True
    if has_index and "indexes" in q and any(term in q for term in _INVENTORY_VERBS):
        return True
    if any(term in q for term in _METADATA_SIGNALS) and any(term in q for term in _INVENTORY_VERBS):
        if any(term in q for term in _INVENTORY_ANALYTICS_SIGNALS):
            return False
        return True
    return any(phrase in q for phrase in _SPLUNK_INFO_PHRASES)


def is_security_question(question: str) -> bool:
    """Detect security investigation questions from analyst wording alone."""
    q = str(question or "").strip().lower()
    if not q:
        return False
    if any(phrase in q for phrase in _SECURITY_QUESTION_PHRASES):
        return True
    if "login" in q and any(term in q for term in ("fail", "failed", "failure", "invalid", "denied")):
        return True
    if "logon" in q and any(term in q for term in ("fail", "failed", "failure", "invalid", "denied")):
        return True
    return False


def _intent_profile(intent: str) -> ReviewProfile | None:
    key = str(intent or "").strip()
    if not key:
        return None
    if key in METADATA_REVIEW_INTENTS:
        return "metadata"
    if key in SECURITY_REVIEW_INTENTS:
        return "security"
    return None


def classify_review_profile(
    question: str,
    *,
    template_intent: str | None = None,
    planner_intent: str | None = None,
) -> ReviewProfile:
    """Classify investigation review profile (metadata / operational / security).

    Priority: template intent → pattern rules → planner intent fallback.
    Template grounding overrides a mismatched planner intent.
    """
    template_profile = _intent_profile(template_intent or "")
    if template_profile is not None:
        return template_profile

    q = str(question or "").strip()
    if q and is_inventory_question(q):
        return "metadata"
    if q and is_security_question(q):
        return "security"

    planner_profile = _intent_profile(planner_intent or "")
    if planner_profile is not None:
        return planner_profile

    return "operational"


def requires_security_review(profile: str) -> bool:
    return str(profile or "").strip() == "security"


def skipped_nodes_for_profile(profile: str) -> list[str]:
    """Journey nodes skipped for a review profile (security_review only for now)."""
    if requires_security_review(profile):
        return []
    return ["security_review"]


def evidence_journey_label_for_profile(profile: str) -> str:
    key = str(profile or "operational").strip()
    if key == "metadata":
        return "Evidence Pack"
    if key == "security":
        return "Security Evidence"
    return "Analyst Review"


def summarize_active_role_for_profile(profile: str) -> str:
    key = str(profile or "operational").strip()
    if key == "security":
        return "security"
    if key == "operational":
        return "analyst"
    return ""


JOURNEY_UI_STEPS: list[dict[str, str]] = [
    {"node": "guardrail", "label": "Guardrail"},
    {"node": "planner", "label": "Planner"},
    {"node": "writer", "label": "SPL Writer"},
    {"node": "security_review", "label": "Security Review"},
    {"node": "run_tool", "label": "Splunk Query"},
    {"node": "evidence_review", "label": "Evidence Review"},
    {"node": "summarize", "label": "Summarize"},
    {"node": "finalize", "label": "Graph close"},
    {"node": "package_response", "label": "Deliver"},
]

# Full LangGraph playbook layout for the runtime-rail level-2 overlay (matches build_graph() branches).
PLAYBOOK_NODES: list[dict[str, Any]] = [
    {"node": "ingest_question", "label": "Ingest", "kind": "linear"},
    {"node": "guardrail", "label": "Guardrail", "kind": "linear"},
    {"node": "planner", "label": "Planner", "kind": "linear"},
    {"node": "writer", "label": "SPL Writer", "kind": "linear"},
    {
        "kind": "branch",
        "branch_id": "writer_route",
        "options": [
            {"node": "spl_validate", "label": "SPL Validate", "profiles": ["operational"]},
            {"node": "security_review", "label": "Security Review", "profiles": ["security"]},
            {
                "node": "writer_direct",
                "label": "Direct",
                "profiles": ["metadata"],
                "resolves_to": "validate_final_plan",
            },
        ],
    },
    {"node": "validate_final_plan", "label": "Validate", "kind": "linear"},
    {"node": "run_tool", "label": "Run Tool", "kind": "linear"},
    {
        "kind": "branch",
        "branch_id": "evidence_route",
        "options": [
            {"node": "deterministic_evidence_pack", "label": "Evidence Pack", "profiles": ["metadata"]},
            {"node": "analyst_evidence_review", "label": "Analyst Evidence", "profiles": ["operational"]},
            {"node": "security_evidence_review", "label": "Security Evidence", "profiles": ["security"]},
        ],
    },
    {"node": "summarize", "label": "Summarize", "kind": "linear"},
    {"node": "finalize", "label": "Finalize", "kind": "linear"},
]

PLAYBOOK_NODE_ORDER: list[str] = [
    "ingest_question",
    "guardrail",
    "planner",
    "writer",
    "spl_validate",
    "security_review",
    "peer_review",
    "peer_review_2",
    "validate_final_plan",
    "run_tool",
    "deterministic_evidence_pack",
    "analyst_evidence_review",
    "security_evidence_review",
    "summarize",
    "finalize",
]

# Visual flowchart nodes for the runtime-rail level-2 overlay (process + decision diamonds).
PLAYBOOK_FLOW_NODES: list[dict[str, Any]] = [
    {"id": "ingest_question", "label": "Ingest", "kind": "process"},
    {"id": "guardrail", "label": "Guardrail", "kind": "process"},
    {"id": "dec_guardrail", "label": "Scope?", "kind": "decision"},
    {"id": "planner", "label": "Planner", "kind": "process"},
    {"id": "writer", "label": "SPL Writer", "kind": "process"},
    {"id": "dec_writer", "label": "Profile?", "kind": "decision"},
    {
        "id": "spl_validate",
        "label": "SPL Validate",
        "kind": "process",
        "profiles": ["operational"],
    },
    {
        "id": "security_review",
        "label": "Security Review",
        "kind": "process",
        "profiles": ["security"],
    },
    {"id": "dec_security", "label": "Clean?", "kind": "decision", "profiles": ["security"]},
    {"id": "peer_review", "label": "Peer Review 1", "kind": "process", "profiles": ["security"]},
    {"id": "peer_review_2", "label": "Peer Review 2", "kind": "process", "profiles": ["security"]},
    {"id": "validate_final_plan", "label": "Validate", "kind": "process"},
    {"id": "dec_validate", "label": "Approved?", "kind": "decision"},
    {"id": "run_tool", "label": "Run Tool", "kind": "process"},
    {"id": "dec_evidence", "label": "Evidence", "kind": "decision"},
    {
        "id": "deterministic_evidence_pack",
        "label": "Evidence Pack",
        "kind": "process",
        "profiles": ["metadata"],
    },
    {
        "id": "analyst_evidence_review",
        "label": "Analyst Evidence",
        "kind": "process",
        "profiles": ["operational"],
    },
    {
        "id": "security_evidence_review",
        "label": "Security Evidence",
        "kind": "process",
        "profiles": ["security"],
    },
    {"id": "summarize", "label": "Summarize", "kind": "process"},
    {"id": "finalize", "label": "Finalize", "kind": "process"},
]

# Node geometry — keep in sync with web_ui_server.py PROCESS_W / DECISION_R / NODE_GAP.
PLAYBOOK_PROCESS_W = 172
PLAYBOOK_PROCESS_H = 50
PLAYBOOK_DECISION_R = 44
PLAYBOOK_NODE_GAP = 24
PLAYBOOK_SPINE_START_X = 100
PLAYBOOK_LEGEND_Y = 618
PLAYBOOK_LEGEND_H = 108
PLAYBOOK_LEGEND_BOTTOM_Y = PLAYBOOK_LEGEND_Y + PLAYBOOK_LEGEND_H
PLAYBOOK_FINISH_ROW_Y = PLAYBOOK_LEGEND_BOTTOM_Y - PLAYBOOK_PROCESS_H // 2
PLAYBOOK_FINISH_MERGE_Y = PLAYBOOK_FINISH_ROW_Y - 37


def _playbook_spine_centers() -> dict[str, int]:
    """Spine row centers with minimum gap between node bounding boxes."""
    sequence: list[tuple[str, str]] = [
        ("ingest_question", "process"),
        ("guardrail", "process"),
        ("dec_guardrail", "decision"),
        ("planner", "process"),
        ("writer", "process"),
        ("dec_writer", "decision"),
    ]

    def _half(kind: str) -> int:
        return PLAYBOOK_PROCESS_W // 2 if kind == "process" else PLAYBOOK_DECISION_R

    centers: dict[str, int] = {}
    x = PLAYBOOK_SPINE_START_X
    for idx, (node_id, kind) in enumerate(sequence):
        centers[node_id] = x
        if idx + 1 < len(sequence):
            _next_id, next_kind = sequence[idx + 1]
            x = x + _half(kind) + PLAYBOOK_NODE_GAP + _half(next_kind)
    return centers


_SPINE_X = _playbook_spine_centers()

# Branch colors for overlay nodes (matches legend path colors).
PLAYBOOK_NODE_BRANCH: dict[str, str] = {
    "ingest_question": "trunk",
    "guardrail": "trunk",
    "dec_guardrail": "gate",
    "planner": "trunk",
    "writer": "trunk",
    "dec_writer": "gate",
    "spl_validate": "operational",
    "security_review": "security",
    "dec_security": "gate",
    "peer_review": "metadata",
    "peer_review_2": "metadata",
    "validate_final_plan": "trunk",
    "dec_validate": "gate",
    "run_tool": "trunk",
    "dec_evidence": "gate",
    "deterministic_evidence_pack": "metadata",
    "analyst_evidence_review": "operational",
    "security_evidence_review": "security",
    "summarize": "trunk",
    "finalize": "trunk",
}

_FLOW_NODE_IDS = {str(node["id"]) for node in PLAYBOOK_FLOW_NODES}
PLAYBOOK_NODE_TIPS: dict[str, str] = {
    node_id: str(meta.get("note") or meta.get("label") or "").strip()
    for node_id, meta in MULTI_MODEL_NODE_PROGRESS.items()
    if node_id in _FLOW_NODE_IDS and str(meta.get("note") or meta.get("label") or "").strip()
}
PLAYBOOK_NODE_TIPS.update(
    {
        "dec_guardrail": "Scope gate: blocks unsupported or out-of-scope questions before planning begins.",
        "dec_writer": "Profile gate: routes the run down OP (operational), META (metadata), or SEC (security) paths.",
        "dec_security": "Clean gate: accepts security-reviewed SPL or loops back when the query stays contested.",
        "dec_validate": "Approval gate: the plan must pass deterministic policy checks before Splunk execution.",
        "dec_evidence": "Evidence gate: sends results to metadata pack, analyst review, or security evidence review.",
    }
)

_FINISH_SUMMARIZE_X = 520
_FINISH_FINALIZE_X = _FINISH_SUMMARIZE_X + PLAYBOOK_PROCESS_W + PLAYBOOK_NODE_GAP
LANE_SEC_DROP_X = 1012
# Profile? aligns with the security column below it.
PROFILE_DEC_WRITER_X = LANE_SEC_DROP_X
PROFILE_DEC_WRITER_Y = 36

# Concept A compact-spine layout (~1040×680 viewBox — fits overlay without horizontal scroll).
# Row 1 spine y=58; SPL Validate under Writer; merge row y=290; evidence y=530; finish aligned to legend bottom.
PLAYBOOK_LAYOUT: dict[str, dict[str, Any]] = {
    "ingest_question": {"x": _SPINE_X["ingest_question"], "y": 58},
    "guardrail": {"x": _SPINE_X["guardrail"], "y": 58},
    "dec_guardrail": {"x": _SPINE_X["dec_guardrail"], "y": 58},
    "planner": {"x": _SPINE_X["planner"], "y": 58},
    "writer": {"x": _SPINE_X["writer"], "y": 58},
    "dec_writer": {"x": PROFILE_DEC_WRITER_X, "y": PROFILE_DEC_WRITER_Y},
    "spl_validate": {"x": _SPINE_X["writer"], "y": 168},
    "security_review": {"x": LANE_SEC_DROP_X, "y": 132},
    "dec_security": {"x": LANE_SEC_DROP_X, "y": 248},
    "peer_review": {"x": LANE_SEC_DROP_X, "y": 358},
    "peer_review_2": {"x": LANE_SEC_DROP_X, "y": 468},
    "validate_final_plan": {"x": 420, "y": 290},
    "dec_validate": {"x": 580, "y": 290},
    "run_tool": {"x": 740, "y": 290},
    "dec_evidence": {"x": 740, "y": 398},
    "deterministic_evidence_pack": {"x": 280, "y": 530},
    "analyst_evidence_review": {"x": 520, "y": 530},
    "security_evidence_review": {"x": 760, "y": 530},
    "summarize": {"x": _FINISH_SUMMARIZE_X, "y": PLAYBOOK_FINISH_ROW_Y},
    "finalize": {"x": _FINISH_FINALIZE_X, "y": PLAYBOOK_FINISH_ROW_Y},
}

# Inline SVG path data (24×24 viewBox) for playbook flowchart node badges — no emoji.
PLAYBOOK_NODE_ICONS: dict[str, str] = {
    "ingest_question": "M19 9h-4V3H9v6H5l7 7 7-7zM5 18v2h14v-2H5z",
    "guardrail": "M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z",
    "dec_guardrail": "M12 8c-2.21 0-4 1.79-4 4s1.79 4 4 4 4-1.79 4-4-1.79-4-4-4zm8.94 3A8.994 8.994 0 0013 3.06V1h-2v2.06A8.994 8.994 0 003.06 11H1v2h2.06A8.994 8.994 0 0011 20.94V23h2v-2.06A8.994 8.994 0 0020.94 13H23v-2h-2.06z",
    "planner": "M19 3h-4.18C14.4 1.84 13.3 1 12 1c-1.3 0-2.4.84-2.82 2H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm-7 0c.55 0 1 .45 1 1s-.45 1-1 1-1-.45-1-1 .45-1 1-1zm2 14H7v-2h7v2zm3-4H7v-2h10v2zm0-4H7V7h10v2z",
    "writer": "M9.4 16.6L4.8 12l4.6-4.6L8 6l-6 6 6 6 1.4-1.4zm5.2 0l4.6-4.6-4.6-4.6L16 6l6 6-6 6-1.4-1.4z",
    "dec_writer": "M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z",
    "spl_validate": "M15.5 14h-.79l-.28-.27A6.471 6.471 0 0016 9.5 6.5 6.5 0 109.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C8.01 14 6 11.99 6 9.5S8.01 5 10.5 5 15 7.01 15 9.5 12.99 14 10.5 14z",
    "security_review": "M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z",
    "dec_security": "M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z",
    "peer_review": "M16 11c1.66 0 2.99-1.34 2.99-3S17.66 5 16 5c-1.66 0-3 1.34-3 3s1.34 3 3 3zm-8 0c1.66 0 2.99-1.34 2.99-3S9.66 5 8 5C6.34 5 5 6.34 5 8s1.34 3 3 3zm0 2c-2.33 0-7 1.17-7 3.5V19h14v-2.5c0-2.33-4.67-3.5-7-3.5z",
    "peer_review_2": "M16 11c1.66 0 2.99-1.34 2.99-3S17.66 5 16 5c-1.66 0-3 1.34-3 3s1.34 3 3 3zm-8 0c1.66 0 2.99-1.34 2.99-3S9.66 5 8 5C6.34 5 5 6.34 5 8s1.34 3 3 3zm0 2c-2.33 0-7 1.17-7 3.5V19h14v-2.5c0-2.33-4.67-3.5-7-3.5z",
    "validate_final_plan": "M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-2 15l-4-4 1.41-1.41L10 14.17l6.59-6.59L18 9l-8 8z",
    "dec_validate": "M4.25 5.61C6.27 8.2 10 13 10 13v6c0 .55.45 1 1 1h2c.55 0 1-.45 1-1v-6s3.72-4.8 5.74-7.39C20.25 4.95 19.08 4 18 4H6c-1.08 0-2.25.95-1.75 1.61z",
    "run_tool": "M20 4H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V6c0-1.1-.9-2-2-2zm-2 12H6v-2h12v2zm-3.5-5L6 9.25V7.28L13.62 10 6 12.72V10.75l8.5-2.75z",
    "dec_evidence": "M15.5 14h-.79l-.28-.27A6.471 6.471 0 0016 9.5 6.5 6.5 0 109.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C8.01 14 6 11.99 6 9.5S8.01 5 10.5 5 15 7.01 15 9.5 12.99 14 10.5 14z",
    "deterministic_evidence_pack": "M10 4H4c-1.1 0-1.99.9-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2h-8l-2-2z",
    "analyst_evidence_review": "M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z",
    "security_evidence_review": "M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-2 15l-4-4 1.41-1.41L10 14.17l6.59-6.59L18 9l-8 8z",
    "summarize": "M14 2H6c-1.1 0-2 .9-2 2v16c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V8l-6-6zm2 16H8v-2h8v2zm0-4H8v-2h8v2zm-3-5V3.5L18.5 9H13z",
    "finalize": "M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z",
}

PLAYBOOK_PERIMETER_X = 20
LANE_SPINE_Y = 58
LANE_TOP_Y = 22
LANE_OP_BUS_X = 866
LANE_PROFILE_ELBOW_X = 934
_SEC_LOOP_X = LANE_SEC_DROP_X + PLAYBOOK_PROCESS_W // 2 + 14
LANE_META_Y = 228
LANE_MERGE_X = 468
LANE_EVIDENCE_Y = 478

PLAYBOOK_EDGES: list[dict[str, Any]] = [
    {"from": "ingest_question", "to": "guardrail", "branch": "trunk"},
    {"from": "guardrail", "to": "dec_guardrail", "branch": "trunk"},
    {
        "from": "dec_guardrail",
        "to": "planner",
        "label": "supported",
        "label_short": "OK",
        "branch": "trunk",
        "label_at": {
            "x": (_SPINE_X["dec_guardrail"] + _SPINE_X["planner"]) // 2,
            "y": 36,
        },
    },
    {
        "from": "dec_guardrail",
        "to": "summarize",
        "label": "blocked",
        "label_short": "BLOCK",
        "branch": "blocked",
        "shortcut": True,
        "anchor_from": "bottom",
        "anchor_to": "left",
        "waypoints": [
            {"x": _SPINE_X["dec_guardrail"], "y": 96},
            {"x": PLAYBOOK_PERIMETER_X, "y": 96},
            {"x": PLAYBOOK_PERIMETER_X, "y": PLAYBOOK_FINISH_ROW_Y},
            {"x": 462, "y": PLAYBOOK_FINISH_ROW_Y},
        ],
        "label_at": {"x": 58, "y": 328},
    },
    {"from": "planner", "to": "writer", "branch": "trunk"},
    {
        "from": "writer",
        "to": "dec_writer",
        "branch": "trunk",
        "anchor_from": "right",
        "anchor_to": "left",
        "waypoints": [
            {"x": LANE_PROFILE_ELBOW_X, "y": 58},
            {"x": LANE_PROFILE_ELBOW_X, "y": PROFILE_DEC_WRITER_Y},
        ],
    },
    {
        "from": "writer",
        "to": "spl_validate",
        "branch": "operational",
        "profiles": ["operational"],
        "anchor_from": "bottom",
        "anchor_to": "top",
    },
    {
        "from": "dec_writer",
        "to": "spl_validate",
        "label": "operational",
        "label_short": "OP",
        "branch": "operational",
        "profiles": ["operational"],
        "anchor_from": "bottom",
        "anchor_to": "top",
        "waypoints": [
            {"x": PROFILE_DEC_WRITER_X, "y": 118},
            {"x": LANE_OP_BUS_X, "y": 118},
            {"x": LANE_OP_BUS_X, "y": 168},
        ],
        "label_at": {
            "x": (LANE_OP_BUS_X + _SPINE_X["writer"]) // 2,
            "y": 106,
        },
    },
    {
        "from": "dec_writer",
        "to": "validate_final_plan",
        "label": "metadata",
        "label_short": "META",
        "branch": "metadata",
        "profiles": ["metadata"],
        "anchor_from": "bottom",
        "anchor_to": "top",
        "waypoints": [
            {"x": PROFILE_DEC_WRITER_X, "y": 196},
            {"x": 920, "y": 196},
            {"x": 920, "y": LANE_META_Y},
            {"x": LANE_MERGE_X, "y": LANE_META_Y},
        ],
        "label_at": {"x": 812, "y": 212},
    },
    {
        "from": "dec_writer",
        "to": "security_review",
        "label": "security",
        "label_short": "SEC",
        "branch": "security",
        "profiles": ["security"],
        "anchor_from": "bottom",
        "anchor_to": "top",
        "label_at": {"x": LANE_SEC_DROP_X + 54, "y": 88},
    },
    {
        "from": "spl_validate",
        "to": "validate_final_plan",
        "branch": "operational",
        "profiles": ["operational"],
        "anchor_from": "left",
        "anchor_to": "right",
        "waypoints": [
            {"x": LANE_OP_BUS_X, "y": 168},
            {"x": LANE_OP_BUS_X, "y": LANE_META_Y},
            {"x": LANE_MERGE_X, "y": LANE_META_Y},
            {"x": LANE_MERGE_X, "y": 290},
        ],
    },
    {
        "from": "security_review",
        "to": "dec_security",
        "branch": "security",
        "profiles": ["security"],
        "anchor_from": "bottom",
        "anchor_to": "top",
    },
    {
        "from": "dec_security",
        "to": "validate_final_plan",
        "label": "clean",
        "label_short": "OK",
        "branch": "security",
        "profiles": ["security"],
        "anchor_from": "left",
        "anchor_to": "right",
        "waypoints": [
            {"x": LANE_SEC_DROP_X, "y": 248},
            {"x": LANE_MERGE_X, "y": 258},
            {"x": LANE_MERGE_X, "y": 290},
        ],
        "label_at": {"x": 704, "y": 250},
    },
    {
        "from": "dec_security",
        "to": "security_review",
        "label": "contested",
        "label_short": "NO",
        "branch": "security",
        "profiles": ["security"],
        "anchor_from": "right",
        "anchor_to": "right",
        "waypoints": [
            {"x": _SEC_LOOP_X, "y": 248},
            {"x": _SEC_LOOP_X, "y": 132},
            {"x": LANE_SEC_DROP_X + PLAYBOOK_PROCESS_W // 2 - 4, "y": 132},
        ],
        "label_at": {"x": _SEC_LOOP_X + 10, "y": 192},
    },
    {
        "from": "dec_security",
        "to": "peer_review",
        "label": "contested",
        "label_short": "?",
        "branch": "security",
        "profiles": ["security"],
        "anchor_from": "bottom",
        "anchor_to": "top",
        "label_at": {"x": 1016, "y": 296},
    },
    {
        "from": "peer_review",
        "to": "peer_review_2",
        "branch": "security",
        "profiles": ["security"],
        "anchor_from": "bottom",
        "anchor_to": "top",
    },
    {
        "from": "peer_review_2",
        "to": "validate_final_plan",
        "branch": "security",
        "profiles": ["security"],
        "anchor_from": "left",
        "anchor_to": "bottom",
        "waypoints": [
            {"x": LANE_SEC_DROP_X, "y": 468},
            {"x": LANE_MERGE_X, "y": 468},
            {"x": LANE_MERGE_X, "y": 290},
        ],
    },
    {
        "from": "validate_final_plan",
        "to": "dec_validate",
        "branch": "trunk",
        "anchor_from": "right",
        "anchor_to": "left",
    },
    {
        "from": "dec_validate",
        "to": "run_tool",
        "label": "approved",
        "label_short": "OK",
        "branch": "trunk",
        "anchor_from": "right",
        "anchor_to": "left",
        "label_at": {"x": 660, "y": 268},
    },
    {
        "from": "dec_validate",
        "to": "summarize",
        "branch": "blocked",
        "shortcut": True,
        "anchor_from": "left",
        "anchor_to": "left",
        "waypoints": [
            {"x": 534, "y": 290},
            {"x": PLAYBOOK_PERIMETER_X, "y": 290},
            {"x": PLAYBOOK_PERIMETER_X, "y": PLAYBOOK_FINISH_ROW_Y},
            {"x": 462, "y": PLAYBOOK_FINISH_ROW_Y},
        ],
    },
    {
        "from": "run_tool",
        "to": "dec_evidence",
        "branch": "trunk",
        "anchor_from": "bottom",
        "anchor_to": "top",
    },
    {
        "from": "dec_evidence",
        "to": "deterministic_evidence_pack",
        "label": "metadata",
        "label_short": "META",
        "branch": "metadata",
        "profiles": ["metadata"],
        "anchor_from": "bottom",
        "anchor_to": "top",
        "waypoints": [{"x": 740, "y": 472}, {"x": 280, "y": 472}],
        "label_at": {"x": 402, "y": 458},
    },
    {
        "from": "dec_evidence",
        "to": "analyst_evidence_review",
        "label": "operational",
        "label_short": "OP",
        "branch": "operational",
        "profiles": ["operational"],
        "anchor_from": "bottom",
        "anchor_to": "top",
        "waypoints": [{"x": 740, "y": LANE_EVIDENCE_Y}, {"x": 520, "y": LANE_EVIDENCE_Y}],
        "label_at": {"x": 618, "y": 464},
    },
    {
        "from": "dec_evidence",
        "to": "security_evidence_review",
        "label": "security",
        "label_short": "SEC",
        "branch": "security",
        "profiles": ["security"],
        "anchor_from": "bottom",
        "anchor_to": "top",
        "waypoints": [{"x": 740, "y": 484}, {"x": 760, "y": 484}],
        "label_at": {"x": 792, "y": 470},
    },
    {
        "from": "deterministic_evidence_pack",
        "to": "summarize",
        "branch": "metadata",
        "profiles": ["metadata"],
        "anchor_from": "bottom",
        "anchor_to": "top",
        "waypoints": [{"x": 280, "y": PLAYBOOK_FINISH_MERGE_Y}, {"x": 520, "y": PLAYBOOK_FINISH_MERGE_Y}],
    },
    {
        "from": "analyst_evidence_review",
        "to": "summarize",
        "branch": "operational",
        "profiles": ["operational"],
        "anchor_from": "bottom",
        "anchor_to": "top",
    },
    {
        "from": "security_evidence_review",
        "to": "summarize",
        "branch": "security",
        "profiles": ["security"],
        "anchor_from": "bottom",
        "anchor_to": "top",
        "waypoints": [{"x": 760, "y": PLAYBOOK_FINISH_MERGE_Y}, {"x": 520, "y": PLAYBOOK_FINISH_MERGE_Y}],
    },
    {"from": "summarize", "to": "finalize", "branch": "trunk", "anchor_from": "right", "anchor_to": "left"},
]


def _patch_playbook_edge(
    edges: list[dict[str, Any]],
    from_id: str,
    to_id: str,
    **updates: Any,
) -> None:
    for edge in edges:
        if edge.get("from") == from_id and edge.get("to") == to_id:
            edge.update(updates)
            return
    raise KeyError(f"playbook edge not found: {from_id} -> {to_id}")


def _build_playbook_layout_presets() -> dict[str, dict[str, Any]]:
    """Named overlay layout presets; canonical remains the runtime default."""
    canonical_layout = copy.deepcopy(PLAYBOOK_LAYOUT)
    canonical_edges = copy.deepcopy(PLAYBOOK_EDGES)
    presets: dict[str, dict[str, Any]] = {
        "canonical": {"layout": canonical_layout, "edges": canonical_edges},
    }

    # Variant A — early gates (Scope?, Clean?, Approved?, Evidence) in bottom-left above legend.
    va_layout = copy.deepcopy(PLAYBOOK_LAYOUT)
    va_spine_y = 58
    va_ingest_x = 100
    va_guardrail_x = 296
    va_planner_x = 492
    va_writer_x = 688
    va_sec_x = 960
    va_layout.update(
        {
            "ingest_question": {"x": va_ingest_x, "y": va_spine_y},
            "guardrail": {"x": va_guardrail_x, "y": va_spine_y},
            "dec_guardrail": {"x": 80, "y": 510},
            "planner": {"x": va_planner_x, "y": va_spine_y},
            "writer": {"x": va_writer_x, "y": va_spine_y},
            "dec_writer": {"x": 860, "y": 36},
            "spl_validate": {"x": va_writer_x, "y": 168},
            "security_review": {"x": va_sec_x, "y": 140},
            "dec_security": {"x": 160, "y": 390},
            "peer_review": {"x": va_sec_x, "y": 310},
            "peer_review_2": {"x": va_sec_x, "y": 420},
            "validate_final_plan": {"x": 380, "y": 275},
            "dec_validate": {"x": 180, "y": 555},
            "run_tool": {"x": 540, "y": 275},
            "dec_evidence": {"x": 280, "y": 490},
            "deterministic_evidence_pack": {"x": 200, "y": 530},
            "analyst_evidence_review": {"x": 480, "y": 530},
            "security_evidence_review": {"x": 760, "y": 530},
        }
    )
    va_edges = copy.deepcopy(PLAYBOOK_EDGES)
    _patch_playbook_edge(
        va_edges,
        "guardrail",
        "dec_guardrail",
        anchor_from="bottom",
        anchor_to="top",
    )
    _patch_playbook_edge(
        va_edges,
        "dec_guardrail",
        "planner",
        label="supported",
        label_short="OK",
        branch="trunk",
        anchor_from="right",
        anchor_to="left",
        waypoints=[
            {"x": 80, "y": 430},
            {"x": va_planner_x - 120, "y": 430},
            {"x": va_planner_x - 120, "y": va_spine_y},
        ],
        label_at={"x": 220, "y": 418},
    )
    _patch_playbook_edge(
        va_edges,
        "dec_guardrail",
        "summarize",
        waypoints=[
            {"x": 80, "y": 554},
            {"x": PLAYBOOK_PERIMETER_X, "y": 554},
            {"x": PLAYBOOK_PERIMETER_X, "y": PLAYBOOK_FINISH_ROW_Y},
            {"x": 462, "y": PLAYBOOK_FINISH_ROW_Y},
        ],
        label_at={"x": 58, "y": 628},
    )
    _patch_playbook_edge(
        va_edges,
        "writer",
        "dec_writer",
        waypoints=[
            {"x": 820, "y": va_spine_y},
            {"x": 820, "y": 36},
        ],
    )
    _patch_playbook_edge(
        va_edges,
        "dec_writer",
        "spl_validate",
        waypoints=[
            {"x": 860, "y": 118},
            {"x": 820, "y": 118},
            {"x": 820, "y": 168},
        ],
        label_at={"x": 760, "y": 106},
    )
    _patch_playbook_edge(
        va_edges,
        "dec_writer",
        "validate_final_plan",
        waypoints=[
            {"x": 860, "y": 196},
            {"x": 900, "y": 196},
            {"x": 900, "y": 210},
            {"x": 440, "y": 210},
        ],
        label_at={"x": 780, "y": 200},
    )
    _patch_playbook_edge(
        va_edges,
        "dec_writer",
        "security_review",
        label_at={"x": va_sec_x + 54, "y": 88},
    )
    _patch_playbook_edge(
        va_edges,
        "spl_validate",
        "validate_final_plan",
        waypoints=[
            {"x": 820, "y": 168},
            {"x": 820, "y": 210},
            {"x": 440, "y": 210},
            {"x": 440, "y": 275},
        ],
    )
    _patch_playbook_edge(
        va_edges,
        "dec_security",
        "validate_final_plan",
        waypoints=[
            {"x": 160, "y": 390},
            {"x": 320, "y": 250},
            {"x": 440, "y": 250},
        ],
        label_at={"x": 240, "y": 318},
    )
    _patch_playbook_edge(
        va_edges,
        "dec_security",
        "security_review",
        waypoints=[
            {"x": 218, "y": 390},
            {"x": 218, "y": 140},
            {"x": va_sec_x - PLAYBOOK_PROCESS_W // 2 + 4, "y": 140},
        ],
        label_at={"x": 228, "y": 260},
    )
    _patch_playbook_edge(
        va_edges,
        "dec_security",
        "peer_review",
        label_at={"x": 960, "y": 296},
    )
    _patch_playbook_edge(
        va_edges,
        "peer_review_2",
        "validate_final_plan",
        waypoints=[
            {"x": va_sec_x, "y": 420},
            {"x": 440, "y": 420},
            {"x": 440, "y": 275},
        ],
    )
    _patch_playbook_edge(
        va_edges,
        "dec_validate",
        "summarize",
        waypoints=[
            {"x": 180, "y": 555},
            {"x": PLAYBOOK_PERIMETER_X, "y": 555},
            {"x": PLAYBOOK_PERIMETER_X, "y": PLAYBOOK_FINISH_ROW_Y},
            {"x": 462, "y": PLAYBOOK_FINISH_ROW_Y},
        ],
    )
    _patch_playbook_edge(
        va_edges,
        "dec_evidence",
        "deterministic_evidence_pack",
        waypoints=[{"x": 280, "y": 472}, {"x": 200, "y": 472}],
        label_at={"x": 240, "y": 458},
    )
    _patch_playbook_edge(
        va_edges,
        "dec_evidence",
        "analyst_evidence_review",
        waypoints=[{"x": 540, "y": LANE_EVIDENCE_Y}, {"x": 480, "y": LANE_EVIDENCE_Y}],
        label_at={"x": 500, "y": 464},
    )
    _patch_playbook_edge(
        va_edges,
        "dec_evidence",
        "security_evidence_review",
        waypoints=[{"x": 540, "y": 484}, {"x": 760, "y": 484}],
        label_at={"x": 640, "y": 470},
    )
    presets["variant-a"] = {"layout": va_layout, "edges": va_edges}

    # Variant B — security column lower/right, wider evidence fan, blocked paths in left margin.
    vb_layout = copy.deepcopy(PLAYBOOK_LAYOUT)
    vb_sec_x = 1020
    vb_layout.update(
        {
            "security_review": {"x": vb_sec_x, "y": 180},
            "dec_security": {"x": vb_sec_x, "y": 300},
            "peer_review": {"x": vb_sec_x, "y": 410},
            "peer_review_2": {"x": vb_sec_x, "y": 520},
            "dec_validate": {"x": 120, "y": 520},
            "dec_evidence": {"x": 200, "y": 450},
            "validate_final_plan": {"x": 420, "y": 300},
            "run_tool": {"x": 740, "y": 300},
            "deterministic_evidence_pack": {"x": 220, "y": 530},
            "analyst_evidence_review": {"x": 520, "y": 530},
            "security_evidence_review": {"x": 880, "y": 530},
        }
    )
    vb_edges = copy.deepcopy(PLAYBOOK_EDGES)
    _patch_playbook_edge(
        vb_edges,
        "dec_guardrail",
        "summarize",
        waypoints=[
            {"x": _SPINE_X["dec_guardrail"], "y": 120},
            {"x": PLAYBOOK_PERIMETER_X, "y": 120},
            {"x": PLAYBOOK_PERIMETER_X, "y": PLAYBOOK_FINISH_ROW_Y},
            {"x": 462, "y": PLAYBOOK_FINISH_ROW_Y},
        ],
        label_at={"x": 48, "y": 340},
    )
    _patch_playbook_edge(
        vb_edges,
        "dec_security",
        "validate_final_plan",
        waypoints=[
            {"x": vb_sec_x, "y": 300},
            {"x": LANE_MERGE_X, "y": 310},
            {"x": LANE_MERGE_X, "y": 300},
        ],
        label_at={"x": 704, "y": 292},
    )
    _patch_playbook_edge(
        vb_edges,
        "dec_security",
        "security_review",
        waypoints=[
            {"x": vb_sec_x + PLAYBOOK_PROCESS_W // 2 + 14, "y": 300},
            {"x": vb_sec_x + PLAYBOOK_PROCESS_W // 2 + 14, "y": 180},
            {"x": vb_sec_x + PLAYBOOK_PROCESS_W // 2 - 4, "y": 180},
        ],
        label_at={"x": vb_sec_x + 24, "y": 240},
    )
    _patch_playbook_edge(
        vb_edges,
        "peer_review_2",
        "validate_final_plan",
        waypoints=[
            {"x": vb_sec_x, "y": 520},
            {"x": LANE_MERGE_X, "y": 520},
            {"x": LANE_MERGE_X, "y": 300},
        ],
    )
    _patch_playbook_edge(
        vb_edges,
        "dec_validate",
        "summarize",
        waypoints=[
            {"x": 120, "y": 555},
            {"x": PLAYBOOK_PERIMETER_X, "y": 555},
            {"x": PLAYBOOK_PERIMETER_X, "y": PLAYBOOK_FINISH_ROW_Y},
            {"x": 462, "y": PLAYBOOK_FINISH_ROW_Y},
        ],
    )
    _patch_playbook_edge(
        vb_edges,
        "dec_evidence",
        "deterministic_evidence_pack",
        waypoints=[{"x": 740, "y": 468}, {"x": 220, "y": 468}],
        label_at={"x": 360, "y": 454},
    )
    _patch_playbook_edge(
        vb_edges,
        "dec_evidence",
        "analyst_evidence_review",
        waypoints=[{"x": 740, "y": LANE_EVIDENCE_Y}, {"x": 520, "y": LANE_EVIDENCE_Y}],
        label_at={"x": 620, "y": 464},
    )
    _patch_playbook_edge(
        vb_edges,
        "dec_evidence",
        "security_evidence_review",
        waypoints=[{"x": 740, "y": 490}, {"x": 880, "y": 490}],
        label_at={"x": 820, "y": 476},
    )
    _patch_playbook_edge(
        vb_edges,
        "security_evidence_review",
        "summarize",
        waypoints=[
            {"x": 880, "y": PLAYBOOK_FINISH_MERGE_Y},
            {"x": 520, "y": PLAYBOOK_FINISH_MERGE_Y},
        ],
    )
    presets["variant-b"] = {"layout": vb_layout, "edges": vb_edges}

    # Variant C — two-tier spine: ingest/planner/writer upper; validate/run lower; gates in left gutter.
    vc_upper_y = 52
    vc_lower_y = 230
    vc_gutter_x = 70
    vc_layout = copy.deepcopy(PLAYBOOK_LAYOUT)
    vc_layout.update(
        {
            "ingest_question": {"x": 100, "y": vc_upper_y},
            "guardrail": {"x": 280, "y": vc_upper_y},
            "dec_guardrail": {"x": 440, "y": vc_upper_y},
            "planner": {"x": 580, "y": vc_upper_y},
            "writer": {"x": 760, "y": vc_upper_y},
            "dec_writer": {"x": 920, "y": vc_upper_y},
            "spl_validate": {"x": 760, "y": 140},
            "security_review": {"x": 980, "y": 150},
            "dec_security": {"x": vc_gutter_x, "y": 280},
            "peer_review": {"x": 980, "y": 340},
            "peer_review_2": {"x": 980, "y": 450},
            "validate_final_plan": {"x": 400, "y": vc_lower_y},
            "dec_validate": {"x": vc_gutter_x, "y": 420},
            "run_tool": {"x": 560, "y": vc_lower_y},
            "dec_evidence": {"x": vc_gutter_x, "y": 500},
            "deterministic_evidence_pack": {"x": 240, "y": 540},
            "analyst_evidence_review": {"x": 500, "y": 540},
            "security_evidence_review": {"x": 780, "y": 540},
        }
    )
    vc_edges = copy.deepcopy(PLAYBOOK_EDGES)
    _patch_playbook_edge(
        vc_edges,
        "dec_guardrail",
        "planner",
        label_at={"x": 510, "y": 36},
    )
    _patch_playbook_edge(
        vc_edges,
        "dec_guardrail",
        "summarize",
        waypoints=[
            {"x": 440, "y": 96},
            {"x": PLAYBOOK_PERIMETER_X, "y": 96},
            {"x": PLAYBOOK_PERIMETER_X, "y": PLAYBOOK_FINISH_ROW_Y},
            {"x": 462, "y": PLAYBOOK_FINISH_ROW_Y},
        ],
        label_at={"x": 48, "y": 310},
    )
    _patch_playbook_edge(
        vc_edges,
        "writer",
        "dec_writer",
        anchor_from="right",
        anchor_to="left",
        waypoints=[
            {"x": 880, "y": vc_upper_y},
        ],
    )
    _patch_playbook_edge(
        vc_edges,
        "dec_writer",
        "spl_validate",
        waypoints=[
            {"x": 920, "y": 110},
            {"x": 840, "y": 110},
            {"x": 840, "y": 140},
        ],
        label_at={"x": 860, "y": 98},
    )
    _patch_playbook_edge(
        vc_edges,
        "dec_writer",
        "validate_final_plan",
        waypoints=[
            {"x": 920, "y": 200},
            {"x": 920, "y": 210},
            {"x": 460, "y": 210},
            {"x": 460, "y": vc_lower_y},
        ],
        label_at={"x": 820, "y": 198},
    )
    _patch_playbook_edge(
        vc_edges,
        "dec_writer",
        "security_review",
        label_at={"x": 980, "y": 88},
    )
    _patch_playbook_edge(
        vc_edges,
        "spl_validate",
        "validate_final_plan",
        waypoints=[
            {"x": 840, "y": 140},
            {"x": 840, "y": 210},
            {"x": 460, "y": 210},
            {"x": 460, "y": vc_lower_y},
        ],
    )
    _patch_playbook_edge(
        vc_edges,
        "dec_security",
        "validate_final_plan",
        waypoints=[
            {"x": vc_gutter_x, "y": 280},
            {"x": 280, "y": 280},
            {"x": 280, "y": vc_lower_y},
        ],
        label_at={"x": 160, "y": 268},
    )
    _patch_playbook_edge(
        vc_edges,
        "dec_security",
        "security_review",
        waypoints=[
            {"x": 114, "y": 280},
            {"x": 114, "y": 150},
            {"x": 980 - PLAYBOOK_PROCESS_W // 2 + 4, "y": 150},
        ],
        label_at={"x": 124, "y": 210},
    )
    _patch_playbook_edge(
        vc_edges,
        "dec_security",
        "peer_review",
        label_at={"x": 980, "y": 296},
    )
    _patch_playbook_edge(
        vc_edges,
        "peer_review_2",
        "validate_final_plan",
        waypoints=[
            {"x": 980, "y": 450},
            {"x": 460, "y": 450},
            {"x": 460, "y": vc_lower_y},
        ],
    )
    _patch_playbook_edge(
        vc_edges,
        "validate_final_plan",
        "dec_validate",
        anchor_from="left",
        anchor_to="right",
        waypoints=[
            {"x": 314, "y": vc_lower_y},
            {"x": 314, "y": 420},
        ],
    )
    _patch_playbook_edge(
        vc_edges,
        "dec_validate",
        "run_tool",
        label_at={"x": 480, "y": 248},
    )
    _patch_playbook_edge(
        vc_edges,
        "dec_validate",
        "summarize",
        waypoints=[
            {"x": vc_gutter_x, "y": 420},
            {"x": PLAYBOOK_PERIMETER_X, "y": 420},
            {"x": PLAYBOOK_PERIMETER_X, "y": PLAYBOOK_FINISH_ROW_Y},
            {"x": 462, "y": PLAYBOOK_FINISH_ROW_Y},
        ],
    )
    _patch_playbook_edge(
        vc_edges,
        "run_tool",
        "dec_evidence",
        anchor_from="bottom",
        anchor_to="top",
        waypoints=[
            {"x": 560, "y": 320},
            {"x": vc_gutter_x, "y": 320},
            {"x": vc_gutter_x, "y": 500},
        ],
    )
    _patch_playbook_edge(
        vc_edges,
        "dec_evidence",
        "deterministic_evidence_pack",
        waypoints=[{"x": 240, "y": 520}, {"x": 240, "y": 540}],
        label_at={"x": 180, "y": 512},
    )
    _patch_playbook_edge(
        vc_edges,
        "dec_evidence",
        "analyst_evidence_review",
        waypoints=[{"x": 400, "y": 520}, {"x": 500, "y": 520}],
        label_at={"x": 440, "y": 508},
    )
    _patch_playbook_edge(
        vc_edges,
        "dec_evidence",
        "security_evidence_review",
        waypoints=[{"x": 640, "y": 520}, {"x": 780, "y": 520}],
        label_at={"x": 700, "y": 508},
    )
    presets["variant-c"] = {"layout": vc_layout, "edges": vc_edges}

    return presets


PLAYBOOK_LAYOUT_PRESETS: dict[str, dict[str, Any]] = _build_playbook_layout_presets()
PLAYBOOK_DEFAULT_LAYOUT_PRESET = "canonical"


def get_playbook_layout_preset(name: str | None = None) -> dict[str, Any]:
    """Return layout + edges for a named overlay preset (defaults to canonical)."""
    key = str(name or PLAYBOOK_DEFAULT_LAYOUT_PRESET).strip() or PLAYBOOK_DEFAULT_LAYOUT_PRESET
    preset = PLAYBOOK_LAYOUT_PRESETS.get(key)
    if preset is None:
        preset = PLAYBOOK_LAYOUT_PRESETS[PLAYBOOK_DEFAULT_LAYOUT_PRESET]
    return preset


def list_playbook_layout_presets() -> list[str]:
    return list(PLAYBOOK_LAYOUT_PRESETS.keys())


PLAYBOOK_ACTIVE_NODE_ALIASES: dict[str, str] = {
    "peer_review": "peer_review",
    "peer_review_2": "peer_review_2",
    "peer_review_1": "peer_review",
    "peer_reviewer": "peer_review",
    "peer_reviewer_1": "peer_review",
    "peer_reviewer_2": "peer_review_2",
    "ingest_question": "ingest_question",
    "query_planner": "planner",
    "query_writer": "writer",
    "validation": "validate_final_plan",
    "execution": "run_tool",
    "summary": "summarize",
    "package_response": "finalize",
    "evidence_review": "analyst_evidence_review",
}

# node_timings_ms / stage_log keys rolled up to each runtime-rail journey step.
JOURNEY_TIMING_MS_KEYS: dict[str, list[str]] = {
    "guardrail": ["guardrail"],
    "planner": ["planner", "field_bind"],
    "writer": ["writer"],
    "security_review": ["security_review", "peer_review_1", "peer_review_2"],
    "run_tool": ["validation", "run_tool"],
    "evidence_review": [
        "evidence_review",
        "analyst_evidence_review",
        "security_evidence_review",
        "deterministic_evidence_pack",
    ],
    "summarize": ["summarize"],
    "finalize": ["finalize"],
    "package_response": ["package_response"],
}

# Maps LangGraph node ids to the active-model chip highlighted during a run.
NODE_ACTIVE_ROLE: dict[str, str] = {
    "planner": "planner",
    "writer": "writer",
    "spl_validate": "analyst",
    "security_review": "security",
    "peer_review": "peers",
    "peer_review_2": "peers",
    "evidence_review": "analyst",
    "analyst_evidence_review": "analyst",
    "security_evidence_review": "security",
    "deterministic_evidence_pack": "",
    "summarize": "analyst",
    "package_response": "",
    "finalize": "",
}


def journey_step_index(node_id: str) -> int:
    key = str(node_id or "").strip()
    for index, step in enumerate(JOURNEY_UI_STEPS):
        if step.get("node") == key:
            return index
    return -1


def journey_state_for_progress_pct(pct: int | float | None) -> tuple[str, int]:
    """Return the active journey node and last completed step index for a progress percent."""
    value = max(0, min(100, int(pct or 0)))
    packaging_pct = int(progress_for_multi_model_node("package_response").get("pct") or 99)
    finalize_pct = int(progress_for_multi_model_node("finalize").get("pct") or 98)
    last_index = len(JOURNEY_UI_STEPS) - 1
    last_node = JOURNEY_UI_STEPS[last_index]["node"]
    packaging_index = journey_step_index("package_response")
    if value >= packaging_pct:
        return last_node, last_index
    finalize_index = journey_step_index("finalize")
    if value >= finalize_pct and finalize_index >= 0:
        return "finalize", max(0, finalize_index - 1)

    active_node = JOURNEY_UI_STEPS[0]["node"]
    completed_through = -1
    for index, step in enumerate(JOURNEY_UI_STEPS):
        threshold = int(progress_for_multi_model_node(step["node"]).get("pct") or 0)
        if value >= threshold:
            completed_through = index
            if index + 1 < len(JOURNEY_UI_STEPS):
                active_node = JOURNEY_UI_STEPS[index + 1]["node"]
            else:
                active_node = step["node"]
        else:
            active_node = step["node"]
            break
    return active_node, completed_through


def synthetic_stage_event_for_progress(
    pct: int | float | None,
    *,
    label: str = "",
    source: str = "llm_assisted",
) -> dict[str, Any]:
    active_node, _completed_through = journey_state_for_progress_pct(pct)
    info = progress_for_multi_model_node(active_node)
    normalized_pct = max(0, min(100, int(pct or 0)))
    return {
        "source": source,
        "node": active_node,
        "progress_pct": normalized_pct,
        "title": info.get("title", ""),
        "label": label or info.get("label", ""),
        "note": info.get("note", ""),
        "indeterminate": False,
    }


WORKFLOW_STAGE_TO_JOURNEY_NODE: dict[str, str] = {
    "guardrail": "guardrail",
    "planner": "planner",
    "field_bind": "planner",
    "query_writer": "writer",
    "writer": "writer",
    "spl_validate": "writer",
    "security_reviewer": "security_review",
    "reviewer": "security_review",
    "peer_reviewer": "security_review",
    "peer_reviewer_1": "security_review",
    "peer_reviewer_2": "security_review",
    "peer_review_1": "security_review",
    "peer_review_2": "security_review",
    "validation": "run_tool",
    "validate_final_plan": "run_tool",
    "execution": "run_tool",
    "run_tool": "run_tool",
    "evidence_review": "evidence_review",
    "analyst_evidence_review": "evidence_review",
    "security_evidence_review": "evidence_review",
    "deterministic_evidence_pack": "evidence_review",
    "summary": "summarize",
    "summarize": "summarize",
    "finalize": "finalize",
    "package_response": "package_response",
}


def journey_timings_ms_from_result(result: dict[str, Any] | None) -> dict[str, int]:
    """Return per journey-step durations in ms from a completed investigation payload."""
    if not isinstance(result, dict):
        return {}
    node_timings = result.get("node_timings_ms")
    if isinstance(node_timings, dict) and node_timings:
        timings: dict[str, int] = {}
        for step in JOURNEY_UI_STEPS:
            node = str(step.get("node", "")).strip()
            keys = JOURNEY_TIMING_MS_KEYS.get(node, [node])
            total_ms = sum(int(node_timings.get(key, 0) or 0) for key in keys)
            if total_ms > 0:
                timings[node] = total_ms
        return timings

    logs = result.get("stage_logs")
    if not isinstance(logs, list):
        return {}
    totals: dict[str, int] = {}
    for entry in logs:
        if not isinstance(entry, dict):
            continue
        stage = str(entry.get("stage", "")).strip()
        journey_node = WORKFLOW_STAGE_TO_JOURNEY_NODE.get(stage, "")
        if not journey_node:
            continue
        totals[journey_node] = totals.get(journey_node, 0) + int(entry.get("duration_ms", 0) or 0)
    return {node: ms for node, ms in totals.items() if ms > 0}


def journey_completion_from_workflow(workflow: list[dict[str, Any]] | None) -> tuple[str, int]:
    """Post-run journey state: all UI steps complete when model_workflow is present."""
    last_index = len(JOURNEY_UI_STEPS) - 1
    last_node = JOURNEY_UI_STEPS[last_index]["node"]
    if not workflow:
        return "", -1
    return last_node, last_index


def should_skip_security_review(
    *,
    intent: str = "",
    selected_tool: str = "",
    question: str = "",
    review_profile: str = "",
) -> bool:
    """Return True when security review adds no value for this plan."""
    profile = str(review_profile or "").strip()
    if profile:
        return not requires_security_review(profile)
    if question and is_inventory_question(question):
        return True
    if question and is_security_question(question):
        return False
    tool = str(selected_tool or "").strip()
    if tool in SECURITY_REVIEW_SKIP_TOOLS:
        return True
    intent_key = str(intent or "").strip()
    if intent_key in METADATA_REVIEW_INTENTS:
        return True
    if intent_key in SECURITY_REVIEW_INTENTS:
        return False
    return intent_key in SECURITY_REVIEW_SKIP_INTENTS


def should_skip_inventory_llm_review(
    *,
    question: str = "",
    intent: str = "",
    selected_tool: str = "",
) -> bool:
    """Return True when Foundation-Sec / reasoning review stages should stay deterministic."""
    return should_skip_security_review(intent=intent, selected_tool=selected_tool, question=question)


def journey_skipped_nodes_from_result(result: dict[str, Any] | None) -> list[str]:
    if not isinstance(result, dict):
        return []
    raw = result.get("skipped_nodes") or result.get("journey_skipped_nodes") or []
    if not isinstance(raw, list):
        raw = []
    known = {step["node"] for step in JOURNEY_UI_STEPS}
    out: list[str] = []
    for item in raw:
        node = str(item or "").strip()
        if node in known and node not in out:
            out.append(node)
    if result.get("packaging_skipped") is True and "package_response" not in out:
        out.append("package_response")
    return out


def skipped_stage_event_payload(node: str, *, reason: str = "", source: str = "multi_model") -> dict[str, Any]:
    info = progress_for_multi_model_node(node)
    return {
        "source": source,
        "node": node,
        "stage": None,
        "progress_pct": info.get("pct"),
        "title": info.get("title", ""),
        "label": "skipped",
        "note": reason or "This stage was not required for this question.",
        "indeterminate": False,
        "skipped": True,
        "status": "skipped",
    }


def progress_event_payload(*, node: str = "", stage: str = "", source: str = "multi_model") -> dict[str, Any]:
    info = progress_for_multi_model_node(node) if node else progress_for_stage_log(stage)
    return {
        "source": source,
        "node": node or None,
        "stage": stage or None,
        "progress_pct": info.get("pct"),
        "title": info.get("title", ""),
        "label": info.get("label", ""),
        "note": info.get("note", ""),
        "indeterminate": info.get("pct") is None,
    }
