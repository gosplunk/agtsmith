#!/usr/bin/env python3
"""Honest investigation progress mapping for LangGraph multi-model runs."""

from __future__ import annotations

import copy

from typing import Any, Literal

from question_intelligence import question_has_index_token

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
        "note": (
            "Before drafting, the plan is grounded to real indexes/sourcetypes: keyword scoring "
            "blends with semantic embedding retrieval (nomic-embed-text), optionally enriched by a "
            "lightweight edge classifier hint. The writer then turns the grounded plan into "
            "read-only Splunk SPL or MCP tool args."
        ),
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
        "pct": 75,
        "title": "Semantic coverage",
        "label": "Checking semantic coverage...",
        "note": "The typed plan, final SPL, and declared output schema are compared before any Splunk call.",
    },
    "semantic_candidate_select": {
        "pct": 77,
        "title": "Semantic candidate",
        "label": "Selecting semantic candidate plan...",
        "note": "When multiple grounded plan candidates survive the gates, the strongest semantic match is selected.",
    },
    "run_tool": {
        "pct": 79,
        "title": "Splunk retrieval",
        "label": "Retrieving evidence from Splunk...",
        "note": "The approved read-only plan is executing against Splunk via MCP.",
    },
    "post_execution": {
        "pct": 83,
        "title": "Post-execution",
        "label": "Normalizing Splunk results...",
        "note": "Raw Splunk rows are normalized, capped, and shaped into evidence before analyst or security review.",
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
    "semantic_candidate_select": MULTI_MODEL_NODE_PROGRESS["semantic_candidate_select"],
    "execution": MULTI_MODEL_NODE_PROGRESS["run_tool"],
    "post_execution": MULTI_MODEL_NODE_PROGRESS["post_execution"],
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
        "splunk_internal_health",
        "splunk_license_usage",
        "forwarder_connectivity",
        "internal_splunkd_health",
        "internal_auth_failures",
        "linux_sourcetypes",
        "linux_host_activity",
        "linux_auth_failures",
        "linux_successful_logins",
        "linux_privilege_escalation",
        "linux_privilege_escalation_activity",
        "linux_session_activity",
        "linux_audit_activity",
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
    # "index"/"indexes" substring check plus typo tolerance (e.g. "idexes", "indexs")
    # so misspelled inventory questions ("which idexes do I have access to?") are
    # still recognized instead of falling through to a security/auth classification.
    has_index = "index" in q or "indexes" in q or question_has_index_token(q)
    if has_index and any(term in q for term in _INVENTORY_DATA_SIGNALS):
        return True
    if has_index and any(term in q for term in _INVENTORY_ANALYTICS_SIGNALS):
        return False
    if has_index and any(phrase in q for phrase in _INVENTORY_INDEX_PHRASES):
        return True
    if has_index and any(term in q for term in _INVENTORY_VERBS):
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
    """Journey nodes skipped for a review profile (branch-specific nodes only)."""
    key = str(profile or "").strip()
    skipped: list[str] = []
    if key != "security":
        skipped.extend(["security_review", "peer_review", "peer_review_2"])
    if key != "operational":
        skipped.append("spl_validate")
    return skipped


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
    {"node": "field_bind", "label": "Field Binding"},
    {"node": "field_discovery", "label": "Field Discovery"},
    {"node": "field_strategy", "label": "Field Strategy"},
    {"node": "domain_knowledge", "label": "Domain Knowledge"},
    {"node": "writer", "label": "SPL Writer"},
    {"node": "spl_validate", "label": "SPL Validate"},
    {"node": "security_review", "label": "Security Review"},
    {"node": "peer_review", "label": "Peer Review 1"},
    {"node": "peer_review_2", "label": "Peer Review 2"},
    {"node": "validate_final_plan", "label": "Plan Validation"},
    {"node": "field_policy", "label": "Field Policy"},
    {"node": "semantic_gate", "label": "Semantic Coverage"},
    {"node": "semantic_candidate_select", "label": "Semantic Candidate"},
    {"node": "run_tool", "label": "Splunk Query"},
    {"node": "post_execution", "label": "Post-Execution"},
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
    "field_bind",
    "field_discovery",
    "field_strategy",
    "domain_knowledge",
    "writer",
    "spl_validate",
    "security_review",
    "peer_review",
    "peer_review_2",
    "validate_final_plan",
    "field_policy",
    "semantic_gate",
    "semantic_candidate_select",
    "run_tool",
    "post_execution",
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
    {"id": "dec_guardrail", "label": "In scope?", "kind": "decision"},
    {"id": "planner", "label": "Planner", "kind": "process"},
    {"id": "field_bind", "label": "Field Binding", "kind": "process"},
    {"id": "field_discovery", "label": "Field Discovery", "kind": "process"},
    {"id": "field_strategy", "label": "Field Strategy", "kind": "process"},
    {"id": "domain_knowledge", "label": "Domain Knowledge", "kind": "process"},
    {"id": "writer", "label": "SPL Writer", "kind": "process"},
    {"id": "dec_writer", "label": "Review profile?", "kind": "decision"},
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
    {
        "id": "dec_security",
        "label": "Security profile?",
        "kind": "decision",
        "profiles": ["security"],
    },
    {"id": "peer_review", "label": "Peer Review 1", "kind": "process", "profiles": ["security"]},
    {"id": "peer_review_2", "label": "Peer Review 2", "kind": "process", "profiles": ["security"]},
    {"id": "validate_final_plan", "label": "Validate", "kind": "process"},
    {"id": "dec_validate", "label": "Approved?", "kind": "decision"},
    {"id": "field_policy", "label": "Field Policy", "kind": "process"},
    {"id": "semantic_gate", "label": "Semantic Coverage", "kind": "process"},
    {"id": "semantic_candidate_select", "label": "Semantic Candidate", "kind": "process"},
    {"id": "run_tool", "label": "Run Tool", "kind": "process"},
    {"id": "post_execution", "label": "Post-Execution", "kind": "process"},
    {"id": "dec_evidence", "label": "Evidence needed?", "kind": "decision"},
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
PLAYBOOK_NODE_GAP = 52
PLAYBOOK_SPINE_START_X = 380

# Diagram framework. The SVG is intentionally taller than the viewport so the
# approved, spacious design can scroll without shrinking node labels.
PLAYBOOK_HEADER_Y = 18
PLAYBOOK_HEADER_H = 52
PLAYBOOK_CONTENT_X = 150
PLAYBOOK_CONTENT_RIGHT_X = 1580

# Top-to-bottom bus rows.
BUS_INTAKE_Y = 110
BUS_GUARDRAIL_Y = 175
BUS_SCOPE_GATE_Y = 254
BUS_GROUNDING_Y = 335
BUS_FIELD_BIND_Y = 395
BUS_FIELD_DISCOVERY_Y = 465
BUS_FIELD_STRATEGY_Y = 535
BUS_DOMAIN_KNOWLEDGE_Y = 605
BUS_WRITER_Y = 675
BUS_PROFILE_GATE_Y = 755
BUS_PROFILE_Y = 845
BUS_SECURITY_GATE_Y = 930
BUS_PEER_REVIEW_Y = 1015
BUS_PEER_REVIEW_2_Y = 1100
BUS_VALIDATE_Y = 1195
BUS_VALIDATE_GATE_Y = 1280
BUS_POLICY_Y = 1390
BUS_RUN_TOOL_Y = 1495
BUS_POST_EXEC_Y = 1575
BUS_EVIDENCE_GATE_Y = 1660
BUS_EVIDENCE_Y = 1765
BUS_FINISH_Y = 1880
BUS_FINALIZE_Y = 1960
BUS_GROUNDING_ROW2_Y = BUS_FIELD_STRATEGY_Y
PLAYBOOK_GROUNDING_ROW_Y = BUS_GROUNDING_Y
PLAYBOOK_POLICY_ROW_Y = BUS_POLICY_Y
PLAYBOOK_LEGEND_Y = 1860
PLAYBOOK_LEGEND_H = 108
PLAYBOOK_LEGEND_BOTTOM_Y = PLAYBOOK_LEGEND_Y + PLAYBOOK_LEGEND_H
PLAYBOOK_FINISH_ROW_Y = BUS_FINISH_Y
PLAYBOOK_FINISH_MERGE_Y = BUS_FINISH_Y - 55
PLAYBOOK_SEC_STACK_STEP = 85

# Lane column centers (x), matching the approved four-column target.
LANE_CORE_X = 380
LANE_OP_X = 760
LANE_META_X = 1080
LANE_SEC_X = 1400
LANE_MERGE_BUS_X = 820
LANE_SEC_DROP_X = LANE_SEC_X
LANE_OP_BUS_X = LANE_OP_X
LANE_MERGE_X = LANE_MERGE_BUS_X
LANE_META_Y = BUS_PROFILE_Y
LANE_EVIDENCE_Y = BUS_EVIDENCE_Y - 56
LANE_SPINE_Y = BUS_INTAKE_Y
LANE_TOP_Y = PLAYBOOK_HEADER_Y
PLAYBOOK_PERIMETER_X = 136

# Overlay SVG viewBox — keep in sync with web_ui_server.py FLOW_VIEWBOX.
PLAYBOOK_VIEWBOX = {"x": 0, "y": 0, "w": 1600, "h": 2040}

PLAYBOOK_LANES: list[dict[str, Any]] = [
    {"id": "core", "label": "Core flow", "x1": 150, "x2": 610, "x": LANE_CORE_X},
    {
        "id": "operational",
        "label": "Operational",
        "x1": 610,
        "x2": 930,
        "x": LANE_OP_X,
    },
    {"id": "metadata", "label": "Metadata", "x1": 930, "x2": 1230, "x": LANE_META_X},
    {"id": "security", "label": "Security", "x1": 1230, "x2": 1580, "x": LANE_SEC_X},
]

# Phase timers aggregate these exact runtime-rail timing buckets. They do not
# maintain their own clocks.
PLAYBOOK_PHASES: list[dict[str, Any]] = [
    {
        "id": "intake",
        "index": 1,
        "label": "Intake",
        "y1": 72,
        "y2": 300,
        "timing_nodes": ["guardrail"],
    },
    {
        "id": "grounding",
        "index": 2,
        "label": "Grounding",
        "y1": 300,
        "y2": 710,
        "timing_nodes": [
            "planner",
            "field_bind",
            "field_discovery",
            "field_strategy",
            "domain_knowledge",
            "writer",
        ],
    },
    {
        "id": "review_profile",
        "index": 3,
        "label": "Review profile",
        "y1": 710,
        "y2": 1150,
        "timing_nodes": [
            "spl_validate",
            "security_review",
            "peer_review",
            "peer_review_2",
        ],
    },
    {
        "id": "validation_execution",
        "index": 4,
        "label": "Validation & execution",
        "y1": 1150,
        "y2": 1710,
        "timing_nodes": [
            "validate_final_plan",
            "field_policy",
            "semantic_gate",
            "semantic_candidate_select",
            "run_tool",
            "post_execution",
        ],
    },
    {
        "id": "evidence",
        "index": 5,
        "label": "Evidence",
        "y1": 1710,
        "y2": 1830,
        "timing_nodes": ["evidence_review"],
    },
    {
        "id": "finish",
        "index": 6,
        "label": "Finish",
        "y1": 1830,
        "y2": 2025,
        "timing_nodes": ["summarize", "finalize"],
    },
]


def _playbook_spine_centers() -> dict[str, int]:
    """Return the common x center for the vertical core spine."""
    return {
        node_id: LANE_CORE_X
        for node_id in (
            "ingest_question",
            "guardrail",
            "dec_guardrail",
            "planner",
            "writer",
        )
    }


_SPINE_X = _playbook_spine_centers()
PROFILE_DEC_WRITER_X = _SPINE_X["writer"]
PROFILE_DEC_WRITER_Y = BUS_PROFILE_GATE_Y

# Branch colors for overlay nodes (matches legend path colors).
PLAYBOOK_NODE_BRANCH: dict[str, str] = {
    "ingest_question": "trunk",
    "guardrail": "trunk",
    "dec_guardrail": "gate",
    "planner": "trunk",
    "field_bind": "trunk",
    "field_discovery": "trunk",
    "field_strategy": "trunk",
    "domain_knowledge": "trunk",
    "writer": "trunk",
    "dec_writer": "gate",
    "spl_validate": "operational",
    "security_review": "security",
    "dec_security": "gate",
    "peer_review": "security",
    "peer_review_2": "security",
    "validate_final_plan": "trunk",
    "dec_validate": "gate",
    "field_policy": "trunk",
    "semantic_gate": "trunk",
    "semantic_candidate_select": "trunk",
    "run_tool": "trunk",
    "post_execution": "trunk",
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
        "dec_writer": "Profile gate: routes the run down operational, metadata, or security paths.",
        "dec_security": "Clean gate: accepts security-reviewed SPL or sends contested queries to peer review.",
        "dec_validate": "Approval gate: the plan must pass deterministic policy checks before Splunk execution.",
        "dec_evidence": "Evidence gate: sends results to metadata pack, analyst review, or security evidence review.",
    }
)

_FINISH_SUMMARIZE_X = LANE_MERGE_BUS_X
_FINISH_FINALIZE_X = LANE_MERGE_BUS_X


def _chain_row_x(start_x: int, count: int) -> list[int]:
    step = PLAYBOOK_PROCESS_W + PLAYBOOK_NODE_GAP
    return [start_x + idx * step for idx in range(count)]


def _build_swimlane_layout() -> dict[str, dict[str, int]]:
    """Top-to-bottom positions for the approved four-lane playbook."""
    layout: dict[str, dict[str, int]] = {
        "ingest_question": {"x": LANE_CORE_X, "y": BUS_INTAKE_Y},
        "guardrail": {"x": LANE_CORE_X, "y": BUS_GUARDRAIL_Y},
        "dec_guardrail": {"x": LANE_CORE_X, "y": BUS_SCOPE_GATE_Y},
        "planner": {"x": LANE_CORE_X, "y": BUS_GROUNDING_Y},
        "field_bind": {"x": LANE_CORE_X, "y": BUS_FIELD_BIND_Y},
        "field_discovery": {"x": LANE_CORE_X, "y": BUS_FIELD_DISCOVERY_Y},
        "field_strategy": {"x": LANE_CORE_X, "y": BUS_FIELD_STRATEGY_Y},
        "domain_knowledge": {"x": LANE_CORE_X, "y": BUS_DOMAIN_KNOWLEDGE_Y},
        "writer": {"x": LANE_CORE_X, "y": BUS_WRITER_Y},
        "dec_writer": {"x": LANE_CORE_X, "y": BUS_PROFILE_GATE_Y},
    }
    layout["spl_validate"] = {"x": LANE_OP_X, "y": BUS_PROFILE_Y}
    layout["security_review"] = {"x": LANE_SEC_X, "y": BUS_PROFILE_Y}
    layout["dec_security"] = {"x": LANE_SEC_X, "y": BUS_SECURITY_GATE_Y}
    layout["peer_review"] = {"x": LANE_SEC_X, "y": BUS_PEER_REVIEW_Y}
    layout["peer_review_2"] = {"x": LANE_SEC_X, "y": BUS_PEER_REVIEW_2_Y}

    layout["validate_final_plan"] = {"x": LANE_MERGE_BUS_X, "y": BUS_VALIDATE_Y}
    layout["dec_validate"] = {"x": LANE_MERGE_BUS_X, "y": BUS_VALIDATE_GATE_Y}
    layout["run_tool"] = {"x": LANE_MERGE_BUS_X, "y": BUS_RUN_TOOL_Y}
    layout["post_execution"] = {"x": LANE_MERGE_BUS_X, "y": BUS_POST_EXEC_Y}
    layout["dec_evidence"] = {"x": LANE_MERGE_BUS_X, "y": BUS_EVIDENCE_GATE_Y}

    policy_ids = ("field_policy", "semantic_gate", "semantic_candidate_select")
    for node_id, x in zip(policy_ids, (LANE_CORE_X, LANE_OP_X, LANE_META_X)):
        layout[node_id] = {"x": x, "y": BUS_POLICY_Y}

    layout["deterministic_evidence_pack"] = {"x": LANE_META_X, "y": BUS_EVIDENCE_Y}
    layout["analyst_evidence_review"] = {"x": LANE_OP_X, "y": BUS_EVIDENCE_Y}
    layout["security_evidence_review"] = {"x": LANE_SEC_X, "y": BUS_EVIDENCE_Y}
    layout["summarize"] = {"x": _FINISH_SUMMARIZE_X, "y": BUS_FINISH_Y}
    layout["finalize"] = {"x": _FINISH_FINALIZE_X, "y": BUS_FINALIZE_Y}
    return layout


PLAYBOOK_LAYOUT: dict[str, dict[str, Any]] = _build_swimlane_layout()

# Every graph counter resolves to one of the exact timing buckets displayed by
# the LangGraph Journey rail. Decision diamonds deliberately mirror the source
# stage that performs the routing decision.
PLAYBOOK_TIMING_SOURCE: dict[str, str] = {
    "ingest_question": "guardrail",
    "guardrail": "guardrail",
    "dec_guardrail": "guardrail",
    "planner": "planner",
    "field_bind": "field_bind",
    "field_discovery": "field_discovery",
    "field_strategy": "field_strategy",
    "domain_knowledge": "domain_knowledge",
    "writer": "writer",
    "dec_writer": "writer",
    "spl_validate": "spl_validate",
    "security_review": "security_review",
    "dec_security": "security_review",
    "peer_review": "peer_review",
    "peer_review_2": "peer_review_2",
    "validate_final_plan": "validate_final_plan",
    "dec_validate": "validate_final_plan",
    "field_policy": "field_policy",
    "semantic_gate": "semantic_gate",
    "semantic_candidate_select": "semantic_candidate_select",
    "run_tool": "run_tool",
    "post_execution": "post_execution",
    "dec_evidence": "post_execution",
    "deterministic_evidence_pack": "evidence_review",
    "analyst_evidence_review": "evidence_review",
    "security_evidence_review": "evidence_review",
    "summarize": "summarize",
    "finalize": "finalize",
}


def _midpoint(
    layout: dict[str, dict[str, int]],
    from_id: str,
    to_id: str,
    *,
    offset_y: int = -14,
) -> dict[str, int]:
    fx = int(layout[from_id]["x"])
    fy = int(layout[from_id]["y"])
    tx = int(layout[to_id]["x"])
    ty = int(layout[to_id]["y"])
    return {"x": (fx + tx) // 2, "y": min(fy, ty) + offset_y}


def route_playbook_edge(
    layout: dict[str, dict[str, int]],
    from_id: str,
    to_id: str,
    *,
    anchor_from: str = "",
    anchor_to: str = "",
    channel_x: int | None = None,
    via_y: int | None = None,
) -> tuple[str, str, list[dict[str, int]]]:
    """Orthogonal lane routing between two playbook nodes."""
    fx = int(layout[from_id]["x"])
    fy = int(layout[from_id]["y"])
    tx = int(layout[to_id]["x"])
    ty = int(layout[to_id]["y"])
    dx = tx - fx
    dy = ty - fy
    if not anchor_from or not anchor_to:
        if abs(dy) > abs(dx) * 0.55:
            anchor_from = anchor_from or ("bottom" if dy > 0 else "top")
            anchor_to = anchor_to or ("top" if dy > 0 else "bottom")
        else:
            anchor_from = anchor_from or ("right" if dx > 0 else "left")
            anchor_to = anchor_to or ("left" if dx > 0 else "right")
    waypoints: list[dict[str, int]] = []
    if channel_x is not None:
        bus_y = via_y if via_y is not None else (fy + ty) // 2
        waypoints = [{"x": channel_x, "y": bus_y}]
    elif via_y is not None and fx != tx:
        waypoints = [{"x": fx, "y": via_y}, {"x": tx, "y": via_y}]
    elif fx != tx and fy != ty:
        mid_y = (fy + ty) // 2
        waypoints = [{"x": fx, "y": mid_y}, {"x": tx, "y": mid_y}]
    return anchor_from, anchor_to, waypoints


def _edge(
    layout: dict[str, dict[str, int]],
    from_id: str,
    to_id: str,
    branch: str = "trunk",
    *,
    label: str = "",
    label_short: str = "",
    profiles: list[str] | None = None,
    shortcut: bool = False,
    anchor_from: str = "",
    anchor_to: str = "",
    channel_x: int | None = None,
    via_y: int | None = None,
    waypoints: list[dict[str, int]] | None = None,
    label_at: dict[str, int] | None = None,
) -> dict[str, Any]:
    if waypoints is None:
        anchor_from, anchor_to, waypoints = route_playbook_edge(
            layout,
            from_id,
            to_id,
            anchor_from=anchor_from,
            anchor_to=anchor_to,
            channel_x=channel_x,
            via_y=via_y,
        )
    edge: dict[str, Any] = {
        "from": from_id,
        "to": to_id,
        "branch": branch,
        "anchor_from": anchor_from,
        "anchor_to": anchor_to,
    }
    if waypoints:
        edge["waypoints"] = waypoints
    if profiles:
        edge["profiles"] = profiles
    if shortcut:
        edge["shortcut"] = True
    if label:
        edge["label"] = label
        edge["label_short"] = label_short or label
        edge["label_at"] = label_at or _midpoint(layout, from_id, to_id)
    return edge


def _build_swimlane_edges(layout: dict[str, dict[str, int]]) -> list[dict[str, Any]]:
    """Build playbook edges with lane-routed waypoints."""
    edges: list[dict[str, Any]] = [
        _edge(layout, "ingest_question", "guardrail"),
        _edge(layout, "guardrail", "dec_guardrail"),
        _edge(
            layout,
            "dec_guardrail",
            "planner",
            label="Supported",
            label_short="Supported",
        ),
        _edge(
            layout,
            "dec_guardrail",
            "summarize",
            branch="blocked",
            label="Blocked",
            label_short="Blocked",
            shortcut=True,
            anchor_from="left",
            anchor_to="left",
            waypoints=[
                {"x": PLAYBOOK_PERIMETER_X, "y": BUS_SCOPE_GATE_Y},
                {"x": PLAYBOOK_PERIMETER_X, "y": BUS_FINISH_Y},
                {"x": layout["summarize"]["x"] - PLAYBOOK_PROCESS_W // 2, "y": BUS_FINISH_Y},
            ],
            label_at={"x": PLAYBOOK_PERIMETER_X, "y": (BUS_SCOPE_GATE_Y + BUS_FINISH_Y) // 2},
        ),
        _edge(layout, "planner", "field_bind"),
        _edge(layout, "field_bind", "field_discovery"),
        _edge(layout, "field_discovery", "field_strategy"),
        _edge(layout, "field_strategy", "domain_knowledge"),
        _edge(layout, "domain_knowledge", "writer"),
        _edge(
            layout,
            "writer",
            "dec_writer",
            anchor_from="bottom",
            anchor_to="top",
        ),
        _edge(
            layout,
            "dec_writer",
            "spl_validate",
            branch="operational",
            profiles=["operational"],
            label="Operational",
            label_short="Operational",
            anchor_from="bottom",
            anchor_to="top",
            via_y=800,
            label_at={"x": 570, "y": 790},
        ),
        _edge(
            layout,
            "dec_writer",
            "validate_final_plan",
            branch="metadata",
            profiles=["metadata"],
            label="Metadata",
            label_short="Metadata",
            anchor_from="bottom",
            anchor_to="top",
            waypoints=[
                {"x": LANE_CORE_X, "y": 800},
                {"x": LANE_META_X, "y": 800},
                {"x": LANE_META_X, "y": BUS_VALIDATE_Y - 55},
                {"x": LANE_MERGE_BUS_X, "y": BUS_VALIDATE_Y - 55},
            ],
            label_at={"x": LANE_META_X, "y": 790},
        ),
        _edge(
            layout,
            "dec_writer",
            "security_review",
            branch="security",
            profiles=["security"],
            label="Security",
            label_short="Security",
            anchor_from="bottom",
            anchor_to="top",
            via_y=800,
            label_at={"x": 1285, "y": 790},
        ),
        _edge(
            layout,
            "spl_validate",
            "validate_final_plan",
            branch="operational",
            profiles=["operational"],
            anchor_from="bottom",
            anchor_to="top",
            waypoints=[
                {"x": LANE_OP_X, "y": BUS_VALIDATE_Y - 55},
                {"x": LANE_MERGE_BUS_X, "y": BUS_VALIDATE_Y - 55},
            ],
        ),
        _edge(
            layout,
            "security_review",
            "dec_security",
            branch="security",
            profiles=["security"],
            anchor_from="bottom",
            anchor_to="top",
        ),
        _edge(
            layout,
            "dec_security",
            "validate_final_plan",
            branch="security",
            profiles=["security"],
            label="Approved",
            label_short="Approved",
            anchor_from="left",
            anchor_to="right",
            waypoints=[
                {"x": 1260, "y": BUS_SECURITY_GATE_Y},
                {"x": 1260, "y": BUS_VALIDATE_Y},
                {
                    "x": LANE_MERGE_BUS_X + PLAYBOOK_PROCESS_W // 2,
                    "y": BUS_VALIDATE_Y,
                },
            ],
            label_at={"x": 1210, "y": BUS_VALIDATE_Y - 12},
        ),
        _edge(
            layout,
            "dec_security",
            "peer_review",
            branch="security",
            profiles=["security"],
            label="Peer review",
            label_short="Peer review",
            anchor_from="bottom",
            anchor_to="top",
        ),
        _edge(
            layout,
            "peer_review",
            "peer_review_2",
            branch="security",
            profiles=["security"],
            anchor_from="bottom",
            anchor_to="top",
        ),
        _edge(
            layout,
            "peer_review_2",
            "validate_final_plan",
            branch="security",
            profiles=["security"],
            anchor_from="left",
            anchor_to="top",
            waypoints=[
                {"x": 1180, "y": BUS_PEER_REVIEW_2_Y},
                {"x": 1180, "y": BUS_VALIDATE_Y - 55},
                {"x": LANE_MERGE_BUS_X, "y": BUS_VALIDATE_Y - 55},
            ],
        ),
        _edge(
            layout,
            "validate_final_plan",
            "dec_validate",
            anchor_from="bottom",
            anchor_to="top",
        ),
        _edge(
            layout,
            "dec_validate",
            "field_policy",
            label="Approved",
            label_short="Approved",
            anchor_from="bottom",
            anchor_to="top",
            via_y=BUS_POLICY_Y - 48,
            label_at={"x": 585, "y": BUS_POLICY_Y - 58},
        ),
        _edge(layout, "field_policy", "semantic_gate"),
        _edge(layout, "semantic_gate", "semantic_candidate_select"),
        _edge(
            layout,
            "semantic_candidate_select",
            "run_tool",
            anchor_from="bottom",
            anchor_to="top",
            waypoints=[
                {"x": LANE_META_X, "y": BUS_RUN_TOOL_Y - 48},
                {"x": LANE_MERGE_BUS_X, "y": BUS_RUN_TOOL_Y - 48},
            ],
        ),
        _edge(
            layout,
            "dec_validate",
            "summarize",
            branch="blocked",
            shortcut=True,
            anchor_from="left",
            anchor_to="left",
            waypoints=[
                {"x": layout["dec_validate"]["x"] - PLAYBOOK_DECISION_R, "y": BUS_VALIDATE_Y},
                {"x": PLAYBOOK_PERIMETER_X, "y": BUS_VALIDATE_Y},
                {"x": PLAYBOOK_PERIMETER_X, "y": BUS_FINISH_Y},
                {"x": layout["summarize"]["x"] - PLAYBOOK_PROCESS_W // 2, "y": BUS_FINISH_Y},
            ],
        ),
        _edge(
            layout,
            "run_tool",
            "post_execution",
            anchor_from="bottom",
            anchor_to="top",
        ),
        _edge(
            layout,
            "post_execution",
            "dec_evidence",
            anchor_from="bottom",
            anchor_to="top",
        ),
        _edge(
            layout,
            "dec_evidence",
            "deterministic_evidence_pack",
            branch="metadata",
            profiles=["metadata"],
            label="Metadata",
            label_short="Metadata",
            anchor_from="bottom",
            anchor_to="top",
            via_y=BUS_EVIDENCE_Y - 52,
            label_at={"x": 1000, "y": BUS_EVIDENCE_Y - 62},
        ),
        _edge(
            layout,
            "dec_evidence",
            "analyst_evidence_review",
            branch="operational",
            profiles=["operational"],
            label="Operational",
            label_short="Operational",
            anchor_from="bottom",
            anchor_to="top",
            via_y=BUS_EVIDENCE_Y - 52,
            label_at={"x": 690, "y": BUS_EVIDENCE_Y - 62},
        ),
        _edge(
            layout,
            "dec_evidence",
            "security_evidence_review",
            branch="security",
            profiles=["security"],
            label="Security",
            label_short="Security",
            anchor_from="bottom",
            anchor_to="top",
            via_y=BUS_EVIDENCE_Y - 52,
            label_at={"x": 1290, "y": BUS_EVIDENCE_Y - 62},
        ),
        _edge(
            layout,
            "deterministic_evidence_pack",
            "summarize",
            branch="metadata",
            profiles=["metadata"],
            anchor_from="bottom",
            anchor_to="top",
            waypoints=[
                {"x": LANE_META_X, "y": PLAYBOOK_FINISH_MERGE_Y},
                {"x": LANE_MERGE_BUS_X, "y": PLAYBOOK_FINISH_MERGE_Y},
            ],
        ),
        _edge(
            layout,
            "analyst_evidence_review",
            "summarize",
            branch="operational",
            profiles=["operational"],
            anchor_from="bottom",
            anchor_to="top",
            waypoints=[
                {"x": LANE_OP_X, "y": PLAYBOOK_FINISH_MERGE_Y},
                {"x": LANE_MERGE_BUS_X, "y": PLAYBOOK_FINISH_MERGE_Y},
            ],
        ),
        _edge(
            layout,
            "security_evidence_review",
            "summarize",
            branch="security",
            profiles=["security"],
            anchor_from="bottom",
            anchor_to="top",
            waypoints=[
                {"x": LANE_SEC_X, "y": PLAYBOOK_FINISH_MERGE_Y},
                {"x": LANE_MERGE_BUS_X, "y": PLAYBOOK_FINISH_MERGE_Y},
            ],
        ),
        _edge(
            layout,
            "summarize",
            "finalize",
            anchor_from="bottom",
            anchor_to="top",
        ),
    ]
    return edges


PLAYBOOK_EDGES: list[dict[str, Any]] = _build_swimlane_edges(PLAYBOOK_LAYOUT)


# Visual decision gates map to LangGraph conditional source nodes for topology checks.
PLAYBOOK_DECISION_SOURCES: dict[str, str] = {
    "dec_guardrail": "guardrail",
    "dec_writer": "writer",
    "dec_security": "security_review",
    "dec_validate": "validate_final_plan",
    "dec_evidence": "post_execution",
}

# Edges that exist only for visual grouping (process -> its decision diamond).
PLAYBOOK_VISUAL_TRUNK_EDGES: set[tuple[str, str]] = {
    ("guardrail", "dec_guardrail"),
    ("writer", "dec_writer"),
    ("security_review", "dec_security"),
    ("validate_final_plan", "dec_validate"),
    ("post_execution", "dec_evidence"),
}


def playbook_topology_from_build_graph() -> list[dict[str, Any]]:
    """Expected LangGraph routing edges for overlay topology validation."""
    return [
        {"from": "ingest_question", "to": "guardrail", "branch": "trunk"},
        {"from": "guardrail", "to": "planner", "label": "Supported", "branch": "trunk"},
        {"from": "guardrail", "to": "summarize", "label": "Blocked", "branch": "blocked"},
        {"from": "planner", "to": "field_bind", "branch": "trunk"},
        {"from": "field_bind", "to": "field_discovery", "branch": "trunk"},
        {"from": "field_discovery", "to": "field_strategy", "branch": "trunk"},
        {"from": "field_strategy", "to": "domain_knowledge", "branch": "trunk"},
        {"from": "domain_knowledge", "to": "writer", "branch": "trunk"},
        {"from": "writer", "to": "spl_validate", "label": "Operational", "branch": "operational", "profiles": ["operational"]},
        {"from": "writer", "to": "validate_final_plan", "label": "Metadata", "branch": "metadata", "profiles": ["metadata"]},
        {"from": "writer", "to": "security_review", "label": "Security", "branch": "security", "profiles": ["security"]},
        {"from": "spl_validate", "to": "validate_final_plan", "branch": "operational", "profiles": ["operational"]},
        {"from": "security_review", "to": "validate_final_plan", "label": "Approved", "branch": "security", "profiles": ["security"]},
        {"from": "security_review", "to": "peer_review", "label": "Peer review", "branch": "security", "profiles": ["security"]},
        {"from": "peer_review", "to": "peer_review_2", "branch": "security", "profiles": ["security"]},
        {"from": "peer_review_2", "to": "validate_final_plan", "branch": "security", "profiles": ["security"]},
        {"from": "validate_final_plan", "to": "field_policy", "label": "Approved", "branch": "trunk"},
        {"from": "validate_final_plan", "to": "summarize", "branch": "blocked"},
        {"from": "field_policy", "to": "semantic_gate", "branch": "trunk"},
        {"from": "semantic_gate", "to": "semantic_candidate_select", "branch": "trunk"},
        {"from": "semantic_candidate_select", "to": "run_tool", "branch": "trunk"},
        {"from": "run_tool", "to": "post_execution", "branch": "trunk"},
        {"from": "post_execution", "to": "deterministic_evidence_pack", "label": "Metadata", "branch": "metadata", "profiles": ["metadata"]},
        {"from": "post_execution", "to": "analyst_evidence_review", "label": "Operational", "branch": "operational", "profiles": ["operational"]},
        {"from": "post_execution", "to": "security_evidence_review", "label": "Security", "branch": "security", "profiles": ["security"]},
        {"from": "deterministic_evidence_pack", "to": "summarize", "branch": "metadata", "profiles": ["metadata"]},
        {"from": "analyst_evidence_review", "to": "summarize", "branch": "operational", "profiles": ["operational"]},
        {"from": "security_evidence_review", "to": "summarize", "branch": "security", "profiles": ["security"]},
        {"from": "summarize", "to": "finalize", "branch": "trunk"},
    ]


def _visual_edge_to_langgraph(edge: dict[str, Any]) -> tuple[str, str]:
    from_id = str(edge["from"])
    to_id = str(edge["to"])
    if (from_id, to_id) in PLAYBOOK_VISUAL_TRUNK_EDGES:
        return ("", "")
    lang_from = PLAYBOOK_DECISION_SOURCES.get(from_id, from_id)
    lang_to = PLAYBOOK_DECISION_SOURCES.get(to_id, to_id)
    return lang_from, lang_to


def playbook_visual_edges_match_topology() -> bool:
    """Return True when every non-visual-trunk overlay edge maps to build_graph routing."""
    expected_keys: set[tuple[str, str, str]] = set()
    for item in playbook_topology_from_build_graph():
        label = str(item.get("label") or "").strip()
        profiles = tuple(item.get("profiles") or [])
        expected_keys.add((str(item["from"]), str(item["to"]), label))
        if profiles:
            expected_keys.add((str(item["from"]), str(item["to"]), label))

    seen: set[tuple[str, str, str]] = set()
    for edge in PLAYBOOK_EDGES:
        pair = _visual_edge_to_langgraph(edge)
        if not pair[0]:
            continue
        label = str(edge.get("label") or "").strip()
        key = (pair[0], pair[1], label)
        seen.add(key)
    for item in playbook_topology_from_build_graph():
        label = str(item.get("label") or "").strip()
        key = (str(item["from"]), str(item["to"]), label)
        if key not in seen and not label:
            # Unlabeled trunk edges
            if (str(item["from"]), str(item["to"]), "") not in seen:
                bare = (str(item["from"]), str(item["to"]), "")
                if bare not in seen:
                    return False
        elif label and key not in seen:
            return False
    return True


def assert_playbook_topology() -> None:
    """Raise AssertionError when overlay edges diverge from LangGraph routing."""
    expected: dict[tuple[str, str], dict[str, Any]] = {}
    for item in playbook_topology_from_build_graph():
        key = (str(item["from"]), str(item["to"]))
        expected[key] = item

    mapped: dict[tuple[str, str], dict[str, Any]] = {}
    for edge in PLAYBOOK_EDGES:
        lang_from, lang_to = _visual_edge_to_langgraph(edge)
        if not lang_from:
            continue
        key = (lang_from, lang_to)
        mapped[key] = edge

    missing = [key for key in expected if key not in mapped]
    if missing:
        raise AssertionError(f"playbook overlay missing LangGraph edges: {missing[:5]}")

    forbidden = [
        edge
        for edge in PLAYBOOK_EDGES
        if edge.get("from") == "writer" and edge.get("to") == "spl_validate"
    ]
    if len(forbidden) > 0:
        raise AssertionError("writer must not connect directly to spl_validate; use dec_writer")

    loop_back = [
        edge
        for edge in PLAYBOOK_EDGES
        if edge.get("from") == "dec_security" and edge.get("to") == "security_review"
    ]
    if loop_back:
        raise AssertionError("dec_security must not loop back to security_review")


assert_playbook_topology()

# Inline SVG path data (24×24 viewBox) for playbook flowchart node badges — no emoji.
PLAYBOOK_NODE_ICONS: dict[str, str] = {
    "ingest_question": "M19 9h-4V3H9v6H5l7 7 7-7zM5 18v2h14v-2H5z",
    "guardrail": "M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z",
    "dec_guardrail": "M12 8c-2.21 0-4 1.79-4 4s1.79 4 4 4 4-1.79 4-4-1.79-4-4-4zm8.94 3A8.994 8.994 0 0013 3.06V1h-2v2.06A8.994 8.994 0 003.06 11H1v2h2.06A8.994 8.994 0 0011 20.94V23h2v-2.06A8.994 8.994 0 0020.94 13H23v-2h-2.06z",
    "planner": "M19 3h-4.18C14.4 1.84 13.3 1 12 1c-1.3 0-2.4.84-2.82 2H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm-7 0c.55 0 1 .45 1 1s-.45 1-1 1-1-.45-1-1 .45-1 1-1zm2 14H7v-2h7v2zm3-4H7v-2h10v2zm0-4H7V7h10v2z",
    "field_bind": "M3.9 12c0-1.71 1.39-3.1 3.1-3.1h4V7H7c-2.76 0-5 2.24-5 5s2.24 5 5 5h4v-1.9H7c-1.71 0-3.1-1.39-3.1-3.1zM8 13h8v-2H8v2zm9-6h-4v1.9h4c1.71 0 3.1 1.39 3.1 3.1s-1.39 3.1-3.1 3.1h-4V17h4c2.76 0 5-2.24 5-5s-2.24-5-5-5z",
    "field_discovery": "M15.5 14h-.79l-.28-.27A6.471 6.471 0 0016 9.5 6.5 6.5 0 109.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C8.01 14 6 11.99 6 9.5S8.01 5 10.5 5 15 7.01 15 9.5 12.99 14 10.5 14z",
    "field_strategy": "M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 18c-4.41 0-8-3.59-8-8s3.59-8 8-8 8 3.59 8 8-3.59 8-8 8zm.5-13H11v6l5.25 3.15.75-1.23-4.5-2.67z",
    "domain_knowledge": "M12 3L2 8.5l10 5.5 8.5-4.68V17h2V8.5L12 3zM6 13.18v4.34L12 21l6-3.48v-4.34L12 16.5l-6-3.32z",
    "writer": "M9.4 16.6L4.8 12l4.6-4.6L8 6l-6 6 6 6 1.4-1.4zm5.2 0l4.6-4.6-4.6-4.6L16 6l6 6-6 6-1.4-1.4z",
    "dec_writer": "M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z",
    "spl_validate": "M15.5 14h-.79l-.28-.27A6.471 6.471 0 0016 9.5 6.5 6.5 0 109.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C8.01 14 6 11.99 6 9.5S8.01 5 10.5 5 15 7.01 15 9.5 12.99 14 10.5 14z",
    "security_review": "M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z",
    "dec_security": "M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z",
    "peer_review": "M16 11c1.66 0 2.99-1.34 2.99-3S17.66 5 16 5c-1.66 0-3 1.34-3 3s1.34 3 3 3zm-8 0c1.66 0 2.99-1.34 2.99-3S9.66 5 8 5C6.34 5 5 6.34 5 8s1.34 3 3 3zm0 2c-2.33 0-7 1.17-7 3.5V19h14v-2.5c0-2.33-4.67-3.5-7-3.5z",
    "peer_review_2": "M16 11c1.66 0 2.99-1.34 2.99-3S17.66 5 16 5c-1.66 0-3 1.34-3 3s1.34 3 3 3zm-8 0c1.66 0 2.99-1.34 2.99-3S9.66 5 8 5C6.34 5 5 6.34 5 8s1.34 3 3 3zm0 2c-2.33 0-7 1.17-7 3.5V19h14v-2.5c0-2.33-4.67-3.5-7-3.5z",
    "validate_final_plan": "M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-2 15l-4-4 1.41-1.41L10 14.17l6.59-6.59L18 9l-8 8z",
    "dec_validate": "M4.25 5.61C6.27 8.2 10 13 10 13v6c0 .55.45 1 1 1h2c.55 0 1-.45 1-1v-6s3.72-4.8 5.74-7.39C20.25 4.95 19.08 4 18 4H6c-1.08 0-2.25.95-1.75 1.61z",
    "field_policy": "M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z",
    "semantic_gate": "M19.35 10.04A7.49 7.49 0 0012 4C9.11 4 6.6 5.64 5.35 8.04A6 6 0 000 14a6 6 0 006 6h13a5 5 0 005-5c0-2.64-2.05-4.78-4.65-4.96zM14 13v4h-4v-4H7l5-5 5 5h-3z",
    "semantic_candidate_select": "M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-2 15l-4-4 1.41-1.41L10 14.17l6.59-6.59L18 9l-8 8z",
    "run_tool": "M20 4H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V6c0-1.1-.9-2-2-2zm-2 12H6v-2h12v2zm-3.5-5L6 9.25V7.28L13.62 10 6 12.72V10.75l8.5-2.75z",
    "post_execution": "M10 4H4c-1.1 0-1.99.9-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2h-8l-2-2zm2 13l-4-4 1.41-1.41L11 14.17l4.59-4.59L17 11l-5 6z",
    "dec_evidence": "M15.5 14h-.79l-.28-.27A6.471 6.471 0 0016 9.5 6.5 6.5 0 109.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C8.01 14 6 11.99 6 9.5S8.01 5 10.5 5 15 7.01 15 9.5 12.99 14 10.5 14z",
    "deterministic_evidence_pack": "M10 4H4c-1.1 0-1.99.9-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2h-8l-2-2z",
    "analyst_evidence_review": "M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z",
    "security_evidence_review": "M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-2 15l-4-4 1.41-1.41L10 14.17l6.59-6.59L18 9l-8 8z",
    "summarize": "M14 2H6c-1.1 0-2 .9-2 2v16c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V8l-6-6zm2 16H8v-2h8v2zm0-4H8v-2h8v2zm-3-5V3.5L18.5 9H13z",
    "finalize": "M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z",
}



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
    """Named overlay layout presets; canonical remains the runtime default.

    Historical variant-a/b/c comparison layouts were retired once the grounding
    and policy node chains were added to the canonical spine — maintaining three
    fully hand-tuned alternate layouts in lockstep with every new playbook node
    is not worth the upkeep now that canonical has been settled on as the
    runtime default. See git history for the retired variants if a future
    layout exploration needs a starting point.
    """
    canonical_layout = copy.deepcopy(PLAYBOOK_LAYOUT)
    canonical_edges = copy.deepcopy(PLAYBOOK_EDGES)
    presets: dict[str, dict[str, Any]] = {
        "canonical": {"layout": canonical_layout, "edges": canonical_edges},
    }
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
# Every LangGraph node with its own tracked duration gets its own bucket so the
# right rail and playbook overlay show honest, non-aggregated timing per stage.
JOURNEY_TIMING_MS_KEYS: dict[str, list[str]] = {
    "guardrail": ["guardrail"],
    "planner": ["planner"],
    "field_bind": ["field_bind"],
    "field_discovery": ["field_discovery"],
    "field_strategy": ["field_strategy"],
    "domain_knowledge": ["domain_knowledge"],
    "writer": ["writer"],
    "spl_validate": ["spl_validate"],
    "security_review": ["security_review"],
    "peer_review": ["peer_review_1"],
    "peer_review_2": ["peer_review_2"],
    "validate_final_plan": ["validation"],
    "field_policy": ["field_policy"],
    "semantic_gate": ["semantic_gate"],
    "semantic_candidate_select": ["semantic_candidate_select"],
    "run_tool": ["run_tool"],
    "post_execution": ["post_execution"],
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
    # Field binding performs optional semantic domain retrieval with the
    # configured embedding model. The model row is omitted when that index is
    # unavailable, so the UI still falls back to Idle for deterministic-only runs.
    "field_bind": "grounding",
    "field_discovery": "",
    "field_strategy": "",
    "domain_knowledge": "",
    "writer": "writer",
    "spl_validate": "analyst",
    "security_review": "security",
    "peer_review": "peers",
    "peer_review_2": "peers",
    "validate_final_plan": "",
    "field_policy": "",
    "semantic_gate": "",
    "semantic_candidate_select": "",
    "run_tool": "",
    "post_execution": "",
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
    "field_bind": "field_bind",
    "field_discovery": "field_discovery",
    "field_strategy": "field_strategy",
    "domain_knowledge": "domain_knowledge",
    "query_writer": "writer",
    "writer": "writer",
    "spl_writer": "writer",
    "spl_validate": "spl_validate",
    "security_reviewer": "security_review",
    "reviewer": "security_review",
    "peer_reviewer": "peer_review",
    "peer_reviewer_1": "peer_review",
    "peer_reviewer_2": "peer_review_2",
    "peer_review_1": "peer_review",
    "peer_review_2": "peer_review_2",
    "validation": "validate_final_plan",
    "validate_final_plan": "validate_final_plan",
    "field_policy": "field_policy",
    "semantic_gate": "semantic_gate",
    "semantic_candidate_select": "semantic_candidate_select",
    "execution": "run_tool",
    "run_tool": "run_tool",
    "post_execution": "post_execution",
    "evidence_review": "evidence_review",
    "analyst_evidence_review": "evidence_review",
    "security_evidence_review": "evidence_review",
    "deterministic_evidence_pack": "evidence_review",
    "summary": "summarize",
    "summarize": "summarize",
    "finalize": "finalize",
    "package_response": "package_response",
}

JOURNEY_NODE_IDS: frozenset[str] = frozenset(step["node"] for step in JOURNEY_UI_STEPS)

# LangGraph node id -> duration field written by that node (stream update delta).
GRAPH_NODE_DURATION_FIELDS: dict[str, str] = {
    "guardrail": "guardrail_duration_ms",
    "planner": "planner_duration_ms",
    "field_bind": "field_bind_duration_ms",
    "field_discovery": "field_discovery_duration_ms",
    "field_strategy": "field_strategy_duration_ms",
    "domain_knowledge": "domain_knowledge_duration_ms",
    "writer": "writer_duration_ms",
    "spl_validate": "spl_validate_duration_ms",
    "security_review": "security_review_duration_ms",
    "peer_review": "peer_review_duration_ms",
    "peer_review_2": "peer_review_2_duration_ms",
    "validate_final_plan": "validation_duration_ms",
    "field_policy": "field_policy_duration_ms",
    "semantic_gate": "semantic_gate_duration_ms",
    "semantic_candidate_select": "semantic_candidate_duration_ms",
    "run_tool": "run_tool_duration_ms",
    "post_execution": "post_execution_duration_ms",
    "analyst_evidence_review": "evidence_review_duration_ms",
    "security_evidence_review": "evidence_review_duration_ms",
    "deterministic_evidence_pack": "evidence_review_duration_ms",
    "evidence_review": "evidence_review_duration_ms",
    "summarize": "summarize_duration_ms",
    "finalize": "finalize_duration_ms",
}


def journey_node_for_graph_node(node_id: str) -> str:
    """Map a LangGraph node id to the runtime-rail journey step id (if any)."""
    key = str(node_id or "").strip()
    if not key or key == "ingest_question":
        return ""
    if key in JOURNEY_NODE_IDS:
        return key
    mapped = WORKFLOW_STAGE_TO_JOURNEY_NODE.get(key, "")
    if mapped in JOURNEY_NODE_IDS:
        return mapped
    return ""


def graph_node_duration_ms(node_id: str, node_delta: dict[str, Any] | None) -> int:
    """Read measured node duration from a LangGraph stream update delta."""
    key = str(node_id or "").strip()
    if not key or not isinstance(node_delta, dict):
        return 0
    field = GRAPH_NODE_DURATION_FIELDS.get(key, "")
    if field and field in node_delta:
        return max(0, int(node_delta.get(field, 0) or 0))
    return 0


def _display_spl_for_tool_plan(selected_tool: str, tool_args: dict[str, Any]) -> str:
    """Human-readable SPL for UI when only MCP tool metadata is available."""
    args = tool_args if isinstance(tool_args, dict) else {}
    query = str(args.get("query", "")).strip()
    if query:
        return query
    tool = str(selected_tool or "").strip()
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


def executed_spl_from_result(result: dict[str, Any] | None) -> str:
    """Resolve the SPL (or MCP tool equivalent) that was actually dispatched."""
    if not isinstance(result, dict):
        return ""
    generated = str(result.get("generated_spl", "")).strip()
    if generated:
        return generated
    query_args = result.get("query_args", {}) if isinstance(result.get("query_args"), dict) else {}
    query = str(query_args.get("query", "")).strip()
    if query:
        return query
    details = result.get("selected_spl_details", [])
    if isinstance(details, list):
        for item in reversed(details):
            if not isinstance(item, dict):
                continue
            detail_query = str(item.get("query", "")).strip()
            if detail_query:
                return detail_query
    evidence = result.get("evidence", {}) if isinstance(result.get("evidence"), dict) else {}
    query_or_args = evidence.get("query_or_args", {}) if isinstance(evidence.get("query_or_args"), dict) else {}
    query = str(query_or_args.get("query", "")).strip()
    if query:
        return query
    adjudication = result.get("final_adjudication", {}) if isinstance(result.get("final_adjudication"), dict) else {}
    selected_args = adjudication.get("selected_args", {}) if isinstance(adjudication.get("selected_args"), dict) else {}
    query = str(selected_args.get("query", "")).strip()
    if query:
        return query
    for key in ("query_writer_output", "writer_output"):
        writer = result.get(key, {}) if isinstance(result.get(key), dict) else {}
        tool_args = writer.get("tool_args", {}) if isinstance(writer.get("tool_args"), dict) else {}
        query = str(tool_args.get("query", "")).strip()
        if query:
            return query
    selected_tool = str(result.get("selected_tool", "")).strip()
    plan_args = query_args or query_or_args or selected_args
    if not isinstance(plan_args, dict):
        plan_args = {}
    return _display_spl_for_tool_plan(selected_tool, plan_args)


def journey_timings_ms_from_result(result: dict[str, Any] | None) -> dict[str, int]:
    """Return per journey-step durations in ms from a completed investigation payload."""
    if not isinstance(result, dict):
        return {}
    timings: dict[str, int] = {}
    node_timings = result.get("node_timings_ms")
    if isinstance(node_timings, dict) and node_timings:
        for step in JOURNEY_UI_STEPS:
            node = str(step.get("node", "")).strip()
            keys = JOURNEY_TIMING_MS_KEYS.get(node, [node])
            present_keys = [key for key in keys if key in node_timings]
            if present_keys:
                timings[node] = sum(int(node_timings.get(key, 0) or 0) for key in present_keys)

    logs = result.get("stage_logs")
    totals: dict[str, int] = {}
    if isinstance(logs, list):
        for entry in logs:
            if not isinstance(entry, dict):
                continue
            stage = str(entry.get("stage", "")).strip()
            journey_node = WORKFLOW_STAGE_TO_JOURNEY_NODE.get(stage, "")
            if not journey_node:
                continue
            totals[journey_node] = totals.get(journey_node, 0) + int(
                entry.get("duration_ms", 0) or 0
            )
    for node, total_ms in totals.items():
        if node not in timings or timings[node] <= 0:
            timings[node] = total_ms
    return timings


def journey_completion_from_workflow(workflow: list[dict[str, Any]] | None) -> tuple[str, int]:
    """Legacy helper — do not treat model_workflow catalog as executed stages."""
    if not workflow:
        return "", -1
    return "", -1


# LangGraph journey nodes bypassed by MCP Chat deterministic (template + MCP tool) runs.
MCP_DETERMINISTIC_JOURNEY_SKIP: frozenset[str] = frozenset(
    {
        "guardrail",
        "planner",
        "field_bind",
        "field_discovery",
        "field_strategy",
        "domain_knowledge",
        "spl_validate",
        "security_review",
        "peer_review",
        "peer_review_2",
        "validate_final_plan",
        "field_policy",
        "semantic_gate",
        "semantic_candidate_select",
        "post_execution",
        "evidence_review",
        "summarize",
        "finalize",
    }
)


def _writer_path_mode_from_result(result: dict[str, Any]) -> str:
    logs = result.get("stage_logs")
    if isinstance(logs, list):
        for entry in reversed(logs):
            if not isinstance(entry, dict):
                continue
            stage = str(entry.get("stage", "")).strip()
            if stage not in {"writer", "query_writer", "spl_writer"}:
                continue
            model = str(entry.get("model", "")).strip().lower()
            if model == "saved_query_library":
                return "library"
            if model == "deterministic_spl_plan_compiler":
                return "deterministic"
    writer = result.get("query_writer_output", {})
    if not isinstance(writer, dict):
        writer = result.get("writer_output", {}) if isinstance(result.get("writer_output"), dict) else {}
    source = str(writer.get("source", "")).strip().lower()
    if source == "saved_query_library" or str(writer.get("reason", "")).startswith("saved_query_library"):
        return "library"
    if source in {
        "domain_knowledge",
        "writer_template_bypass",
        "writer_template_fallback",
        "writer_bypass",
        "validated_bound_analytical_plan",
        "environment_profile_index_activity",
    }:
        return "deterministic"
    if source:
        return "llm"
    return ""


def journey_rail_state_from_result(
    result: dict[str, Any] | None,
    *,
    pipeline_effective: str = "",
    spl_run_time_ms: int | None = None,
    run_wall_ms: int | None = None,
    packaging_skipped: bool = False,
    packaging_duration_ms: int = 0,
) -> dict[str, Any]:
    """Honest runtime-rail snapshot: which stages ran, were skipped, and how long."""
    if not isinstance(result, dict):
        result = {}
    pipeline = str(pipeline_effective or "").strip().lower()
    meta_pipeline = str((result.get("meta") or {}).get("pipeline", "")).strip().lower() if isinstance(result.get("meta"), dict) else ""
    node_timings = result.get("node_timings_ms")
    stage_logs = result.get("stage_logs")
    has_graph_trace = (
        (isinstance(node_timings, dict) and bool(node_timings))
        or (isinstance(stage_logs, list) and bool(stage_logs))
    )
    short_path = pipeline == "deterministic" or meta_pipeline == "mcp_direct" or (
        not has_graph_trace and str(result.get("selected_tool", "")).strip().startswith("splunk_get_")
    )

    skipped: set[str] = set()
    for raw in result.get("skipped_nodes") or []:
        node = str(raw or "").strip()
        if node:
            skipped.add(node)
    profile = str(result.get("review_profile", "")).strip()
    for node in skipped_nodes_for_profile(profile):
        skipped.add(node)
    if packaging_skipped:
        skipped.add("package_response")

    timings = journey_timings_ms_from_result(result)
    completed: set[str] = set()
    if short_path:
        skipped.update(MCP_DETERMINISTIC_JOURNEY_SKIP)
        run_ms = int(spl_run_time_ms or run_wall_ms or 0)
        completed.update({"writer", "run_tool"})
        timings.setdefault("writer", 0)
        timings["run_tool"] = run_ms
        if not packaging_skipped:
            completed.add("package_response")
            if packaging_duration_ms > 0:
                timings["package_response"] = int(packaging_duration_ms)
        writer_path = "deterministic"
    else:
        writer_path = _writer_path_mode_from_result(result)
        log_nodes: set[str] = set()
        if isinstance(stage_logs, list):
            for entry in stage_logs:
                if not isinstance(entry, dict):
                    continue
                stage = str(entry.get("stage", "")).strip()
                mapped = WORKFLOW_STAGE_TO_JOURNEY_NODE.get(stage, "")
                if mapped:
                    log_nodes.add(mapped)
        for step in JOURNEY_UI_STEPS:
            node = str(step.get("node", "")).strip()
            if not node or node in skipped:
                continue
            ms = int(timings.get(node, -1))
            if ms >= 0 and (ms > 0 or node in log_nodes):
                completed.add(node)
        if "run_tool" not in completed and int(timings.get("run_tool", 0) or 0) > 0:
            completed.add("run_tool")
        if not packaging_skipped and packaging_duration_ms > 0:
            completed.add("package_response")
            timings.setdefault("package_response", int(packaging_duration_ms))

    completed -= skipped
    ordered_completed = [
        str(step.get("node", "")).strip()
        for step in JOURNEY_UI_STEPS
        if str(step.get("node", "")).strip() in completed
    ]
    ordered_skipped = [
        str(step.get("node", "")).strip()
        for step in JOURNEY_UI_STEPS
        if str(step.get("node", "")).strip() in skipped
    ]
    completed_through = -1
    for node in ordered_completed + ordered_skipped:
        idx = journey_step_index(node)
        if idx >= 0:
            completed_through = max(completed_through, idx)

    return {
        "short_path": short_path,
        "writer_path_mode": writer_path,
        "completed_nodes": ordered_completed,
        "skipped_nodes": ordered_skipped,
        "timings_ms": {
            node: int(timings[node] or 0)
            for node in ordered_completed
            if node in timings
        },
        "completed_through": completed_through,
    }


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
        "phase": "complete",
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
