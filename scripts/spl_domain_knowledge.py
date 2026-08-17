#!/usr/bin/env python3
"""SPL domain knowledge: pattern oracles, tool routing, and anti-pattern guards."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from minimal_question_to_answer import map_question_to_template, template_to_query_args
from query_templates import question_requests_cardinality

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PATTERNS_PATH = PROJECT_ROOT / "artifacts" / "knowledge" / "spl_domain_patterns.json"

# Seed patterns used when artifact is missing or as merge base during build.
BUILTIN_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "index_count_cardinality",
        "intent": "top_indexes",
        "triggers": ["how many indexes", "number of indexes", "count of indexes", "total indexes"],
        "trigger_regex": [r"\b(?:how many|number of|count of|total number of)\s+indexes?\b"],
        "preferred_tool": "splunk_run_query",
        "query_template": "search index=* NOT index=_* | stats dc(index) as index_count",
        "anti_patterns": [r"\|\s*stats\s+count\s*$", r"\|\s*stats\s+count\s*\|"],
        "explanation": "Count distinct indexes (dc/index or metadata tool), not total events.",
        "tags": ["inventory", "cardinality"],
        "priority": 100,
    },
    {
        "id": "index_inventory_list",
        "intent": "top_indexes",
        "triggers": ["list indexes", "show indexes", "what indexes", "indexes i can access", "which indexes do i"],
        "preferred_tool": "splunk_get_indexes",
        "query_template": "",
        "anti_patterns": [r"\|\s*stats\s+count\s*$"],
        "explanation": "Pure index inventory uses splunk_get_indexes metadata, not event totals.",
        "tags": ["inventory"],
        "priority": 95,
    },
    {
        "id": "index_volume_ranking",
        "intent": "top_indexes",
        "triggers": ["busiest indexes", "most events", "top indexes", "indexes had the most", "indexes have data"],
        "preferred_tool": "splunk_run_query",
        "query_template": "search index=* NOT index=_* | stats count by index | sort - count",
        "anti_patterns": [r"\|\s*stats\s+count\s*$"],
        "explanation": "Rank indexes by event volume with stats count by index.",
        "tags": ["inventory", "top_n"],
        "priority": 80,
    },
    {
        "id": "sourcetype_count_cardinality",
        "intent": "index_sourcetype_volume",
        "triggers": ["how many sourcetypes", "number of sourcetypes", "count of sourcetypes"],
        "trigger_regex": [r"\b(?:how many|number of|count of)\s+sourcetypes?\b"],
        "preferred_tool": "splunk_run_query",
        "query_template": "search index=* NOT index=_* | stats dc(sourcetype) as sourcetype_count",
        "anti_patterns": [r"\|\s*stats\s+count\s*$"],
        "explanation": "Count distinct sourcetypes with dc(sourcetype).",
        "tags": ["inventory", "cardinality"],
        "priority": 90,
    },
    {
        "id": "sourcetype_volume_by_index",
        "intent": "index_sourcetype_volume",
        "triggers": ["sourcetypes by index", "top sourcetypes", "sourcetype volume"],
        "preferred_tool": "splunk_run_query",
        "query_template": "search index=* NOT index=_* | stats count by index sourcetype | sort - count",
        "anti_patterns": [],
        "explanation": "Break down sourcetype volume per index.",
        "tags": ["inventory"],
        "priority": 75,
    },
    {
        "id": "internal_audit_auth_failures",
        "intent": "internal_auth_failures",
        "triggers": ["_audit auth", "audittrail", "audit auth failure", "splunk audit failure"],
        "trigger_regex": [r"\b_?audit\b.*\b(fail|failure|failed)\b", r"\baudittrail\b.*\b(fail|failure|failed)\b"],
        "preferred_tool": "splunk_run_query",
        "query_template": "search index=_audit sourcetype=audittrail info=failed | stats count by host user src | sort - count",
        "anti_patterns": [r"\|\s*rest\s", r"index=\*(?!.*_audit)"],
        "explanation": "Splunk audit auth failures use index=_audit sourcetype=audittrail info=failed.",
        "tags": ["platform_ops", "audit"],
        "priority": 92,
    },
    {
        "id": "splunk_internal_volume",
        "intent": "splunk_internal_health",
        "triggers": ["splunk internal", "internal sourcetype", "_internal"],
        "preferred_tool": "splunk_run_query",
        "query_template": "search index=_internal | stats count by sourcetype | sort - count",
        "anti_patterns": [r"index=\*(?!.*_internal)", r"\|\s*table\s+sourcetype", r"\|\s*stats\s+count\s+by\s+source\b"],
        "explanation": "Splunk platform health queries must scope index=_internal.",
        "tags": ["platform_ops"],
        "priority": 85,
    },
    {
        "id": "internal_scheduler_activity",
        "intent": "splunk_internal_health",
        "triggers": ["scheduler activity", "scheduler", "search scheduler"],
        "trigger_regex": [r"\bscheduler\b.*\b(?:activity|volume|health)\b"],
        "preferred_tool": "splunk_run_query",
        "query_template": "search index=_internal sourcetype=scheduler | stats count by host | sort - count",
        "anti_patterns": [r"index=\*(?!.*_internal)", r"sourcetype=splunkd"],
        "explanation": "Scheduler telemetry lives in _internal sourcetype=scheduler.",
        "tags": ["platform_ops", "scheduler"],
        "priority": 90,
    },
    {
        "id": "internal_splunkd_health",
        "intent": "internal_splunkd_health",
        "triggers": ["splunkd volume", "splunkd health", "splunkd errors", "splunkd component"],
        "trigger_regex": [r"\bsplunkd\b.*\b(?:volume|health|error|component|activity)\b"],
        "preferred_tool": "splunk_run_query",
        "query_template": "search index=_internal sourcetype=splunkd | stats count by host component | sort - count",
        "anti_patterns": [r"index=\*(?!.*_internal)", r"sourcetype=scheduler"],
        "explanation": "Splunkd diagnostics use index=_internal sourcetype=splunkd with host/component breakdown.",
        "tags": ["platform_ops", "splunkd"],
        "priority": 91,
    },
    {
        "id": "internal_sourcetype_inventory",
        "intent": "internal_sourcetypes",
        "triggers": ["internal sourcetype", "sourcetypes in _internal", "list sourcetype"],
        "trigger_regex": [r"\b_?internal\b.*\bsourcetype"],
        "preferred_tool": "splunk_run_query",
        "query_template": "search index=_internal | stats count by sourcetype | sort - count",
        "anti_patterns": [r"stats\s+count\s+by\s+index\b", r"\|\s*stats\s+count\s+by\s+source\b", r"index=\*(?!.*_internal)"],
        "explanation": "Internal sourcetype inventory uses index=_internal with stats by sourcetype.",
        "tags": ["platform_ops", "inventory"],
        "priority": 93,
    },
    {
        "id": "forwarder_connectivity",
        "intent": "forwarder_connectivity",
        "triggers": ["forwarder", "deployment client", "heartbeat"],
        "preferred_tool": "splunk_run_query",
        "query_template": "search index=_internal (sourcetype=splunkd OR sourcetype=deploymentclient) | stats count by host sourcetype | sort - count",
        "anti_patterns": [],
        "explanation": "Forwarder health lives in _internal splunkd/deploymentclient sourcetypes.",
        "tags": ["platform_ops"],
        "priority": 80,
    },
    {
        "id": "splunk_license_usage",
        "intent": "splunk_license_usage",
        "triggers": ["license usage", "license quota", "splunk license", "license consumption"],
        "trigger_regex": [r"\blicense\b.*\b(?:usage|quota|consumption)\b", r"\bsplunk\b.*\blicense\b"],
        "preferred_tool": "splunk_run_query",
        "query_template": "search index=_internal sourcetype=splunkd OR sourcetype=license_usage | stats count by sourcetype host | sort - count",
        "anti_patterns": [
            r"sourcetype=splunkd(?!.*license_usage)",
            r"index=\*(?!.*_internal)",
        ],
        "explanation": "License usage spans _internal sourcetype=splunkd and sourcetype=license_usage.",
        "tags": ["platform_ops", "license"],
        "priority": 94,
    },
    {
        "id": "linux_sourcetype_inventory",
        "intent": "linux_sourcetypes",
        "triggers": ["linux sourcetype", "sourcetypes in linux", "linux index sourcetype"],
        "trigger_regex": [r"\blinux\b.*\bsourcetype", r"\bsourcetype\b.*\blinux\b"],
        "preferred_tool": "splunk_run_query",
        "query_template": "search index=linux | stats count by sourcetype | sort - count",
        "anti_patterns": [r"stats\s+count\s+by\s+index\b", r"\|\s*stats\s+count\s+by\s+source\b", r"index=\*(?!.*\blinux\b)"],
        "explanation": "Linux sourcetype inventory uses index=linux with stats by sourcetype.",
        "tags": ["linux", "inventory"],
        "priority": 93,
    },
    {
        "id": "linux_host_activity",
        "intent": "linux_host_activity",
        "triggers": ["linux host", "hosts in linux", "linux index host"],
        "trigger_regex": [r"\blinux\b.*\bhost", r"\bhost\b.*\blinux\b.*\b(?:index|sending|events)\b"],
        "preferred_tool": "splunk_run_query",
        "query_template": "search index=linux | stats count by host sourcetype | sort - count",
        "anti_patterns": [r"index=\*(?!.*\blinux\b)", r"stats\s+count\s+by\s+sourcetype\b(?!.*\bhost\b)"],
        "explanation": "Linux host activity uses index=linux with stats by host and sourcetype.",
        "tags": ["linux", "inventory"],
        "priority": 90,
    },
    {
        "id": "linux_auth_failures_oracle",
        "intent": "linux_auth_failures",
        "triggers": ["linux failed login", "linux auth failure", "ssh brute force"],
        "preferred_tool": "splunk_run_query",
        "query_template": (
            "search index=linux (source=\"/var/log/auth.log\" OR source=\"/var/log/secure\") "
            "(\"Failed password\" OR \"authentication failure\" OR \"Invalid user\") "
            "| stats count by host user src_ip port | sort - count"
        ),
        "anti_patterns": [r"event(?:code|id)=4625", r"sourcetype=XmlWinEventLog"],
        "explanation": "Linux auth failures use auth.log/secure sources, not Windows EventCode.",
        "tags": ["linux", "auth_failure"],
        "priority": 92,
    },
    {
        "id": "linux_sudo_activity_oracle",
        "intent": "linux_privilege_escalation_activity",
        "triggers": [
            "sudo activity",
            "sudo behavior",
            "su activity",
            "su behavior",
            "sudo sessions",
            "root session",
        ],
        "trigger_regex": [r"\blinux\b.*\bsudo\b", r"\bsudo\b.*\bactivity\b"],
        "preferred_tool": "splunk_run_query",
        "query_template": "",
        "anti_patterns": [
            r"\|\s*stats\b.*\|\s*table\b",
            r"stats\s+count\s+by\s+host\s+user\s+src_ip\s*\|\s*table\b",
        ],
        "explanation": "Linux sudo activity is an evidence table query with rex/eval fields, not a stats summary.",
        "tags": ["linux", "privilege_escalation"],
        "priority": 91,
    },
    {
        "id": "cross_platform_failed_login",
        "intent": "failed_login_activity",
        "triggers": ["failed login", "failed logon", "authentication failure"],
        "preferred_tool": "splunk_run_query",
        "query_template": "",
        "anti_patterns": [
            r"^(?!.*\|\s*append\s*\[).*event(?:code|id)=4625",
        ],
        "explanation": "Cross-platform auth uses separate Linux + Windows branches with append, never mixed sourcetypes.",
        "tags": ["security", "cross_platform"],
        "priority": 88,
    },
    {
        "id": "apache_suspicious_activity",
        "intent": "apache_suspicious_activity",
        "triggers": ["suspicious activity", "suspicious web", "malicious web", "web attack", "web reconnaissance"],
        "trigger_regex": [r"\b(?:suspicious|malicious|anomalous|weird)\b.*\b(?:web|access|request|activity)\b"],
        "preferred_tool": "splunk_run_query",
        "query_template": "",
        "anti_patterns": [r"sourcetype=stream:http", r"sourcetype=osquery", r"access_combined(?!.*(?:where|search status))"],
        "explanation": "General Apache suspicion requires explicit status, method, sensitive-path, or user-agent criteria and every requested output dimension.",
        "tags": ["web", "apache", "security"],
        "priority": 98,
    },
    {
        "id": "apache_sensitive_path_probing",
        "intent": "apache_sensitive_path_probing",
        "triggers": ["sensitive path", "admin path", ".env", ".git", "wp-admin", "phpmyadmin", "path probing"],
        "trigger_regex": [r"\b(?:sensitive|admin|configuration)\b.*\b(?:path|uri|endpoint|file)\b"],
        "preferred_tool": "splunk_run_query",
        "query_template": "",
        "anti_patterns": [r"sourcetype=stream:http", r"(?!.*(?:uri|path)).*access_combined"],
        "explanation": "Sensitive Apache path hunts must filter concrete administrative, secret, backup, or framework paths.",
        "tags": ["web", "apache", "security"],
        "priority": 96,
    },
    {
        "id": "apache_404_scanning",
        "intent": "apache_404_scanning",
        "triggers": ["404 scanning", "404 scanner", "404 probing", "top 404 source ips"],
        "trigger_regex": [r"\b404\b.*\b(?:scan|scanner|probe|probing|source ip)\b"],
        "preferred_tool": "splunk_run_query",
        "query_template": "",
        "anti_patterns": [r"sourcetype=stream:http", r"(?!.*status=404).*access_combined"],
        "explanation": "404 scanning requires status=404 plus source/path concentration or diversity, not only a host timechart.",
        "tags": ["web", "apache", "security"],
        "priority": 94,
    },
    {
        "id": "apache_access_summary",
        "intent": "apache_access_top_ips",
        "triggers": ["top client ips", "top source ips", "apache access", "access_combined", "web access logs"],
        "trigger_regex": [r"\b(?:top|summarize|show)\b.*\b(?:client|source)\s+ips?\b"],
        "preferred_tool": "splunk_run_query",
        "query_template": "",
        "anti_patterns": [r"sourcetype=stream:http", r"sourcetype=osquery"],
        "explanation": "Apache access summaries preserve the analyst-requested IP, status, method, path, and user-agent dimensions.",
        "tags": ["web", "apache"],
        "priority": 88,
    },
    {
        "id": "apache_suspicious_user_agents",
        "intent": "apache_suspicious_user_agents",
        "triggers": ["suspicious user agent", "suspicious agent", "web crawler", "suspicious bot", "scanner user agent"],
        "preferred_tool": "splunk_run_query",
        "query_template": "",
        "anti_patterns": [r"sourcetype=access_combined(?!.*stats)", r"(?!.*useragent)(?!.*clientip).*access_combined", r"access_combined(?!.*where)"],
        "explanation": "Apache UA hunts need a concrete scanner/bot/empty-agent predicate plus useragent and clientip output.",
        "tags": ["web", "apache"],
        "priority": 92,
    },
    {
        "id": "windows_failed_logon_eventcode",
        "intent": "windows_auth_failures",
        "triggers": ["windows failed logon", "windows failed login", "eventcode 4625", "eventid 4625"],
        "preferred_tool": "splunk_run_query",
        "query_template": "",
        "anti_patterns": [r"xmlwineventlog(?!.*4625)", r"wineventlog(?!.*4625)"],
        "explanation": "Windows failed logons require EventCode=4625 or EventID=4625.",
        "tags": ["security", "windows"],
        "priority": 82,
    },
]


@dataclass(frozen=True)
class DomainPattern:
    id: str
    intent: str
    triggers: tuple[str, ...]
    trigger_regex: tuple[str, ...]
    preferred_tool: str
    query_template: str
    anti_patterns: tuple[str, ...]
    explanation: str
    tags: tuple[str, ...]
    priority: int

    @classmethod
    def from_row(cls, row: dict[str, Any]) -> DomainPattern:
        return cls(
            id=str(row.get("id", "")).strip(),
            intent=str(row.get("intent", "")).strip(),
            triggers=tuple(str(x).strip().lower() for x in row.get("triggers", []) if str(x).strip()),
            trigger_regex=tuple(str(x).strip() for x in row.get("trigger_regex", []) if str(x).strip()),
            preferred_tool=str(row.get("preferred_tool", "splunk_run_query")).strip() or "splunk_run_query",
            query_template=str(row.get("query_template", "")).strip(),
            anti_patterns=tuple(str(x).strip() for x in row.get("anti_patterns", []) if str(x).strip()),
            explanation=str(row.get("explanation", "")).strip(),
            tags=tuple(str(x).strip() for x in row.get("tags", []) if str(x).strip()),
            priority=int(row.get("priority", 50) or 50),
        )


@dataclass(frozen=True)
class DomainResolution:
    pattern_id: str
    intent: str
    preferred_tool: str
    query: str
    confidence: float
    explanation: str
    anti_patterns: tuple[str, ...]
    source: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "pattern_id": self.pattern_id,
            "intent": self.intent,
            "preferred_tool": self.preferred_tool,
            "query": self.query,
            "confidence": self.confidence,
            "explanation": self.explanation,
            "anti_patterns": list(self.anti_patterns),
            "source": self.source,
        }


def patterns_path() -> Path:
    override = str(__import__("os").getenv("SPL_DOMAIN_PATTERNS_PATH", "")).strip()
    return Path(override) if override else DEFAULT_PATTERNS_PATH


@lru_cache(maxsize=1)
def load_patterns() -> list[DomainPattern]:
    path = patterns_path()
    rows: list[dict[str, Any]] = list(BUILTIN_PATTERNS)
    if path.is_file():
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            artifact_rows = payload.get("patterns", payload) if isinstance(payload, dict) else payload
            if isinstance(artifact_rows, list):
                seen = {str(r.get("id", "")) for r in rows if isinstance(r, dict)}
                for row in artifact_rows:
                    if isinstance(row, dict) and str(row.get("id", "")).strip() and row["id"] not in seen:
                        rows.append(row)
                        seen.add(str(row["id"]))
        except Exception:
            pass
    out: list[DomainPattern] = []
    for row in rows:
        if not isinstance(row, dict) or not str(row.get("id", "")).strip():
            continue
        out.append(DomainPattern.from_row(row))
    return out


# Tools that cannot filter by time or event volume at all -- pure catalog/metadata
# lookups. A pattern preferring one of these must never win for a question that
# needs an actual time-scoped or volume-scoped search; the tool structurally
# cannot answer it. This reuses the same authoritative disqualifier list the MCP
# deterministic router and saved-query shortcut gate already use, so all three
# subsystems agree on what counts as "needs a real search".
_NO_TIME_FILTER_TOOLS: frozenset[str] = frozenset(
    {"splunk_get_indexes", "splunk_get_info", "splunk_get_metadata"}
)


def _question_needs_time_scoped_search(question: str) -> bool:
    from mcp_deterministic_routing import question_disqualified_for_deterministic

    return bool(question_disqualified_for_deterministic(question))


def _score_pattern(pattern: DomainPattern, question: str, intent: str = "") -> float:
    q = (question or "").strip().lower()
    if not q:
        return 0.0
    score = float(pattern.priority)
    intent_l = (intent or "").strip().lower()
    exact_intent = bool(intent_l and pattern.intent and pattern.intent == intent_l)
    partial_intent = bool(
        intent_l and pattern.intent and (pattern.intent in intent_l or intent_l in pattern.intent)
    )
    if exact_intent:
        score += 25.0
    elif partial_intent:
        score += 10.0
    trigger_hits = sum(1 for trig in pattern.triggers if trig and trig in q)
    score += trigger_hits * 20.0
    regex_hit = False
    for expr in pattern.trigger_regex:
        try:
            if re.search(expr, q, flags=re.IGNORECASE):
                score += 30.0
                regex_hit = True
        except re.error:
            continue
    mapped = map_question_to_template(question)
    mapped_match = mapped.intent == pattern.intent
    if mapped_match:
        score += 15.0
    # Eligibility gate: a pattern's own anti_patterns/query_template only apply when
    # something about THIS question's text specifically matched it (a literal trigger
    # phrase or trigger_regex). Intent-level agreement (exact_intent/partial_intent/
    # mapped_match) is deliberately excluded from this gate -- it is a useful
    # tie-breaking bonus among patterns that already have genuine textual signal, but
    # by itself it lets every pattern sharing an intent claim equal relevance, at which
    # point raw `priority` (a static authoring knob, not a per-question relevance
    # signal) decides the winner. That previously let ultra-specific, single-exact-
    # phrase "gold oracle" patterns (and other high-priority-but-irrelevant patterns)
    # outrank the correct general-purpose template for any differently-worded question
    # sharing their intent, wrongly applying their narrow anti_patterns everywhere.
    if not (trigger_hits or regex_hit):
        return 0.0
    if pattern.preferred_tool in _NO_TIME_FILTER_TOOLS and _question_needs_time_scoped_search(question):
        return 0.0
    if question_requests_cardinality(question) and "cardinality" in pattern.tags:
        score += 20.0
    cardinality_q = question_requests_cardinality(question) or any(
        tok in q for tok in ("how many", "number of", "count of", "total number of")
    )
    volume_q = any(tok in q for tok in ("busiest", "most events", "top indexes", "had the most"))
    if cardinality_q and not volume_q:
        if "cardinality" in pattern.tags:
            score += 25.0
        if pattern.id in {"index_volume_ranking", "template_top_indexes"} or "top_n" in pattern.tags:
            score -= 55.0
    if volume_q and not cardinality_q:
        if pattern.id in {"index_volume_ranking", "template_top_indexes"} or "top_n" in pattern.tags:
            score += 20.0
        if pattern.id == "index_count_cardinality":
            score -= 55.0
    q_l = (question or "").lower()
    if any(term in q_l for term in ("_internal", "splunk internal", "internal index", "_audit")):
        if pattern.intent in {
            "splunk_internal_health",
            "internal_sourcetypes",
            "splunk_license_usage",
            "forwarder_connectivity",
            "internal_splunkd_health",
            "internal_auth_failures",
        }:
            score += 25.0
        if pattern.intent == "top_indexes" or "index_volume" in pattern.id:
            score -= 40.0
    if "license" in q_l and pattern.intent == "splunk_license_usage":
        score += 35.0
    if "splunkd" in q_l and pattern.intent == "internal_splunkd_health":
        score += 30.0
    from question_intelligence import APACHE_WEB_INTENTS, extract_explicit_sourcetype

    explicit_st = extract_explicit_sourcetype(question)
    if explicit_st == "access_combined":
        if pattern.intent in APACHE_WEB_INTENTS and (
            mapped_match or exact_intent or trigger_hits or regex_hit
        ):
            score += 40.0
        elif pattern.intent == "osquery_process_activity" or "osquery" in pattern.id:
            score -= 80.0
        elif pattern.intent in {"stream_http_activity"}:
            score -= 40.0
    elif explicit_st and explicit_st.lower() not in pattern.query_template.lower():
        if pattern.intent == "osquery_process_activity" and explicit_st != "osquery:results":
            score -= 50.0
    return score


def match_patterns(question: str, *, intent: str = "", min_score: float = 70.0) -> list[tuple[DomainPattern, float]]:
    scored: list[tuple[DomainPattern, float]] = []
    for pattern in load_patterns():
        value = _score_pattern(pattern, question, intent=intent)
        if value >= min_score:
            scored.append((pattern, value))
    scored.sort(key=lambda item: (item[1], item[0].priority), reverse=True)
    return scored


def _materialize_query(pattern: DomainPattern, question: str) -> str:
    if pattern.query_template:
        return pattern.query_template
    mapped = map_question_to_template(question)
    if mapped.intent == pattern.intent or not pattern.intent:
        return str(template_to_query_args(mapped, question).get("query", "")).strip()
    if pattern.intent:
        for template in __import__("query_templates", fromlist=["TEMPLATES"]).TEMPLATES:
            if template.intent == pattern.intent:
                return str(template_to_query_args(template, question).get("query", "")).strip()
    return ""


def resolve_domain_knowledge(question: str, *, intent: str = "") -> DomainResolution | None:
    matches = match_patterns(question, intent=intent)
    if not matches:
        return None
    pattern, score = matches[0]
    query = _materialize_query(pattern, question)
    confidence = min(0.99, max(0.5, score / 150.0))
    return DomainResolution(
        pattern_id=pattern.id,
        intent=pattern.intent or intent or map_question_to_template(question).intent,
        preferred_tool=pattern.preferred_tool,
        query=query,
        confidence=round(confidence, 3),
        explanation=pattern.explanation,
        anti_patterns=pattern.anti_patterns,
        source="spl_domain_knowledge",
    )


def format_domain_knowledge_context(resolution: DomainResolution | None, *, max_chars: int = 900) -> str:
    if resolution is None:
        return ""
    lines = [
        "SPL domain oracle (authoritative for this question shape):",
        f"- pattern_id: {resolution.pattern_id}",
        f"- intent: {resolution.intent}",
        f"- preferred_tool: {resolution.preferred_tool}",
        f"- guidance: {resolution.explanation}",
    ]
    if resolution.query:
        lines.append(f"- canonical_query: {resolution.query}")
    if resolution.anti_patterns:
        lines.append("- avoid_patterns: " + "; ".join(resolution.anti_patterns[:4]))
    text = "\n".join(lines)
    return text[:max_chars]


def validate_query_against_domain_knowledge(
    query: str,
    *,
    question: str,
    intent: str = "",
) -> tuple[bool, str]:
    resolution = resolve_domain_knowledge(question, intent=intent)
    if resolution is None:
        return True, "domain_ok"
    lowered = str(query or "").lower()
    for anti in resolution.anti_patterns:
        try:
            if re.search(anti, lowered, flags=re.IGNORECASE):
                return False, f"domain_anti_pattern:{resolution.pattern_id}:{anti}"
        except re.error:
            continue
    if resolution.query and resolution.preferred_tool == "splunk_run_query":
        if resolution.intent == "splunk_license_usage" and "license_usage" not in lowered:
            return False, f"domain_missing_license_usage:{resolution.pattern_id}"
        if " by index" in resolution.query.lower() and "| stats count" in lowered and " by " not in lowered.split("| stats", 1)[-1]:
            return False, f"domain_missing_breakdown:{resolution.pattern_id}"
        if "dc(index)" in resolution.query.lower() and "dc(index)" not in lowered and "stats count" in lowered:
            return False, f"domain_wrong_cardinality:{resolution.pattern_id}"
        if "by sourcetype" in resolution.query.lower() and "by sourcetype" not in lowered:
            if re.search(r"\|\s*stats\s+count\s+by\s+source\b", lowered):
                return False, f"domain_wrong_breakdown:{resolution.pattern_id}"
    return True, "domain_ok"


def apply_domain_postprocess(
    query: str,
    *,
    question: str,
    intent: str = "",
    bound: dict[str, Any] | None = None,
) -> str:
    if bound and bound.get("matched"):
        resolution = DomainResolution(
            pattern_id=str(bound.get("pattern_id", "")),
            intent=str(bound.get("intent", intent)),
            preferred_tool=str(bound.get("preferred_tool", "splunk_run_query")),
            query=str(bound.get("query", "")),
            confidence=float(bound.get("confidence", 0) or 0),
            explanation=str(bound.get("explanation", "")),
            anti_patterns=tuple(str(x) for x in bound.get("anti_patterns", []) if str(x).strip()),
            source=str(bound.get("source", "spl_domain_knowledge")),
        )
    else:
        resolution = resolve_domain_knowledge(question, intent=intent)
    if resolution is None or not resolution.query:
        return query
    if resolution.confidence < 0.85:
        return query
    current = str(query or "").strip()
    if not current:
        return resolution.query
    ok, _reason = validate_query_against_domain_knowledge(current, question=question, intent=intent)
    if ok:
        return current
    if resolution.preferred_tool == "splunk_run_query" or "|" in resolution.query:
        return resolution.query
    return query


def bind_domain_knowledge_for_plan(question: str, planner_output: dict[str, Any]) -> dict[str, Any]:
    intent = str(planner_output.get("intent", "")).strip()
    resolution = resolve_domain_knowledge(question, intent=intent)
    if resolution is None:
        return {"matched": False}
    payload = resolution.to_dict()
    payload["matched"] = True
    payload["context"] = format_domain_knowledge_context(resolution)
    if resolution.preferred_tool == "splunk_run_query" and resolution.query:
        payload["tool_args"] = {
            "query": resolution.query,
            "earliest_time": str((planner_output.get("tool_args") or {}).get("earliest_time", "-7d")),
            "latest_time": str((planner_output.get("tool_args") or {}).get("latest_time", "now")),
            "row_limit": int((planner_output.get("tool_args") or {}).get("row_limit", 50) or 50),
        }
    return payload
