#!/usr/bin/env python3
"""Retrieve SPL snippets from Splunk Offline Docs compact RAG index."""

from __future__ import annotations

import json
import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from question_intelligence import infer_question_dimensions

try:
    from windows_event_code_catalog import intents_for_question, rag_tokens_for_intent
except ImportError:  # pragma: no cover
    def intents_for_question(_question: str) -> list[str]:
        return []

    def rag_tokens_for_intent(_intent: str) -> set[str]:
        return set()

INDEX_PATH_DEFAULT = Path("artifacts/knowledge/spl_offline_docs_rag_index.json")

FORBIDDEN_SNIPPET_TERMS: tuple[str, ...] = (
    "| collect",
    "| sendalert",
    "| outputlookup",
    "| delete",
    "| script",
    "| rest",
)

SPL_COMMAND_TOKENS: tuple[str, ...] = (
    "stats",
    "rex",
    "eval",
    "where",
    "table",
    "tstats",
    "timechart",
    "join",
    "lookup",
    "transaction",
    "dedup",
    "sort",
    "head",
    "tail",
    "append",
    "multisearch",
    "bin",
    "chart",
    "fields",
    "rename",
    "fillnull",
    "coalesce",
    "spath",
    "regex",
    "subsearch",
)

INTENT_TOPIC_ANCHORS: dict[str, tuple[str, ...]] = {
    "top_indexes": ("index", "indexes"),
    "metadata_inventory": ("metadata", "metasearch", "sourcetype"),
    "index_sourcetype_volume": ("sourcetype", "index"),
    "host_activity_summary": ("host", "index"),
    "index_staleness": ("index", "event count"),
    "splunk_internal_health": ("_internal", "splunkd", "health report", "scheduler"),
    "internal_sourcetypes": ("_internal", "splunkd", "sourcetype"),
    "splunk_license_usage": ("license", "license_usage"),
    "forwarder_connectivity": ("forwarder", "deploymentclient", "splunkd"),
    "web_traffic_summary": ("http", "web", "apache", "access_combined", "uri"),
    "apache_access_top_ips": ("http", "web", "apache", "access_combined", "clientip"),
    "apache_suspicious_activity": ("http", "web", "apache", "access_combined", "uri", "user agent"),
    "apache_404_spike": ("http", "web", "apache", "404"),
    "failed_login_activity": ("failed login", "failed logon", "4625", "authentication failure"),
    "linux_auth_failures": ("failed password", "authentication failure", "auth.log"),
    "windows_auth_failures": ("failed logon", "4625", "xmlwineventlog"),
    "network_flow_summary": ("network flow", "src_ip", "dest_ip", "destination port"),
    "app_error_spike": ("application error", "error log", "exceptions"),
}

INTENT_TOPIC_NEGATIVE_TERMS: dict[str, tuple[str, ...]] = {
    "web_traffic_summary": ("splunk web", "web.conf", "browser", "https encryption"),
    "apache_access_top_ips": ("splunk web", "web.conf", "browser", "https encryption"),
    "apache_suspicious_activity": ("splunk web", "web.conf", "browser", "https encryption"),
    "apache_404_spike": ("splunk web", "web.conf", "browser", "https encryption"),
}

QUESTION_STOP_TOKENS: frozenset[str] = frozenset(
    {
        "activity",
        "days",
        "hours",
        "investigate",
        "last",
        "most",
        "over",
        "show",
        "summary",
        "using",
        "which",
        "with",
    }
)


def _index_path() -> Path:
    override = str(os.getenv("SPL_OFFLINE_DOCS_RAG_INDEX", "")).strip()
    if override:
        return Path(override)
    return INDEX_PATH_DEFAULT


def _question_tokens(question: str, *, intent: str = "") -> set[str]:
    q = f"{question} {intent}".lower()
    tokens = {
        token
        for token in re.findall(r"[a-z0-9_]{3,}", q)
        if token not in QUESTION_STOP_TOKENS
    }
    dims = infer_question_dimensions(question)
    for key in ("platforms", "activities", "shapes"):
        for value in dims.get(key, []):
            token = str(value).strip().lower()
            if token:
                tokens.add(token)
    intent_name = str(intent or "").strip().lower()
    if intent_name == "botsv3_named_sourcetype_overview":
        tokens.update({"botsv3", "sourcetype", "overview", "stats", "head"})
    elif intent_name in {"stream_dns_activity", "windows_sysmon_dns_activity"}:
        tokens.update({"dns", "stream", "spath", "reply_code"})
    elif intent_name in {"windows_auth_failures", "failed_login_activity"}:
        tokens.update({"4625", "xmlwineventlog", "logon", "failed"})
    elif intent_name in {"windows_successful_logons"}:
        tokens.update({"4624", "xmlwineventlog", "logon", "successful"})
    elif intent_name in {"windows_process_activity"}:
        tokens.update({"eventid", "1", "sysmon", "image", "commandline", "parentimage"})
    elif intent_name in {"windows_process_audit_activity"}:
        tokens.update({"4688", "process", "command_line", "new_process_name"})
    elif intent_name in {"windows_sysmon_network_activity"}:
        tokens.update({"sysmon", "eventid", "3", "destinationip", "network"})
    elif intent_name in {"windows_sysmon_dns_activity"}:
        tokens.update({"sysmon", "eventid", "22", "queryname", "dns"})
    elif intent_name in {"windows_credential_access_activity"}:
        tokens.update({"5379", "credential", "targetname"})
    elif intent_name in {"windows_privilege_assigned_activity"}:
        tokens.update({"4672", "privilege", "privilegelist"})
    elif intent_name in {"top_indexes"}:
        tokens.update({"index", "indexes", "stats", "count", "retrieve", "events", "volume", "busiest"})
    elif intent_name in {"metadata_inventory"}:
        tokens.update({"metadata", "metasearch", "hosts", "sources", "sourcetypes", "inventory"})
    elif intent_name in {"index_sourcetype_volume"}:
        tokens.update({"sourcetype", "stats", "count", "index", "volume"})
    elif intent_name in {"splunk_internal_health", "internal_sourcetypes"}:
        tokens.update({"_internal", "scheduler", "search_telemetry", "splunkd", "internal"})
    elif intent_name in {"splunk_license_usage"}:
        tokens.update({"license", "quota", "_internal", "usage"})
    elif intent_name in {"forwarder_connectivity"}:
        tokens.update({"forwarder", "deploymentclient", "splunkd", "connectivity"})
    elif intent_name in {"host_activity_summary", "index_staleness"}:
        tokens.update({"host", "index", "stats", "count", "activity"})
    elif intent_name in {
        "web_traffic_summary",
        "apache_access_top_ips",
        "apache_suspicious_activity",
        "apache_404_spike",
        "apache_404_scanning",
        "apache_suspicious_user_agents",
        "apache_sensitive_path_probing",
    }:
        tokens.update({"web", "access", "access_combined", "clientip", "uri", "status", "stats"})
    elif intent_name in {"network_flow_summary", "aws_vpc_flow_activity"}:
        tokens.update({"network", "flow", "src", "dest", "port", "stats"})
    elif intent_name in {"app_error_spike"}:
        tokens.update({"error", "sourcetype", "host", "stats", "count"})
    for intent_guess in intents_for_question(question):
        tokens.update(rag_tokens_for_intent(intent_guess))
    return tokens


def _extract_spl_examples(text: str, *, max_chars: int) -> str:
    blocks = re.findall(r"```(?:spl|SPL)?\s*([\s\S]*?)```", text, flags=re.IGNORECASE)
    if not blocks:
        blocks = re.findall(r"(search[^\n`]{20,}(?:\|[^\n`]{0,200}){0,8})", text, flags=re.IGNORECASE)
    if not blocks:
        return ""
    merged = "\n".join(block.strip() for block in blocks[:2] if block.strip())
    if len(merged) > max_chars:
        return merged[: max_chars - 3].rstrip() + "..."
    return merged


def _score_topic(row: dict[str, Any], tokens: set[str], *, intent: str = "") -> int:
    title = str(row.get("title", "")).lower()
    path = str(row.get("path", "")).lower()
    text = str(row.get("text", "")).lower()
    intent_name = str(intent or "").strip().lower()
    score = 0
    for token in tokens:
        if token in title:
            score += 8
        if token in path:
            score += 4
        if token in text:
            score += 2
            if "_" in token:
                score += 98
    for cmd in SPL_COMMAND_TOKENS:
        if cmd in tokens and (cmd in title or cmd in path or f"| {cmd}" in text or f" {cmd} " in text):
            score += 10
    category = str(row.get("category", "")).strip().lower()
    anchors = INTENT_TOPIC_ANCHORS.get(intent_name, ())
    title_path = f"{title} {path}"
    score += sum(24 for anchor in anchors if anchor in title_path)
    score += sum(4 for anchor in anchors if anchor in text)
    score -= sum(
        80
        for negative_term in INTENT_TOPIC_NEGATIVE_TERMS.get(intent_name, ())
        if negative_term in title_path
    )
    if category == "inventory" and intent_name in {"top_indexes", "metadata_inventory", "index_sourcetype_volume", "host_activity_summary"}:
        score += 12
    if category == "platform_ops" and intent_name in {
        "splunk_internal_health",
        "splunk_license_usage",
        "forwarder_connectivity",
        "internal_sourcetypes",
    }:
        score += 12
    if "search-reference" in path or "search-manual" in path:
        score += 3
    if "optimizing-searches" in path:
        score += 2
    return score


def _topic_matches_intent(row: dict[str, Any], *, intent: str, tokens: set[str]) -> bool:
    anchors = INTENT_TOPIC_ANCHORS.get(str(intent or "").strip().lower(), ())
    if not anchors:
        return True
    title_path = f"{row.get('title', '')} {row.get('path', '')}".lower()
    text = str(row.get("text", "")).lower()
    if any("_" in token and token in f"{title_path} {text}" for token in tokens):
        return True
    if any(anchor in title_path for anchor in anchors):
        return True
    if (
        sum(1 for anchor in anchors if anchor in text) >= 2
        and bool(_extract_spl_examples(text, max_chars=120))
    ):
        return True
    is_search_reference = "search-reference" in title_path or "search-manual" in title_path
    return is_search_reference and any(
        command in tokens and command in title_path for command in SPL_COMMAND_TOKENS
    )


@lru_cache(maxsize=2)
def _load_index(path_str: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    path = Path(path_str)
    if not path.exists():
        return {}, []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}, []
    if not isinstance(payload, dict):
        return {}, []
    topics = payload.get("topics", [])
    if not isinstance(topics, list):
        topics = []
    cleaned = [row for row in topics if isinstance(row, dict) and str(row.get("text", "")).strip()]
    return payload, cleaned


def offline_docs_index_available(*, index_path: Path | None = None) -> bool:
    path = index_path or _index_path()
    payload, topics = _load_index(str(path.resolve()))
    return bool(topics) and int(payload.get("topic_count", 0) or 0) > 0


def build_offline_docs_context(
    question: str,
    *,
    intent: str = "",
    max_topics: int = 3,
    max_chars: int = 1200,
    index_path: Path | None = None,
) -> str:
    path = index_path or _index_path()
    payload, topics = _load_index(str(path.resolve()))
    if not topics:
        return ""

    tokens = _question_tokens(question, intent=intent)
    ranked: list[tuple[int, dict[str, Any]]] = []
    intent_aligned: list[tuple[int, dict[str, Any]]] = []
    for row in topics:
        text = str(row.get("text", ""))
        lowered = text.lower()
        if any(term in lowered for term in FORBIDDEN_SNIPPET_TERMS):
            continue
        score = _score_topic(row, tokens, intent=intent)
        if score <= 0 and not tokens:
            score = 1
        if score <= 0:
            continue
        ranked.append((score, row))
        if _topic_matches_intent(row, intent=intent, tokens=tokens):
            intent_aligned.append((score, row))

    if not ranked:
        return ""
    if str(intent or "").strip().lower() in INTENT_TOPIC_ANCHORS:
        if not intent_aligned:
            return ""
        ranked = intent_aligned

    ranked.sort(key=lambda item: item[0], reverse=True)
    lines: list[str] = ["[SPL_OFFLINE_DOCS]"]
    built_at = str(payload.get("built_at", "")).strip()
    if built_at:
        lines.append(f"index_built_at={built_at}")
    lines.append("Curated SPL guidance from help.splunk.com (offline docs corpus).")

    budget = max(200, max_chars)
    used = len("\n".join(lines))
    per_topic = max(180, int((budget - used) / max(1, max_topics)))

    seen_titles: set[str] = set()
    for _score, row in ranked:
        title = str(row.get("title", "")).strip()
        normalized_title = re.sub(r"\s+", " ", title.lower())
        if normalized_title in seen_titles:
            continue
        seen_titles.add(normalized_title)
        doc_path = str(row.get("path", "")).strip()
        text = str(row.get("text", "")).strip()
        example = _extract_spl_examples(text, max_chars=min(420, per_topic // 2))
        snippet = text if len(text) <= per_topic else text[: per_topic - 3].rstrip() + "..."
        block_lines = [f"title={title}", f"path={doc_path}"]
        if example:
            block_lines.append(f"example_spl={example}")
        block_lines.append(f"summary={snippet}")
        block = "\n".join(block_lines)
        if used + len(block) + 2 > budget:
            remaining = budget - used - 2
            if remaining < 80:
                break
            block = block[: remaining - 3].rstrip() + "..."
        lines.append(block)
        used += len(block) + 2
        if len(seen_titles) >= max(1, max_topics):
            break

    return "\n".join(lines).strip()


def clear_offline_docs_cache() -> None:
    _load_index.cache_clear()
