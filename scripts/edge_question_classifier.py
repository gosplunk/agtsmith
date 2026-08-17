#!/usr/bin/env python3
"""Lightweight edge-model question classifier.

Turns a raw analyst question into a small, environment-agnostic structured
hint (platform / activity / data_category / entities / time_hint) using the
optional edge router model (default: gemma3:1b -- Google/US, non-Chinese,
~815MB, right-sized for classification-only work).

This is intentionally NOT another reasoning stage: it never sees the
environment profile, never writes SPL, and its only consumer today is
`domain_embedding_retrieval.retrieve_domain_scores`, which uses the
resulting hint text to enrich the embedding query used for domain/sourcetype
retrieval. Disabled by default (EDGE_LLM_ENABLED=0); any failure degrades to
an empty hint with zero impact on existing behavior.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from typing import Any

import urllib.error
import urllib.request

from runtime_config import (
    get_edge_llm_enabled,
    get_edge_llm_host,
    get_edge_llm_model,
    get_edge_llm_timeout_sec,
    get_ollama_host,
)

_CLASSIFIER_SYSTEM_PROMPT = (
    "You classify security-analyst questions about log/event data. "
    "Return ONLY a compact JSON object with these keys: "
    '"platform" (e.g. windows, linux, apache, o365, aws, okta, azure_ad, splunk_internal, network, unknown), '
    '"activity" (e.g. failed_login, successful_login, privilege_escalation, web_access, web_error, '
    "process_creation, network_flow, inventory, health, unknown), "
    '"data_category" (e.g. authentication, web, endpoint, identity, cloud_audit, network, platform_health, unknown), '
    '"entities" (short list of literal usernames/hosts/IPs/services mentioned, else empty list), '
    '"time_hint" (short phrase like "last 24 hours", "last month", or "unspecified"). '
    "Use lowercase snake_case values. No prose, no markdown, JSON only."
)

_JSON_OBJECT_RE = re.compile(r"\{.*\}", re.DOTALL)
_ALLOWED_KEYS = ("platform", "activity", "data_category", "entities", "time_hint")


def _post_json(url: str, payload: dict[str, Any], *, timeout: float) -> dict[str, Any]:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8")
    data = json.loads(raw)
    return data if isinstance(data, dict) else {}


def _edge_llm_base_url() -> str:
    host = get_edge_llm_host()
    return (host or get_ollama_host()).rstrip("/")


def _extract_json_object(text: str) -> dict[str, Any]:
    text = str(text or "").strip()
    if not text:
        return {}
    try:
        parsed = json.loads(text)
        return parsed if isinstance(parsed, dict) else {}
    except json.JSONDecodeError:
        pass
    match = _JSON_OBJECT_RE.search(text)
    if not match:
        return {}
    try:
        parsed = json.loads(match.group(0))
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _sanitize_classification(raw: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(raw, dict):
        return {}
    out: dict[str, Any] = {}
    for key in _ALLOWED_KEYS:
        if key not in raw:
            continue
        value = raw[key]
        if key == "entities":
            if isinstance(value, list):
                out[key] = [str(item).strip() for item in value if str(item).strip()][:8]
            elif isinstance(value, str) and value.strip():
                out[key] = [value.strip()]
            continue
        text = str(value).strip().lower()
        if text and text not in {"unknown", "unspecified", "none", "n/a"}:
            out[key] = text
    return out


def classify_question(question: str, *, timeout_sec: float | None = None) -> dict[str, Any]:
    """Return a structured hint for `question`, or {} if unavailable/disabled.

    Never raises: any Ollama/network/parse failure degrades to an empty dict
    so callers can safely treat this as a pure enrichment signal.
    """
    question = str(question or "").strip()
    if not question or not get_edge_llm_enabled():
        return {}
    model = get_edge_llm_model()
    if not model:
        return {}
    timeout = timeout_sec if timeout_sec is not None else float(get_edge_llm_timeout_sec() or "60")
    base_url = _edge_llm_base_url()
    if not base_url:
        return {}
    payload = {
        "model": model,
        "prompt": f"{_CLASSIFIER_SYSTEM_PROMPT}\n\nQuestion: {question}\nJSON:",
        "format": "json",
        "stream": False,
        "options": {"temperature": 0.0},
    }
    try:
        data = _post_json(f"{base_url}/api/generate", payload, timeout=timeout)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
        return {}
    response_text = str(data.get("response", ""))
    return _sanitize_classification(_extract_json_object(response_text))


def classification_to_query_hint(classification: dict[str, Any]) -> str:
    """Render a structured classification as compact text for embedding enrichment."""
    if not isinstance(classification, dict) or not classification:
        return ""
    parts: list[str] = []
    for key in _ALLOWED_KEYS:
        value = classification.get(key)
        if not value:
            continue
        if isinstance(value, list):
            if value:
                parts.append(f"{key}={' '.join(value)}")
        else:
            parts.append(f"{key}={value}")
    return " ".join(parts)


@lru_cache(maxsize=256)
def _cached_query_hint(question: str) -> str:
    return classification_to_query_hint(classify_question(question))


def question_query_hint(question: str, *, use_cache: bool = True) -> str:
    """Best-effort structured hint text for `question` (empty when disabled/unavailable)."""
    question = str(question or "").strip()
    if not question:
        return ""
    if use_cache:
        return _cached_query_hint(question)
    return classification_to_query_hint(classify_question(question))
