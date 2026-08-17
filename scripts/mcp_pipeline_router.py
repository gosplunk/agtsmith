"""Edge-LLM MCP pipeline router (deterministic MCP vs full LLM-assisted).

Uses a lightweight Ollama model (default gemma3:1b) when enabled, with hard
code vetoes and keyword allowlist fallback. Defaults to LLM-assisted on any
uncertainty, timeout, or parse failure.
"""

from __future__ import annotations

import json
import re
from typing import Any

import urllib.error
import urllib.request

from mcp_deterministic_routing import classify_mcp_deterministic_eligibility
from runtime_config import (
    get_edge_llm_enabled,
    get_edge_llm_host,
    get_edge_llm_model,
    get_edge_llm_timeout_sec,
    get_ollama_host,
    mcp_deterministic_auto_route,
    mcp_deterministic_min_confidence,
    mcp_pipeline_router_enabled,
)

MCP_CHAT_PIPELINE_ASSISTED = "assisted"
MCP_CHAT_PIPELINE_DETERMINISTIC = "deterministic"

_PIPELINE_ROUTER_SYSTEM = (
    "You route Splunk analyst chat questions to exactly one pipeline. "
    "Return ONLY one JSON object with ALL keys shown below.\n\n"
    "Keys (required):\n"
    '- "route": "deterministic_mcp" or "llm_assisted"\n'
    '- "mcp_tool": "splunk_get_indexes" | "splunk_get_info" | '
    '"splunk_get_metadata" | "none"\n'
    '- "needs_event_search": boolean\n'
    '- "needs_time_window": boolean\n'
    '- "confidence": number 0.0-1.0\n'
    '- "reason": short_snake_case phrase\n\n'
    "deterministic_mcp = pure inventory only (index names, Splunk version, "
    "global host/sourcetype lists). NO time range. NO searching events.\n"
    "llm_assisted = everything else (data in time windows, counts, investigations, SPL).\n\n"
    "Examples:\n"
    'Q: What indexes do I have access to?\n'
    'JSON: {"route":"deterministic_mcp","mcp_tool":"splunk_get_indexes",'
    '"needs_event_search":false,"needs_time_window":false,"confidence":0.98,'
    '"reason":"index_inventory"}\n'
    'Q: What indexes had data in the last 15 minutes?\n'
    'JSON: {"route":"llm_assisted","mcp_tool":"none","needs_event_search":true,'
    '"needs_time_window":true,"confidence":0.99,"reason":"time_bound_data"}\n'
    'Q: What is the Splunk version?\n'
    'JSON: {"route":"deterministic_mcp","mcp_tool":"splunk_get_info",'
    '"needs_event_search":false,"needs_time_window":false,"confidence":0.97,'
    '"reason":"splunk_instance_info"}\n'
)

_ALLOWED_DETERMINISTIC_TOOLS: frozenset[str] = frozenset(
    {
        "splunk_get_indexes",
        "splunk_get_metadata",
        "splunk_get_info",
    }
)

_DETERMINISTIC_REASON_TOKENS: tuple[str, ...] = (
    "index_inventory",
    "splunk_instance_info",
    "metadata_inventory",
    "pure_inventory",
    "host_list",
    "instance_info",
)


def _edge_suggests_deterministic(router: dict[str, Any]) -> bool:
    reason = str(router.get("reason", "")).strip().lower()
    return any(token in reason for token in _DETERMINISTIC_REASON_TOKENS)


def _keyword_fallback_meta(keyword_eligibility: dict[str, Any], *, router_method: str) -> dict[str, Any]:
    return {
        "requested_pipeline": MCP_CHAT_PIPELINE_ASSISTED,
        "effective_pipeline": MCP_CHAT_PIPELINE_DETERMINISTIC,
        "auto_routed": True,
        "auto_route_reason": str(keyword_eligibility.get("reason", "")),
        "router_method": router_method,
        "eligibility": keyword_eligibility,
    }


_ROUTE_ALIASES = {
    "deterministic": "deterministic_mcp",
    "deterministic_mcp": "deterministic_mcp",
    "llm": "llm_assisted",
    "llm_assisted": "llm_assisted",
    "assisted": "llm_assisted",
}


def _post_json(url: str, payload: dict[str, Any], *, timeout: float) -> dict[str, Any]:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8")
    data = json.loads(raw)
    return data if isinstance(data, dict) else {}


def _edge_base_url() -> str:
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
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        return {}
    try:
        parsed = json.loads(match.group(0))
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _sanitize_router_output(raw: dict[str, Any]) -> dict[str, Any]:
    route = _ROUTE_ALIASES.get(str(raw.get("route", "")).strip().lower(), "llm_assisted")
    tool = str(raw.get("mcp_tool", "none")).strip().lower()
    if tool not in _ALLOWED_DETERMINISTIC_TOOLS:
        tool = "none"
    try:
        confidence = float(raw.get("confidence", 0.0))
    except Exception:
        confidence = 0.0
    confidence = max(0.0, min(1.0, confidence))
    # gemma3:1b sometimes returns only {"route": ...}; treat as incomplete.
    incomplete = "confidence" not in raw or "mcp_tool" not in raw
    if incomplete and confidence == 0.0:
        confidence = 0.0
    reason = str(raw.get("reason", "")).strip() or ("incomplete_edge_json" if incomplete else "edge_router")
    return {
        "route": route,
        "mcp_tool": tool if route == "deterministic_mcp" else "none",
        "needs_event_search": bool(raw.get("needs_event_search")),
        "needs_time_window": bool(raw.get("needs_time_window")),
        "confidence": round(confidence, 3),
        "reason": reason,
        "source": "edge_llm",
        "incomplete": incomplete,
    }


def classify_pipeline_with_edge_llm(
    question: str,
    *,
    timeout_sec: float | None = None,
) -> dict[str, Any]:
    """Call the edge model for a pipeline route hint, or {} if unavailable."""
    question = str(question or "").strip()
    if not question or not get_edge_llm_enabled() or not mcp_pipeline_router_enabled():
        return {}
    model = get_edge_llm_model()
    if not model:
        return {}
    timeout = float(timeout_sec if timeout_sec is not None else get_edge_llm_timeout_sec() or "8")
    base_url = _edge_base_url()
    if not base_url:
        return {}
    payload = {
        "model": model,
        "prompt": f"{_PIPELINE_ROUTER_SYSTEM}\n\nQuestion: {question}\nJSON:",
        "format": "json",
        "stream": False,
        "options": {"temperature": 0.0},
    }
    try:
        data = _post_json(f"{base_url}/api/generate", payload, timeout=timeout)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
        return {}
    response_text = str(data.get("response", ""))
    sanitized = _sanitize_router_output(_extract_json_object(response_text))
    return sanitized if sanitized else {}


def apply_pipeline_hard_vetoes(router: dict[str, Any], question: str) -> dict[str, Any]:
    """Downgrade deterministic routes that fail non-negotiable safety checks."""
    out = dict(router) if isinstance(router, dict) else {}
    vetoes: list[str] = []

    keyword_block = classify_mcp_deterministic_eligibility(question)
    kw_reason = str(keyword_block.get("reason", "")).strip()
    if not keyword_block.get("eligible") and kw_reason.startswith("disqualified:"):
        vetoes.append(kw_reason)

    if out.get("needs_event_search"):
        vetoes.append("needs_event_search")
    if out.get("needs_time_window"):
        vetoes.append("needs_time_window")

    min_conf = mcp_deterministic_min_confidence()
    if float(out.get("confidence", 0.0) or 0.0) < min_conf:
        vetoes.append(f"confidence_below_{min_conf}")

    tool = str(out.get("mcp_tool", "")).strip()
    if out.get("route") == "deterministic_mcp":
        if tool not in _ALLOWED_DETERMINISTIC_TOOLS:
            vetoes.append(f"tool_not_allowed:{tool or 'none'}")
        elif not keyword_block.get("eligible"):
            vetoes.append(f"keyword_gate:{kw_reason or 'not_eligible'}")

    if vetoes:
        out["route"] = "llm_assisted"
        out["mcp_tool"] = "none"
        out["veto_reasons"] = vetoes
        out["vetoed"] = True
    else:
        out["vetoed"] = False
        out.setdefault("veto_reasons", [])
    return out


def _eligibility_from_router(router: dict[str, Any], question: str) -> dict[str, Any]:
    keyword = classify_mcp_deterministic_eligibility(question)
    if router.get("route") != "deterministic_mcp" or router.get("vetoed"):
        return {
            "eligible": False,
            "reason": router.get("reason") or "llm_assisted",
            "category": "",
            "selected_tool": keyword.get("selected_tool", ""),
            "intent": keyword.get("intent", ""),
            "router": router,
        }
    tool = str(router.get("mcp_tool", "")).strip()
    category = {
        "splunk_get_indexes": "index_inventory",
        "splunk_get_info": "splunk_instance_info",
        "splunk_get_metadata": "metadata_inventory",
    }.get(tool, "")
    return {
        "eligible": True,
        "reason": f"{category}:{router.get('reason', 'edge_router')}",
        "category": category,
        "selected_tool": tool,
        "intent": keyword.get("intent", ""),
        "metadata_args": keyword.get("metadata_args", {}),
        "router": router,
    }


def resolve_pipeline_route(
    question: str,
    requested_pipeline: str | None,
    *,
    use_edge_llm: bool | None = None,
) -> tuple[str, dict[str, Any]]:
    """Choose assisted vs deterministic MCP pipeline for a question."""
    requested = str(requested_pipeline or MCP_CHAT_PIPELINE_ASSISTED).strip().lower()
    keyword_eligibility = classify_mcp_deterministic_eligibility(question)

    if requested == MCP_CHAT_PIPELINE_DETERMINISTIC:
        return MCP_CHAT_PIPELINE_DETERMINISTIC, {
            "requested_pipeline": MCP_CHAT_PIPELINE_DETERMINISTIC,
            "effective_pipeline": MCP_CHAT_PIPELINE_DETERMINISTIC,
            "auto_routed": False,
            "auto_route_reason": "",
            "router_method": "manual_deterministic",
            "eligibility": keyword_eligibility,
        }

    if not mcp_deterministic_auto_route():
        return MCP_CHAT_PIPELINE_ASSISTED, {
            "requested_pipeline": MCP_CHAT_PIPELINE_ASSISTED,
            "effective_pipeline": MCP_CHAT_PIPELINE_ASSISTED,
            "auto_routed": False,
            "auto_route_reason": "",
            "router_method": "auto_route_disabled",
            "eligibility": keyword_eligibility,
        }

    edge_enabled = (
        use_edge_llm
        if use_edge_llm is not None
        else (get_edge_llm_enabled() and mcp_pipeline_router_enabled())
    )
    router_method = "keyword_allowlist"
    router_output: dict[str, Any] = {}

    if edge_enabled:
        raw_edge = classify_pipeline_with_edge_llm(question)
        if raw_edge and not raw_edge.get("incomplete"):
            router_output = apply_pipeline_hard_vetoes(raw_edge, question)
            router_method = "edge_llm"
        elif raw_edge:
            router_method = "edge_llm_incomplete_keyword_fallback"
        else:
            router_method = "edge_llm_unavailable_keyword_fallback"

    if router_method == "edge_llm" and router_output:
        eligibility = _eligibility_from_router(router_output, question)
        if eligibility.get("eligible"):
            return MCP_CHAT_PIPELINE_DETERMINISTIC, {
                "requested_pipeline": MCP_CHAT_PIPELINE_ASSISTED,
                "effective_pipeline": MCP_CHAT_PIPELINE_DETERMINISTIC,
                "auto_routed": True,
                "auto_route_reason": str(eligibility.get("reason", "")),
                "router_method": router_method,
                "router": router_output,
                "eligibility": eligibility,
            }
        if keyword_eligibility.get("eligible") and (
            router_output.get("vetoed")
            or (
                router_output.get("route") == "llm_assisted"
                and _edge_suggests_deterministic(router_output)
            )
        ):
            meta = _keyword_fallback_meta(
                keyword_eligibility,
                router_method="edge_llm_safe_keyword_fallback",
            )
            meta["router"] = router_output
            return MCP_CHAT_PIPELINE_DETERMINISTIC, meta
        return MCP_CHAT_PIPELINE_ASSISTED, {
            "requested_pipeline": MCP_CHAT_PIPELINE_ASSISTED,
            "effective_pipeline": MCP_CHAT_PIPELINE_ASSISTED,
            "auto_routed": False,
            "auto_route_reason": "",
            "router_method": router_method,
            "router": router_output,
            "eligibility": eligibility,
        }

    # Keyword-only fallback (edge unavailable, incomplete, or disabled)
    if keyword_eligibility.get("eligible"):
        return MCP_CHAT_PIPELINE_DETERMINISTIC, _keyword_fallback_meta(
            keyword_eligibility,
            router_method=router_method,
        )

    return MCP_CHAT_PIPELINE_ASSISTED, {
        "requested_pipeline": MCP_CHAT_PIPELINE_ASSISTED,
        "effective_pipeline": MCP_CHAT_PIPELINE_ASSISTED,
        "auto_routed": False,
        "auto_route_reason": "",
        "router_method": router_method,
        "eligibility": keyword_eligibility,
    }


def compare_routing_methods(question: str) -> dict[str, Any]:
    """Return keyword vs edge routing decisions for benchmarks and tests."""
    keyword = classify_mcp_deterministic_eligibility(question)
    keyword_pipeline = (
        MCP_CHAT_PIPELINE_DETERMINISTIC if keyword.get("eligible") else MCP_CHAT_PIPELINE_ASSISTED
    )
    edge_raw = classify_pipeline_with_edge_llm(question)
    edge_vetoed = apply_pipeline_hard_vetoes(edge_raw, question) if edge_raw else {}
    edge_resolved, edge_meta = resolve_pipeline_route(
        question,
        MCP_CHAT_PIPELINE_ASSISTED,
        use_edge_llm=True,
    )
    return {
        "question": question,
        "keyword": {
            "pipeline": keyword_pipeline,
            "eligible": bool(keyword.get("eligible")),
            "reason": keyword.get("reason", ""),
            "tool": keyword.get("selected_tool", ""),
        },
        "edge_llm_raw": edge_raw,
        "edge_llm_vetoed": edge_vetoed,
        "edge_resolved": {
            "pipeline": edge_resolved,
            "method": edge_meta.get("router_method", ""),
            "auto_routed": edge_meta.get("auto_routed", False),
            "reason": edge_meta.get("auto_route_reason", ""),
            "router": edge_meta.get("router", {}),
        },
    }
