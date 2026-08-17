"""Strict MCP deterministic pipeline eligibility (no LLM planner/writer).

Only pure inventory / metadata / Splunk-info questions with a single
read-only MCP tool and no investigative reasoning qualify. Any ambiguity
falls through to the LLM-assisted pipeline.
"""

from __future__ import annotations

import re
from typing import Any

from investigation_progress import SECURITY_REVIEW_INTENTS
from langgraph_minimal_flow import determine_splunk_tool
from minimal_question_to_answer import map_question_to_template

# Questions matching these substrings are never auto-routed (investigation / SPL).
_DISQUALIFY_SUBSTRINGS: tuple[str, ...] = (
    "investigate",
    "suspicious",
    "malware",
    "attack",
    "compromise",
    "breach",
    "exploit",
    "failed login",
    "failed logon",
    "auth fail",
    "brute",
    "privilege",
    "lateral",
    "exfil",
    "beacon",
    "c2 ",
    "command and control",
    "ransomware",
    "phish",
    "ioc",
    "threat",
    "anomal",
    "unusual",
    "why ",
    "explain ",
    "compare ",
    "correlat",
    "most events",
    "top ",
    "highest",
    "largest",
    "busiest",
    "have data",
    "has data",
    "had data",
    "having data",
    "with data",
    "contain data",
    "containing data",
    "received data",
    "indexes that",
    "indexes with",
    "index that",
    "index with",
    "event volume",
    "events in",
    "in the last",
    "over the last",
    "within the last",
    "during the last",
    "for the last",
    "last hour",
    "last day",
    "last week",
    "last 24",
    "last 7",
    "last 30",
    "last 60",
    "last 90",
    "last 15",
    "last 5",
    "last 10",
    "last minute",
    "last minutes",
    "minutes ago",
    "hours ago",
    "days ago",
    "today",
    "yesterday",
    "past ",
    "previous ",
    "all time",
    "ever ",
    "write ",
    "delete ",
    "drop ",
    "create ",
    "modify ",
    "update index",
    "run script",
)

# Strict inventory wording -> splunk_get_indexes (must not include data/time signals above).
_INDEX_INVENTORY_PHRASES: tuple[str, ...] = (
    "list indexes",
    "show indexes",
    "what indexes",
    "which indexes can i",
    "which indexes do i",
    "indexes i can access",
    "indexes available",
    "available indexes",
    "index inventory",
    "index list",
    "how many indexes",
    "number of indexes",
    "count of indexes",
    "what index can i",
    "which index can i",
)

# Splunk instance metadata (no event search).
_SPLUNK_INFO_PHRASES: tuple[str, ...] = (
    "splunk info",
    "splunk version",
    "server info",
    "instance info",
    "platform info",
    "what version of splunk",
    "which version of splunk",
)

# Global metadata inventory (index=*); no per-index drilldown required.
_METADATA_PHRASES: tuple[str, ...] = (
    "list hosts",
    "show hosts",
    "what hosts",
    "which hosts",
    "list sources",
    "show sources",
    "what sources",
    "which sources",
    "list sourcetypes",
    "show sourcetypes",
    "what sourcetypes",
    "which sourcetypes",
    "metadata inventory",
    "list metadata",
    "show metadata",
)

# Intents that may use splunk_get_* tools without LLM SPL generation.
_DETERMINISTIC_INTENTS: frozenset[str] = frozenset(
    {
        "top_indexes",
        "metadata_inventory",
        "splunk_info",
        "internal_sourcetypes",
    }
)

_TOOL_DEFAULT_INTENTS: dict[str, str] = {
    "splunk_get_indexes": "top_indexes",
    "splunk_get_metadata": "metadata_inventory",
    "splunk_get_info": "splunk_info",
}

_DETERMINISTIC_TOOLS: frozenset[str] = frozenset(
    {
        "splunk_get_indexes",
        "splunk_get_metadata",
        "splunk_get_info",
    }
)


def _normalized_question(question: str) -> str:
    text = str(question or "").strip().lower()
    text = re.sub(r"\s+", " ", text)
    return text


def _contains_any(text: str, phrases: tuple[str, ...]) -> bool:
    return any(phrase in text for phrase in phrases)


def _is_disqualified(text: str) -> str:
    for term in _DISQUALIFY_SUBSTRINGS:
        if term in text:
            return term
    if re.search(r"\blast\s+\d+\s*(m|min|mins|minute|minutes|h|hr|hrs|hour|hours|d|day|days|w|wk|week|weeks)\b", text):
        return "time_window:last_n_units"
    if re.search(r"\blast\s+\d+\b", text):
        return "time_window:last_n"
    if re.search(r"\b(past|previous)\s+\d+\s*(m|min|mins|minute|minutes|h|hr|hrs|hour|hours|d|day|days|w|wk|week|weeks)\b", text):
        return "time_window:past_n_units"
    if re.search(r"\bindex\s*=\s*\S+", text):
        return "explicit_index_filter"
    if re.search(r"\bsourcetype\s*=\s*\S+", text):
        return "explicit_sourcetype_filter"
    return ""


def question_disqualified_for_deterministic(question: str) -> str:
    """Return a disqualifier token when the question needs full search/LLM, else ''."""
    return _is_disqualified(_normalized_question(question))


def classify_mcp_deterministic_eligibility(question: str) -> dict[str, Any]:
    """Return whether MCP chat may skip LLM stages for this question."""
    q = _normalized_question(question)
    if not q:
        return {
            "eligible": False,
            "reason": "empty_question",
            "category": "",
            "selected_tool": "",
            "intent": "",
        }

    disqualifier = _is_disqualified(q)
    if disqualifier:
        return {
            "eligible": False,
            "reason": f"disqualified:{disqualifier}",
            "category": "",
            "selected_tool": "",
            "intent": "",
        }

    template = map_question_to_template(question)
    template_intent = str(template.intent or "").strip()

    selected_tool, tool_reason, metadata_args, chain_mode = determine_splunk_tool(
        question,
        template_intent,
    )

    if (
        selected_tool not in _DETERMINISTIC_TOOLS
        and template_intent in SECURITY_REVIEW_INTENTS
    ):
        return {
            "eligible": False,
            "reason": f"security_intent:{template_intent}",
            "category": "",
            "selected_tool": selected_tool,
            "intent": template_intent,
        }

    if chain_mode:
        return {
            "eligible": False,
            "reason": f"multi_step_chain:{chain_mode}",
            "category": "",
            "selected_tool": selected_tool,
            "intent": template_intent,
        }

    if selected_tool not in _DETERMINISTIC_TOOLS:
        return {
            "eligible": False,
            "reason": f"requires_spl_or_llm:{selected_tool}:{tool_reason}",
            "category": "",
            "selected_tool": selected_tool,
            "intent": template_intent,
        }

    effective_intent = _TOOL_DEFAULT_INTENTS.get(selected_tool, template_intent)
    category = ""
    if selected_tool == "splunk_get_indexes":
        if not (_contains_any(q, _INDEX_INVENTORY_PHRASES) or effective_intent == "top_indexes"):
            return {
                "eligible": False,
                "reason": "index_tool_without_strict_inventory_wording",
                "category": "",
                "selected_tool": selected_tool,
                "intent": effective_intent,
            }
        category = "index_inventory"
    elif selected_tool == "splunk_get_info":
        if not _contains_any(q, _SPLUNK_INFO_PHRASES):
            return {
                "eligible": False,
                "reason": "splunk_info_tool_without_strict_info_wording",
                "category": "",
                "selected_tool": selected_tool,
                "intent": effective_intent,
            }
        category = "splunk_instance_info"
    elif selected_tool == "splunk_get_metadata":
        if not _contains_any(q, _METADATA_PHRASES):
            return {
                "eligible": False,
                "reason": "metadata_tool_without_strict_metadata_wording",
                "category": "",
                "selected_tool": selected_tool,
                "intent": effective_intent,
            }
        category = "metadata_inventory"
    else:
        return {
            "eligible": False,
            "reason": "unsupported_deterministic_tool",
            "category": "",
            "selected_tool": selected_tool,
            "intent": effective_intent,
        }

    if effective_intent not in _DETERMINISTIC_INTENTS:
        return {
            "eligible": False,
            "reason": f"intent_not_inventory:{effective_intent}",
            "category": category,
            "selected_tool": selected_tool,
            "intent": effective_intent,
        }

    return {
        "eligible": True,
        "reason": f"{category}:{tool_reason}",
        "category": category,
        "selected_tool": selected_tool,
        "intent": effective_intent,
        "metadata_args": metadata_args if isinstance(metadata_args, dict) else {},
    }


def resolve_mcp_chat_pipeline(question: str, requested_pipeline: str | None) -> tuple[str, dict[str, Any]]:
    """Choose assisted vs deterministic MCP pipeline for a question."""
    from mcp_pipeline_router import resolve_pipeline_route

    return resolve_pipeline_route(question, requested_pipeline)


def deterministic_mcp_allowlist_summary() -> list[dict[str, str]]:
    """Human-readable allowlist for docs and UI tooltips."""
    rows: list[dict[str, str]] = []
    for phrase in _INDEX_INVENTORY_PHRASES:
        rows.append({"category": "index_inventory", "example": phrase, "tool": "splunk_get_indexes"})
    for phrase in _SPLUNK_INFO_PHRASES:
        rows.append({"category": "splunk_instance_info", "example": phrase, "tool": "splunk_get_info"})
    for phrase in _METADATA_PHRASES:
        rows.append({"category": "metadata_inventory", "example": phrase, "tool": "splunk_get_metadata"})
    return rows
