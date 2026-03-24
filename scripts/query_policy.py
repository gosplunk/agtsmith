#!/usr/bin/env python3
"""Read-only query policy checks for lab Splunk query arguments."""

from __future__ import annotations

import re
from typing import Any

FORBIDDEN_QUERY_TERMS = (
    "| outputlookup",
    "| collect",
    "| delete",
    "| rest",
    "| script",
)

INLINE_CONTROL_PATTERNS = (
    (re.compile(r"\bearliest_time\s*=", flags=re.IGNORECASE), "earliest_time"),
    (re.compile(r"\blatest_time\s*=", flags=re.IGNORECASE), "latest_time"),
    (re.compile(r"\brow_limit\s*=", flags=re.IGNORECASE), "row_limit"),
)


def _extract_indexes(query: str) -> list[str]:
    matches = re.findall(r"index\s*=\s*(?:\"([^\"]+)\"|'([^']+)'|([^\s|()]+))", query, flags=re.IGNORECASE)
    vals: list[str] = []
    for a, b, c in matches:
        v = (a or b or c or "").strip()
        if v:
            vals.append(v)
    out: list[str] = []
    for v in vals:
        if v not in out:
            out.append(v)
    return out


def _question_allows_internal_indexes(question: str) -> bool:
    q = (question or "").lower()
    allow_terms = (
        "splunk internal",
        "internal index",
        "_internal",
        "_audit",
        "splunk auth",
        "splunk login",
        "splunk logins",
        "internal auth",
        "audittrail",
        "splunk platform",
        "scheduler",
        "audittrail",
        "splunkd",
    )
    return any(term in q for term in allow_terms)


def validate_query_args(
    query_args: dict[str, Any],
    *,
    question: str = "",
    max_row_limit: int = 200,
) -> tuple[bool, str]:
    """Validate planned Splunk query args against a minimal lab safety policy."""
    query = str(query_args.get("query", "")).strip()
    earliest = str(query_args.get("earliest_time", "")).strip()
    latest = str(query_args.get("latest_time", "")).strip()
    row_limit = query_args.get("row_limit")

    if not query:
        return False, "missing_query"
    if not query.lower().startswith("search "):
        return False, "query_must_start_with_search"
    lowered = query.lower()
    for term in FORBIDDEN_QUERY_TERMS:
        if term in lowered:
            return False, f"forbidden_query_term:{term.strip()}"
    for pattern, label in INLINE_CONTROL_PATTERNS:
        if pattern.search(query):
            return False, f"query_contains_inline_control:{label}"

    if not earliest or not latest:
        return False, "missing_time_bounds"

    if not isinstance(row_limit, int):
        return False, "row_limit_must_be_int"
    if row_limit < 1:
        return False, "row_limit_must_be_positive"
    if row_limit > max_row_limit:
        return False, f"row_limit_exceeds_max:{max_row_limit}"

    # Hard rule: internal indexes are excluded by default unless the question explicitly asks for them.
    allows_internal = _question_allows_internal_indexes(question)
    indexes = _extract_indexes(query)
    if not allows_internal:
        for idx in indexes:
            if idx == "_*":
                continue
            if idx.startswith("_"):
                return False, "internal_index_requires_explicit_question_context"
        lowered_q = query.lower()
        if "index=*" in lowered_q and "not index=_*" not in lowered_q and "index!=_*" not in lowered_q:
            return False, "wildcard_index_requires_internal_exclusion"

    return True, "query_policy_ok"
