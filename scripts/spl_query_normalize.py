#!/usr/bin/env python3
"""Normalize common SPL writer defects before validation/scoring."""

from __future__ import annotations

import re
from typing import Any

from environment_profile import load_environment_profile


def _clean_sourcetype_token(token: str) -> str:
    text = str(token or "").strip().strip('"').strip("'")
    while text and text[-1] in ")]},":
        text = text[:-1]
    return text.strip()


def normalize_sourcetype_clauses(query: str) -> str:
    """Quote sourcetype values and strip trailing punctuation from bare tokens."""
    text = str(query or "")
    if not text:
        return text

    def _repl_quoted(match: re.Match[str]) -> str:
        value = _clean_sourcetype_token(match.group(1))
        return f'sourcetype="{value}"' if value else match.group(0)

    def _repl_bare(match: re.Match[str]) -> str:
        value = _clean_sourcetype_token(match.group(1))
        return f'sourcetype="{value}"' if value else match.group(0)

    text = re.sub(r'sourcetype="([^"]+)"', _repl_quoted, text, flags=re.IGNORECASE)
    text = re.sub(r"sourcetype=([^\s|\"]+)", _repl_bare, text, flags=re.IGNORECASE)
    return re.sub(r"\s+", " ", text).strip()


def _known_sourcetypes(profile: dict[str, Any] | None) -> dict[str, str]:
    profile = profile if isinstance(profile, dict) else load_environment_profile()
    st_to_idx = profile.get("sourcetype_to_indexes", {}) if isinstance(profile, dict) else {}
    if not isinstance(st_to_idx, dict):
        return {}
    return {str(k).strip().lower(): str(k).strip() for k in st_to_idx.keys() if str(k).strip()}


HALLUCINATED_SOURCETYPE_MAP = {
    "auth-too_small": "auth.log",
    "auth-4": "auth.log",
    "auth-too-small": "auth.log",
}


def _remap_hallucinated_sourcetypes(query: str, known: dict[str, str]) -> str:
    def _repl(match: re.Match[str]) -> str:
        value = _clean_sourcetype_token(match.group(1))
        mapped = HALLUCINATED_SOURCETYPE_MAP.get(value.lower())
        if mapped and mapped.lower() in known:
            return f'sourcetype="{known[mapped.lower()]}"'
        if value.lower() in known:
            return f'sourcetype="{known[value.lower()]}"'
        return match.group(0)

    return re.sub(r'sourcetype="([^"]+)"', _repl, query, flags=re.IGNORECASE)


def drop_invented_sourcetypes(query: str, *, profile: dict[str, Any] | None = None) -> str:
    """Remove sourcetype filters that are not present in the environment profile."""
    known = _known_sourcetypes(profile)
    if not known:
        return query
    text = normalize_sourcetype_clauses(query)
    text = _remap_hallucinated_sourcetypes(text, known)

    def _replace(match: re.Match[str]) -> str:
        value = _clean_sourcetype_token(match.group(1))
        if not value:
            return ""
        if value.lower() in known:
            return f'sourcetype="{known[value.lower()]}"'
        return ""

    parts = re.sub(r'sourcetype="([^"]+)"', _replace, text, flags=re.IGNORECASE)
    parts = re.sub(r"\(\s*\)", "", parts)
    parts = re.sub(r"\(\s*OR\s*OR\s*", "(", parts, flags=re.IGNORECASE)
    parts = re.sub(r"\s{2,}", " ", parts).strip()
    return parts


def normalize_writer_query(
    query: str,
    *,
    profile: dict[str, Any] | None = None,
    drop_unknown_sourcetypes: bool = True,
) -> str:
    text = normalize_sourcetype_clauses(query)
    if drop_unknown_sourcetypes:
        text = drop_invented_sourcetypes(text, profile=profile)
    return text
