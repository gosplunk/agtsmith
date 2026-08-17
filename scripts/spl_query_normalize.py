#!/usr/bin/env python3
"""Normalize common SPL writer defects before validation/scoring."""

from __future__ import annotations

import re
from typing import Any

from environment_profile import load_environment_profile


def _split_sourcetype_token(token: str) -> tuple[str, str]:
    """Split a raw sourcetype token into (value, trailing_structural_chars).

    A bare regex match for `sourcetype=X` can accidentally swallow trailing SPL
    syntax that isn't part of the value, e.g. the closing paren in
    `(sourcetype=syslog)`. That trailing punctuation must be preserved by the
    caller (re-appended after the quoted value) or the query's parens/lists go
    unbalanced once the sourcetype is normalized or dropped.
    """
    text = str(token or "").strip()
    trailing = ""
    while text and text[-1] in ")]},":
        trailing = text[-1] + trailing
        text = text[:-1]
    text = text.strip('"').strip("'").strip()
    return text, trailing


def _clean_sourcetype_token(token: str) -> str:
    value, _trailing = _split_sourcetype_token(token)
    return value


def normalize_sourcetype_clauses(query: str) -> str:
    """Quote sourcetype values and strip trailing punctuation from bare tokens."""
    text = str(query or "")
    if not text:
        return text

    def _repl_quoted(match: re.Match[str]) -> str:
        value, trailing = _split_sourcetype_token(match.group(1))
        return f'sourcetype="{value}"{trailing}' if value else match.group(0)

    def _repl_bare(match: re.Match[str]) -> str:
        value, trailing = _split_sourcetype_token(match.group(1))
        return f'sourcetype="{value}"{trailing}' if value else match.group(0)

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


_OR_CHAIN_RE = re.compile(
    r'sourcetype="[^"]+"(?:\s+OR\s+sourcetype="[^"]+")+',
    re.IGNORECASE,
)
_ST_TOKEN_RE = re.compile(r'sourcetype="([^"]+)"', re.IGNORECASE)


def drop_invented_sourcetypes(query: str, *, profile: dict[str, Any] | None = None) -> str:
    """Gracefully degrade sourcetype `OR` lists that include an unknown value.

    Sourcetypes are commonly written as `OR` lists (e.g.
    `(sourcetype=a OR sourcetype=b)`). If at least one alternative in the list
    is a known sourcetype, the query degrades gracefully by dropping only the
    unknown alternative(s) and deduping the rest, rather than hard-failing the
    whole query -- so a canonical or LLM-written query isn't blocked just
    because one option in a list happens to be absent from this environment's
    observed sourcetype inventory.

    This only touches multi-member `OR` chains. A standalone `sourcetype=X`
    with no `OR` alternative, or a chain where *every* member is unknown, is
    left untouched deliberately -- there is nothing valid to fall back to, so
    the downstream structural validator should still hard-block it as a likely
    wholesale hallucination.
    """
    known = _known_sourcetypes(profile)
    if not known:
        return query
    text = normalize_sourcetype_clauses(query)
    text = _remap_hallucinated_sourcetypes(text, known)

    def _replace_chain(match: re.Match[str]) -> str:
        chain = match.group(0)
        members = _ST_TOKEN_RE.findall(chain)
        known_members = [known[m.lower()] for m in members if m.lower() in known]
        if not known_members:
            return chain
        seen: set[str] = set()
        deduped: list[str] = []
        for value in known_members:
            if value.lower() not in seen:
                seen.add(value.lower())
                deduped.append(value)
        return " OR ".join(f'sourcetype="{value}"' for value in deduped)

    text = _OR_CHAIN_RE.sub(_replace_chain, text)
    return re.sub(r"\s{2,}", " ", text).strip()


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
