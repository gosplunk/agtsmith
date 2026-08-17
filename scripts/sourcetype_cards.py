#!/usr/bin/env python3
"""Load and select sourcetype oracle cards for writer/RAG prompts."""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from environment_profile import KNOWN_SOURCETYPE_SEMANTICS, load_environment_profile
from minimal_question_to_answer import map_question_to_template

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CARDS_PATH_DEFAULT = PROJECT_ROOT / "artifacts" / "environment" / "sourcetype_cards.json"
INTERNAL_CARDS_PATH_DEFAULT = PROJECT_ROOT / "artifacts" / "environment" / "internal_sourcetype_cards.json"
LINUX_CARDS_PATH_DEFAULT = PROJECT_ROOT / "artifacts" / "environment" / "linux_sourcetype_cards.json"


def cards_path() -> Path:
    override = str(__import__("os").environ.get("SPL_SOURCETYPE_CARDS_PATH", "")).strip()
    return Path(override) if override else CARDS_PATH_DEFAULT


def internal_cards_path() -> Path:
    override = str(__import__("os").environ.get("SPL_INTERNAL_SOURCETYPE_CARDS_PATH", "")).strip()
    return Path(override) if override else INTERNAL_CARDS_PATH_DEFAULT


def linux_cards_path() -> Path:
    override = str(__import__("os").environ.get("SPL_LINUX_SOURCETYPE_CARDS_PATH", "")).strip()
    return Path(override) if override else LINUX_CARDS_PATH_DEFAULT


def _question_is_linux_dataset(question: str) -> bool:
    q = (question or "").lower()
    return any(
        term in q
        for term in (
            "index=linux",
            "linux index",
            "linux sourcetype",
            "linux host",
            "linux auth",
            "linux sudo",
            "linux audit",
            "linux failed login",
            "linux session",
        )
    ) or bool(re.search(r"\blinux\b.*\b(?:sourcetype|host|auth|sudo|audit|session)\b", q))


def _question_is_internal_platform(question: str) -> bool:
    q = (question or "").lower()
    return any(
        term in q
        for term in (
            "_internal",
            "splunk internal",
            "internal index",
            "_audit",
            "scheduler",
            "splunkd",
            "forwarder",
            "license usage",
            "splunk license",
        )
    )


@lru_cache(maxsize=2)
def load_cards(*, path: str | None = None) -> list[dict[str, Any]]:
    card_path = Path(path) if path else cards_path()
    if not card_path.is_file():
        return []
    try:
        rows = json.loads(card_path.read_text(encoding="utf-8"))
    except Exception:
        return []
    if not isinstance(rows, list):
        return []
    return [row for row in rows if isinstance(row, dict) and str(row.get("sourcetype", "")).strip()]


@lru_cache(maxsize=1)
def load_internal_cards(*, path: str | None = None) -> list[dict[str, Any]]:
    card_path = Path(path) if path else internal_cards_path()
    if not card_path.is_file():
        return []
    try:
        rows = json.loads(card_path.read_text(encoding="utf-8"))
    except Exception:
        return []
    if not isinstance(rows, list):
        return []
    return [row for row in rows if isinstance(row, dict) and str(row.get("sourcetype", "")).strip()]


@lru_cache(maxsize=1)
def load_linux_cards(*, path: str | None = None) -> list[dict[str, Any]]:
    card_path = Path(path) if path else linux_cards_path()
    if not card_path.is_file():
        return []
    try:
        rows = json.loads(card_path.read_text(encoding="utf-8"))
    except Exception:
        return []
    if not isinstance(rows, list):
        return []
    return [row for row in rows if isinstance(row, dict) and str(row.get("sourcetype", "")).strip()]


def card_for_sourcetype(sourcetype: str, *, cards: list[dict[str, Any]] | None = None) -> dict[str, Any] | None:
    st = str(sourcetype or "").strip()
    if not st:
        return None
    rows = cards if cards is not None else load_cards()
    st_l = st.lower()
    for row in rows:
        if str(row.get("sourcetype", "")).strip().lower() == st_l:
            return row
    return None


def _score_card(question: str, intent: str, card: dict[str, Any]) -> int:
    q = question.lower()
    intent_l = intent.strip().lower()
    score = 0
    st = str(card.get("sourcetype", "")).lower()
    if st and st in q:
        score += 8
    tags = [str(t).lower() for t in card.get("tags", []) if str(t).strip()]
    for tag in tags:
        if tag and tag in q:
            score += 2
    use_cases = [str(u).lower() for u in card.get("use_cases", []) if str(u).strip()]
    if intent_l and intent_l in use_cases:
        score += 10
    if intent_l and intent_l in q:
        score += 1
    card_text = str(card.get("card_text", "")).lower()
    for token in re.findall(r"[a-z0-9_]{4,}", q):
        if token in card_text:
            score += 1
    return score


def cards_for_question(
    question: str,
    *,
    intent: str = "",
    max_cards: int = 3,
    cards: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    rows = cards if cards is not None else load_cards()
    if cards is None and _question_is_internal_platform(question):
        internal_rows = load_internal_cards()
        if internal_rows:
            by_st = {str(r.get("sourcetype", "")).lower(): r for r in rows if isinstance(r, dict)}
            for row in internal_rows:
                st_key = str(row.get("sourcetype", "")).lower()
                if st_key:
                    by_st[st_key] = row
            rows = list(by_st.values())
    if cards is None and _question_is_linux_dataset(question):
        linux_rows = load_linux_cards()
        if linux_rows:
            by_st = {str(r.get("sourcetype", "")).lower(): r for r in rows if isinstance(r, dict)}
            for row in linux_rows:
                st_key = str(row.get("sourcetype", "")).lower()
                if st_key:
                    by_st[st_key] = row
            rows = list(by_st.values())
    if not rows:
        return []
    intent_name = intent.strip() or map_question_to_template(question).intent
    scored = [( _score_card(question, intent_name, row), row) for row in rows]
    scored.sort(key=lambda item: item[0], reverse=True)
    chosen: list[dict[str, Any]] = []
    for score, row in scored:
        if score <= 0 and chosen:
            break
        if score <= 0 and not chosen:
            # fallback: first card matching template intent indexes
            mapped = map_question_to_template(question)
            if mapped.intent == intent_name:
                chosen.append(row)
                break
            continue
        chosen.append(row)
        if len(chosen) >= max(1, max_cards):
            break
    return chosen[:max_cards]


def format_cards_context(cards: list[dict[str, Any]], *, max_chars: int = 900) -> str:
    if not cards:
        return ""
    lines = ["[SOURCETYPE_CARDS]"]
    for card in cards:
        st = str(card.get("sourcetype", "")).strip()
        indexes = card.get("indexes", [])
        fields = card.get("top_fields", [])
        idx_text = ", ".join(str(i) for i in indexes[:6]) if isinstance(indexes, list) else ""
        field_text = ", ".join(str(f) for f in fields[:8]) if isinstance(fields, list) else ""
        fragment = str(card.get("gold_query_fragment", "")).strip()
        anti = card.get("anti_patterns", [])
        anti_text = "; ".join(str(a) for a in anti[:3]) if isinstance(anti, list) else ""
        lines.append(
            f"- sourcetype={st} indexes=[{idx_text}] top_fields=[{field_text}] "
            f"fragment={fragment[:180]} anti={anti_text}"
        )
    text = "\n".join(lines)
    return text[:max_chars] if len(text) > max_chars else text


def semantic_for_sourcetype(sourcetype: str) -> dict[str, Any]:
    st = str(sourcetype or "").strip()
    if not st:
        return {}
    if st in KNOWN_SOURCETYPE_SEMANTICS:
        return dict(KNOWN_SOURCETYPE_SEMANTICS[st])
    st_l = st.lower()
    for key, value in KNOWN_SOURCETYPE_SEMANTICS.items():
        if key.lower() == st_l:
            return dict(value)
    return {}
