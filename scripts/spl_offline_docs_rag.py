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


def _index_path() -> Path:
    override = str(os.getenv("SPL_OFFLINE_DOCS_RAG_INDEX", "")).strip()
    if override:
        return Path(override)
    return INDEX_PATH_DEFAULT


def _question_tokens(question: str, *, intent: str = "") -> set[str]:
    q = f"{question} {intent}".lower()
    tokens = {t for t in re.findall(r"[a-z0-9_]{3,}", q)}
    dims = infer_question_dimensions(question)
    for key in ("platforms", "activities", "shapes"):
        for value in dims.get(key, []):
            token = str(value).strip().lower()
            if token:
                tokens.add(token)
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


def _score_topic(row: dict[str, Any], tokens: set[str]) -> int:
    title = str(row.get("title", "")).lower()
    path = str(row.get("path", "")).lower()
    text = str(row.get("text", "")).lower()
    score = 0
    for token in tokens:
        if token in title:
            score += 8
        if token in path:
            score += 4
        if token in text:
            score += 2
    for cmd in SPL_COMMAND_TOKENS:
        if cmd in tokens and (cmd in title or cmd in path or f"| {cmd}" in text or f" {cmd} " in text):
            score += 10
    if "search-reference" in path or "search-manual" in path:
        score += 3
    if "optimizing-searches" in path:
        score += 2
    return score


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
    for row in topics:
        text = str(row.get("text", ""))
        lowered = text.lower()
        if any(term in lowered for term in FORBIDDEN_SNIPPET_TERMS):
            continue
        score = _score_topic(row, tokens)
        if score <= 0 and not tokens:
            score = 1
        if score <= 0:
            continue
        ranked.append((score, row))

    if not ranked:
        return ""

    ranked.sort(key=lambda item: item[0], reverse=True)
    lines: list[str] = ["[SPL_OFFLINE_DOCS]"]
    built_at = str(payload.get("built_at", "")).strip()
    if built_at:
        lines.append(f"index_built_at={built_at}")
    lines.append("Curated SPL guidance from help.splunk.com (offline docs corpus).")

    budget = max(200, max_chars)
    used = len("\n".join(lines))
    per_topic = max(180, int((budget - used) / max(1, max_topics)))

    for _score, row in ranked[: max(1, max_topics)]:
        title = str(row.get("title", "")).strip()
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
            break
        lines.append(block)
        used += len(block) + 2

    return "\n".join(lines).strip()


def clear_offline_docs_cache() -> None:
    _load_index.cache_clear()
