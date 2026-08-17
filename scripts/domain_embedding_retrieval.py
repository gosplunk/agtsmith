#!/usr/bin/env python3
"""Embedding-based domain/sourcetype retrieval for authoritative domain resolution.

Replaces exhaustive keyword scoring with a similarity lookup: each
(index, sourcetype) pair in the environment profile is embedded once (via
`build_domain_embedding_index.py`, using the same Ollama nomic-embed-text
pipeline as `spl_embedding_rag.py`) and cached to disk. At query time this
module embeds the question (optionally enriched with a structured hint from
`edge_question_classifier`) and ranks cached domains by cosine similarity.

This is additive by design: `environment_profile.resolve_authoritative_domains_for_question`
blends these scores into its existing keyword-based score rather than
replacing it, so behavior is unchanged whenever the index is missing, stale,
or the embedding backend is unreachable -- every function here degrades to
an empty result on any failure.
"""

from __future__ import annotations

import json
import math
import os
from functools import lru_cache
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DOMAIN_INDEX_PATH_DEFAULT = PROJECT_ROOT / "artifacts" / "spl_rag" / "domain_embedding_index.json"


def domain_index_path() -> Path:
    override = str(os.getenv("SPL_DOMAIN_EMBEDDING_INDEX_PATH", "")).strip()
    return Path(override) if override else DOMAIN_INDEX_PATH_DEFAULT


def domain_embedding_enabled() -> bool:
    return str(os.getenv("SPL_DOMAIN_EMBEDDING_RETRIEVAL_ENABLED", "1")).strip().lower() not in {"0", "false", "no"}


@lru_cache(maxsize=1)
def _load_domain_index_cached(path_str: str) -> dict[str, Any]:
    idx_path = Path(path_str)
    if not idx_path.is_file():
        return {"documents": []}
    try:
        data = json.loads(idx_path.read_text(encoding="utf-8"))
    except Exception:
        return {"documents": []}
    return data if isinstance(data, dict) else {"documents": []}


def load_domain_index(*, path: str | Path | None = None) -> dict[str, Any]:
    idx_path = Path(path) if path else domain_index_path()
    return _load_domain_index_cached(str(idx_path))


def domain_index_available(*, path: str | Path | None = None) -> bool:
    data = load_domain_index(path=path)
    docs = data.get("documents", [])
    return isinstance(docs, list) and len(docs) > 0


def _sourcetype_semantic_text(sourcetype: str, semantics: dict[str, Any]) -> str:
    sem = semantics.get(sourcetype, {}) if isinstance(semantics, dict) else {}
    if not isinstance(sem, dict):
        return ""
    description = str(sem.get("description", "")).strip()
    use_cases = [str(item).strip() for item in sem.get("use_cases", []) if str(item).strip()] if isinstance(sem.get("use_cases"), list) else []
    parts = [description]
    if use_cases:
        parts.append("use cases: " + ", ".join(use_cases))
    return " ".join(part for part in parts if part)


def build_domain_documents(profile: dict[str, Any]) -> list[dict[str, Any]]:
    """Build one embeddable document per (index, sourcetype) pair from a profile.

    `profile` is expected to already have semantics attached (i.e. the output
    of `environment_profile.attach_semantics(...)`).
    """
    indexes = profile.get("indexes", []) if isinstance(profile, dict) else []
    semantics = profile.get("sourcetype_semantics", {}) if isinstance(profile, dict) else {}
    if not isinstance(semantics, dict):
        semantics = {}
    docs: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    if not isinstance(indexes, list):
        return docs
    for row in indexes:
        if not isinstance(row, dict):
            continue
        idx = str(row.get("index", "")).strip()
        sourcetypes = [str(st).strip() for st in row.get("sourcetypes", []) if str(st).strip()]
        if not idx or not sourcetypes:
            continue
        for st in sourcetypes:
            key = (idx.lower(), st.lower())
            if key in seen:
                continue
            seen.add(key)
            sem_text = _sourcetype_semantic_text(st, semantics)
            text = f"index {idx} sourcetype {st}" + (f" - {sem_text}" if sem_text else "")
            docs.append(
                {
                    "id": f"domain:{idx}:{st}",
                    "index": idx,
                    "sourcetype": st,
                    "text": text,
                }
            )
    return docs


def _cosine(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return -1.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0 or nb == 0:
        return -1.0
    return dot / (na * nb)


def retrieve_domain_scores(
    question: str,
    *,
    query_hint: str = "",
    path: str | Path | None = None,
) -> dict[str, float]:
    """Return a `{"index::sourcetype": cosine_score}` map for `question`.

    Cosine scores are clamped to [0, 1] (negative similarity treated as 0).
    Returns {} on any failure (no index, no embedder reachable, etc.) so
    callers can treat this purely as an optional additive signal.
    """
    if not domain_embedding_enabled():
        return {}
    question = str(question or "").strip()
    if not question:
        return {}
    data = load_domain_index(path=path)
    docs = data.get("documents", [])
    if not isinstance(docs, list) or not docs:
        return {}
    model = str(data.get("model", "nomic-embed-text"))
    query_text = f"{question} {query_hint}".strip() if query_hint else question
    try:
        from spl_embedding_rag import embed_query

        query_vec = embed_query(query_text, model=model)
    except Exception:
        return {}
    if not query_vec:
        return {}
    scores: dict[str, float] = {}
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        idx = str(doc.get("index", "")).strip()
        st = str(doc.get("sourcetype", "")).strip()
        emb = doc.get("embedding", [])
        if not idx or not st or not isinstance(emb, list) or not emb:
            continue
        cos = _cosine(query_vec, emb)
        if cos <= 0:
            continue
        key = f"{idx.lower()}::{st.lower()}"
        if cos > scores.get(key, 0.0):
            scores[key] = cos
    return scores


def index_level_scores(domain_scores: dict[str, float]) -> dict[str, float]:
    """Collapse `{"index::sourcetype": score}` into `{"index": max_score}`."""
    out: dict[str, float] = {}
    for key, score in domain_scores.items():
        idx = key.split("::", 1)[0]
        if score > out.get(idx, 0.0):
            out[idx] = score
    return out
