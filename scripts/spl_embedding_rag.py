#!/usr/bin/env python3
"""Embedding-backed SPL RAG retrieval (numpy cosine + Ollama embedder)."""

from __future__ import annotations

import json
import math
import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

import urllib.error
import urllib.request

PROJECT_ROOT = Path(__file__).resolve().parent.parent
INDEX_PATH_DEFAULT = PROJECT_ROOT / "artifacts" / "spl_rag" / "embedding_index.json"
OLLAMA_BASE = os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434").rstrip("/")


def index_path() -> Path:
    override = str(os.getenv("SPL_EMBEDDING_INDEX_PATH", "")).strip()
    return Path(override) if override else INDEX_PATH_DEFAULT


def embedding_enabled() -> bool:
    return str(os.getenv("SPL_EMBEDDING_RAG_ENABLED", "1")).strip().lower() not in {"0", "false", "no"}


@lru_cache(maxsize=1)
def load_index(*, path: str | None = None) -> dict[str, Any]:
    idx_path = Path(path) if path else index_path()
    if not idx_path.is_file():
        return {"documents": []}
    try:
        data = json.loads(idx_path.read_text(encoding="utf-8"))
    except Exception:
        return {"documents": []}
    return data if isinstance(data, dict) else {"documents": []}


def index_available() -> bool:
    data = load_index()
    docs = data.get("documents", [])
    return isinstance(docs, list) and len(docs) > 0


def _post_json(url: str, payload: dict[str, Any], *, timeout: float = 120.0) -> dict[str, Any]:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8")
    data = json.loads(raw)
    return data if isinstance(data, dict) else {}


def embed_texts(texts: list[str], *, model: str = "nomic-embed-text") -> list[list[float]]:
    vectors: list[list[float]] = []
    for text in texts:
        payload = {"model": model, "prompt": text}
        try:
            data = _post_json(f"{OLLAMA_BASE}/api/embeddings", payload)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
            vectors.append([])
            continue
        emb = data.get("embedding", [])
        vectors.append([float(x) for x in emb] if isinstance(emb, list) else [])
    return vectors


def embed_query(text: str, *, model: str = "nomic-embed-text") -> list[float]:
    rows = embed_texts([text], model=model)
    return rows[0] if rows else []


def _cosine(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return -1.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0 or nb == 0:
        return -1.0
    return dot / (na * nb)


def _keyword_score(question: str, intent: str, doc: dict[str, Any]) -> float:
    q = question.lower()
    score = 0.0
    intent_l = intent.strip().lower()
    doc_intent = str(doc.get("intent", "")).lower()
    if intent_l and doc_intent == intent_l:
        score += 2.0
    text = f"{doc.get('text', '')} {doc.get('query', '')}".lower()
    for token in re.findall(r"[a-z0-9_]{4,}", q):
        if token in text:
            score += 0.25
    return score


def retrieve_documents(
    question: str,
    *,
    intent: str = "",
    top_k: int = 4,
    alpha: float = 0.75,
) -> list[dict[str, Any]]:
    data = load_index()
    docs = data.get("documents", [])
    if not isinstance(docs, list) or not docs:
        return []
    model = str(data.get("model", "nomic-embed-text"))
    query_vec = embed_query(f"{question} {intent}".strip(), model=model)
    scored: list[tuple[float, dict[str, Any]]] = []
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        emb = doc.get("embedding", [])
        cos = _cosine(query_vec, emb) if query_vec and isinstance(emb, list) else 0.0
        kw = _keyword_score(question, intent, doc)
        hybrid = alpha * cos + (1.0 - alpha) * min(kw / 4.0, 1.0)
        scored.append((hybrid, doc))
    scored.sort(key=lambda item: item[0], reverse=True)
    return [doc for score, doc in scored[: max(1, top_k)] if score > 0]


def build_embedding_context(
    question: str,
    *,
    intent: str = "",
    max_chars: int = 900,
    top_k: int = 4,
) -> str:
    if not embedding_enabled() or not index_available():
        return ""
    hits = retrieve_documents(question, intent=intent, top_k=top_k)
    if not hits:
        return ""
    lines = ["[EMBEDDING_RAG]"]
    for doc in hits:
        kind = str(doc.get("kind", "doc"))
        doc_id = str(doc.get("id", ""))
        query = str(doc.get("query", "")).strip()
        text = str(doc.get("text", "")).strip()
        snippet = query or text
        lines.append(f"- {kind}:{doc_id} {snippet[:220]}")
    merged = "\n".join(lines)
    return merged[:max_chars] if len(merged) > max_chars else merged
