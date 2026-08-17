#!/usr/bin/env python3
"""Analyst-driven saved query library: save, list, embed, and shortcut retrieval."""

from __future__ import annotations

import re
import unicodedata
from typing import Any

from holdout_firewall import HoldoutLeakageError, filter_holdout_records
from local_learning import (
    _candidate,
    _compile_spl_optimization_repository,
    _sanitize_learning_proposal,
    _utc_now,
    approved_learning_records,
    load_learning_registry,
    save_learning_registry,
    set_learning_record_status,
    write_spl_optimization_repository,
)
from runtime_config import (
    saved_query_auto_threshold,
    saved_query_include_optimization_assets,
    saved_query_save_requires_approval,
    saved_query_shortcut_enabled,
    saved_query_suggest_threshold,
)

SOURCE_ANALYST_SAVED = "analyst_saved"

# Saved queries with these intents answer static inventory, not time-scoped event search.
_INVENTORY_SHORTCUT_INTENTS: frozenset[str] = frozenset(
    {
        "inventory_indexes",
        "top_indexes",
        "metadata_inventory",
        "splunk_info",
        "internal_sourcetypes",
    }
)


def is_savable_spl_query(query: str) -> bool:
    """Return True for non-empty SPL suitable for analyst saves."""
    clean = str(query or "").strip()
    if not clean:
        return False
    if clean.lower().startswith("search "):
        return True
    # Generating commands (| rest, | metadata, | inputlookup, etc.) are valid standalone SPL.
    return clean.startswith("|")


def _normalize_question_text(value: str) -> str:
    text = unicodedata.normalize("NFKC", str(value or "")).casefold()
    return re.sub(r"\s+", " ", text).strip()


def learning_record_text_fields(row: dict[str, Any]) -> tuple[str, str]:
    """Return (question_text, query_text) for a learning / saved-query record."""
    if not isinstance(row, dict):
        return "", ""
    proposal = row.get("proposal", {}) if isinstance(row.get("proposal", {}), dict) else {}
    question = str(row.get("supporting_question", "")).strip()
    if not question:
        question = str(proposal.get("use_when", "")).strip()
    if not question:
        tokens = proposal.get("match_tokens", [])
        if isinstance(tokens, list):
            question = " ".join(str(item).strip() for item in tokens if str(item).strip())
    query = str(proposal.get("query_template", "")).strip()
    if not query:
        query = str(row.get("supporting_spl", "")).strip()
    return question, query


def learning_record_to_index_doc(row: dict[str, Any]) -> dict[str, Any] | None:
    question, query = learning_record_text_fields(row)
    if not question or not query:
        return None
    record_id = str(row.get("id", "")).strip()
    if not record_id:
        return None
    source = str(row.get("source", "")).strip()
    kind = "saved_query" if source == SOURCE_ANALYST_SAVED else "learning"
    intent = str(row.get("intent", "")).strip()
    return {
        "id": f"{kind}:{record_id}",
        "kind": kind,
        "intent": intent,
        "text": f"{question} {intent} {query}",
        "query": query,
        "source": source,
        "record_id": record_id,
    }


def _question_tokens(question: str) -> list[str]:
    return [tok for tok in re.findall(r"[a-z0-9_]{3,}", question.lower()) if tok]


def _proposal_aliases(proposal: dict[str, Any]) -> list[str]:
    aliases = proposal.get("aliases", [])
    if isinstance(aliases, str):
        aliases = [aliases]
    if not isinstance(aliases, list):
        return []
    return [str(item).strip() for item in aliases if str(item).strip()]


def _upsert_registry_record(record: dict[str, Any]) -> dict[str, Any]:
    registry = load_learning_registry()
    records = registry.get("records", [])
    if not isinstance(records, list):
        records = []
    rec_id = str(record.get("id", "")).strip()
    merged = False
    for idx, row in enumerate(records):
        if not isinstance(row, dict):
            continue
        if str(row.get("id", "")).strip() != rec_id:
            continue
        preserved_created = str(row.get("created_at", "")).strip() or str(record.get("created_at", "")).strip()
        record["created_at"] = preserved_created or _utc_now()
        records[idx] = record
        merged = True
        break
    if not merged:
        records.append(record)
    registry["records"] = records
    save_learning_registry(registry)
    existing_repo_payload = registry  # compile uses records list
    write_spl_optimization_repository(
        _compile_spl_optimization_repository(registry.get("records", []))
    )
    return record


def save_analyst_query(
    *,
    question: str,
    query: str,
    intent: str = "",
    aliases: list[str] | None = None,
    use_when: str = "",
    saved_by: str = "",
    result_excerpt: str = "",
) -> dict[str, Any]:
    clean_question = str(question or "").strip()
    clean_query = str(query or "").strip()
    if not clean_question:
        raise ValueError("question is required")
    if not is_savable_spl_query(clean_query):
        raise ValueError("query must start with 'search ' or a generating command such as '| rest'")
    clean_intent = str(intent or "").strip() or "investigation_saved"
    alias_values = [str(item).strip() for item in (aliases or []) if str(item).strip()]
    match_tokens = _question_tokens(clean_question)[:12]
    proposal, _ = _sanitize_learning_proposal(
        "spl_pattern_asset",
        {
            "query_template": clean_query,
            "match_tokens": match_tokens,
            "aliases": alias_values,
            "use_when": str(use_when or clean_question).strip(),
            "why": "analyst_saved",
        },
    )
    record = _candidate(
        intent=clean_intent,
        kind="spl_pattern_asset",
        proposal=proposal,
        reason="analyst_saved_query_library",
        supporting_question=clean_question,
        supporting_spl=clean_query,
        supporting_result_excerpt=str(result_excerpt or "").strip(),
    )
    record["source"] = SOURCE_ANALYST_SAVED
    record["saved_by"] = str(saved_by or "").strip() or "unknown"
    record["saved_at"] = _utc_now()
    record["status"] = "pending" if saved_query_save_requires_approval() else "approved"
    allowed, rejected = filter_holdout_records([record])
    if not allowed:
        raise HoldoutLeakageError("saved query rejected by holdout firewall")
    if rejected:
        raise HoldoutLeakageError("saved query rejected by holdout firewall")
    saved = _upsert_registry_record(record)
    index_doc = learning_record_to_index_doc(saved)
    if index_doc:
        try:
            from spl_embedding_rag import upsert_index_document

            upsert_index_document(index_doc)
        except Exception:
            pass
    return saved


def list_saved_queries(*, status: str = "approved", source: str = SOURCE_ANALYST_SAVED) -> list[dict[str, Any]]:
    status_l = str(status or "").strip().lower()
    source_l = str(source or "").strip().lower()
    rows: list[dict[str, Any]] = []
    data = load_learning_registry()
    records = data.get("records", [])
    if not isinstance(records, list):
        return []
    for row in records:
        if not isinstance(row, dict):
            continue
        if str(row.get("kind", "")).strip() != "spl_pattern_asset":
            continue
        if source_l and str(row.get("source", "")).strip().lower() != source_l:
            continue
        if status_l and str(row.get("status", "")).strip().lower() != status_l:
            continue
        rows.append(row)
    allowed, _rejected = filter_holdout_records(rows)
    return allowed


def get_saved_query_record(record_id: str) -> dict[str, Any] | None:
    wanted = str(record_id or "").strip()
    if not wanted:
        return None
    for row in approved_learning_records():
        if str(row.get("id", "")).strip() == wanted:
            if str(row.get("source", "")).strip() == SOURCE_ANALYST_SAVED or saved_query_include_optimization_assets():
                return row
    return None


def delete_or_stale_saved_query(record_id: str) -> bool:
    return set_learning_record_status(str(record_id or "").strip(), "stale")


def _empty_shortcut() -> dict[str, Any]:
    return {"mode": "none", "score": 0.0, "record": None, "query": "", "reason": ""}


def _shortcut_from_record(record: dict[str, Any], *, score: float, mode: str, reason: str) -> dict[str, Any]:
    _question, query = learning_record_text_fields(record)
    return {
        "mode": mode,
        "score": float(score),
        "record": record,
        "query": query,
        "reason": reason,
        "record_id": str(record.get("id", "")).strip(),
        "intent": str(record.get("intent", "")).strip(),
    }


def resolve_forced_saved_query(record_id: str) -> dict[str, Any]:
    record = get_saved_query_record(record_id)
    if not record:
        return _empty_shortcut()
    return _shortcut_from_record(record, score=1.0, mode="auto", reason="force_saved_query_id")


def _eligible_shortcut_records() -> list[dict[str, Any]]:
    rows = approved_learning_records()
    if saved_query_include_optimization_assets():
        return [row for row in rows if str(row.get("kind", "")).strip() == "spl_pattern_asset"]
    return [
        row
        for row in rows
        if str(row.get("kind", "")).strip() == "spl_pattern_asset"
        and str(row.get("source", "")).strip() == SOURCE_ANALYST_SAVED
    ]


def _saved_query_supports_event_search(record: dict[str, Any]) -> bool:
    """True when the saved SPL searches events/metrics rather than static catalog REST."""
    _question, query = learning_record_text_fields(record)
    spl = str(query or "").strip().lower()
    if not spl:
        return False
    if spl.startswith("search "):
        return True
    if spl.startswith("| tstats") or spl.startswith("| metasearch"):
        return True
    if spl.startswith("| rest") and "/services/data/indexes" in spl:
        return False
    if spl.startswith("| metadata"):
        return False
    if spl.startswith("| inputlookup"):
        return False
    return spl.startswith("|")


def _saved_query_is_inventory_pattern(record: dict[str, Any]) -> bool:
    intent = str(record.get("intent", "")).strip().lower()
    if intent in _INVENTORY_SHORTCUT_INTENTS:
        return True
    return not _saved_query_supports_event_search(record)


def saved_query_shortcut_blocked_reason(question: str, record: dict[str, Any]) -> str:
    """Return a non-empty reason when a saved query must not auto-run for this question."""
    if not _saved_query_is_inventory_pattern(record):
        return ""
    from mcp_deterministic_routing import question_disqualified_for_deterministic

    disqualifier = question_disqualified_for_deterministic(question)
    if disqualifier:
        return f"inventory_saved_query_incompatible:{disqualifier}"
    return ""


def _exact_alias_match(question: str, record: dict[str, Any]) -> bool:
    normalized = _normalize_question_text(question)
    if not normalized:
        return False
    supporting = _normalize_question_text(str(record.get("supporting_question", "")))
    if supporting and supporting == normalized:
        return True
    proposal = record.get("proposal", {}) if isinstance(record.get("proposal", {}), dict) else {}
    for alias in _proposal_aliases(proposal):
        if _normalize_question_text(alias) == normalized:
            return True
    return False


def _hybrid_record_score(question: str, intent: str, record: dict[str, Any], *, query_vec: list[float], alpha: float = 0.75) -> float:
    from spl_embedding_rag import _cosine, _keyword_score

    doc = learning_record_to_index_doc(record)
    if not doc:
        return 0.0
    emb: list[float] = []
    try:
        from spl_embedding_rag import load_index

        data = load_index()
        docs = data.get("documents", [])
        record_id = str(record.get("id", "")).strip()
        if isinstance(docs, list):
            for item in docs:
                if not isinstance(item, dict):
                    continue
                if str(item.get("record_id", "")).strip() == record_id:
                    vector = item.get("embedding", [])
                    if isinstance(vector, list) and vector:
                        emb = [float(x) for x in vector]
                    break
    except Exception:
        emb = []
    if not emb and query_vec:
        try:
            from spl_embedding_rag import embed_query

            text = str(doc.get("text", "")).strip()
            emb = embed_query(text)
        except Exception:
            emb = []
    cos = _cosine(query_vec, emb) if query_vec and emb else 0.0
    kw = _keyword_score(question, intent, doc)
    return alpha * max(cos, 0.0) + (1.0 - alpha) * min(kw / 4.0, 1.0)


def retrieve_saved_query_shortcut(
    question: str,
    intent: str = "",
    *,
    force_saved_query_id: str = "",
) -> dict[str, Any]:
    if force_saved_query_id:
        return resolve_forced_saved_query(force_saved_query_id)
    if not saved_query_shortcut_enabled():
        return _empty_shortcut()
    records = _eligible_shortcut_records()
    if not records:
        return _empty_shortcut()
    for row in records:
        if _exact_alias_match(question, row):
            blocked = saved_query_shortcut_blocked_reason(question, row)
            if blocked:
                continue
            return _shortcut_from_record(row, score=1.0, mode="auto", reason="exact_question_or_alias_match")
    query_vec: list[float] = []
    try:
        from spl_embedding_rag import embed_query

        query_vec = embed_query(f"{question} {intent}".strip())
    except Exception:
        query_vec = []
    auto_threshold = saved_query_auto_threshold()
    suggest_threshold = saved_query_suggest_threshold()
    best_record: dict[str, Any] | None = None
    best_score = 0.0
    for row in records:
        if saved_query_shortcut_blocked_reason(question, row):
            continue
        score = _hybrid_record_score(question, intent, row, query_vec=query_vec)
        if score > best_score:
            best_score = score
            best_record = row
    if best_record is None or best_score <= 0:
        return _empty_shortcut()
    if best_score >= auto_threshold:
        return _shortcut_from_record(best_record, score=best_score, mode="auto", reason="embedding_shortcut_auto")
    if best_score >= suggest_threshold:
        return _shortcut_from_record(best_record, score=best_score, mode="suggest", reason="embedding_shortcut_suggest")
    return _empty_shortcut()
