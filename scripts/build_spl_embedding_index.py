#!/usr/bin/env python3
"""Build SPL embedding index for hybrid RAG retrieval."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from holdout_firewall import filter_holdout_records
from local_learning import approved_learning_records
from minimal_question_to_answer import map_question_to_template, template_to_query_args
from query_templates import TEMPLATES
from sourcetype_cards import load_cards

PROJECT_ROOT = Path(__file__).resolve().parent.parent
INDEX_PATH_DEFAULT = PROJECT_ROOT / "artifacts" / "spl_rag" / "embedding_index.json"
CASES_PATH = PROJECT_ROOT / "benchmarks" / "spl_cases.json"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_cases() -> list[dict[str, Any]]:
    if not CASES_PATH.is_file():
        return []
    try:
        rows = json.loads(CASES_PATH.read_text(encoding="utf-8"))
    except Exception:
        return []
    return [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []


def build_documents() -> list[dict[str, Any]]:
    docs: list[dict[str, Any]] = []
    for template in TEMPLATES:
        query = str(template_to_query_args(template, f"investigate {template.intent}").get("query", "")).strip()
        docs.append(
            {
                "id": f"template:{template.intent}",
                "kind": "template",
                "intent": template.intent,
                "text": f"{template.intent} {query}",
                "query": query,
            }
        )
    for case in _load_cases():
        q = str(case.get("question", "")).strip()
        intent = str(case.get("intent", "")).strip()
        query = str(case.get("expected_query_contains", case.get("query", ""))).strip()
        if not q:
            continue
        docs.append(
            {
                "id": f"case:{case.get('id', len(docs))}",
                "kind": "benchmark_case",
                "intent": intent,
                "text": f"{q} {intent} {query}",
                "query": query,
            }
        )
    for card in load_cards():
        st = str(card.get("sourcetype", "")).strip()
        if not st:
            continue
        docs.append(
            {
                "id": f"card:{st}",
                "kind": "sourcetype_card",
                "intent": "",
                "text": str(card.get("card_text", "")),
                "query": str(card.get("gold_query_fragment", "")),
                "sourcetype": st,
            }
        )
    for row in approved_learning_records():
        q = str(row.get("question", "")).strip()
        query = str(row.get("query", "")).strip()
        if not q or not query:
            continue
        docs.append(
            {
                "id": f"learning:{row.get('id', len(docs))}",
                "kind": "learning",
                "intent": str(row.get("intent", "")),
                "text": f"{q} {query}",
                "query": query,
            }
        )
    allowed, _rejected = filter_holdout_records(docs)
    return allowed


def main() -> int:
    parser = argparse.ArgumentParser(description="Build SPL embedding index")
    parser.add_argument("--out", default=str(INDEX_PATH_DEFAULT))
    parser.add_argument("--model", default="nomic-embed-text")
    parser.add_argument("--dry-run", action="store_true", help="Build document list without embedding")
    parser.add_argument("--skip-embed", action="store_true", help="Write index documents without calling Ollama")
    args = parser.parse_args()

    docs = build_documents()
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if args.dry_run:
        payload = {"timestamp_utc": _utc_now(), "document_count": len(docs), "documents": docs[:5]}
        print(json.dumps(payload, indent=2))
        return 0

    if args.skip_embed:
        vectors: list[list[float]] = [[] for _ in docs]
    else:
        from spl_embedding_rag import embed_texts

        texts = [str(doc.get("text", "")) for doc in docs]
        vectors = embed_texts(texts, model=args.model)
    for doc, vector in zip(docs, vectors):
        if vector:
            doc["embedding"] = vector
    payload = {
        "timestamp_utc": _utc_now(),
        "model": args.model,
        "document_count": len(docs),
        "documents": docs,
    }
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"documents={len(docs)} out={out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
