#!/usr/bin/env python3
"""Build the domain/sourcetype embedding index used for domain retrieval.

Embeds each (index, sourcetype) pair's semantic description once so
`domain_embedding_retrieval.retrieve_domain_scores` can rank candidates by
cosine similarity instead of exhaustive keyword scoring. Run this after
`env-profile-build` (it reads the current environment profile) -- it is
already wired into `make env-profile-refresh`.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from domain_embedding_retrieval import DOMAIN_INDEX_PATH_DEFAULT, build_domain_documents
from environment_profile import PROFILE_PATH_DEFAULT, attach_semantics, load_environment_profile


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def main() -> int:
    parser = argparse.ArgumentParser(description="Build domain/sourcetype embedding index")
    parser.add_argument("--out", default=str(DOMAIN_INDEX_PATH_DEFAULT))
    parser.add_argument("--profile-path", default=str(PROFILE_PATH_DEFAULT))
    parser.add_argument("--model", default="nomic-embed-text")
    parser.add_argument("--dry-run", action="store_true", help="Build document list without embedding")
    parser.add_argument("--skip-embed", action="store_true", help="Write index documents without calling Ollama")
    args = parser.parse_args()

    profile = attach_semantics(load_environment_profile(args.profile_path))
    docs = build_domain_documents(profile)
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
    embedded_count = sum(1 for doc in docs if doc.get("embedding"))
    payload = {
        "timestamp_utc": _utc_now(),
        "model": args.model,
        "document_count": len(docs),
        "embedded_count": embedded_count,
        "documents": docs,
    }
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"documents={len(docs)} embedded={embedded_count} out={out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
