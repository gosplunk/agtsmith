#!/usr/bin/env python3
"""Build a compact SPL-focused RAG index from Splunk Offline Docs search-index.json."""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_SOURCE = Path(
    "/home/joehaga/ai_projects/Splunk4Offlinedocs/artifacts/staging/"
    "splunk_offline_docs/appserver/static/docs/manifest/search-index.json"
)
OUT_DEFAULT = Path("artifacts/knowledge/spl_offline_docs_rag_index.json")

SPL_PATH_MARKERS: tuple[str, ...] = (
    "search-manual",
    "search-reference",
    "search/reference",
    "optimizing-searches",
    "write-better-searches",
    "understanding-spl",
    "search-language",
    "search-commands",
    "command-quick-reference",
    "eval-function",
    "statistical-and-charting",
    "quick-reference-guide",
    "transforming-commands",
)

SPL_COMMANDS: tuple[str, ...] = (
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
    "subsearch",
    "bin",
    "bucket",
    "chart",
    "fields",
    "rename",
    "fillnull",
    "coalesce",
    "spath",
    "regex",
    "replace",
)

FORBIDDEN_TERMS: tuple[str, ...] = (
    "| collect",
    "| sendalert",
    "| outputlookup",
    "| delete",
)


def _normalize_space(text: str) -> str:
    return re.sub(r"\s+", " ", str(text or "").strip())


def _is_spl_relevant(row: dict[str, Any]) -> bool:
    path = str(row.get("path", "")).lower()
    title = str(row.get("title", "")).lower()
    text = _normalize_space(str(row.get("text", "")))
    if len(text) < 80:
        return False
    if any(term in text.lower() for term in FORBIDDEN_TERMS):
        return False
    if any(marker in path for marker in SPL_PATH_MARKERS):
        return True
    if "/search/" in path and any(f"/{cmd}" in path or f"/{cmd}-" in path for cmd in SPL_COMMANDS):
        return True
    if title.startswith("| ") or title.endswith(" command") or title in SPL_COMMANDS:
        return True
    return False


def _trim_text(text: str, *, max_chars: int) -> str:
    cleaned = _normalize_space(text)
    if len(cleaned) <= max_chars:
        return cleaned
    return cleaned[: max_chars - 3].rstrip() + "..."


def build_index(
    rows: list[dict[str, Any]],
    *,
    max_text_chars: int,
) -> dict[str, Any]:
    topics: list[dict[str, str]] = []
    for row in rows:
        if not isinstance(row, dict) or not _is_spl_relevant(row):
            continue
        text = _trim_text(str(row.get("text", "")), max_chars=max_text_chars)
        if not text:
            continue
        topics.append(
            {
                "id": str(row.get("id", "")).strip(),
                "title": _normalize_space(str(row.get("title", ""))),
                "path": str(row.get("path", "")).strip(),
                "product": str(row.get("product", "")).strip(),
                "text": text,
            }
        )
    topics.sort(key=lambda item: (item["path"], item["title"]))
    return {
        "source": "splunk-offline-docs",
        "built_at": datetime.now(timezone.utc).isoformat(),
        "topic_count": len(topics),
        "topics": topics,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Build SPL-focused offline docs RAG index")
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE, help="search-index.json from Splunk Offline Docs")
    parser.add_argument("--out", type=Path, default=OUT_DEFAULT, help="Output compact RAG index JSON")
    parser.add_argument("--max-text-chars", type=int, default=1500, help="Max chars per topic text snippet")
    args = parser.parse_args()

    if not args.source.exists():
        raise SystemExit(f"source_not_found:{args.source}")

    raw = json.loads(args.source.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise SystemExit("source_must_be_json_array")

    payload = build_index(raw, max_text_chars=max(200, args.max_text_chars))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8")
    print(
        json.dumps(
            {
                "out": str(args.out),
                "topic_count": payload["topic_count"],
                "bytes": args.out.stat().st_size,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
