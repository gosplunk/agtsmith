#!/usr/bin/env python3
"""Build sourcetype oracle cards from environment profile (+ optional live MCP)."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from build_environment_profile import _extract_field_inventory, _field_summary_query
from environment_profile import PROFILE_PATH_DEFAULT, load_environment_profile
from minimal_question_to_answer import map_question_to_template, run_splunk_query_args, template_to_query_args
from query_templates import TEMPLATES
from sourcetype_cards import CARDS_PATH_DEFAULT, semantic_for_sourcetype

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _truncate(text: str, limit: int = 240) -> str:
    text = " ".join(str(text or "").split())
    if len(text) <= limit:
        return text
    return text[: limit - 3].rstrip() + "..."


def _gold_fragment_for_sourcetype(sourcetype: str, indexes: list[str]) -> str:
    st_l = sourcetype.lower()
    for template in TEMPLATES:
        query = str(template_to_query_args(template, f"investigate {template.intent}").get("query", ""))
        if st_l in query.lower():
            return _truncate(query, 320)
    idx_expr = " OR ".join(f"index={idx}" for idx in indexes[:3]) if indexes else "index=*"
    return f'search ({idx_expr}) sourcetype="{sourcetype}" | stats count'


def _anti_patterns_for(sourcetype: str, semantic: dict[str, Any]) -> list[str]:
    st_l = sourcetype.lower()
    patterns: list[str] = []
    if "linux" in st_l or st_l in {"auth.log", "linux_secure", "syslog"}:
        patterns.append("do not mix Windows EventCode=4625 with Linux sourcetypes")
    if "xmlwineventlog" in st_l or "wineventlog" in st_l:
        patterns.append("do not use Linux auth.log filters on Windows XmlWinEventLog")
    if semantic.get("use_cases"):
        patterns.append(f"prefer use_cases={','.join(str(x) for x in semantic.get('use_cases', [])[:3])}")
    return patterns[:4]


def _tags_for(sourcetype: str, semantic: dict[str, Any]) -> list[str]:
    tags: list[str] = []
    st_l = sourcetype.lower()
    if any(x in st_l for x in ("linux", "auth", "secure", "syslog")):
        tags.append("linux")
    if any(x in st_l for x in ("win", "xml", "sysmon")):
        tags.append("windows")
    if any(x in st_l for x in ("access", "apache", "http", "nginx")):
        tags.append("web")
    for uc in semantic.get("use_cases", []) if isinstance(semantic.get("use_cases"), list) else []:
        text = str(uc).strip()
        if text:
            tags.append(text)
    return sorted(set(tags))[:8]


def _build_card_from_profile(
    sourcetype: str,
    *,
    indexes: list[str],
    field_rows: list[dict[str, Any]],
    semantic: dict[str, Any],
) -> dict[str, Any]:
    top_fields = [str(row.get("field", "")).strip() for row in field_rows[:12] if str(row.get("field", "")).strip()]
    field_aliases = semantic.get("field_aliases", {}) if isinstance(semantic.get("field_aliases"), dict) else {}
    sample_values: list[str] = []
    for row in field_rows[:5]:
        for val in row.get("sample_values", []) if isinstance(row.get("sample_values"), list) else []:
            text = str(val).strip()
            if text:
                sample_values.append(text)
            if len(sample_values) >= 3:
                break
        if len(sample_values) >= 3:
            break
    sample_raw = _truncate(" | ".join(sample_values), 180)
    gold = _gold_fragment_for_sourcetype(sourcetype, indexes)
    anti = _anti_patterns_for(sourcetype, semantic)
    tags = _tags_for(sourcetype, semantic)
    card_text = (
        f"Sourcetype {sourcetype} on indexes {', '.join(indexes[:5])}. "
        f"Top fields: {', '.join(top_fields[:8])}. "
        f"Gold fragment: {gold}. "
        f"Avoid: {'; '.join(anti)}."
    )
    return {
        "sourcetype": sourcetype,
        "indexes": indexes,
        "top_fields": top_fields,
        "field_aliases": field_aliases,
        "sample_raw_snippet": sample_raw,
        "gold_query_fragment": gold,
        "anti_patterns": anti,
        "tags": tags,
        "use_cases": list(semantic.get("use_cases", [])) if isinstance(semantic.get("use_cases"), list) else [],
        "card_text": card_text,
    }


def build_cards_from_profile(profile: dict[str, Any], *, scope: str = "all") -> list[dict[str, Any]]:
    if not isinstance(profile, dict):
        return []
    st_to_idx = profile.get("sourcetype_to_indexes", {})
    if not isinstance(st_to_idx, dict):
        st_to_idx = {}
    field_inventory = profile.get("sourcetype_field_inventory", {})
    if not isinstance(field_inventory, dict):
        field_inventory = {}
    internal_indexes = {"_internal", "_audit", "_introspection"}
    linux_indexes = {"linux", "soc_linux"}
    cards: list[dict[str, Any]] = []
    for sourcetype in sorted(st_to_idx.keys()):
        indexes_raw = st_to_idx.get(sourcetype, [])
        indexes = [str(i).strip() for i in indexes_raw if str(i).strip()] if isinstance(indexes_raw, list) else []
        if scope == "internal" and not any(idx in internal_indexes for idx in indexes):
            continue
        if scope == "linux" and not any(idx in linux_indexes for idx in indexes):
            continue
        field_rows = field_inventory.get(sourcetype, [])
        if not isinstance(field_rows, list):
            field_rows = []
        semantic = semantic_for_sourcetype(sourcetype)
        cards.append(_build_card_from_profile(sourcetype, indexes=indexes, field_rows=field_rows, semantic=semantic))
    return cards


def enrich_card_live(sourcetype: str, indexes: list[str], *, sample_size: int = 25) -> list[dict[str, Any]]:
    query_args = {
        "query": _field_summary_query(indexes, sourcetype, sample_size),
        "earliest_time": "-7d",
        "latest_time": "now",
        "row_limit": sample_size,
    }
    data = run_splunk_query_args(query_args, intent="sourcetype_card_live", summary_hint="card field inventory")
    return _extract_field_inventory(data)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build sourcetype oracle cards from environment profile")
    parser.add_argument("--profile", default=str(PROFILE_PATH_DEFAULT))
    parser.add_argument("--out", default=str(CARDS_PATH_DEFAULT))
    parser.add_argument("--sourcetype", default="", help="Build/enrich one sourcetype only")
    parser.add_argument("--live", action="store_true", help="Fetch fieldsummary via MCP when inventory missing")
    parser.add_argument("--top-n", type=int, default=0, help="Limit to top N sourcetypes by index count")
    parser.add_argument(
        "--scope",
        default="all",
        choices=("all", "internal", "linux"),
        help="Build cards for all sourcetypes or only _internal/_audit/_introspection or linux index",
    )
    args = parser.parse_args()

    profile = load_environment_profile(args.profile)
    existing_cards = []
    out_path = Path(args.out)
    if out_path.is_file():
        try:
            existing_cards = json.loads(out_path.read_text(encoding="utf-8"))
        except Exception:
            existing_cards = []
    if not isinstance(existing_cards, list):
        existing_cards = []

    cards = build_cards_from_profile(profile, scope=str(args.scope))
    if args.top_n > 0:
        cards = cards[: args.top_n]

    if args.sourcetype.strip():
        st = args.sourcetype.strip()
        st_to_idx = profile.get("sourcetype_to_indexes", {}) if isinstance(profile, dict) else {}
        indexes = [str(i) for i in st_to_idx.get(st, []) if str(i).strip()] if isinstance(st_to_idx, dict) else []
        field_rows: list[dict[str, Any]] = []
        inv = profile.get("sourcetype_field_inventory", {}) if isinstance(profile, dict) else {}
        if isinstance(inv, dict) and isinstance(inv.get(st), list):
            field_rows = inv.get(st, [])
        if args.live and not field_rows and indexes:
            field_rows = enrich_card_live(st, indexes)
        semantic = semantic_for_sourcetype(st)
        one = _build_card_from_profile(st, indexes=indexes, field_rows=field_rows, semantic=semantic)
        by_st = {str(c.get("sourcetype", "")): c for c in existing_cards if isinstance(c, dict)}
        by_st[st] = one
        cards = [by_st[k] for k in sorted(by_st.keys())]
    elif args.live:
        inv = profile.get("sourcetype_field_inventory", {}) if isinstance(profile, dict) else {}
        st_to_idx = profile.get("sourcetype_to_indexes", {}) if isinstance(profile, dict) else {}
        enriched: list[dict[str, Any]] = []
        for card in cards:
            st = str(card.get("sourcetype", ""))
            field_rows = inv.get(st, []) if isinstance(inv, dict) else []
            indexes = st_to_idx.get(st, []) if isinstance(st_to_idx, dict) else card.get("indexes", [])
            if (not field_rows) and indexes:
                try:
                    field_rows = enrich_card_live(st, list(indexes))
                except Exception:
                    field_rows = []
            semantic = semantic_for_sourcetype(st)
            enriched.append(_build_card_from_profile(st, indexes=list(indexes), field_rows=list(field_rows or []), semantic=semantic))
        cards = enriched

    payload = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "source_profile": str(args.profile),
        "card_count": len(cards),
        "cards": cards,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(cards, indent=2), encoding="utf-8")
    meta_path = out_path.with_suffix(".meta.json")
    meta_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"cards={len(cards)} out={out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
