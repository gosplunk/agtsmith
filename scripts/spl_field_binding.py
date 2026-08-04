#!/usr/bin/env python3
"""Bind planner hints to environment profile / sourcetype cards / MCP fallback."""

from __future__ import annotations

import re
from typing import Any

from environment_profile import (
    load_environment_profile,
    suggest_domains_for_question,
    validate_query_against_environment,
)
from minimal_question_to_answer import map_question_to_template, template_to_query_args
from question_intelligence import (
    extract_explicit_dataset_locks,
    extract_explicit_sourcetype,
    infer_time_window,
)
from sourcetype_cards import card_for_sourcetype, cards_for_question, format_cards_context


def _extract_sourcetype_hint(question: str, planner: dict[str, Any]) -> str:
    explicit = extract_explicit_sourcetype(question)
    if explicit:
        return explicit
    analytical_plan = planner.get("analytical_plan", {})
    if isinstance(analytical_plan, dict):
        datasets = analytical_plan.get("datasets", [])
        if isinstance(datasets, list):
            for branch in datasets:
                if isinstance(branch, dict) and str(branch.get("sourcetype", "")).strip():
                    return str(branch.get("sourcetype", "")).strip()
    for key in ("sourcetype", "preferred_sourcetype"):
        val = str(planner.get(key, "")).strip()
        if val:
            return val
    tool_args = planner.get("tool_args", {})
    if isinstance(tool_args, dict):
        query = str(tool_args.get("query", ""))
        m = re.search(r'sourcetype="([^"]+)"', query, re.I)
        if m:
            return m.group(1)
        m = re.search(r"sourcetype=([^\s|]+)", query, re.I)
        if m:
            return m.group(1).strip('"')
    mapped = map_question_to_template(question)
    query = str(template_to_query_args(mapped, question).get("query", ""))
    m = re.search(r'sourcetype="([^"]+)"', query, re.I)
    if m:
        return m.group(1)
    cards = cards_for_question(question, intent=str(planner.get("intent", mapped.intent)), max_cards=1)
    if cards:
        return str(cards[0].get("sourcetype", "")).strip()
    return ""


def _inventory_field_rows(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [dict(row) for row in value if isinstance(row, dict)]
    if isinstance(value, dict):
        rows = value.get("fields", [])
        if isinstance(rows, list):
            return [dict(row) for row in rows if isinstance(row, dict)]
    return []


def _index_expr_for_sourcetype(profile: dict[str, Any], sourcetype: str) -> str:
    st_to_idx = profile.get("sourcetype_to_indexes", {}) if isinstance(profile, dict) else {}
    if not isinstance(st_to_idx, dict):
        return "index=* NOT index=_*"
    indexes = st_to_idx.get(sourcetype, [])
    if not isinstance(indexes, list) or not indexes:
        return "index=* NOT index=_*"
    cleaned = [str(i).strip() for i in indexes if str(i).strip()]
    if not cleaned:
        return "index=* NOT index=_*"
    if len(cleaned) == 1:
        return f"index={cleaned[0]}"
    return "(" + " OR ".join(f"index={idx}" for idx in cleaned[:5]) + ")"


def _field_hints(card: dict[str, Any] | None, planner: dict[str, Any]) -> list[str]:
    hints: list[str] = []
    for key in ("group_by", "filter_fields", "fields"):
        raw = planner.get(key, [])
        if isinstance(raw, list):
            hints.extend(str(x).strip() for x in raw if str(x).strip())
    analytical_plan = planner.get("analytical_plan", {})
    if isinstance(analytical_plan, dict):
        analysis = analytical_plan.get("analysis", {})
        if isinstance(analysis, dict):
            for key in ("dimensions", "output_fields"):
                raw = analysis.get(key, [])
                if isinstance(raw, list):
                    hints.extend(str(item).strip() for item in raw if str(item).strip())
            for measure in analysis.get("measures", []):
                if isinstance(measure, dict) and str(measure.get("field", "")).strip():
                    hints.append(str(measure.get("field", "")).strip())
    if card:
        top_fields = card.get("top_fields", [])
        if isinstance(top_fields, list):
            hints.extend(str(x).strip() for x in top_fields[:6] if str(x).strip())
    deduped: list[str] = []
    seen: set[str] = set()
    for hint in hints:
        key = hint.lower()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(hint)
    return deduped[:10]


def bind_fields_for_plan(
    question: str,
    planner_output: dict[str, Any],
    *,
    profile: dict[str, Any] | None = None,
    allow_mcp_fallback: bool = False,
) -> dict[str, Any]:
    planner = dict(planner_output or {})
    profile = profile if isinstance(profile, dict) else load_environment_profile()
    question_earliest, question_latest = infer_time_window(question)
    intent = str(planner.get("intent", "")).strip() or map_question_to_template(question).intent
    sourcetype = _extract_sourcetype_hint(question, planner)
    suggested_domains = suggest_domains_for_question(
        question,
        intent=intent,
        max_indexes=4,
        max_sourcetypes_per_index=2,
    )
    sourcetype_to_indexes = (
        profile.get("sourcetype_to_indexes", {})
        if isinstance(profile, dict)
        and isinstance(profile.get("sourcetype_to_indexes"), dict)
        else {}
    )
    candidate_domains = [
        {
            "index": (
                str(sourcetype_to_indexes.get(str(domain.get("sourcetypes", [""])[0]).strip(), [""])[0]).strip()
                if isinstance(
                    sourcetype_to_indexes.get(
                        str(domain.get("sourcetypes", [""])[0]).strip(),
                        [],
                    ),
                    list,
                )
                and sourcetype_to_indexes.get(
                    str(domain.get("sourcetypes", [""])[0]).strip(),
                    [],
                )
                else str(domain.get("index", "")).strip()
            ),
            "sourcetype": str(domain.get("sourcetypes", [""])[0]).strip(),
        }
        for domain in suggested_domains
        if isinstance(domain, dict)
        and str(domain.get("index", "")).strip()
        and isinstance(domain.get("sourcetypes"), list)
        and domain.get("sourcetypes")
        and str(domain.get("sourcetypes", [""])[0]).strip()
    ]
    if not sourcetype and candidate_domains:
        sourcetype = candidate_domains[0]["sourcetype"]
    card = card_for_sourcetype(sourcetype) if sourcetype else None
    if not sourcetype:
        cards = cards_for_question(question, intent=intent, max_cards=1)
        if cards:
            card = cards[0]
            sourcetype = str(card.get("sourcetype", "")).strip()

    locks = extract_explicit_dataset_locks(question)
    locked_indexes = locks["indexes"]
    if locked_indexes:
        index_expr = (
            f"index={locked_indexes[0]}"
            if len(locked_indexes) == 1
            else "(" + " OR ".join(f"index={item}" for item in locked_indexes) + ")"
        )
    else:
        index_expr = _index_expr_for_sourcetype(profile, sourcetype) if sourcetype else "index=* NOT index=_*"
    field_hints = _field_hints(card, planner)
    if not field_hints and sourcetype:
        inv = profile.get("sourcetype_field_inventory", {}) if isinstance(profile, dict) else {}
        rows = _inventory_field_rows(inv.get(sourcetype)) if isinstance(inv, dict) else []
        field_hints = [
            str(r.get("field", "")).strip()
            for r in rows[:8]
            if str(r.get("field", "")).strip()
        ]
    inventory = profile.get("sourcetype_field_inventory", {}) if isinstance(profile, dict) else {}
    profile_native_fields: list[str] = []
    selected_sourcetypes = {
        sourcetype,
        *[
            str(domain.get("sourcetype", "")).strip()
            for domain in candidate_domains
        ],
    }
    if isinstance(inventory, dict):
        for selected_sourcetype in selected_sourcetypes:
            rows = _inventory_field_rows(inventory.get(selected_sourcetype))
            profile_native_fields.extend(
                str(row.get("field", "")).strip()
                for row in rows
                if isinstance(row, dict) and str(row.get("field", "")).strip()
            )
    filters = planner.get("filters", [])
    if not isinstance(filters, list):
        filters = []
    bound = {
        "intent": intent,
        "sourcetype": sourcetype,
        "index_expr": index_expr,
        "earliest_time": question_earliest,
        "latest_time": question_latest,
        "indexes": locked_indexes,
        "dataset_locks": locks,
        "field_hints": field_hints,
        "profile_native_fields": list(dict.fromkeys(profile_native_fields)),
        "candidate_domains": candidate_domains,
        "filters": [str(f).strip() for f in filters if str(f).strip()],
        "cards_context": format_cards_context([card], max_chars=500) if card else "",
        "source": "profile",
    }
    if card:
        aliases = card.get("field_aliases", {})
        if isinstance(aliases, dict) and aliases:
            bound["field_aliases"] = aliases
        bound["gold_query_fragment"] = str(card.get("gold_query_fragment", "")).strip()

    if allow_mcp_fallback and sourcetype and not field_hints:
        try:
            from build_sourcetype_cards import enrich_card_live

            st_to_idx = profile.get("sourcetype_to_indexes", {}) if isinstance(profile, dict) else {}
            indexes = [str(i) for i in st_to_idx.get(sourcetype, []) if str(i).strip()] if isinstance(st_to_idx, dict) else []
            if indexes:
                rows = enrich_card_live(sourcetype, indexes)
                bound["field_hints"] = [str(r.get("field", "")).strip() for r in rows[:8] if str(r.get("field", "")).strip()]
                bound["source"] = "mcp_fallback"
        except Exception:
            pass

    probe_args = {
        "query": f"search {index_expr} sourcetype=\"{sourcetype}\" | head 1" if sourcetype else f"search {index_expr} | head 1",
        "earliest_time": question_earliest,
        "latest_time": question_latest,
        "row_limit": 1,
    }
    ok, reason = validate_query_against_environment({"query": probe_args["query"]})
    bound["environment_ok"] = ok
    bound["environment_reason"] = reason
    return bound
