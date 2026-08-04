#!/usr/bin/env python3
"""Observe/prefer migration helpers for planner-produced AnalyticalPlan output."""

from __future__ import annotations

import os
import re
from copy import deepcopy
from typing import Any

from intent_field_contracts import validate_analytical_plan_contract
from question_intelligence import (
    extract_explicit_dataset_locks,
    infer_analytical_shape_hints,
    infer_time_window,
)
from spl_plan_compiler import AnalyticalPlanCompileError, analytical_plan_to_tool_args
from spl_query_schema import (
    MAX_ANALYTICAL_ROWS,
    AnalyticalPlan,
    DatasetBranch,
    parse_analytical_plan,
)
from spl_write_plan_slots import ROLE_GROUP_ALIASES, apply_analytical_field_bindings

ANALYTICAL_PLANNER_MODES = {"observe", "prefer", "enforce"}
_MEASURE_FUNCTION_ALIASES = {
    "average": "avg",
    "cardinality": "dc",
    "distinct": "dc",
    "distinct_count": "dc",
    "unique": "dc",
    "unique_count": "dc",
}
_UNRESOLVED_PLATFORMS = {
    "",
    "*",
    "any",
    "all",
    "unknown",
    "unresolved",
    "none",
    "null",
}


def _candidate_plan_dict(raw_plan: Any) -> dict[str, Any] | None:
    if not isinstance(raw_plan, dict):
        return None
    candidate = raw_plan.get("analytical_plan", raw_plan)
    return deepcopy(candidate) if isinstance(candidate, dict) else None


def _name_tokens(value: Any) -> set[str]:
    return {
        token
        for token in re.findall(r"[a-z0-9]+", str(value or "").casefold())
        if token not in {"pct", "percent", "percentage", "ratio", "share", "rate"}
    }


def _closest_derived_name(requested: Any, names: list[str]) -> str:
    target = _name_tokens(requested)
    if not target or not names:
        return ""
    scored = sorted(
        (
            (len(target & _name_tokens(name)), -abs(len(target) - len(_name_tokens(name))), name)
            for name in names
        ),
        reverse=True,
    )
    return scored[0][2] if scored and scored[0][0] > 0 else ""


def _safe_plan_name(value: Any, fallback: str) -> str:
    candidate = re.sub(r"[^A-Za-z0-9_]", "_", str(value or "").strip())
    candidate = re.sub(r"_+", "_", candidate).strip("_")
    if candidate and candidate[0].isdigit():
        candidate = f"derived_{candidate}"
    return candidate if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", candidate) else fallback


def _measure_condition_signature(measure: dict[str, Any]) -> tuple[str, str, str]:
    condition = measure.get("condition")
    if not isinstance(condition, dict):
        return "", "", ""
    return (
        str(condition.get("field", "")).strip().casefold(),
        str(condition.get("operator", "")).strip().casefold(),
        str(condition.get("value", "")).strip().casefold(),
    )


def _measure_matches_hint(measure: dict[str, Any], hint: dict[str, Any]) -> bool:
    function = str(measure.get("function", "")).strip().casefold()
    hint_function = str(hint.get("function", "")).strip().casefold()
    if function != hint_function:
        return False
    hint_field = str(hint.get("field_hint", hint.get("field", ""))).strip().casefold()
    actual_field = str(measure.get("field", "")).strip().casefold()
    if hint_function != "count" and hint_field and hint_field != actual_field:
        return False
    hint_condition = hint.get("condition")
    if isinstance(hint_condition, dict):
        return _measure_condition_signature(measure) == _measure_condition_signature(
            {"condition": hint_condition}
        )
    return not isinstance(measure.get("condition"), dict)


def _derived_names(analysis: dict[str, Any]) -> list[str]:
    names: list[str] = []
    for key in ("measures", "intersections", "ratios"):
        names.extend(
            str(item.get("name", "")).strip()
            for item in analysis.get(key, [])
            if isinstance(item, dict) and str(item.get("name", "")).strip()
        )
    time_bin = analysis.get("time_bin")
    if isinstance(time_bin, dict) and str(time_bin.get("alias", "")).strip():
        names.append(str(time_bin["alias"]).strip())
    return list(dict.fromkeys(names))


def normalize_analytical_plan_candidate(
    question: str,
    raw_plan: Any,
    *,
    enforce_dataset_locks: bool = False,
) -> Any:
    """Canonicalize safe structural aliases before the single model repair.

    This is deliberately schema-level: it never invents filters or field
    literals. Explicit dataset locks remain authoritative, while unresolved
    scope is represented by ``*`` for later environment binding.
    """
    plan = _candidate_plan_dict(raw_plan)
    if plan is None:
        return raw_plan

    locks = extract_explicit_dataset_locks(question)
    indexes = list(locks["indexes"])
    sourcetypes = list(locks["sourcetypes"])
    datasets = plan.get("datasets", [])
    datasets = [dict(item) for item in datasets if isinstance(item, dict)] if isinstance(datasets, list) else []
    if (indexes or sourcetypes) and enforce_dataset_locks:
        branch_count = max(len(indexes), len(sourcetypes), 1)
        source_branches = datasets or [{}]
        rebound: list[dict[str, Any]] = []
        for position in range(branch_count):
            source = dict(source_branches[min(position, len(source_branches) - 1)])
            source_index = str(source.get("index", "")).strip()
            if "/" in source_index:
                possible_index, possible_sourcetype = source_index.split("/", 1)
                if possible_index and possible_sourcetype:
                    source["index"] = possible_index
                    source["sourcetype"] = (
                        str(source.get("sourcetype", "")).strip()
                        or possible_sourcetype
                    )
            if indexes:
                source["index"] = indexes[min(position, len(indexes) - 1)]
            if sourcetypes:
                source["sourcetype"] = sourcetypes[min(position, len(sourcetypes) - 1)]
            rebound.append(source)
        datasets = rebound
    else:
        for branch in datasets:
            index_name = str(branch.get("index", "")).strip()
            sourcetype = str(branch.get("sourcetype", "")).strip()
            platform = str(branch.get("platform", "")).strip()
            if "/" in index_name:
                possible_index, possible_sourcetype = index_name.split("/", 1)
                if possible_index and possible_sourcetype:
                    index_name = possible_index
                    sourcetype = sourcetype or possible_sourcetype
            if not index_name or "*" in index_name or index_name.casefold() in {
                "index",
                "name",
                "name-or-*",
                "unknown",
            }:
                index_name = "*"
            branch["index"] = index_name
            if sourcetype:
                branch["sourcetype"] = sourcetype
            if platform.casefold() in _UNRESOLVED_PLATFORMS:
                branch["platform"] = ""
    for branch in datasets:
        platform = str(branch.get("platform", "")).strip()
        if platform.casefold() in _UNRESOLVED_PLATFORMS:
            branch["platform"] = ""
    plan["datasets"] = datasets

    analysis = plan.get("analysis", {})
    if not isinstance(analysis, dict):
        return plan
    shape_hints = infer_analytical_shape_hints(question)
    measures = analysis.get("measures", [])
    measures = [dict(item) for item in measures if isinstance(item, dict)] if isinstance(measures, list) else []
    renamed_measures: dict[str, str] = {}
    for measure in measures:
        original_name = str(measure.get("name", "")).strip()
        normalized_name = re.sub(r"[^A-Za-z0-9_]", "_", original_name)
        if normalized_name and normalized_name[0].isdigit():
            normalized_name = f"measure_{normalized_name}"
        if original_name and normalized_name and normalized_name != original_name:
            renamed_measures[original_name] = normalized_name
            measure["name"] = normalized_name
    question_l = str(question or "").casefold()
    positive_state = re.search(
        r"\b(success(?:ful)?|succeeded|allowed|ok|good)\b",
        question_l,
    )
    negative_state = re.search(
        r"\b(unsuccessful|failed|failure|denied|error|bad|non-good)\b",
        question_l,
    )
    state_comparison = positive_state and negative_state
    positive_literal = (
        "allowed"
        if positive_state and positive_state.group(1) == "allowed"
        else "ok"
        if positive_state and positive_state.group(1) == "ok"
        else "success"
    )
    state_field = next(
        (
            field_name
            for field_name in ("result", "state", "status", "outcome", "action")
            if re.search(rf"\b{field_name}s?\b", question_l)
        ),
        "",
    )
    for measure in measures:
        function = str(measure.get("function", "")).strip().casefold()
        measure["function"] = _MEASURE_FUNCTION_ALIASES.get(function, function)
        if measure["function"] == "exists":
            field_name = str(measure.get("field", "")).strip()
            measure["function"] = "count"
            measure.pop("field", None)
            if field_name and not isinstance(measure.get("condition"), dict):
                measure["condition"] = {
                    "field": field_name,
                    "operator": "exists",
                    "value": None,
                }
        if measure["function"] == "count":
            measure.pop("field", None)
        elif not re.fullmatch(
            r"[A-Za-z_][A-Za-z0-9_.:-]*",
            str(measure.get("field", "")).strip(),
        ):
            inferred_field = re.sub(
                r"(?:^distinct_|^unique_|_cardinality$|_count$)",
                "",
                str(measure.get("name", "")).strip(),
            )
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.:-]*", inferred_field):
                measure["field"] = inferred_field
        measure_name = str(measure.get("name", "")).casefold()
        if (
            state_comparison
            and state_field
            and measure["function"] == "count"
            and not isinstance(measure.get("condition"), dict)
        ):
            if re.search(r"(?:^|_)(?:unsuccess|fail|error|bad|non_good)", measure_name):
                measure["condition"] = {
                    "field": state_field,
                    "operator": "neq",
                    "value": positive_literal,
                }
            elif re.search(
                r"(?:^|_)(?:success|succeed|allow|good|ok)",
                measure_name,
            ):
                measure["condition"] = {
                    "field": state_field,
                    "operator": "eq",
                    "value": positive_literal,
                }
    raw_ratios = analysis.get("ratios", [])
    if (
        isinstance(raw_ratios, list)
        and raw_ratios
        and not any(
            item.get("function") == "count"
            and not isinstance(item.get("condition"), dict)
            for item in measures
        )
    ):
        existing_names = {
            str(item.get("name", "")).strip()
            for item in measures
        }
        total_name = "total_events"
        suffix = 2
        while total_name in existing_names:
            total_name = f"total_events_{suffix}"
            suffix += 1
        measures.insert(
            0,
            {"name": total_name, "function": "count"},
        )
    analysis["measures"] = measures

    # Recover omitted compositional primitives from the deterministic question
    # contract. These additions are structural only: fields come from the
    # question's stable semantic roles or the proposed plan, never from output
    # words such as "counts" or "values".
    for hint in shape_hints.get("measures", []):
        if not isinstance(hint, dict):
            continue
        if any(_measure_matches_hint(item, hint) for item in measures):
            continue
        function = str(hint.get("function", "")).strip().casefold()
        field_hint = str(hint.get("field_hint", "")).strip()
        condition = hint.get("condition")
        if function != "count" and not field_hint:
            continue
        fallback = f"{function}_events" if function else "derived_measure"
        name = _safe_plan_name(hint.get("name_hint"), fallback)
        existing_names = {
            str(item.get("name", "")).strip()
            for item in measures
            if str(item.get("name", "")).strip()
        }
        base_name = name
        suffix = 2
        while name in existing_names:
            name = f"{base_name}_{suffix}"
            suffix += 1
        measure: dict[str, Any] = {"name": name, "function": function}
        if function != "count":
            measure["field"] = field_hint
        if isinstance(condition, dict):
            measure["condition"] = deepcopy(condition)
        measures.append(measure)
    analysis["measures"] = measures
    measure_names = [str(item.get("name", "")).strip() for item in measures if str(item.get("name", "")).strip()]
    unconditional_counts = [
        str(item.get("name", "")).strip()
        for item in measures
        if item.get("function") == "count"
        and not isinstance(item.get("condition"), dict)
        and str(item.get("name", "")).strip()
    ]
    conditional_counts = [
        str(item.get("name", "")).strip()
        for item in measures
        if item.get("function") == "count"
        and isinstance(item.get("condition"), dict)
        and str(item.get("name", "")).strip()
    ]

    intersections = analysis.get("intersections", [])
    intersections = (
        [dict(item) for item in intersections if isinstance(item, dict)]
        if isinstance(intersections, list)
        else []
    )
    # The intersection primitive is evaluated against event fields before
    # aggregation. Models often copy the output aliases of ``values`` measures
    # (for example ``host_values``) into ``intersection.fields``. That is
    # structurally plausible but compiles to isnotnull(host_values), which is
    # not the source field and silently changes the aggregate result. Resolve
    # only exact values/list measure aliases; do not infer arbitrary fields.
    value_measure_fields = {
        str(item.get("name", "")).strip().casefold(): str(item.get("field", "")).strip()
        for item in measures
        if (
            item.get("function") in {"values", "list"}
            and str(item.get("name", "")).strip()
            and str(item.get("field", "")).strip()
        )
    }
    for intersection in intersections:
        fields = intersection.get("fields", [])
        if not isinstance(fields, list):
            continue
        intersection["fields"] = [
            value_measure_fields.get(str(field).strip().casefold(), str(field).strip())
            for field in fields
            if str(field).strip()
        ]
    intersection_fields = [
        str(item.get("field", "")).strip()
        for item in measures
        if item.get("function") in {"values", "list"} and str(item.get("field", "")).strip()
    ]
    if not intersections and shape_hints.get("intersections"):
        hint = shape_hints["intersections"][0]
        hinted_fields = (
            [
                str(item).strip()
                for item in hint.get("fields", [])
                if str(item).strip()
            ]
            if isinstance(hint, dict) and isinstance(hint.get("fields"), list)
            else []
        )
        intersection_fields.extend(hinted_fields)
        if len(set(intersection_fields)) >= 2:
            intersections = [
                {
                    "name": _safe_plan_name(
                        hint.get("name_hint") if isinstance(hint, dict) else "",
                        "intersection_events",
                    ),
                    "fields": list(dict.fromkeys(intersection_fields))[:2],
                }
            ]
    collected_fields = re.search(
        r"\bcollect\b[^,.!?;]*?\b([A-Za-z_][A-Za-z0-9_.:-]*)\b"
        r"\s+and\s+([A-Za-z_][A-Za-z0-9_.:-]*)\b(?:\s+values?)?",
        str(question or ""),
        flags=re.IGNORECASE,
    )
    if collected_fields:
        intersection_fields.extend(
            [collected_fields.group(1), collected_fields.group(2)]
        )
    for intersection in intersections:
        fields = intersection.get("fields", [])
        fields = [str(item).strip() for item in fields if str(item).strip()] if isinstance(fields, list) else []
        if len(set(fields)) < 2 and len(set(intersection_fields)) >= 2:
            intersection["fields"] = list(dict.fromkeys(intersection_fields))[:2]
        elif len(set(fields)) < 2:
            intersection["fields"] = []
    intersections = [
        intersection
        for intersection in intersections
        if len(
            {
                str(item).strip()
                for item in intersection.get("fields", [])
                if str(item).strip()
            }
        )
        >= 2
    ]
    analysis["intersections"] = intersections
    intersection_names = [
        str(item.get("name", "")).strip()
        for item in intersections
        if str(item.get("name", "")).strip()
    ]

    ratios = analysis.get("ratios", [])
    if not ratios and shape_hints.get("ratios"):
        unconditional = [
            str(item.get("name", "")).strip()
            for item in measures
            if item.get("function") == "count"
            and not isinstance(item.get("condition"), dict)
            and str(item.get("name", "")).strip()
        ]
        conditional = [
            str(item.get("name", "")).strip()
            for item in measures
            if isinstance(item.get("condition"), dict)
            and str(item.get("name", "")).strip()
        ]
        if not unconditional:
            measures.insert(0, {"name": "total_events", "function": "count"})
            unconditional = ["total_events"]
        if conditional:
            ratio_hint = shape_hints["ratios"][0]
            ratios = [
                {
                    "name": _safe_plan_name(ratio_hint.get("name_hint"), "derived_pct"),
                    "numerator": conditional[0],
                    "denominator": unconditional[0],
                    "scale": ratio_hint.get("scale", 100),
                    "zero_policy": "null",
                }
            ]
    ratios = [dict(item) for item in ratios if isinstance(item, dict)] if isinstance(ratios, list) else []
    for ratio in ratios:
        numerator = str(ratio.get("numerator", "")).strip()
        denominator = str(ratio.get("denominator", "")).strip()
        numerator = renamed_measures.get(numerator, numerator)
        denominator = renamed_measures.get(denominator, denominator)
        if denominator not in measure_names and unconditional_counts:
            denominator = _closest_derived_name(denominator, unconditional_counts) or unconditional_counts[0]
        if numerator not in measure_names:
            candidates = [name for name in conditional_counts if name != denominator]
            numerator = _closest_derived_name(ratio.get("name", numerator), candidates) or (
                candidates[0] if len(candidates) == 1 else numerator
            )
        ratio["numerator"] = numerator
        ratio["denominator"] = denominator
        ratio["zero_policy"] = (
            str(ratio.get("zero_policy", "null")).strip().casefold()
            if str(ratio.get("zero_policy", "null")).strip().casefold() in {"null", "zero"}
            else "null"
        )
        scale = ratio.get("scale", 100 if re.search(r"pct|percent|share", str(ratio.get("name", "")), re.I) else 1)
        ratio["scale"] = scale if isinstance(scale, (int, float)) and not isinstance(scale, bool) and 0 < scale <= 10000 else 1
    analysis["ratios"] = ratios
    ratio_names = [str(item.get("name", "")).strip() for item in ratios if str(item.get("name", "")).strip()]
    if not analysis.get("time_bin") and shape_hints.get("time_bin"):
        analysis["time_bin"] = {
            "field": "_time",
            "span": str(shape_hints["time_bin"]).strip(),
            "alias": "bucket",
        }

    result_fields = list(
        dict.fromkeys(
            [
                *[str(item).strip() for item in analysis.get("dimensions", []) if str(item).strip()],
                *measure_names,
                *intersection_names,
                *ratio_names,
            ]
        )
    )
    rankings = analysis.get("ranking", [])
    rankings = [dict(item) for item in rankings if isinstance(item, dict)] if isinstance(rankings, list) else []
    if (
        "ranking" not in analysis
        and isinstance(shape_hints.get("ranking"), dict)
        and shape_hints["ranking"]
    ):
        ranking_hint = shape_hints["ranking"]
        ranking_field = ratio_names[-1] if ratio_names else (measure_names[-1] if measure_names else "")
        if ranking_field:
            rankings = [
                {
                    "field": ranking_field,
                    "direction": ranking_hint.get("direction", "desc"),
                    "limit": ranking_hint.get("limit", 20),
                }
            ]
    for ranking in rankings:
        field_name = str(ranking.get("field", "")).strip()
        if field_name not in result_fields:
            field_name = (
                _closest_derived_name(field_name, result_fields)
                or (ratio_names[-1] if ratio_names else "")
                or (measure_names[-1] if measure_names else "")
            )
        ranking["field"] = field_name
        ranking["direction"] = (
            str(ranking.get("direction", "desc")).strip().casefold()
            if str(ranking.get("direction", "desc")).strip().casefold() in {"asc", "desc"}
            else "desc"
        )
        try:
            limit = int(ranking.get("limit", 10))
        except (TypeError, ValueError):
            limit = 10
        ranking["limit"] = min(max(limit, 1), MAX_ANALYTICAL_ROWS)
    analysis["ranking"] = rankings

    output_fields = analysis.get("output_fields", [])
    output_fields = [str(item).strip() for item in output_fields if str(item).strip()] if isinstance(output_fields, list) else []
    normalized_outputs: list[str] = []
    for field_name in output_fields:
        if field_name in result_fields:
            normalized_outputs.append(field_name)
            continue
        replacement = _closest_derived_name(field_name, result_fields)
        if not replacement and re.search(r"pct|percent|share|ratio|rate", field_name, re.I) and len(ratio_names) == 1:
            replacement = ratio_names[0]
        if not replacement and re.search(r"distinct|unique|cardinal", field_name, re.I):
            dc_names = [
                str(item.get("name", "")).strip()
                for item in measures
                if item.get("function") == "dc" and str(item.get("name", "")).strip()
            ]
            if len(dc_names) == 1:
                replacement = dc_names[0]
        if replacement:
            normalized_outputs.append(replacement)
    output_candidates = list(result_fields)
    if isinstance(analysis.get("time_bin"), dict):
        time_alias = str(analysis["time_bin"].get("alias", "")).strip()
        if time_alias:
            output_candidates.append(time_alias)
    for hint_name in shape_hints.get("output_fields", []):
        replacement = _closest_derived_name(hint_name, output_candidates)
        if replacement:
            normalized_outputs.append(replacement)
    if not normalized_outputs:
        normalized_outputs.extend(
            str(item).strip()
            for item in analysis.get("dimensions", [])
            if str(item).strip()
        )
        normalized_outputs.extend(_derived_names(analysis))
    analysis["output_fields"] = list(dict.fromkeys(normalized_outputs))
    plan["analysis"] = analysis

    execution = plan.get("execution", {})
    if isinstance(execution, dict):
        # The question owns the time contract. Explicit ranges and all-time
        # phrases are preserved; otherwise every typed plan receives the same
        # bounded default as the legacy/tool path.
        inferred_earliest, inferred_latest = infer_time_window(question)
        execution["earliest"] = inferred_earliest
        execution["latest"] = inferred_latest
        try:
            row_limit = int(execution.get("row_limit", 100))
        except (TypeError, ValueError):
            row_limit = 100
        execution["row_limit"] = min(max(row_limit, 1), MAX_ANALYTICAL_ROWS)
        plan["execution"] = execution
    return plan


def analytical_planner_mode() -> str:
    """Return the safe rollout mode; unknown values retain legacy behavior."""
    mode = str(os.getenv("AGTSMITH_ANALYTICAL_PLANNER_MODE", "observe")).strip().lower()
    return mode if mode in ANALYTICAL_PLANNER_MODES else "observe"


def validate_planner_analytical_plan(
    question: str,
    raw_plan: Any,
    *,
    enforce_dataset_locks: bool = False,
) -> dict[str, Any]:
    """Return structured schema/contract/lock diagnostics for one proposed plan."""
    normalized = normalize_analytical_plan_candidate(
        question,
        raw_plan,
        enforce_dataset_locks=enforce_dataset_locks,
    )
    parsed = parse_analytical_plan(normalized)
    valid, errors = validate_analytical_plan_contract(question, normalized)
    return {
        "present": raw_plan is not None,
        "valid": valid,
        "errors": errors,
        "dataset_locks": extract_explicit_dataset_locks(question),
        "plan": parsed.to_dict() if parsed is not None else None,
    }


def _indexes_from_binding(field_bind: dict[str, Any]) -> list[str]:
    explicit = field_bind.get("indexes")
    if isinstance(explicit, list):
        values = [
            str(item).strip()
            for item in explicit
            if str(item).strip() and "*" not in str(item)
        ]
        if values:
            return list(dict.fromkeys(values))
    expression = str(field_bind.get("index_expr", ""))
    matches = re.findall(
        r'index\s*=\s*(?:"([^"]+)"|\'([^\']+)\'|([A-Za-z0-9_.:-]+))',
        expression,
        flags=re.IGNORECASE,
    )
    return list(
        dict.fromkeys(
            next((part for part in match if part), "").strip()
            for match in matches
            if any(match)
        )
    )


def _profile_aliases_for_field(field_name: str) -> tuple[str, ...]:
    """Resolve one plan field without crossing ambiguous role boundaries."""
    name = str(field_name or "").strip()
    lowered = name.casefold()
    if lowered in {"dest", "dest_ip", "destip", "destinationip", "destination_ip"}:
        return ROLE_GROUP_ALIASES["dest_ip"]
    if lowered in {"host", "hostname", "computer", "dvc", "device"}:
        return ("host", "hostname", "computer", "dvc", "device")
    return ROLE_GROUP_ALIASES.get(name, (name,))


def bind_analytical_plan(
    question: str,
    raw_plan: Any,
    *,
    field_bind: dict[str, Any] | None = None,
    field_strategy: dict[str, Any] | None = None,
) -> AnalyticalPlan:
    """Bind unresolved dataset/field slots without changing explicit question locks."""
    parsed = parse_analytical_plan(normalize_analytical_plan_candidate(question, raw_plan))
    if parsed is None:
        raise AnalyticalPlanCompileError("analytical_plan_missing_or_malformed")
    plan = deepcopy(parsed)
    binding = field_bind if isinstance(field_bind, dict) else {}
    locks = extract_explicit_dataset_locks(question)
    locked_indexes = locks["indexes"]
    locked_sourcetypes = locks["sourcetypes"]
    bound_indexes = _indexes_from_binding(binding)
    bound_sourcetype = str(binding.get("sourcetype", "")).strip()
    candidate_domains = [
        {
            "index": str(item.get("index", "")).strip(),
            "sourcetype": str(item.get("sourcetype", "")).strip(),
        }
        for item in binding.get("candidate_domains", [])
        if isinstance(item, dict)
        and str(item.get("index", "")).strip()
        and str(item.get("sourcetype", "")).strip()
    ]

    if locked_indexes:
        target_indexes = locked_indexes
    else:
        target_indexes = bound_indexes
    if len(locked_sourcetypes) == 1:
        target_sourcetype = locked_sourcetypes[0]
    elif len(locked_sourcetypes) > 1:
        # Multi-branch locks are already paired in the typed plan. Never collapse
        # them to the first sourcetype while binding unresolved environment slots.
        target_sourcetype = ""
    else:
        target_sourcetype = bound_sourcetype

    rebound: list[DatasetBranch] = []
    candidate_indexes = {
        domain["index"].casefold()
        for domain in candidate_domains
    }
    candidate_sourcetypes = {
        domain["sourcetype"].casefold()
        for domain in candidate_domains
    }
    for position, branch in enumerate(plan.datasets):
        unresolved_index = (
            branch.index in {"", "*"}
            or "*" in branch.index
            or (
                not locked_indexes
                and bool(candidate_domains)
                and branch.index.casefold() not in candidate_indexes
            )
            or (
                not locked_sourcetypes
                and bool(candidate_domains)
                and bool(branch.sourcetype)
                and branch.sourcetype.casefold() not in candidate_sourcetypes
            )
        )
        if (
            unresolved_index
            and not locked_indexes
            and candidate_domains
        ):
            domain = next(
                (
                    item
                    for item in candidate_domains
                    if branch.sourcetype
                    and item["sourcetype"].casefold()
                    == branch.sourcetype.casefold()
                ),
                candidate_domains[min(position, len(candidate_domains) - 1)],
            )
            rebound.append(
                DatasetBranch(
                    index=domain["index"],
                    sourcetype=domain["sourcetype"],
                    platform=branch.platform,
                    filters=deepcopy(branch.filters),
                )
            )
            continue
        indexes = target_indexes if unresolved_index and target_indexes else [branch.index]
        for index_name in indexes:
            rebound.append(
                DatasetBranch(
                    index=index_name,
                    sourcetype=branch.sourcetype or target_sourcetype,
                    platform=branch.platform,
                    filters=deepcopy(branch.filters),
                )
            )
    plan.datasets = rebound
    strategy = deepcopy(field_strategy) if isinstance(field_strategy, dict) else {}
    profile_native_fields = [
        str(item).strip()
        for item in binding.get("profile_native_fields", [])
        if str(item).strip()
    ]
    if profile_native_fields:
        roles = strategy.get("roles", {})
        roles = deepcopy(roles) if isinstance(roles, dict) else {}
        profile_by_lower = {
            field_name.casefold(): field_name
            for field_name in profile_native_fields
        }
        referenced = set(plan.dimensions)
        for measure in plan.measures:
            if str(measure.get("field", "")).strip():
                referenced.add(str(measure.get("field", "")).strip())
            condition = measure.get("condition")
            if isinstance(condition, dict) and str(condition.get("field", "")).strip():
                referenced.add(str(condition.get("field", "")).strip())
        for intersection in plan.intersections:
            referenced.update(
                str(item).strip()
                for item in intersection.get("fields", [])
                if str(item).strip()
            )
        for branch in plan.datasets:
            for predicate in branch.filters:
                if str(predicate.get("field", "")).strip():
                    referenced.add(str(predicate.get("field", "")).strip())
        for role_name in referenced:
            aliases = _profile_aliases_for_field(role_name)
            trusted = [
                profile_by_lower[alias.casefold()]
                for alias in aliases
                if alias.casefold() in profile_by_lower
            ]
            if not trusted:
                continue
            existing = roles.get(role_name, {})
            existing = deepcopy(existing) if isinstance(existing, dict) else {}
            existing["trusted_fields"] = list(dict.fromkeys(trusted))
            existing["classification"] = (
                "native" if len(trusted) == 1 else "alias_coalesce"
            )
            roles[role_name] = existing
        strategy["roles"] = roles
        strategy["trusted_fields"] = list(
            dict.fromkeys(
                [
                    *[
                        str(item)
                        for item in strategy.get("trusted_fields", [])
                        if str(item).strip()
                    ],
                    *profile_native_fields,
                ]
            )
        )
    plan = apply_analytical_field_bindings(plan, strategy)
    valid, errors = validate_analytical_plan_contract(question, plan)
    if not valid:
        raise AnalyticalPlanCompileError(";".join(errors))
    return plan


def compile_bound_analytical_plan(
    question: str,
    raw_plan: Any,
    *,
    intent: str = "",
    field_bind: dict[str, Any] | None = None,
    field_strategy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Bind and compile one validated plan into bounded read-only tool arguments."""
    plan = bind_analytical_plan(
        question,
        raw_plan,
        field_bind=field_bind,
        field_strategy=field_strategy,
    )
    candidate = analytical_plan_to_tool_args(plan, intent=intent)
    candidate["source"] = "analytical_plan_compiler"
    candidate["reason"] = "validated_bound_analytical_plan"
    candidate["analytical_planner_mode"] = analytical_planner_mode()
    return candidate
