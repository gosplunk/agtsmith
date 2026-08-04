#!/usr/bin/env python3
"""Shared, deterministic scoring for live SPL result equivalence."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any


def _analysis(plan: Mapping[str, Any] | None) -> Mapping[str, Any]:
    payload = plan if isinstance(plan, Mapping) else {}
    analysis = payload.get("analysis", {})
    return analysis if isinstance(analysis, Mapping) else {}


def _field_identity(field: Any, plan: Mapping[str, Any] | None) -> frozenset[str]:
    """Return a plan-owned identity for a native or normalized field."""
    name = str(field or "").strip().casefold()
    if not name:
        return frozenset()
    for normalization in (plan or {}).get("normalizations", []) if isinstance(plan, Mapping) else []:
        if not isinstance(normalization, Mapping):
            continue
        output = str(normalization.get("output", "")).strip().casefold()
        fields = {
            str(item).strip().casefold()
            for item in normalization.get("fields", [])
            if str(item).strip()
        }
        if name == output or name in fields:
            return frozenset(fields or {output or name})
    return frozenset({name})


def _measure_identity(measure: Mapping[str, Any], plan: Mapping[str, Any] | None) -> tuple[str, frozenset[str]]:
    function = str(measure.get("function", "")).strip().casefold()
    field = measure.get("field", "*")
    return function, _field_identity(field, plan)


def _output_identity(
    field: Any,
    analysis: Mapping[str, Any],
    plan: Mapping[str, Any] | None,
) -> tuple[Any, ...]:
    name = str(field or "").strip()
    for measure in analysis.get("measures", []):
        if isinstance(measure, Mapping) and str(measure.get("name", "")).strip().casefold() == name.casefold():
            return ("measure", *_measure_identity(measure, plan))
    for intersection in analysis.get("intersections", []):
        if isinstance(intersection, Mapping) and str(intersection.get("name", "")).strip().casefold() == name.casefold():
            fields = frozenset(
                _field_identity(item, plan)
                for item in intersection.get("fields", [])
                if str(item).strip()
            )
            return ("intersection", fields)
    for ratio in analysis.get("ratios", []):
        if isinstance(ratio, Mapping) and str(ratio.get("name", "")).strip().casefold() == name.casefold():
            return (
                "ratio",
                str(ratio.get("numerator", "")).strip().casefold(),
                str(ratio.get("denominator", "")).strip().casefold(),
            )
    time_bin = analysis.get("time_bin")
    if isinstance(time_bin, Mapping) and (
        name.casefold() == str(time_bin.get("alias", "")).strip().casefold()
        or name.casefold() == str(time_bin.get("field", "")).strip().casefold()
    ):
        return ("time_bin", _field_identity(time_bin.get("field", "_time"), plan))
    return ("field", _field_identity(name, plan))


def _candidate_to_reference_field_map(
    reference_plan: Mapping[str, Any] | None,
    candidate_plan: Mapping[str, Any] | None,
) -> dict[str, str]:
    """Align result aliases using typed-plan semantics, never row position."""
    if not isinstance(reference_plan, Mapping) or not isinstance(candidate_plan, Mapping):
        return {}
    reference_analysis = _analysis(reference_plan)
    candidate_analysis = _analysis(candidate_plan)
    reference_fields = [
        str(item).strip()
        for item in reference_analysis.get("output_fields", [])
        if str(item).strip()
    ]
    candidate_fields = [
        str(item).strip()
        for item in candidate_analysis.get("output_fields", [])
        if str(item).strip()
    ]
    mapping: dict[str, str] = {}
    for candidate in candidate_fields:
        if any(candidate.casefold() == reference.casefold() for reference in reference_fields):
            target = next(
                reference
                for reference in reference_fields
                if candidate.casefold() == reference.casefold()
            )
            mapping[candidate] = target
            continue
        identity = _output_identity(candidate, candidate_analysis, candidate_plan)
        matches = [
            reference
            for reference in reference_fields
            if _output_identity(reference, reference_analysis, reference_plan) == identity
        ]
        if len(matches) == 1:
            mapping[candidate] = matches[0]
    return mapping


def _align_candidate_rows(
    candidate_rows: list[dict[str, Any]],
    *,
    reference_plan: Mapping[str, Any] | None,
    candidate_plan: Mapping[str, Any] | None,
) -> list[dict[str, Any]]:
    mapping = _candidate_to_reference_field_map(reference_plan, candidate_plan)
    if not mapping:
        return candidate_rows
    aligned: list[dict[str, Any]] = []
    for row in candidate_rows:
        updated = dict(row)
        lower_keys = {str(key).casefold(): key for key in row}
        for source, target in mapping.items():
            if target in updated:
                continue
            source_key = source if source in row else lower_keys.get(source.casefold())
            if source_key is not None:
                updated[target] = row[source_key]
        aligned.append(updated)
    return aligned


def _normalized_value(value: Any) -> str:
    if isinstance(value, (list, tuple, set)):
        return ",".join(sorted(_normalized_value(item) for item in value))
    if isinstance(value, Mapping):
        return ",".join(
            f"{_normalized_value(key)}={_normalized_value(item)}"
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        )
    return str(value if value is not None else "").strip().casefold()


def row_keys(rows: Iterable[Mapping[str, Any]], fields: Iterable[str]) -> set[str]:
    selected = tuple(str(field) for field in fields)
    keys: set[str] = set()
    for row in rows:
        parts = tuple(_normalized_value(row.get(field, "")) for field in selected)
        if any(parts):
            keys.add("|".join(parts))
    return keys


def jaccard(candidate: set[str], reference: set[str]) -> float:
    if not candidate and not reference:
        return 1.0
    if not candidate or not reference:
        return 0.0
    return len(candidate & reference) / len(candidate | reference)


def entity_recall(candidate: set[str], reference: set[str]) -> float:
    if not reference:
        return 1.0
    if not candidate:
        return 0.0
    return len(candidate & reference) / len(reference)


def row_ratio(candidate_count: int, reference_count: int) -> float:
    candidate = max(0, int(candidate_count))
    reference = max(0, int(reference_count))
    if candidate == 0 and reference == 0:
        return 1.0
    if candidate == 0 or reference == 0:
        return 0.0
    return min(candidate, reference) / max(candidate, reference)


def top_k_overlap(
    candidate_rows: Iterable[Mapping[str, Any]],
    reference_rows: Iterable[Mapping[str, Any]],
    *,
    fields: Iterable[str],
    k: int = 10,
) -> float:
    limit = max(1, int(k))
    candidate = list(candidate_rows)[:limit]
    reference = list(reference_rows)[:limit]
    return jaccard(row_keys(candidate, fields), row_keys(reference, fields))


def empty_result_score(candidate_count: int, reference_count: int) -> float:
    """Reward agreement only; a candidate-only empty result is never equivalent."""
    candidate_empty = int(candidate_count) == 0
    reference_empty = int(reference_count) == 0
    return 1.0 if candidate_empty == reference_empty else 0.0


def score_result_equivalence(
    *,
    candidate_rows: list[dict[str, Any]],
    reference_rows: list[dict[str, Any]],
    compare_fields: Iterable[str],
    entity_fields: Iterable[str] = (),
    top_k: int = 10,
    reference_plan: Mapping[str, Any] | None = None,
    candidate_plan: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    candidate_rows = _align_candidate_rows(
        candidate_rows,
        reference_plan=reference_plan,
        candidate_plan=candidate_plan,
    )
    compare = tuple(compare_fields)
    entities = tuple(entity_fields) or compare
    candidate_keys = row_keys(candidate_rows, compare)
    reference_keys = row_keys(reference_rows, compare)
    candidate_entities = row_keys(candidate_rows, entities)
    reference_entities = row_keys(reference_rows, entities)
    metrics = {
        "jaccard": jaccard(candidate_keys, reference_keys),
        "entity_recall": entity_recall(candidate_entities, reference_entities),
        "entity_jaccard": jaccard(candidate_entities, reference_entities),
        "row_ratio": row_ratio(len(candidate_rows), len(reference_rows)),
        "top_k_overlap": top_k_overlap(
            candidate_rows,
            reference_rows,
            fields=entities,
            k=top_k,
        ),
        "empty_result_score": empty_result_score(
            len(candidate_rows),
            len(reference_rows),
        ),
    }
    metrics["equivalence_score"] = (
        0.30 * metrics["jaccard"]
        + 0.25 * metrics["entity_recall"]
        + 0.15 * metrics["row_ratio"]
        + 0.20 * metrics["top_k_overlap"]
        + 0.10 * metrics["empty_result_score"]
    )
    return {
        key: round(float(value), 4)
        for key, value in metrics.items()
    }
