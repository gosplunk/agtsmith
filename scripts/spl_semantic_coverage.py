#!/usr/bin/env python3
"""Deterministic semantic coverage scoring for AnalyticalPlan and compiled SPL."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from typing import Any, Iterable

from apache_intent import APACHE_DIMENSION_FIELDS, query_has_requested_apache_dimensions
from question_intelligence import (
    extract_explicit_dataset_locks,
    infer_analytical_shape_hints,
    validate_query_dataset_locks,
)
from score_result_equivalence import entity_recall, jaccard
from spl_query_schema import AnalyticalPlan, parse_analytical_plan, validate_analytical_plan

SEMANTIC_COVERAGE_VERSION = "1.0"
STATIC_COVERAGE_THRESHOLD = 0.90
STATIC_COMPONENT_WEIGHTS: dict[str, float] = {
    "dataset_scope": 0.16,
    "filters": 0.14,
    "dimensions": 0.14,
    "measures": 0.14,
    "shape": 0.14,
    "output_schema": 0.14,
    "safety": 0.14,
}

_ROLE_ALIASES: dict[str, tuple[str, ...]] = {
    **APACHE_DIMENSION_FIELDS,
    "host": ("host", "hostname", "dest_host"),
    "user": (
        "user",
        "username",
        "user_name",
        "account",
        "account_name",
        "userprincipalname",
        "user_principal_name",
        "user principal name",
    ),
    "src_ip": (
        "src_ip",
        "src",
        "srcip",
        "clientip",
        "sourceip",
        "source_ip",
        "ipaddress",
        "ip_address",
        "ip address",
    ),
    "dest_ip": (
        "dest_ip",
        "destinationip",
        "destination_ip",
        "destination ip",
        "dest",
        "observed_dest_ip",
    ),
    "action": (
        "action",
        "outcome",
        "result",
        "result_state",
        "state",
        "status",
        "status_code",
        "sc_status",
    ),
}
_AGGREGATIONS = (
    "count",
    "dc",
    "sum",
    "avg",
    "min",
    "max",
    "values",
    "list",
    "earliest",
    "latest",
    "first",
    "last",
)


def _unique(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(str(value).strip() for value in values if str(value).strip()))


def _normalized_literal(value: Any) -> str:
    if isinstance(value, list):
        return json.dumps(value, sort_keys=True, separators=(",", ":")).casefold()
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value if value is not None else "").strip().strip("\"'").casefold()


def _predicate_signature(predicate: dict[str, Any]) -> str:
    field_name = str(predicate.get("field", "")).strip().casefold()
    operator = str(predicate.get("operator", "")).strip().casefold()
    return f"{field_name}:{operator}:{_normalized_literal(predicate.get('value'))}"


def _measure_signature(measure: dict[str, Any]) -> str:
    function = str(measure.get("function", "")).strip().casefold()
    field_name = str(
        measure.get("field", measure.get("field_hint", ""))
    ).strip().casefold() or "*"
    return f"{function}:{field_name}"


def _canonical_role(field_name: str) -> str:
    lowered = str(field_name or "").strip().casefold()
    for role, aliases in _ROLE_ALIASES.items():
        if lowered == role or lowered in {item.casefold() for item in aliases}:
            return role
    return lowered


def _canonical_fields(fields: Iterable[str]) -> set[str]:
    return {_canonical_role(item) for item in fields if str(item).strip()}


def _plan_aliases(plan: AnalyticalPlan) -> dict[str, str]:
    """Map native and semantic aliases to the plan's normalized outputs."""
    aliases: dict[str, str] = {}
    for normalization in plan.normalizations:
        output = _canonical_role(normalization.output)
        for field_name in (normalization.output, *normalization.fields):
            raw = str(field_name).strip().casefold()
            if raw:
                aliases[raw] = output
                aliases[_canonical_role(raw)] = output
        if output == "state":
            for field_name in (
                "state",
                "status",
                "status_code",
                "result",
                "result_state",
                "outcome",
                "action",
            ):
                aliases[field_name] = output
    return aliases


def _canonical_for_plan(field_name: Any, aliases: dict[str, str]) -> str:
    raw = str(field_name or "").strip().casefold()
    canonical = _canonical_role(raw)
    return aliases.get(raw, aliases.get(canonical, canonical))


def _predicate_signature_for_plan(
    predicate: dict[str, Any],
    aliases: dict[str, str],
) -> str:
    normalized = dict(predicate)
    normalized["field"] = _canonical_for_plan(predicate.get("field", ""), aliases)
    return _predicate_signature(normalized)


def _measure_signature_for_plan(
    measure: dict[str, Any],
    aliases: dict[str, str],
) -> str:
    normalized = dict(measure)
    field_name = measure.get("field", measure.get("field_hint", ""))
    if str(field_name).strip():
        normalized["field"] = _canonical_for_plan(field_name, aliases)
    return _measure_signature(normalized)


def _coverage_score(actual: Iterable[str], required: Iterable[str], *, exact: bool = False) -> float:
    actual_set = {str(item).casefold() for item in actual if str(item).strip()}
    required_set = {str(item).casefold() for item in required if str(item).strip()}
    if not required_set:
        return 1.0
    recall = entity_recall(actual_set, required_set)
    if not exact:
        return round(recall, 4)
    return round((recall + jaccard(actual_set, required_set)) / 2.0, 4)


def _missing(actual: Iterable[str], required: Iterable[str]) -> list[str]:
    actual_set = {str(item).casefold() for item in actual if str(item).strip()}
    return sorted(
        str(item)
        for item in required
        if str(item).strip() and str(item).casefold() not in actual_set
    )


def _plan_predicates(plan: AnalyticalPlan) -> list[dict[str, Any]]:
    predicates: list[dict[str, Any]] = []
    for branch in plan.datasets:
        predicates.extend(branch.filters)
    for measure in plan.measures:
        condition = measure.get("condition")
        if isinstance(condition, dict):
            predicates.append(condition)
    predicates.extend(plan.post_aggregation_predicates)
    return predicates


def _plan_shapes(
    plan: AnalyticalPlan,
    requested_shapes: set[str] | None = None,
) -> set[str]:
    shapes: set[str] = set()
    if plan.measures:
        shapes.add("aggregate")
    if plan.time_bin:
        span = str(plan.time_bin.get("span", "")).strip().casefold()
        shapes.update({"time_bin", f"time_bin:{span}"})
    if plan.ranking:
        shapes.add("ranking")
        for rank in plan.ranking:
            direction = str(rank.get("direction", "desc")).strip().casefold()
            shapes.add(f"ranking:{direction}")
            shapes.add(f"ranking:{direction}:{int(rank.get('limit', plan.execution.row_limit))}")
    if plan.ratios:
        shapes.add("ratio")
    if plan.intersections:
        shapes.add("intersection")
    if (
        requested_shapes
        and "comparison" in requested_shapes
        and (
        sum(bool(measure.get("condition")) for measure in plan.measures) >= 2
        or (
            plan.ratios
            and any(bool(measure.get("condition")) for measure in plan.measures)
        )
        )
    ):
        shapes.add("comparison")
    if plan.post_aggregation_predicates:
        shapes.add("threshold")
    # Multiple measures are common in ratios, thresholds, and conditional
    # aggregates. They become a comparison only when the question requests
    # comparison semantics; do not infer that shape from measure cardinality.
    if any(
        str(measure.get("function", "")).strip().casefold() in {"earliest", "first"}
        for measure in plan.measures
    ):
        shapes.add("first_seen")
    if (
        len(plan.measures) == 1
        and not plan.dimensions
        and str(plan.measures[0].get("function", "")).strip().casefold() in {"count", "dc"}
    ):
        shapes.add("cardinality")
    return shapes


def _question_shapes(question: str, hints: dict[str, Any]) -> set[str]:
    q = str(question or "").casefold()
    shapes: set[str] = set()
    time_bin = str(hints.get("time_bin", "")).strip().casefold()
    if time_bin:
        shapes.update({"time_bin", f"time_bin:{time_bin}"})
    ranking = hints.get("ranking")
    if isinstance(ranking, dict) and ranking:
        direction = str(ranking.get("direction", "desc")).strip().casefold()
        limit = int(ranking.get("limit", 0) or 0)
        shapes.update({"ranking", f"ranking:{direction}"})
        if limit:
            shapes.add(f"ranking:{direction}:{limit}")
    if (
        bool(hints.get("cardinality"))
        and not hints.get("dimensions")
        and not ranking
        and not time_bin
        and not re.search(r"\b(?:by|per|for each|each|rank)\b", q)
    ):
        shapes.add("cardinality")
    if any(phrase in q for phrase in ("first seen", "first observed", "first time")):
        shapes.add("first_seen")
    if (
        "percentage" in q
        or "percent" in q
        or "part of total" in q
        or "share of" in q
        or re.search(r"\bratio\b", q)
    ):
        shapes.add("ratio")
    if any(
        phrase in q
        for phrase in (
            "intersection",
            "both sets",
            "both are present",
            "both fields are present",
            "co-occurrence",
            "co occurrence",
        )
    ):
        shapes.add("intersection")
    if hints.get("comparisons") or any(
        phrase in q
        for phrase in (
            "compare",
            "comparison",
            "compared with",
            "compared to",
            " versus ",
            " vs ",
            "baseline",
        )
    ):
        shapes.add("comparison")
    return shapes


@dataclass(frozen=True)
class CoverageSpec:
    version: str = SEMANTIC_COVERAGE_VERSION
    explicit_indexes: tuple[str, ...] = ()
    explicit_sourcetypes: tuple[str, ...] = ()
    indexes: tuple[str, ...] = ()
    sourcetypes: tuple[str, ...] = ()
    filters: tuple[str, ...] = ()
    question_filters: tuple[str, ...] = ()
    dimensions: tuple[str, ...] = ()
    question_dimensions: tuple[str, ...] = ()
    measures: tuple[str, ...] = ()
    question_measures: tuple[str, ...] = ()
    shapes: tuple[str, ...] = ()
    question_shapes: tuple[str, ...] = ()
    output_fields: tuple[str, ...] = ()
    required_fields: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def build_coverage_spec(question: str, analytical_plan: AnalyticalPlan | dict[str, Any]) -> CoverageSpec:
    """Build one immutable semantic contract from question requirements and plan intent."""
    plan = parse_analytical_plan(analytical_plan)
    if plan is None:
        raise ValueError("analytical_plan_missing_or_malformed")
    hints = infer_analytical_shape_hints(question)
    locks = extract_explicit_dataset_locks(question)
    aliases = _plan_aliases(plan)

    plan_filters = [
        _predicate_signature_for_plan(item, aliases)
        for item in _plan_predicates(plan)
    ]
    question_filters = [
        _predicate_signature_for_plan(item, aliases)
        for item in hints.get("filters", [])
        if isinstance(item, dict)
    ]
    plan_measures = [
        _measure_signature_for_plan(item, aliases)
        for item in plan.measures
    ]
    question_measures = [
        _measure_signature_for_plan(item, aliases)
        for item in hints.get("measures", [])
        if isinstance(item, dict)
    ]
    question_dimensions = [
        _canonical_for_plan(item, aliases)
        for item in hints.get("dimensions", [])
        if str(item).strip()
    ]
    plan_dimensions = [_canonical_for_plan(item, aliases) for item in plan.dimensions]
    output_fields = list(plan.output_fields)
    if not output_fields:
        output_fields.extend(plan.dimensions)
        output_fields.extend(str(item.get("name", "")) for item in plan.measures)
        output_fields.extend(str(item.get("name", "")) for item in plan.intersections)
        output_fields.extend(str(item.get("name", "")) for item in plan.ratios)
        if plan.time_bin:
            output_fields.append(str(plan.time_bin.get("alias", "")))
    # Output names are plan-owned. Question hints guide migration recovery, but
    # opaque names such as "ratio" or a paraphrased field label must not become
    # false hard requirements for an already typed plan.

    required_fields: list[str] = []
    required_fields.extend(plan.dimensions)
    for predicate in _plan_predicates(plan):
        required_fields.append(str(predicate.get("field", "")))
    for measure in plan.measures:
        required_fields.append(str(measure.get("field", "")))
    required_fields.extend(question_dimensions)

    requested_shapes = _question_shapes(question, hints)
    plan_shapes = _plan_shapes(plan, requested_shapes)
    indexes = locks["indexes"] or [branch.index for branch in plan.datasets]
    sourcetypes = locks["sourcetypes"] or [
        branch.sourcetype for branch in plan.datasets if branch.sourcetype
    ]
    return CoverageSpec(
        explicit_indexes=_unique(item.casefold() for item in locks["indexes"]),
        explicit_sourcetypes=_unique(item.casefold() for item in locks["sourcetypes"]),
        indexes=_unique(item.casefold() for item in indexes),
        sourcetypes=_unique(item.casefold() for item in sourcetypes),
        filters=_unique(plan_filters + question_filters),
        question_filters=_unique(question_filters),
        dimensions=_unique(plan_dimensions + question_dimensions),
        question_dimensions=_unique(question_dimensions),
        measures=_unique(plan_measures + question_measures),
        question_measures=_unique(question_measures),
        shapes=_unique(sorted(plan_shapes | requested_shapes)),
        question_shapes=_unique(sorted(requested_shapes)),
        output_fields=_unique(_canonical_for_plan(item, aliases) for item in output_fields),
        required_fields=_unique(_canonical_for_plan(item, aliases) for item in required_fields),
    )


def _query_values(query: str, key: str) -> set[str]:
    return {
        next((part for part in match if part), "").strip().casefold()
        for match in re.findall(
            rf'\b{re.escape(key)}\s*=\s*(?:"([^"]+)"|\'([^\']+)\'|([A-Za-z0-9_*.:/-]+))',
            str(query or ""),
            flags=re.IGNORECASE,
        )
        if any(match)
    }


def _spl_has_predicate(query: str, signature: str) -> bool:
    try:
        field_name, operator, literal = signature.split(":", 2)
    except ValueError:
        return False
    query_l = str(query or "").casefold()
    escaped_field = re.escape(field_name)
    if operator == "exists":
        return bool(re.search(rf"(?:isnotnull\(\s*{escaped_field}\s*\)|\b{escaped_field}\s*=\s*\*)", query_l))
    if operator == "not_exists":
        return bool(re.search(rf"(?:isnull\(\s*{escaped_field}\s*\)|not\s+{escaped_field}\s*=\s*\*)", query_l))
    symbols = {
        "eq": r"=",
        "neq": r"!=",
        "lt": r"<",
        "lte": r"<=",
        "gt": r">",
        "gte": r">=",
    }
    if operator in symbols:
        pattern = rf"\b{escaped_field}\s*{symbols[operator]}\s*[\"']?{re.escape(literal)}[\"']?"
        if re.search(pattern, query_l):
            return True
        canonical_field = _canonical_role(field_name)
        for match in re.finditer(
            rf"\b([a-z_][a-z0-9_.:-]*)\s*{symbols[operator]}\s*[\"']?{re.escape(literal)}[\"']?",
            query_l,
        ):
            if _canonical_role(match.group(1)) == canonical_field:
                return True
        return False
    if operator in {"contains", "prefix", "suffix"}:
        return field_name in query_l and literal in query_l
    if operator in {"in", "not_in"}:
        return bool(re.search(rf"\b{escaped_field}\s+in\s*\(", query_l))
    return False


def _spl_dimensions(query: str) -> set[str]:
    query_l = str(query or "").casefold()
    dimensions: set[str] = set()
    for match in re.finditer(r"\|\s*(?:stats|timechart)\b([^|]*)", query_l):
        segment = match.group(1)
        by_match = re.search(r"\bby\s+(.+)$", segment)
        if by_match:
            dimensions.update(
                _canonical_role(item)
                for item in re.findall(r"[a-z_][a-z0-9_.:-]*", by_match.group(1))
                if item not in {"limit", "useother", "usenull"}
            )
    return dimensions


def _matching_parenthesis(text: str, opening: int) -> int:
    """Return the closing parenthesis for one call, or ``-1`` if incomplete."""
    depth = 0
    quote = ""
    escaped = False
    for position in range(opening, len(text)):
        char = text[position]
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if quote:
            if char == quote:
                quote = ""
            continue
        if char in {'"', "'"}:
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return position
    return -1


def _split_top_level_args(expression: str) -> list[str]:
    """Split a function expression without treating nested commas as separators."""
    args: list[str] = []
    start = 0
    depth = 0
    quote = ""
    escaped = False
    for position, char in enumerate(expression):
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if quote:
            if char == quote:
                quote = ""
            continue
        if char in {'"', "'"}:
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")" and depth:
            depth -= 1
        elif char == "," and depth == 0:
            args.append(expression[start:position].strip())
            start = position + 1
    args.append(expression[start:].strip())
    return args


def _aggregate_field(function: str, argument: str) -> str:
    """Extract the semantic field from compiler-emitted aggregate arguments."""
    function = function.casefold()
    argument = argument.strip()
    if function == "count":
        # count(eval(condition)) is still the unfielded count:* measure.
        return "*"
    if argument.casefold().startswith("eval("):
        closing = _matching_parenthesis(argument, argument.find("("))
        if closing == len(argument) - 1:
            inner = argument[argument.find("(") + 1 : closing].strip()
            if inner.casefold().startswith("if("):
                if_closing = _matching_parenthesis(inner, inner.find("("))
                if if_closing == len(inner) - 1:
                    if_args = _split_top_level_args(inner[inner.find("(") + 1 : if_closing])
                    if len(if_args) >= 2:
                        field_match = re.fullmatch(r"[a-z_][a-z0-9_.:-]*", if_args[1])
                        if field_match:
                            return field_match.group(0)
            field_match = re.match(r"[a-z_][a-z0-9_.:-]*", inner)
            if field_match:
                return field_match.group(0)
        return "*"
    field_match = re.match(r"[a-z_][a-z0-9_.:-]*", argument)
    return field_match.group(0) if field_match else "*"


def _spl_measures(query: str) -> set[str]:
    query_l = str(query or "").casefold()
    measures: set[str] = set()
    for stats_match in re.finditer(r"\|\s*(?:stats|timechart)\b([^|]*)", query_l):
        segment = stats_match.group(1)
        for call_match in re.finditer(
            rf"\b({'|'.join(_AGGREGATIONS)})\s*\(",
            segment,
        ):
            opening = segment.find("(", call_match.start())
            closing = _matching_parenthesis(segment, opening)
            if closing < 0:
                continue
            argument = segment[opening + 1 : closing]
            measures.add(
                f"{call_match.group(1)}:{_aggregate_field(call_match.group(1), argument)}"
            )
        for bare_match in re.finditer(
            rf"\b({'|'.join(_AGGREGATIONS)})\b(?!\s*\()",
            segment,
        ):
            measures.add(f"{bare_match.group(1)}:*")
    return measures


def _canonical_spl_measure_signatures(
    signatures: Iterable[str],
    aliases: dict[str, str],
) -> set[str]:
    canonical: set[str] = set()
    for signature in signatures:
        function, _, field_name = str(signature).partition(":")
        canonical.add(
            f"{function}:{_canonical_for_plan(field_name, aliases)}"
        )
    return canonical


def _spl_shapes(query: str, output_fields: set[str]) -> set[str]:
    query_l = str(query or "").casefold()
    shapes: set[str] = set()
    if re.search(r"\|\s*(?:stats|timechart)\b", query_l):
        shapes.add("aggregate")
    bin_match = re.search(r"\|\s*bin\s+\S+\s+span\s*=\s*([0-9]+[smhdwmonqy]+)", query_l)
    if bin_match or "| timechart " in query_l:
        shapes.add("time_bin")
        if bin_match:
            shapes.add(f"time_bin:{bin_match.group(1)}")
        timechart_span = re.search(r"\|\s*timechart\b[^|]*\bspan\s*=\s*([0-9]+[smhdwmonqy]+)", query_l)
        if timechart_span:
            shapes.add(f"time_bin:{timechart_span.group(1)}")
    sort_match = re.search(r"\|\s*sort\b[^|]*?([+-])([a-z_][a-z0-9_.:-]*)", query_l)
    if sort_match:
        direction = "desc" if sort_match.group(1) == "-" else "asc"
        shapes.update({"ranking", f"ranking:{direction}"})
        head_match = re.search(r"\|\s*head\s+(\d+)", query_l)
        if head_match:
            shapes.add(f"ranking:{direction}:{head_match.group(1)}")
    if re.search(r"\|\s*eval\s+\w+\s*=\s*if\([^|]*/[^|]*\)", query_l):
        shapes.add("ratio")
    if "isnotnull(" in query_l and " and " in query_l and "count(eval(" in query_l:
        shapes.add("intersection")
    if re.search(r"\|\s*where\b", query_l):
        shapes.add("threshold")
    if re.search(r"\b(?:earliest|first)\s*\(", query_l):
        shapes.add("first_seen")
    if "comparison" in output_fields or "baseline" in output_fields:
        shapes.add("comparison")
    if len(
        re.findall(r"\bcount\s*\(\s*eval\(", query_l)
    ) >= 2:
        shapes.add("comparison")
    stats_matches = list(re.finditer(r"\|\s*stats\b([^|]*)", query_l))
    if stats_matches:
        final_stats = stats_matches[-1].group(1)
        if " by " not in final_stats and len(_spl_measures("| stats " + final_stats)) == 1:
            shapes.add("cardinality")
    return shapes


def _spl_output_fields(query: str) -> set[str]:
    query_l = str(query or "").casefold()
    for command in ("fields", "table"):
        matches = list(re.finditer(rf"\|\s*{command}\s+([^|]+)", query_l))
        if matches:
            return _canonical_fields(
                item
                for item in re.findall(r"[a-z_][a-z0-9_.:-]*", matches[-1].group(1))
                if item not in {"as"}
            )
    stats_matches = list(re.finditer(r"\|\s*(?:stats|timechart)\b([^|]*)", query_l))
    if not stats_matches:
        return set()
    segment = stats_matches[-1].group(1)
    fields = set(re.findall(r"\bas\s+([a-z_][a-z0-9_.:-]*)", segment))
    by_match = re.search(r"\bby\s+(.+)$", segment)
    if by_match:
        fields.update(re.findall(r"[a-z_][a-z0-9_.:-]*", by_match.group(1)))
    if not fields and re.search(r"\bcount\b", segment):
        fields.add("count")
    stats_end = stats_matches[-1].end()
    fields.update(
        re.findall(
            r"\|\s*eval\s+([a-z_][a-z0-9_.:-]*)\s*=",
            query_l[stats_end:],
        )
    )
    return _canonical_fields(fields)


def _unsupported_required_fields(
    plan: AnalyticalPlan,
    field_strategy: dict[str, Any] | None,
) -> list[str]:
    strategy = field_strategy if isinstance(field_strategy, dict) else {}
    roles = strategy.get("roles", {}) if isinstance(strategy.get("roles"), dict) else {}
    if not roles:
        return []
    normalized_outputs = {_canonical_role(item.output) for item in plan.normalizations}
    normalized_inputs = {
        _canonical_role(field_name)
        for item in plan.normalizations
        for field_name in item.fields
        if str(field_name).strip()
    }
    required_fields: list[str] = list(plan.dimensions)
    required_fields.extend(
        str(predicate.get("field", ""))
        for predicate in _plan_predicates(plan)
    )
    required_fields.extend(
        str(measure.get("field", ""))
        for measure in plan.measures
    )
    unsupported: list[str] = []
    for field_name in required_fields:
        role = _canonical_role(field_name)
        data = roles.get(role)
        candidate_fields = {
            _canonical_role(field_name)
            for field_name in data.get("candidate_fields", [])
            if isinstance(data, dict) and str(field_name).strip()
        } if isinstance(data, dict) and isinstance(data.get("candidate_fields"), list) else set()
        if (
            isinstance(data, dict)
            and not data.get("trusted_fields")
            and role not in candidate_fields
            and role not in normalized_outputs
            and role not in normalized_inputs
            and role not in {"_time", "_raw", "index", "sourcetype", "source"}
        ):
            unsupported.append(role)
    return sorted(set(unsupported))


def _weighted_score(components: dict[str, float]) -> float:
    return round(
        sum(float(components.get(name, 0.0)) * weight for name, weight in STATIC_COMPONENT_WEIGHTS.items()),
        4,
    )


def _hard_failure(kind: str, item: str = "") -> str:
    return f"{kind}:{item}" if item else kind


def evaluate_semantic_coverage(
    *,
    question: str,
    analytical_plan: AnalyticalPlan | dict[str, Any],
    query_args: dict[str, Any],
    field_strategy: dict[str, Any] | None = None,
    safety_ok: bool = True,
    safety_reason: str = "existing_safety_gates_passed",
) -> dict[str, Any]:
    """Score plan, SPL, and declared output schema without executing a candidate."""
    plan = parse_analytical_plan(analytical_plan)
    if plan is None:
        raise ValueError("analytical_plan_missing_or_malformed")
    spec = build_coverage_spec(question, plan)
    query = str((query_args or {}).get("query", "")).strip()

    plan_indexes = {branch.index.casefold() for branch in plan.datasets}
    plan_sourcetypes = {
        branch.sourcetype.casefold() for branch in plan.datasets if branch.sourcetype
    }
    aliases = _plan_aliases(plan)
    plan_filters = {
        _predicate_signature_for_plan(item, aliases)
        for item in _plan_predicates(plan)
    }
    plan_dimensions = {
        _canonical_for_plan(item, aliases)
        for item in plan.dimensions
    }
    plan_measures = {
        _measure_signature_for_plan(item, aliases)
        for item in plan.measures
    }
    plan_shapes = _plan_shapes(plan, set(spec.question_shapes))
    plan_outputs = {
        _canonical_for_plan(item, aliases)
        for item in plan.output_fields
    }
    if not plan_outputs:
        plan_outputs = set(spec.output_fields)

    valid_plan, plan_validation_errors = validate_analytical_plan(plan)
    plan_components = {
        "dataset_scope": _coverage_score(
            plan_indexes | plan_sourcetypes,
            set(spec.indexes) | set(spec.sourcetypes),
            exact=True,
        ),
        "filters": _coverage_score(plan_filters, spec.filters),
        "dimensions": _coverage_score(plan_dimensions, spec.dimensions),
        "measures": _coverage_score(plan_measures, spec.measures),
        "shape": _coverage_score(plan_shapes, spec.shapes),
        "output_schema": _coverage_score(plan_outputs, spec.output_fields),
        "safety": 1.0 if valid_plan else 0.0,
    }
    plan_missing = {
        "filters": _missing(plan_filters, spec.question_filters),
        "dimensions": _missing(plan_dimensions, spec.question_dimensions),
        "measures": _missing(plan_measures, spec.question_measures),
        "shape": _missing(plan_shapes, spec.question_shapes),
        "output_fields": _missing(plan_outputs, spec.output_fields),
    }
    plan_hard: list[str] = []
    if set(spec.explicit_indexes) and plan_indexes != set(spec.explicit_indexes):
        plan_hard.append("dataset:explicit_index_lock_violation")
    if set(spec.explicit_sourcetypes) and plan_sourcetypes != set(spec.explicit_sourcetypes):
        plan_hard.append("dataset:explicit_sourcetype_lock_violation")
    for category, items in plan_missing.items():
        plan_hard.extend(_hard_failure(category.rstrip("s"), item) for item in items)
    unsupported = _unsupported_required_fields(plan, field_strategy)
    plan_hard.extend(_hard_failure("unsupported_field", item) for item in unsupported)
    plan_hard.extend(f"plan_validation:{item}" for item in plan_validation_errors)

    spl_indexes = _query_values(query, "index")
    spl_sourcetypes = _query_values(query, "sourcetype")
    spl_filter_hits = {
        signature for signature in spec.filters if _spl_has_predicate(query, signature)
    }
    spl_dimensions = _spl_dimensions(query)
    spl_measures = _canonical_spl_measure_signatures(_spl_measures(query), aliases)
    spl_outputs = _spl_output_fields(query)
    spl_shapes = _spl_shapes(query, spl_outputs)
    dataset_ok, dataset_reason = validate_query_dataset_locks(question, query)
    apache_ok, apache_reason = query_has_requested_apache_dimensions(question, query)
    spl_components = {
        "dataset_scope": _coverage_score(
            spl_indexes | spl_sourcetypes,
            set(spec.indexes) | set(spec.sourcetypes),
            exact=True,
        ),
        "filters": _coverage_score(spl_filter_hits, spec.filters),
        "dimensions": _coverage_score(spl_dimensions, spec.dimensions),
        "measures": _coverage_score(spl_measures, spec.measures),
        "shape": _coverage_score(spl_shapes, spec.shapes),
        "output_schema": _coverage_score(spl_outputs, spec.output_fields),
        "safety": 1.0 if safety_ok else 0.0,
    }
    spl_missing = {
        "filters": _missing(spl_filter_hits, spec.filters),
        "dimensions": _missing(spl_dimensions, spec.dimensions),
        "measures": _missing(spl_measures, spec.measures),
        "shape": _missing(spl_shapes, spec.shapes),
        "output_fields": _missing(spl_outputs, spec.output_fields),
    }
    spl_hard: list[str] = []
    if not dataset_ok:
        spl_hard.append(f"dataset:{dataset_reason}")
    if set(spec.indexes) and spl_indexes != set(spec.indexes):
        spl_hard.append(
            "dataset:index_scope_mismatch:"
            f"expected={','.join(spec.indexes)}:actual={','.join(sorted(spl_indexes))}"
        )
    if set(spec.sourcetypes) and spl_sourcetypes != set(spec.sourcetypes):
        spl_hard.append(
            "dataset:sourcetype_scope_mismatch:"
            f"expected={','.join(spec.sourcetypes)}:actual={','.join(sorted(spl_sourcetypes))}"
        )
    query_platforms = _query_values(query, "platform")
    plan_platforms = {
        branch.platform.casefold() for branch in plan.datasets if branch.platform
    }
    if query_platforms and plan_platforms and not query_platforms.issubset(plan_platforms):
        spl_hard.append(
            "dataset:conflicting_platform:"
            f"expected={','.join(sorted(plan_platforms))}:actual={','.join(sorted(query_platforms))}"
        )
    for category, items in spl_missing.items():
        spl_hard.extend(_hard_failure(category.rstrip("s"), item) for item in items)
    # The generalized plan/SPL dimension checks above now subsume the legacy
    # Apache adapter. Keep its result as migration telemetry, but do not let
    # mentions used as filters or values masquerade as required group-by
    # dimensions.
    if not safety_ok:
        spl_hard.append(f"safety:{safety_reason}")

    plan_score = _weighted_score(plan_components)
    spl_score = _weighted_score(spl_components)
    static_score = round(0.35 * plan_score + 0.65 * spl_score, 4)
    hard_failures = list(dict.fromkeys(plan_hard + spl_hard))
    passed = not hard_failures and static_score >= STATIC_COVERAGE_THRESHOLD
    missing_feedback = {
        key: sorted(set(plan_missing.get(key, []) + spl_missing.get(key, [])))
        for key in plan_missing
        if plan_missing.get(key) or spl_missing.get(key)
    }
    return {
        "version": SEMANTIC_COVERAGE_VERSION,
        "spec": spec.to_dict(),
        "plan": {
            "score": plan_score,
            "components": plan_components,
            "hard_failures": list(dict.fromkeys(plan_hard)),
            "missing": plan_missing,
        },
        "spl": {
            "score": spl_score,
            "components": spl_components,
            "hard_failures": list(dict.fromkeys(spl_hard)),
            "missing": spl_missing,
            "apache_dimension_adapter": {"ok": apache_ok, "reason": apache_reason},
        },
        "output_schema": {
            "score": spl_components["output_schema"],
            "required": list(spec.output_fields),
            "actual": sorted(spl_outputs),
            "missing": spl_missing["output_fields"],
        },
        "static_score": static_score,
        "threshold": STATIC_COVERAGE_THRESHOLD,
        "passed": passed,
        "hard_failures": hard_failures,
        "live_evidence": {
            "status": "pending_candidate_probe",
            "score": None,
            "reason": "scored_by_semantic_candidate_selector",
        },
        "repair_feedback": {
            "target": "analytical_plan",
            "repair_kind": "structured_plan_only",
            "raw_spl_repair_allowed": False,
            "failure_classes": sorted({item.split(":", 1)[0] for item in hard_failures}),
            "validation_errors": hard_failures,
            "missing": missing_feedback,
            "instructions": [
                "Preserve explicit dataset locks and all existing safety constraints.",
                "Restore missing requested semantics in the typed AnalyticalPlan.",
                "Do not patch or return raw SPL.",
            ],
        },
    }
