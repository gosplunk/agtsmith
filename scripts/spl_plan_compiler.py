#!/usr/bin/env python3
"""Deterministic, read-only compiler for versioned AnalyticalPlan objects."""

from __future__ import annotations

import math
import re
from typing import Any

from spl_query_schema import AnalyticalPlan, parse_analytical_plan, validate_analytical_plan

COMPILER_VERSION = "1.0"
EMITTED_COMMAND_ALLOWLIST = {
    "search", "eval", "rex", "spath", "bin", "stats", "where",
    "sort", "head", "fields",
}


class AnalyticalPlanCompileError(ValueError):
    """Raised when a plan cannot be safely compiled."""


def _quote(value: Any) -> str:
    text = str(value)
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _literal(value: Any) -> str:
    if isinstance(value, bool):
        return "true()" if value else "false()"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise AnalyticalPlanCompileError("non_finite_numeric_literal")
        return repr(value)
    return _quote(value)


def _predicate(predicate: dict[str, Any], *, eval_context: bool) -> str:
    field_name = str(predicate["field"]).strip()
    operator = str(predicate["operator"]).strip().lower()
    value = predicate.get("value")
    if operator == "exists":
        return f"isnotnull({field_name})" if eval_context else f"{field_name}=*"
    if operator == "not_exists":
        return f"isnull({field_name})" if eval_context else f"NOT {field_name}=*"
    if operator in {"in", "not_in"}:
        values = ",".join(_literal(item) for item in value)
        expression = f"{field_name} IN ({values})"
        return f"NOT ({expression})" if operator == "not_in" else expression
    if operator == "contains":
        return (
            f"like({field_name},{_quote('%' + str(value) + '%')})"
            if eval_context
            else f"{field_name}={_quote('*' + str(value) + '*')}"
        )
    if operator == "prefix":
        return (
            f"like({field_name},{_quote(str(value) + '%')})"
            if eval_context
            else f"{field_name}={_quote(str(value) + '*')}"
        )
    if operator == "suffix":
        return (
            f"like({field_name},{_quote('%' + str(value))})"
            if eval_context
            else f"{field_name}={_quote('*' + str(value))}"
        )
    if operator == "regex":
        return (
            f"match({field_name},{_quote(value)})"
            if eval_context
            else f"{field_name}={_quote(value)}"
        )
    spl_operator = {
        "eq": "=", "neq": "!=", "lt": "<", "lte": "<=",
        "gt": ">", "gte": ">=",
    }[operator]
    return f"{field_name}{spl_operator}{_literal(value)}"


def _dataset_clause(branch: Any) -> str:
    terms = ["index=* NOT index=_*" if branch.index == "*" else f"index={_quote(branch.index)}"]
    if branch.sourcetype:
        terms.append(f"sourcetype={_quote(branch.sourcetype)}")
    if branch.platform:
        terms.append(f"platform={_quote(branch.platform)}")
    terms.extend(_predicate(item, eval_context=False) for item in branch.filters)
    return "(" + " ".join(terms) + ")"


def _normalization_stage(normalization: Any) -> str | None:
    if normalization.kind == "native":
        source = normalization.fields[0]
        if source == normalization.output:
            return None
        return f"eval {normalization.output}={source}"
    if normalization.kind == "coalesce":
        return f"eval {normalization.output}=coalesce({','.join(normalization.fields)})"
    if normalization.kind == "rex":
        return f"rex field={normalization.source_field} {_quote(normalization.pattern)}"
    if normalization.kind == "spath":
        return (
            f"spath input={normalization.source_field} "
            f"path={_quote(normalization.path)} output={normalization.output}"
        )
    raise AnalyticalPlanCompileError(f"normalization_kind_not_allowed:{normalization.kind}")


def _measure_expression(measure: dict[str, Any]) -> str:
    name = str(measure["name"]).strip()
    function = str(measure["function"]).strip().lower()
    field_name = str(measure.get("field", "")).strip()
    condition = measure.get("condition")
    if condition is not None:
        condition_expr = _predicate(condition, eval_context=True)
        if function == "count":
            return f"count(eval({condition_expr})) as {name}"
        return f"{function}(eval(if({condition_expr},{field_name},null()))) as {name}"
    if function == "count":
        return f"count as {name}"
    return f"{function}({field_name}) as {name}"


def _commands(query: str) -> list[str]:
    commands = ["search"]
    commands.extend(
        match.group(1).lower()
        for match in re.finditer(r"\|\s*([A-Za-z][A-Za-z0-9_]*)", query)
    )
    return commands


def compile_analytical_plan(plan: AnalyticalPlan | dict[str, Any]) -> str:
    parsed = parse_analytical_plan(plan)
    if parsed is None:
        raise AnalyticalPlanCompileError("analytical_plan_required")
    valid, errors = validate_analytical_plan(parsed)
    if not valid:
        raise AnalyticalPlanCompileError(";".join(errors))

    stages = ["search " + " OR ".join(_dataset_clause(branch) for branch in parsed.datasets)]
    for normalization in parsed.normalizations:
        stage = _normalization_stage(normalization)
        if stage:
            stages.append(stage)

    dimensions = list(parsed.dimensions)
    if parsed.time_bin:
        time_field = str(parsed.time_bin.get("field", "_time")).strip()
        alias = str(parsed.time_bin.get("alias", time_field)).strip()
        span = str(parsed.time_bin["span"]).strip()
        stages.append(f"bin {time_field} span={span}")
        if alias != time_field:
            stages.append(f"eval {alias}={time_field}")
        if alias not in dimensions:
            dimensions.insert(0, alias)

    measure_expressions = [_measure_expression(item) for item in parsed.measures]
    for intersection in parsed.intersections:
        name = str(intersection["name"]).strip()
        fields = [str(item).strip() for item in intersection["fields"]]
        condition = " AND ".join(f"isnotnull({item})" for item in fields)
        measure_expressions.append(f"count(eval({condition})) as {name}")
    if measure_expressions:
        stats = "stats " + " ".join(measure_expressions)
        if dimensions:
            stats += " by " + " ".join(dimensions)
        stages.append(stats)

    for ratio in parsed.ratios:
        name = str(ratio["name"]).strip()
        numerator = str(ratio["numerator"]).strip()
        denominator = str(ratio["denominator"]).strip()
        zero_value = "0" if str(ratio.get("zero_policy", "null")).lower() == "zero" else "null()"
        scale = ratio.get("scale", 1)
        if isinstance(scale, bool) or not isinstance(scale, (int, float)) or not math.isfinite(float(scale)):
            raise AnalyticalPlanCompileError(f"ratio_scale_invalid:{name}")
        stages.append(
            f"eval {name}=if({denominator}=0,{zero_value},"
            f"({numerator}/{denominator})*{_literal(scale)})"
        )
    for predicate in parsed.post_aggregation_predicates:
        stages.append("where " + _predicate(predicate, eval_context=True))

    effective_limit = parsed.execution.row_limit
    for rank in parsed.ranking:
        direction = "-" if str(rank.get("direction", "desc")).lower() == "desc" else "+"
        stages.append(f"sort 0 {direction}{str(rank['field']).strip()}")
        effective_limit = min(effective_limit, int(rank.get("limit", effective_limit)))
    if parsed.output_fields:
        stages.append("fields " + " ".join(parsed.output_fields))
    stages.append(f"head {effective_limit}")

    query = " | ".join(stages)
    emitted = _commands(query)
    blocked = [command for command in emitted if command not in EMITTED_COMMAND_ALLOWLIST]
    if blocked:
        raise AnalyticalPlanCompileError(f"compiler_emitted_blocked_command:{blocked[0]}")
    return query


def analytical_plan_to_tool_args(
    plan: AnalyticalPlan | dict[str, Any],
    *,
    intent: str = "",
) -> dict[str, Any]:
    parsed = parse_analytical_plan(plan)
    if parsed is None:
        raise AnalyticalPlanCompileError("analytical_plan_required")
    query = compile_analytical_plan(parsed)
    return {
        "selected_tool": "splunk_run_query",
        "intent": intent,
        "tool_args": {
            "query": query,
            "earliest_time": parsed.execution.earliest,
            "latest_time": parsed.execution.latest,
            "row_limit": parsed.execution.row_limit,
        },
        "analytical_plan": parsed.to_dict(),
        "analytical_plan_version": parsed.version,
        "spl_plan_compiler_version": COMPILER_VERSION,
    }
