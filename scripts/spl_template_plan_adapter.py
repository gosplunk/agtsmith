#!/usr/bin/env python3
"""Convert representable legacy templates to AnalyticalPlan parity fixtures."""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from typing import Any

from query_templates import QueryTemplate, TEMPLATES
from spl_plan_compiler import AnalyticalPlanCompileError, compile_analytical_plan
from spl_query_schema import AnalyticalPlan, AnalyticalExecution, DatasetBranch


@dataclass(frozen=True)
class TemplatePlanAdapterResult:
    intent: str
    status: str
    plan: AnalyticalPlan | None
    compiled_query: str
    fallback_query: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "intent": self.intent,
            "status": self.status,
            "analytical_plan": self.plan.to_dict() if self.plan else None,
            "compiled_query": self.compiled_query,
            "fallback_query": self.fallback_query,
            "reason": self.reason,
        }


def _split_pipeline(query: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    quote = ""
    escaped = False
    bracket_depth = 0
    for char in query:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\":
            current.append(char)
            escaped = True
            continue
        if quote:
            current.append(char)
            if char == quote:
                quote = ""
            continue
        if char in {'"', "'"}:
            quote = char
            current.append(char)
            continue
        if char == "[":
            bracket_depth += 1
        elif char == "]" and bracket_depth:
            bracket_depth -= 1
        if char == "|" and bracket_depth == 0:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(char)
    parts.append("".join(current).strip())
    return [part for part in parts if part]


def _parse_base(segment: str) -> tuple[DatasetBranch | None, str]:
    if not segment.lower().startswith("search "):
        return None, "base_not_search"
    body = segment[7:].strip()
    if any(token in body for token in ("(", ")", " OR ", " NOT ", " AND ")):
        return None, "compound_dataset_scope"
    try:
        tokens = shlex.split(body)
    except ValueError:
        return None, "base_tokenization_failed"
    index = ""
    sourcetype = ""
    filters: list[dict[str, Any]] = []
    for token in tokens:
        if "=" not in token:
            return None, "free_text_base_filter"
        field_name, value = token.split("=", 1)
        if field_name.lower() == "index":
            index = value
        elif field_name.lower() == "sourcetype":
            sourcetype = value
        elif re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.:-]*", field_name):
            filters.append({"field": field_name, "operator": "eq", "value": value})
        else:
            return None, "base_filter_not_representable"
    if not index:
        return None, "index_scope_missing"
    return DatasetBranch(index=index, sourcetype=sourcetype, filters=filters), ""


def _parse_stats(segment: str) -> tuple[list[dict[str, Any]], list[str], str]:
    match = re.fullmatch(r"stats\s+(.+?)(?:\s+by\s+(.+))?", segment, flags=re.IGNORECASE)
    if not match:
        return [], [], "stats_parse_failed"
    aggregate_text = match.group(1).strip()
    dimensions = match.group(2).split() if match.group(2) else []
    measures: list[dict[str, Any]] = []
    pattern = re.compile(
        r"(count|dc|sum|avg|min|max|values|list|earliest|latest|first|last)"
        r"(?:\(([^)]+)\))?(?:\s+as\s+([A-Za-z_][A-Za-z0-9_.:-]*))?",
        flags=re.IGNORECASE,
    )
    position = 0
    for item in pattern.finditer(aggregate_text):
        if aggregate_text[position:item.start()].strip():
            return [], [], "stats_expression_not_representable"
        function = item.group(1).lower()
        field_name = (item.group(2) or "").strip()
        alias = (item.group(3) or ("count" if function == "count" else f"{function}_{field_name}")).strip()
        measures.append({"name": alias, "function": function, "field": field_name})
        position = item.end()
    if aggregate_text[position:].strip() or not measures:
        return [], [], "stats_expression_not_representable"
    return measures, dimensions, ""


def adapt_template_to_analytical_plan(template: QueryTemplate) -> TemplatePlanAdapterResult:
    parts = _split_pipeline(template.query)
    if not parts:
        return TemplatePlanAdapterResult(
            template.intent, "fallback_only", None, "", template.query, "empty_template"
        )
    branch, reason = _parse_base(parts[0])
    if branch is None:
        return TemplatePlanAdapterResult(
            template.intent, "fallback_only", None, "", template.query, reason
        )
    measures: list[dict[str, Any]] = []
    dimensions: list[str] = []
    ranking: list[dict[str, Any]] = []
    output_fields: list[str] = []
    explicit_head: int | None = None
    for segment in parts[1:]:
        lower = segment.lower()
        if lower.startswith("stats "):
            if measures or output_fields:
                reason = "multiple_terminal_shapes"
                break
            measures, dimensions, reason = _parse_stats(segment)
            if reason:
                break
        elif lower.startswith("sort "):
            match = re.fullmatch(
                r"sort(?:\s+0)?\s+([+-])?\s*([A-Za-z_][A-Za-z0-9_.:-]*)",
                segment,
                flags=re.IGNORECASE,
            )
            if not match:
                reason = "sort_not_representable"
                break
            ranking.append(
                {
                    "field": match.group(2),
                    "direction": "asc" if match.group(1) == "+" else "desc",
                    "limit": template.row_limit,
                }
            )
        elif lower.startswith("head "):
            match = re.fullmatch(r"head\s+(\d+)", segment, flags=re.IGNORECASE)
            if not match:
                reason = "head_not_representable"
                break
            explicit_head = int(match.group(1))
        elif lower.startswith("table "):
            if measures:
                reason = "table_after_aggregation_not_representable"
                break
            output_fields = segment.split()[1:]
        else:
            reason = f"pipeline_stage_fallback:{segment.split()[0].lower()}"
            break
    if reason:
        return TemplatePlanAdapterResult(
            template.intent, "fallback_only", None, "", template.query, reason
        )
    row_limit = min(template.row_limit, explicit_head or template.row_limit)
    for rank in ranking:
        rank["limit"] = row_limit
    plan = AnalyticalPlan(
        datasets=[branch],
        dimensions=dimensions,
        measures=measures,
        ranking=ranking,
        output_fields=output_fields,
        execution=AnalyticalExecution(
            earliest=template.earliest_time,
            latest=template.latest_time,
            row_limit=row_limit,
            materialization="bounded",
        ),
    )
    try:
        compiled = compile_analytical_plan(plan)
    except AnalyticalPlanCompileError as exc:
        return TemplatePlanAdapterResult(
            template.intent,
            "fallback_only",
            None,
            "",
            template.query,
            f"plan_validation_failed:{exc}",
        )
    return TemplatePlanAdapterResult(
        template.intent,
        "represented",
        plan,
        compiled,
        template.query,
        "semantic_shape_parity",
    )


def template_parity_inventory() -> list[TemplatePlanAdapterResult]:
    """Return deterministic represented/fallback coverage for all templates."""
    return [adapt_template_to_analytical_plan(template) for template in TEMPLATES]
