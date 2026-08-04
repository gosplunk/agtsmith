#!/usr/bin/env python3
"""Constrained SPL writer schema: WritePlan slots and materialization."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any


ALLOWED_AGGREGATIONS = {"count", "dc", "sum", "avg", "max", "min", "values", "list"}
ALLOWED_COMMANDS = {"stats", "table", "dedup", "sort", "head", "fields", "rename", "eval", "where", "regex"}


@dataclass
class WritePlan:
    index_expr: str = "index=* NOT index=_*"
    sourcetype: str = ""
    filters: list[str] = field(default_factory=list)
    aggregation: str = "count"
    group_by: list[str] = field(default_factory=list)
    sort_by: str = ""
    sort_dir: str = "desc"
    head_limit: int = 20
    earliest_time: str = "-7d"
    latest_time: str = "now"
    row_limit: int = 100
    extra_pipeline: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "WritePlan":
        data = data if isinstance(data, dict) else {}
        filters = data.get("filters", [])
        group_by = data.get("group_by", data.get("by_fields", []))
        extra = data.get("extra_pipeline", data.get("pipeline", []))
        return cls(
            index_expr=str(data.get("index_expr", data.get("index", "index=* NOT index=_*"))).strip(),
            sourcetype=str(data.get("sourcetype", "")).strip(),
            filters=[str(f).strip() for f in filters if str(f).strip()] if isinstance(filters, list) else [],
            aggregation=str(data.get("aggregation", "count")).strip().lower() or "count",
            group_by=[str(g).strip() for g in group_by if str(g).strip()] if isinstance(group_by, list) else [],
            sort_by=str(data.get("sort_by", "")).strip(),
            sort_dir=str(data.get("sort_dir", "desc")).strip().lower() or "desc",
            head_limit=int(data.get("head_limit", 20) or 20),
            earliest_time=str(data.get("earliest_time", "-7d")).strip() or "-7d",
            latest_time=str(data.get("latest_time", "now")).strip() or "now",
            row_limit=min(int(data.get("row_limit", 100) or 100), 200),
            extra_pipeline=[str(p).strip() for p in extra if str(p).strip()] if isinstance(extra, list) else [],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "index_expr": self.index_expr,
            "sourcetype": self.sourcetype,
            "filters": self.filters,
            "aggregation": self.aggregation,
            "group_by": self.group_by,
            "sort_by": self.sort_by,
            "sort_dir": self.sort_dir,
            "head_limit": self.head_limit,
            "earliest_time": self.earliest_time,
            "latest_time": self.latest_time,
            "row_limit": self.row_limit,
            "extra_pipeline": self.extra_pipeline,
        }


def writer_mode() -> str:
    import os

    return str(os.getenv("AGTSMITH_WRITER_MODE", "free")).strip().lower()


def constrained_mode_enabled() -> bool:
    return writer_mode() == "constrained"


def parse_write_plan(raw: Any) -> WritePlan | None:
    if isinstance(raw, WritePlan):
        return raw
    if isinstance(raw, dict):
        if "write_plan" in raw and isinstance(raw["write_plan"], dict):
            return WritePlan.from_dict(raw["write_plan"])
        if any(k in raw for k in ("index_expr", "sourcetype", "filters", "aggregation")):
            return WritePlan.from_dict(raw)
    if isinstance(raw, str):
        text = raw.strip()
        if not text:
            return None
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return None
        return WritePlan.from_dict(data) if isinstance(data, dict) else None
    return None


def validate_write_plan(plan: WritePlan) -> tuple[bool, str]:
    if not plan.index_expr or not plan.index_expr.lower().startswith("index"):
        return False, "index_expr_must_start_with_index"
    if plan.aggregation not in ALLOWED_AGGREGATIONS:
        return False, f"aggregation_not_allowed:{plan.aggregation}"
    if plan.row_limit <= 0 or plan.row_limit > 200:
        return False, "row_limit_out_of_range"
    for filt in plan.filters:
        if re.search(r"\b(collect|sendalert|outputlookup|delete|drop)\b", filt, re.I):
            return False, "filter_contains_blocked_command"
    for stage in plan.extra_pipeline:
        cmd = stage.split("|", 1)[0].strip().split()[0].lower() if stage.strip() else ""
        if cmd and cmd not in ALLOWED_COMMANDS:
            return False, f"pipeline_command_not_allowed:{cmd}"
    return True, "ok"


def materialize_write_plan(plan: WritePlan) -> str:
    search_parts = [plan.index_expr]
    if plan.sourcetype:
        if "=" in plan.sourcetype:
            search_parts.append(plan.sourcetype)
        else:
            search_parts.append(f'sourcetype="{plan.sourcetype}"')
    search_parts.extend(plan.filters)
    base = "search " + " ".join(part for part in search_parts if part).strip()
    pipeline: list[str] = []
    agg = plan.aggregation
    if plan.group_by:
        by_clause = ", ".join(plan.group_by)
        pipeline.append(f"stats {agg} as count by {by_clause}")
    else:
        pipeline.append(f"stats {agg}")
    pipeline.extend(plan.extra_pipeline)
    if plan.sort_by:
        pipeline.append(f"sort {plan.sort_dir} {plan.sort_by}")
    if plan.head_limit > 0:
        pipeline.append(f"head {plan.head_limit}")
    query = base + (" | " + " | ".join(pipeline) if pipeline else "")
    return re.sub(r"\s+", " ", query).strip()


def write_plan_to_tool_args(plan: WritePlan, *, intent: str = "") -> dict[str, Any]:
    query = materialize_write_plan(plan)
    return {
        "selected_tool": "splunk_run_query",
        "intent": intent,
        "tool_args": {
            "query": query,
            "earliest_time": plan.earliest_time,
            "latest_time": plan.latest_time,
            "row_limit": plan.row_limit,
        },
        "write_plan": plan.to_dict(),
    }


def extract_write_plan_from_candidate(candidate: dict[str, Any]) -> WritePlan | None:
    if not isinstance(candidate, dict):
        return None
    if isinstance(candidate.get("write_plan"), dict):
        return WritePlan.from_dict(candidate["write_plan"])
    tool_args = candidate.get("tool_args", {})
    if not isinstance(tool_args, dict):
        return None
    query = str(tool_args.get("query", "")).strip()
    if not query:
        return None
    return infer_write_plan_from_query(query, tool_args)


def infer_write_plan_from_query(query: str, tool_args: dict[str, Any] | None = None) -> WritePlan:
    tool_args = tool_args if isinstance(tool_args, dict) else {}
    text = " ".join(str(query or "").split())
    plan = WritePlan(
        earliest_time=str(tool_args.get("earliest_time", "-7d")),
        latest_time=str(tool_args.get("latest_time", "now")),
        row_limit=min(int(tool_args.get("row_limit", 100) or 100), 200),
    )
    if not text.lower().startswith("search "):
        plan.index_expr = "index=* NOT index=_*"
        plan.filters = [text] if text else []
        return plan
    body = text[7:]
    segments = [seg.strip() for seg in body.split("|")]
    search_seg = segments[0] if segments else body
    tokens = search_seg.split()
    idx_tokens: list[str] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok.lower().startswith("index=") or tok.lower() == "index":
            if tok.lower() == "index" and i + 1 < len(tokens):
                idx_tokens.append(f"index={tokens[i + 1]}")
                i += 2
                continue
            idx_tokens.append(tok)
        elif tok.upper() in {"NOT", "OR", "AND"} or tok.startswith("("):
            idx_tokens.append(tok)
        elif tok.lower().startswith("sourcetype="):
            plan.sourcetype = tok.split("=", 1)[1].strip('"')
        elif tok.lower() == "sourcetype" and i + 1 < len(tokens):
            plan.sourcetype = tokens[i + 1].strip('"')
            i += 2
            continue
        else:
            plan.filters.append(tok)
        i += 1
    if idx_tokens:
        plan.index_expr = " ".join(idx_tokens)
    for seg in segments[1:]:
        lower = seg.lower()
        if lower.startswith("stats "):
            m = re.match(r"stats\s+(\w+)(?:\s+as\s+\w+)?(?:\s+by\s+(.+))?$", seg, re.I)
            if m:
                plan.aggregation = m.group(1).lower()
                if m.group(2):
                    plan.group_by = [f.strip() for f in m.group(2).split(",") if f.strip()]
        elif lower.startswith("sort "):
            parts = seg.split()
            if len(parts) >= 3:
                plan.sort_dir = parts[1].lower()
                plan.sort_by = parts[2]
        elif lower.startswith("head "):
            try:
                plan.head_limit = int(seg.split()[1])
            except (IndexError, ValueError):
                pass
        else:
            plan.extra_pipeline.append(seg)
    return plan


def constrained_writer_schema_hint() -> str:
    return (
        "Return JSON with write_plan object: "
        "{index_expr, sourcetype, filters[], aggregation, group_by[], sort_by, sort_dir, "
        "head_limit, earliest_time, latest_time, row_limit, extra_pipeline[]}. "
        "Do not emit raw SPL when constrained mode is enabled."
    )


# AnalyticalPlan is deliberately additive. WritePlan remains the constrained
# writer contract until the planner-migration phase switches callers.
ANALYTICAL_PLAN_VERSION = "1.0"
MAX_ANALYTICAL_ROWS = 200
MAX_DATASET_BRANCHES = 8
MAX_PLAN_ITEMS = 32

ALLOWED_FILTER_OPERATORS = {
    "eq", "neq", "lt", "lte", "gt", "gte", "in", "not_in",
    "exists", "not_exists", "contains", "prefix", "suffix",
}
ALLOWED_NORMALIZATION_KINDS = {"native", "coalesce", "rex", "spath"}
ALLOWED_MEASURE_FUNCTIONS = {
    "count", "dc", "sum", "avg", "min", "max", "values", "list",
    "earliest", "latest", "first", "last",
}
ALLOWED_RATIO_ZERO_POLICIES = {"null", "zero"}
ALLOWED_RANK_DIRECTIONS = {"asc", "desc"}
ALLOWED_MATERIALIZATION_PROFILES = {"probe", "interactive", "bounded"}
ALLOWED_TIME_SPANS = re.compile(r"^(?:[1-9]\d*)(?:s|m|h|d|w|mon|q|y)$")
ALLOWED_TIME_VALUES = re.compile(
    r"^(?:0|now|-[1-9]\d*(?:s|m|h|d|w|mon|q|y)"
    r"(?:@(?:s|m|h|d|w|mon|q|y))?|@(?:s|m|h|d|w|mon|q|y)(?:\+\d+[smhdw])?)$",
    re.IGNORECASE,
)
SAFE_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_.:-]*$")
SAFE_DATASET_NAME = re.compile(r"^[A-Za-z0-9_*.:-]+$")
SAFE_PLATFORM = re.compile(r"^[A-Za-z0-9_.:-]+$")


def _list_of_dicts(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [dict(item) for item in value if isinstance(item, dict)]


def _list_of_strings(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


@dataclass
class DatasetBranch:
    index: str
    sourcetype: str = ""
    platform: str = ""
    filters: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DatasetBranch":
        return cls(
            index=str(data.get("index", "")).strip(),
            sourcetype=str(data.get("sourcetype", "")).strip(),
            platform=str(data.get("platform", "")).strip(),
            filters=_list_of_dicts(data.get("filters")),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "sourcetype": self.sourcetype,
            "platform": self.platform,
            "filters": self.filters,
        }


@dataclass
class FieldNormalization:
    output: str
    kind: str = "native"
    fields: list[str] = field(default_factory=list)
    source_field: str = "_raw"
    pattern: str = ""
    path: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FieldNormalization":
        return cls(
            output=str(data.get("output", "")).strip(),
            kind=str(data.get("kind", "native")).strip().lower(),
            fields=_list_of_strings(data.get("fields")),
            source_field=str(data.get("source_field", "_raw")).strip() or "_raw",
            pattern=str(data.get("pattern", "")).strip(),
            path=str(data.get("path", "")).strip(),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "output": self.output,
            "kind": self.kind,
            "fields": self.fields,
            "source_field": self.source_field,
            "pattern": self.pattern,
            "path": self.path,
        }


@dataclass
class AnalyticalExecution:
    earliest: str = "-7d"
    latest: str = "now"
    row_limit: int = 100
    materialization: str = "bounded"

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "AnalyticalExecution":
        data = data if isinstance(data, dict) else {}
        try:
            row_limit = int(data.get("row_limit", 100) or 100)
        except (TypeError, ValueError):
            row_limit = 0
        return cls(
            earliest=str(data.get("earliest", data.get("earliest_time", "-7d"))).strip(),
            latest=str(data.get("latest", data.get("latest_time", "now"))).strip(),
            row_limit=row_limit,
            materialization=str(data.get("materialization", "bounded")).strip().lower(),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "earliest": self.earliest,
            "latest": self.latest,
            "row_limit": self.row_limit,
            "materialization": self.materialization,
        }


@dataclass
class AnalyticalPlan:
    version: str = ANALYTICAL_PLAN_VERSION
    datasets: list[DatasetBranch] = field(default_factory=list)
    normalizations: list[FieldNormalization] = field(default_factory=list)
    dimensions: list[str] = field(default_factory=list)
    measures: list[dict[str, Any]] = field(default_factory=list)
    post_aggregation_predicates: list[dict[str, Any]] = field(default_factory=list)
    time_bin: dict[str, Any] | None = None
    ratios: list[dict[str, Any]] = field(default_factory=list)
    intersections: list[dict[str, Any]] = field(default_factory=list)
    ranking: list[dict[str, Any]] = field(default_factory=list)
    output_fields: list[str] = field(default_factory=list)
    execution: AnalyticalExecution = field(default_factory=AnalyticalExecution)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "AnalyticalPlan":
        data = data if isinstance(data, dict) else {}
        analysis = data.get("analysis", {})
        analysis = analysis if isinstance(analysis, dict) else {}
        raw_time_bin = analysis.get("time_bin")
        return cls(
            version=str(data.get("version", ANALYTICAL_PLAN_VERSION)).strip(),
            datasets=[
                DatasetBranch.from_dict(item)
                for item in _list_of_dicts(data.get("datasets"))
            ],
            normalizations=[
                FieldNormalization.from_dict(item)
                for item in _list_of_dicts(data.get("normalizations"))
            ],
            dimensions=_list_of_strings(analysis.get("dimensions")),
            measures=_list_of_dicts(analysis.get("measures")),
            post_aggregation_predicates=_list_of_dicts(
                analysis.get("post_aggregation_predicates")
            ),
            time_bin=dict(raw_time_bin) if isinstance(raw_time_bin, dict) else None,
            ratios=_list_of_dicts(analysis.get("ratios")),
            intersections=_list_of_dicts(analysis.get("intersections")),
            ranking=_list_of_dicts(analysis.get("ranking")),
            output_fields=_list_of_strings(analysis.get("output_fields")),
            execution=AnalyticalExecution.from_dict(data.get("execution")),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "datasets": [item.to_dict() for item in self.datasets],
            "normalizations": [item.to_dict() for item in self.normalizations],
            "analysis": {
                "dimensions": self.dimensions,
                "measures": self.measures,
                "post_aggregation_predicates": self.post_aggregation_predicates,
                "time_bin": self.time_bin,
                "ratios": self.ratios,
                "intersections": self.intersections,
                "ranking": self.ranking,
                "output_fields": self.output_fields,
            },
            "execution": self.execution.to_dict(),
        }


def parse_analytical_plan(raw: Any) -> AnalyticalPlan | None:
    if isinstance(raw, AnalyticalPlan):
        return raw
    data: Any = raw
    if isinstance(raw, str):
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return None
    if not isinstance(data, dict):
        return None
    if isinstance(data.get("analytical_plan"), dict):
        data = data["analytical_plan"]
    if not any(key in data for key in ("version", "datasets", "analysis")):
        return None
    return AnalyticalPlan.from_dict(data)


def _valid_identifier(value: Any) -> bool:
    return bool(SAFE_IDENTIFIER.fullmatch(str(value or "").strip()))


def _validate_predicate(predicate: dict[str, Any], *, fields_are_measures: bool = False) -> str:
    field_name = str(predicate.get("field", "")).strip()
    operator = str(predicate.get("operator", "")).strip().lower()
    if not _valid_identifier(field_name):
        return "predicate_field_invalid"
    if operator not in ALLOWED_FILTER_OPERATORS:
        return f"predicate_operator_not_allowed:{operator}"
    value = predicate.get("value")
    if operator in {"in", "not_in"}:
        if not isinstance(value, list) or not value or len(value) > MAX_PLAN_ITEMS:
            return "predicate_list_invalid"
    elif operator not in {"exists", "not_exists"} and value is None:
        return "predicate_value_required"
    if fields_are_measures and field_name.startswith("_"):
        return "predicate_measure_invalid"
    return ""


def validate_analytical_plan(plan: AnalyticalPlan) -> tuple[bool, list[str]]:
    errors: list[str] = []
    if plan.version != ANALYTICAL_PLAN_VERSION:
        errors.append(f"unsupported_version:{plan.version}")
    if not plan.datasets or len(plan.datasets) > MAX_DATASET_BRANCHES:
        errors.append("dataset_branch_count_invalid")
    for branch in plan.datasets:
        if not SAFE_DATASET_NAME.fullmatch(branch.index):
            errors.append(f"dataset_index_invalid:{branch.index}")
        if branch.sourcetype and not SAFE_DATASET_NAME.fullmatch(branch.sourcetype):
            errors.append(f"dataset_sourcetype_invalid:{branch.sourcetype}")
        if branch.platform and not SAFE_PLATFORM.fullmatch(branch.platform):
            errors.append(f"dataset_platform_invalid:{branch.platform}")
        if len(branch.filters) > MAX_PLAN_ITEMS:
            errors.append("dataset_filter_count_invalid")
        for predicate in branch.filters:
            reason = _validate_predicate(predicate)
            if reason:
                errors.append(reason)
    if len(plan.normalizations) > MAX_PLAN_ITEMS:
        errors.append("normalization_count_invalid")
    outputs: set[str] = set()
    for normalization in plan.normalizations:
        if not _valid_identifier(normalization.output) or normalization.output in outputs:
            errors.append(f"normalization_output_invalid:{normalization.output}")
        outputs.add(normalization.output)
        if normalization.kind not in ALLOWED_NORMALIZATION_KINDS:
            errors.append(f"normalization_kind_not_allowed:{normalization.kind}")
        if not normalization.fields or any(not _valid_identifier(item) for item in normalization.fields):
            errors.append(f"normalization_fields_invalid:{normalization.output}")
        if normalization.kind == "native" and len(normalization.fields) != 1:
            errors.append(f"normalization_native_arity_invalid:{normalization.output}")
        if normalization.kind == "coalesce" and len(normalization.fields) < 2:
            errors.append(f"normalization_coalesce_arity_invalid:{normalization.output}")
        if normalization.kind == "rex":
            if (
                not _valid_identifier(normalization.source_field)
                or not normalization.pattern
                or len(normalization.pattern) > 512
                or f"?<{normalization.output}>" not in normalization.pattern
            ):
                errors.append(f"normalization_rex_invalid:{normalization.output}")
        if normalization.kind == "spath" and (
            not _valid_identifier(normalization.source_field)
            or not normalization.path
            or len(normalization.path) > 256
        ):
            errors.append(f"normalization_spath_invalid:{normalization.output}")
    if any(not _valid_identifier(item) for item in plan.dimensions):
        errors.append("dimension_invalid")
    if len(plan.dimensions) > MAX_PLAN_ITEMS or len(plan.measures) > MAX_PLAN_ITEMS:
        errors.append("analysis_item_count_invalid")
    measure_names: set[str] = set()
    for measure in plan.measures:
        name = str(measure.get("name", "")).strip()
        function = str(measure.get("function", "")).strip().lower()
        field_name = str(measure.get("field", "")).strip()
        if not _valid_identifier(name) or name in measure_names:
            errors.append(f"measure_name_invalid:{name}")
        measure_names.add(name)
        if function not in ALLOWED_MEASURE_FUNCTIONS:
            errors.append(f"measure_function_not_allowed:{function}")
        if function != "count" and not _valid_identifier(field_name):
            errors.append(f"measure_field_invalid:{name}")
        condition = measure.get("condition")
        if condition is not None:
            if not isinstance(condition, dict):
                errors.append(f"measure_condition_invalid:{name}")
            else:
                reason = _validate_predicate(condition)
                if reason:
                    errors.append(f"measure_condition_invalid:{name}:{reason}")
    if not plan.measures and not plan.output_fields:
        errors.append("analysis_requires_measure_or_output")
    if plan.time_bin is not None:
        field_name = str(plan.time_bin.get("field", "_time")).strip()
        span = str(plan.time_bin.get("span", "")).strip()
        alias = str(plan.time_bin.get("alias", field_name)).strip()
        if not _valid_identifier(field_name) or not _valid_identifier(alias):
            errors.append("time_bin_field_invalid")
        if not ALLOWED_TIME_SPANS.fullmatch(span):
            errors.append("time_bin_span_invalid")
    derived_names = set(measure_names)
    for intersection in plan.intersections:
        name = str(intersection.get("name", "")).strip()
        fields = _list_of_strings(intersection.get("fields"))
        if (
            not _valid_identifier(name)
            or name in derived_names
            or len(fields) < 2
            or any(not _valid_identifier(item) for item in fields)
        ):
            errors.append(f"intersection_invalid:{name}")
        derived_names.add(name)
    for ratio in plan.ratios:
        name = str(ratio.get("name", "")).strip()
        numerator = str(ratio.get("numerator", "")).strip()
        denominator = str(ratio.get("denominator", "")).strip()
        scale = ratio.get("scale", 1)
        if (
            not _valid_identifier(name)
            or not _valid_identifier(numerator)
            or not _valid_identifier(denominator)
            or numerator not in derived_names
            or denominator not in derived_names
            or name in derived_names
            or str(ratio.get("zero_policy", "null")).lower() not in ALLOWED_RATIO_ZERO_POLICIES
            or isinstance(scale, bool)
            or not isinstance(scale, (int, float))
            or not (0 < float(scale) <= 10000)
        ):
            errors.append(f"ratio_invalid:{name}")
        derived_names.add(name)
    for predicate in plan.post_aggregation_predicates:
        reason = _validate_predicate(predicate, fields_are_measures=True)
        if reason:
            errors.append(f"post_aggregation_{reason}")
        elif str(predicate.get("field", "")).strip() not in derived_names | set(plan.dimensions):
            errors.append("post_aggregation_field_unknown")
    result_fields = derived_names | set(plan.dimensions)
    if plan.time_bin:
        result_fields.add(str(plan.time_bin.get("alias", plan.time_bin.get("field", "_time"))).strip())
    for rank in plan.ranking:
        field_name = str(rank.get("field", "")).strip()
        direction = str(rank.get("direction", "desc")).strip().lower()
        try:
            limit = int(rank.get("limit", plan.execution.row_limit))
        except (TypeError, ValueError):
            limit = 0
        if not _valid_identifier(field_name) or direction not in ALLOWED_RANK_DIRECTIONS:
            errors.append("ranking_invalid")
        elif plan.measures and field_name not in result_fields:
            errors.append("ranking_field_unknown")
        if limit <= 0 or limit > MAX_ANALYTICAL_ROWS:
            errors.append("ranking_limit_out_of_range")
    if any(not _valid_identifier(item) for item in plan.output_fields):
        errors.append("output_field_invalid")
    if plan.measures and any(item not in result_fields for item in plan.output_fields):
        errors.append("output_field_unknown")
    execution = plan.execution
    if not ALLOWED_TIME_VALUES.fullmatch(execution.earliest):
        errors.append("earliest_time_invalid")
    if not ALLOWED_TIME_VALUES.fullmatch(execution.latest):
        errors.append("latest_time_invalid")
    if execution.row_limit <= 0 or execution.row_limit > MAX_ANALYTICAL_ROWS:
        errors.append("row_limit_out_of_range")
    if execution.materialization not in ALLOWED_MATERIALIZATION_PROFILES:
        errors.append("materialization_profile_not_allowed")
    return not errors, errors
