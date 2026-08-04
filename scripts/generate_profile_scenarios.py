#!/usr/bin/env python3
"""Generate deterministic compositional SPL scenarios from environment metadata.

The protected eval21 corpus is never a generation input. It is consulted only
through the existing holdout firewall after generation to reject overlap before
artifacts are written.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from holdout_firewall import (
    DEFAULT_MANIFEST_PATH,
    assert_no_holdout_leakage,
    load_split_manifest,
)
from question_intelligence import DEFAULT_UNBOUNDED_EARLIEST
from spl_plan_compiler import COMPILER_VERSION, compile_analytical_plan
from spl_query_schema import ANALYTICAL_PLAN_VERSION, SAFE_DATASET_NAME, SAFE_IDENTIFIER

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_LIBRARY_PATH = PROJECT_ROOT / "benchmarks" / "composition_library.yaml"
DEFAULT_PROFILE_PATH = PROJECT_ROOT / "artifacts" / "environment" / "environment_profile_latest.json"
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "benchmarks" / "scenario_splits" / "generated"
GENERATOR_VERSION = "1.0"
ARTIFACT_SCHEMA_VERSION = 1
SPLITS = ("train", "dev", "holdout")
SPLIT_RESTRICTION = {"train": 0, "dev": 1, "holdout": 2}

SAFE_STATE_VALUES = frozenset(
    {
        "allow",
        "allowed",
        "block",
        "blocked",
        "denied",
        "error",
        "failed",
        "failure",
        "noerror",
        "nxdomain",
        "ok",
        "success",
        "succeeded",
    }
)


class ScenarioGenerationError(ValueError):
    """Raised when metadata cannot be safely converted into scenarios."""


@dataclass(frozen=True)
class FieldMetadata:
    name: str
    sample_values: tuple[str, ...] = ()


@dataclass(frozen=True)
class Domain:
    domain_id: str
    index: str
    sourcetype: str
    kind: str
    platform: str
    fields: tuple[FieldMetadata, ...]
    roles: dict[str, FieldMetadata]


@dataclass(frozen=True)
class ScenarioSeed:
    domain_key: str
    composition_id: str
    family: str
    context: dict[str, Any]
    plan: dict[str, Any]
    domain_summary: dict[str, Any]
    metadata_fields: tuple[str, ...]


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_value(value: Any) -> str:
    return _sha256_bytes(_canonical_json(value).encode("utf-8"))


def _read_json_object(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise ScenarioGenerationError(f"json_object_required:{path}")
    return payload, raw


def _read_yaml_object(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    payload = yaml.safe_load(raw.decode("utf-8"))
    if not isinstance(payload, dict):
        raise ScenarioGenerationError(f"yaml_object_required:{path}")
    return payload, raw


def _protected_source_paths(manifest_path: Path) -> set[Path]:
    manifest = load_split_manifest(manifest_path)
    protected = manifest.get("protected_sources", [])
    if not isinstance(protected, list):
        return set()
    resolved: set[Path] = set()
    for item in protected:
        candidate = Path(str(item))
        if not candidate.is_absolute():
            candidate = PROJECT_ROOT / candidate
        resolved.add(candidate.resolve())
    return resolved


def _assert_generation_input_allowed(path: Path, *, manifest_path: Path) -> None:
    if path.resolve() in _protected_source_paths(manifest_path):
        raise ScenarioGenerationError(f"protected_holdout_input_forbidden:{path}")


def _safe_name(value: Any, *, dataset: bool = False) -> str:
    text = str(value or "").strip()
    pattern = SAFE_DATASET_NAME if dataset else SAFE_IDENTIFIER
    return text if pattern.fullmatch(text) else ""


def _field_rows(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [dict(item) for item in value if isinstance(item, dict)]
    if isinstance(value, dict):
        rows = value.get("fields", [])
        if isinstance(rows, list):
            return [dict(item) for item in rows if isinstance(item, dict)]
    return []


def _field_metadata(value: Any) -> tuple[FieldMetadata, ...]:
    fields: list[FieldMetadata] = []
    seen: set[str] = set()
    for row in _field_rows(value):
        name = _safe_name(row.get("field"))
        if not name or name.casefold() in seen or name.startswith("_"):
            continue
        count = row.get("count")
        if isinstance(count, (int, float)) and not isinstance(count, bool) and count <= 0:
            continue
        samples = row.get("sample_values", row.get("values", []))
        if not isinstance(samples, list):
            samples = []
        safe_samples = tuple(
            str(item).strip()
            for item in samples[:5]
            if str(item).strip()
            and str(item).strip().casefold()
            not in {"[]", "{}", "null", "none", "unknown"}
        )
        fields.append(FieldMetadata(name=name, sample_values=safe_samples))
        seen.add(name.casefold())
    return tuple(fields)


def _populated_dataset_pairs(profile: dict[str, Any]) -> set[tuple[str, str]] | None:
    """Return discovered non-empty pairs, or None for legacy profiles without counts."""
    rows = profile.get("indexes", [])
    if not isinstance(rows, list):
        return None
    count_metadata_present = any(
        isinstance(row, dict)
        and isinstance(row.get("sourcetype_event_counts"), dict)
        and bool(row.get("sourcetype_event_counts"))
        for row in rows
    )
    if not count_metadata_present:
        return None
    populated: set[tuple[str, str]] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        index_name = str(row.get("index", "")).strip()
        counts = row.get("sourcetype_event_counts", {})
        if not index_name or not isinstance(counts, dict):
            continue
        for sourcetype, count in counts.items():
            if (
                isinstance(count, (int, float))
                and not isinstance(count, bool)
                and count > 0
            ):
                populated.add((index_name.casefold(), str(sourcetype).strip().casefold()))
    return populated


def _infer_kind(index: str, sourcetype: str) -> str:
    text = f"{index} {sourcetype}".casefold()
    if any(token in text for token in ("cloud", "aws", "azure", "o365", "gcp", "aad")):
        return "cloud"
    if any(token in text for token in ("dns", "bind", "domain")):
        return "dns"
    if any(token in text for token in ("access", "proxy", "http", "web", "iis")):
        return "web"
    if any(token in text for token in ("auth", "secure", "winevent", "security", "audit")):
        return "auth"
    return "generic"


def _infer_platform(index: str, sourcetype: str, kind: str) -> str:
    text = f"{index} {sourcetype}".casefold()
    if any(token in text for token in ("winevent", "windows", "sysmon")):
        return "windows"
    if any(token in text for token in ("linux", "syslog", "secure", "auditd")):
        return "linux"
    return kind if kind in {"cloud", "dns", "web"} else "generic"


def _select_roles(
    fields: tuple[FieldMetadata, ...],
    role_aliases: dict[str, Any],
) -> dict[str, FieldMetadata]:
    by_name = {field.name.casefold(): field for field in fields}
    selected: dict[str, FieldMetadata] = {}
    for role, aliases in role_aliases.items():
        if not isinstance(aliases, list):
            continue
        for alias in aliases:
            match = by_name.get(str(alias).strip().casefold())
            if match is not None:
                selected[str(role)] = match
                break
    return selected


def derive_domains(profile: dict[str, Any], library: dict[str, Any]) -> list[Domain]:
    role_aliases = library.get("role_aliases", {})
    if not isinstance(role_aliases, dict):
        raise ScenarioGenerationError("role_aliases_required")
    st_to_indexes = profile.get("sourcetype_to_indexes", {})
    if not isinstance(st_to_indexes, dict):
        raise ScenarioGenerationError("profile_sourcetype_to_indexes_required")
    global_inventory = profile.get("sourcetype_field_inventory", {})
    index_inventory = profile.get("index_sourcetype_field_inventory", {})
    if not isinstance(global_inventory, dict):
        global_inventory = {}
    if not isinstance(index_inventory, dict):
        index_inventory = {}
    populated_pairs = _populated_dataset_pairs(profile)

    domains: list[Domain] = []
    for sourcetype, indexes in sorted(st_to_indexes.items(), key=lambda item: str(item[0]).casefold()):
        safe_sourcetype = _safe_name(sourcetype, dataset=True)
        if not safe_sourcetype or not isinstance(indexes, list):
            continue
        for index in sorted({str(item).strip() for item in indexes}):
            safe_index = _safe_name(index, dataset=True)
            if not safe_index or safe_index.startswith("_"):
                continue
            if (
                populated_pairs is not None
                and (safe_index.casefold(), safe_sourcetype.casefold())
                not in populated_pairs
            ):
                continue
            specific = index_inventory.get(safe_index, {})
            if not isinstance(specific, dict):
                specific = {}
            fields = _field_metadata(specific.get(safe_sourcetype))
            if not fields:
                fields = _field_metadata(global_inventory.get(safe_sourcetype))
            if not fields:
                continue
            kind = _infer_kind(safe_index, safe_sourcetype)
            roles = _select_roles(fields, role_aliases)
            if not roles:
                continue
            domains.append(
                Domain(
                    domain_id=f"{safe_index}::{safe_sourcetype}",
                    index=safe_index,
                    sourcetype=safe_sourcetype,
                    kind=kind,
                    platform=_infer_platform(safe_index, safe_sourcetype, kind),
                    fields=fields,
                    roles=roles,
                )
            )
    return sorted(domains, key=lambda item: item.domain_id.casefold())


def assign_split(
    domain_key: str,
    composition_id: str,
    *,
    seed: int,
    train_percent: int,
    dev_percent: int,
) -> str:
    digest = hashlib.sha256(f"{seed}:{domain_key}:{composition_id}".encode("utf-8")).digest()
    bucket = int.from_bytes(digest[:8], "big") % 100
    if bucket < train_percent:
        return "train"
    if bucket < train_percent + dev_percent:
        return "dev"
    return "holdout"


def _normalization(role: str, fields: list[str]) -> dict[str, Any]:
    unique = list(dict.fromkeys(fields))
    return {
        "output": role,
        "kind": "native" if len(unique) == 1 else "coalesce",
        "fields": unique,
    }


def _normalizations(domain: Domain, roles: list[str]) -> list[dict[str, Any]]:
    return [_normalization(role, [domain.roles[role].name]) for role in roles]


def _base_plan(
    domain: Domain,
    *,
    roles: list[str],
    dimensions: list[str],
    measures: list[dict[str, Any]],
    output_fields: list[str],
    execution: dict[str, Any],
    post: list[dict[str, Any]] | None = None,
    time_bin: dict[str, Any] | None = None,
    ratios: list[dict[str, Any]] | None = None,
    intersections: list[dict[str, Any]] | None = None,
    ranking: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "version": ANALYTICAL_PLAN_VERSION,
        "datasets": [{"index": domain.index, "sourcetype": domain.sourcetype}],
        "normalizations": _normalizations(domain, roles),
        "analysis": {
            "dimensions": dimensions,
            "measures": measures,
            "post_aggregation_predicates": post or [],
            "time_bin": time_bin,
            "ratios": ratios or [],
            "intersections": intersections or [],
            "ranking": ranking or [],
            "output_fields": output_fields,
        },
        "execution": copy.deepcopy(execution),
    }


def _role_label(domain: Domain, role: str) -> str:
    field = domain.roles.get(role)
    return field.name if field else role.replace("_", " ")


def _safe_state_value(field: FieldMetadata) -> str | int | None:
    for raw in field.sample_values:
        value = raw.strip()
        if re.fullmatch(r"\d{1,3}", value):
            return int(value)
        if value.casefold() in SAFE_STATE_VALUES:
            return value
    return None


def _eligible_roles(domain: Domain, configured: Any) -> list[str]:
    if not isinstance(configured, list):
        return []
    return [str(role) for role in configured if str(role) in domain.roles]


def _execution(
    library: dict[str, Any],
    profile: dict[str, Any] | None = None,
) -> dict[str, Any]:
    windows = library.get("time_windows", {})
    base = windows.get("base", {}) if isinstance(windows, dict) else {}
    profile_window = (
        profile.get("time_window", {})
        if isinstance(profile, dict) and isinstance(profile.get("time_window"), dict)
        else {}
    )
    return {
        "earliest": str(
            profile_window.get("earliest_time", base.get("earliest", DEFAULT_UNBOUNDED_EARLIEST))
        ),
        "latest": str(
            profile_window.get("latest_time", base.get("latest", "now"))
        ),
        "row_limit": 100,
        "materialization": "bounded",
    }


def _seed_summary(domain: Domain) -> dict[str, Any]:
    return {
        "domain_id": domain.domain_id,
        "index": domain.index,
        "sourcetype": domain.sourcetype,
        "kind": domain.kind,
        "platform": domain.platform,
    }


def _top_n_seed(
    domain: Domain,
    family_id: str,
    spec: dict[str, Any],
    execution: dict[str, Any],
) -> ScenarioSeed | None:
    roles = _eligible_roles(domain, spec.get("eligible_roles"))
    if len(roles) < int(spec.get("required_role_count", 2)):
        return None
    dimension, secondary = roles[:2]
    threshold = int(spec.get("threshold", 3))
    top_n = int(spec.get("top_n", 10))
    plan = _base_plan(
        domain,
        roles=[dimension, secondary],
        dimensions=[dimension],
        measures=[
            {"name": "events", "function": "count"},
            {"name": f"distinct_{secondary}", "function": "dc", "field": secondary},
        ],
        post=[{"field": "events", "operator": "gte", "value": threshold}],
        ranking=[{"field": "events", "direction": "desc", "limit": top_n}],
        output_fields=[dimension, "events", f"distinct_{secondary}"],
        execution=execution,
    )
    return ScenarioSeed(
        domain_key=domain.domain_id,
        composition_id=family_id,
        family=family_id,
        context={
            "index": domain.index,
            "sourcetype": domain.sourcetype,
            "top_n": top_n,
            "threshold": threshold,
            "dimension_role": dimension,
            "secondary_role": secondary,
            "dimension_label": _role_label(domain, dimension),
            "secondary_label": _role_label(domain, secondary),
        },
        plan=plan,
        domain_summary=_seed_summary(domain),
        metadata_fields=(domain.roles[dimension].name, domain.roles[secondary].name),
    )


def _multivalue_seed(
    domain: Domain,
    family_id: str,
    spec: dict[str, Any],
    execution: dict[str, Any],
) -> ScenarioSeed | None:
    roles = _eligible_roles(domain, spec.get("eligible_roles"))
    if len(roles) < int(spec.get("required_role_count", 3)):
        return None
    dimension, first_value, second_value = roles[:3]
    first_name = f"{first_value}_values"
    second_name = f"{second_value}_values"
    plan = _base_plan(
        domain,
        roles=[dimension, first_value, second_value],
        dimensions=[dimension],
        measures=[
            {"name": "events", "function": "count"},
            {"name": first_name, "function": "values", "field": first_value},
            {"name": second_name, "function": "values", "field": second_value},
        ],
        intersections=[
            {
                "name": "intersection_events",
                "fields": [first_value, second_value],
            }
        ],
        output_fields=[dimension, "events", first_name, second_name, "intersection_events"],
        execution=execution,
    )
    return ScenarioSeed(
        domain_key=domain.domain_id,
        composition_id=family_id,
        family=family_id,
        context={
            "index": domain.index,
            "sourcetype": domain.sourcetype,
            "dimension_role": dimension,
            "first_value_role": first_value,
            "second_value_role": second_value,
            "dimension_label": _role_label(domain, dimension),
            "first_value_label": _role_label(domain, first_value),
            "second_value_label": _role_label(domain, second_value),
        },
        plan=plan,
        domain_summary=_seed_summary(domain),
        metadata_fields=tuple(domain.roles[role].name for role in (dimension, first_value, second_value)),
    )


def _state_seed(
    domain: Domain,
    family_id: str,
    spec: dict[str, Any],
    execution: dict[str, Any],
    *,
    time_binned: bool,
) -> ScenarioSeed | None:
    if "state" not in domain.roles:
        return None
    dimension_roles = _eligible_roles(domain, spec.get("dimension_roles"))
    if not dimension_roles:
        return None
    dimension = dimension_roles[0]
    state_value = _safe_state_value(domain.roles["state"])
    if state_value is None:
        return None
    threshold = int(spec.get("threshold_percent", 20 if time_binned else 10))
    numerator = "matching_state_events" if time_binned else "selected_events"
    ratio_name = "state_pct" if time_binned else "selected_pct"
    plan = _base_plan(
        domain,
        roles=[dimension, "state"],
        dimensions=[dimension],
        measures=[
            {"name": "total_events", "function": "count"},
            {
                "name": numerator,
                "function": "count",
                "condition": {"field": "state", "operator": "eq", "value": state_value},
            },
        ],
        time_bin=(
            {"field": "_time", "span": str(spec.get("span", "15m")), "alias": "bucket"}
            if time_binned
            else None
        ),
        ratios=[
            {
                "name": ratio_name,
                "numerator": numerator,
                "denominator": "total_events",
                "scale": 100,
                "zero_policy": "zero",
            }
        ],
        post=(
            [{"field": ratio_name, "operator": "gt", "value": threshold}]
            if time_binned
            else []
        ),
        ranking=[{"field": ratio_name, "direction": "desc", "limit": 20}],
        output_fields=(
            ["bucket", dimension, "total_events", numerator, ratio_name]
            if time_binned
            else [dimension, "total_events", numerator, ratio_name]
        ),
        execution=execution,
    )
    return ScenarioSeed(
        domain_key=domain.domain_id,
        composition_id=family_id,
        family=family_id,
        context={
            "index": domain.index,
            "sourcetype": domain.sourcetype,
            "dimension_role": dimension,
            "state_role": "state",
            "dimension_label": _role_label(domain, dimension),
            "state_label": _role_label(domain, "state"),
            "state_value": state_value,
            "threshold_percent": threshold,
        },
        plan=plan,
        domain_summary=_seed_summary(domain),
        metadata_fields=(domain.roles[dimension].name, domain.roles["state"].name),
    )


def _cloud_seed(
    domain: Domain,
    family_id: str,
    spec: dict[str, Any],
    execution: dict[str, Any],
) -> ScenarioSeed | None:
    if domain.kind not in set(spec.get("domain_kinds", [])):
        return None
    if not {"operation", "state"}.issubset(domain.roles):
        return None
    configured = {str(item).casefold() for item in spec.get("success_values", [])}
    success: str | int = "success"
    for raw in domain.roles["state"].sample_values:
        if raw.casefold() in configured:
            success = int(raw) if raw.isdigit() else raw
            break
    plan = _base_plan(
        domain,
        roles=["operation", "state"],
        dimensions=["operation"],
        measures=[
            {"name": "total_events", "function": "count"},
            {
                "name": "successful_events",
                "function": "count",
                "condition": {"field": "state", "operator": "eq", "value": success},
            },
            {
                "name": "unsuccessful_events",
                "function": "count",
                "condition": {"field": "state", "operator": "neq", "value": success},
            },
        ],
        ratios=[
            {
                "name": "unsuccessful_pct",
                "numerator": "unsuccessful_events",
                "denominator": "total_events",
                "scale": 100,
                "zero_policy": "zero",
            }
        ],
        ranking=[{"field": "unsuccessful_pct", "direction": "desc", "limit": 20}],
        output_fields=[
            "operation",
            "total_events",
            "successful_events",
            "unsuccessful_events",
            "unsuccessful_pct",
        ],
        execution=execution,
    )
    return ScenarioSeed(
        domain_key=domain.domain_id,
        composition_id=family_id,
        family=family_id,
        context={
            "index": domain.index,
            "sourcetype": domain.sourcetype,
            "operation_role": "operation",
            "state_role": "state",
            "operation_label": _role_label(domain, "operation"),
            "state_label": _role_label(domain, "state"),
        },
        plan=plan,
        domain_summary=_seed_summary(domain),
        metadata_fields=(domain.roles["operation"].name, domain.roles["state"].name),
    )


def _dns_seed(
    domain: Domain,
    family_id: str,
    spec: dict[str, Any],
    execution: dict[str, Any],
) -> ScenarioSeed | None:
    if domain.kind not in set(spec.get("domain_kinds", [])):
        return None
    if not {"query", "answer"}.issubset(domain.roles):
        return None
    mapping_roles = _eligible_roles(domain, spec.get("mapping_roles"))
    if not mapping_roles:
        return None
    mapping = mapping_roles[0]
    threshold = int(spec.get("diversity_threshold", 2))
    plan = _base_plan(
        domain,
        roles=[mapping, "query", "answer"],
        dimensions=[mapping, "query"],
        measures=[
            {"name": "events", "function": "count"},
            {"name": "answer_diversity", "function": "dc", "field": "answer"},
        ],
        post=[{"field": "answer_diversity", "operator": "gte", "value": threshold}],
        ranking=[{"field": "answer_diversity", "direction": "desc", "limit": 20}],
        output_fields=[mapping, "query", "events", "answer_diversity"],
        execution=execution,
    )
    return ScenarioSeed(
        domain_key=domain.domain_id,
        composition_id=family_id,
        family=family_id,
        context={
            "index": domain.index,
            "sourcetype": domain.sourcetype,
            "mapping_role": mapping,
            "query_role": "query",
            "answer_role": "answer",
            "mapping_label": _role_label(domain, mapping),
            "query_label": _role_label(domain, "query"),
            "answer_label": _role_label(domain, "answer"),
            "diversity_threshold": threshold,
        },
        plan=plan,
        domain_summary=_seed_summary(domain),
        metadata_fields=(
            domain.roles[mapping].name,
            domain.roles["query"].name,
            domain.roles["answer"].name,
        ),
    )


def _cross_event_seeds(
    domains: list[Domain],
    family_id: str,
    spec: dict[str, Any],
    execution: dict[str, Any],
) -> list[ScenarioSeed]:
    eligible = [str(item) for item in spec.get("eligible_shared_roles", [])]
    candidates: list[tuple[str, Domain, Domain]] = []
    for left_index, left in enumerate(domains):
        for right in domains[left_index + 1 :]:
            shared = next((role for role in eligible if role in left.roles and role in right.roles), "")
            if shared:
                candidates.append((shared, left, right))
    seeds: list[ScenarioSeed] = []
    for shared, left, right in candidates[: int(spec.get("max_pairs", 8))]:
        aliases = [left.roles[shared].name, right.roles[shared].name]
        plan = {
            "version": ANALYTICAL_PLAN_VERSION,
            "datasets": [
                {"index": left.index, "sourcetype": left.sourcetype},
                {"index": right.index, "sourcetype": right.sourcetype},
            ],
            "normalizations": [_normalization(shared, aliases)],
            "analysis": {
                "dimensions": [shared],
                "measures": [
                    {"name": "events", "function": "count"},
                    {"name": "source_types", "function": "dc", "field": "sourcetype"},
                ],
                "post_aggregation_predicates": [
                    {"field": "source_types", "operator": "gte", "value": 2}
                ],
                "time_bin": None,
                "ratios": [],
                "intersections": [],
                "ranking": [{"field": "events", "direction": "desc", "limit": 20}],
                "output_fields": [shared, "events", "source_types"],
            },
            "execution": copy.deepcopy(execution),
        }
        domain_key = "+".join(sorted((left.domain_id, right.domain_id)))
        seeds.append(
            ScenarioSeed(
                domain_key=domain_key,
                composition_id=family_id,
                family=family_id,
                context={
                    "left_index": left.index,
                    "left_sourcetype": left.sourcetype,
                    "left_kind": left.kind,
                    "right_index": right.index,
                    "right_sourcetype": right.sourcetype,
                    "right_kind": right.kind,
                    "dimension_role": shared,
                    "dimension_label": " / ".join(aliases),
                },
                plan=plan,
                domain_summary={
                    "domain_id": domain_key,
                    "kind": "cross_event",
                    "platform": left.platform if left.platform == right.platform else "mixed",
                    "datasets": [
                        {"index": left.index, "sourcetype": left.sourcetype},
                        {"index": right.index, "sourcetype": right.sourcetype},
                    ],
                },
                metadata_fields=tuple(dict.fromkeys(aliases)),
            )
        )
    return seeds


def build_scenario_seeds(
    profile: dict[str, Any],
    library: dict[str, Any],
) -> list[ScenarioSeed]:
    domains = derive_domains(profile, library)
    families = library.get("families", {})
    if not isinstance(families, dict):
        raise ScenarioGenerationError("composition_families_required")
    execution = _execution(library, profile)
    seeds: list[ScenarioSeed] = []
    for family_id, raw_spec in families.items():
        if not isinstance(raw_spec, dict):
            continue
        spec = dict(raw_spec)
        builder = str(spec.get("builder", family_id))
        if builder == "cross_event_correlation":
            seeds.extend(_cross_event_seeds(domains, str(family_id), spec, execution))
            continue
        for domain in domains:
            seed: ScenarioSeed | None = None
            if builder == "top_n_cardinality":
                seed = _top_n_seed(domain, str(family_id), spec, execution)
            elif builder == "multivalue_intersection":
                seed = _multivalue_seed(domain, str(family_id), spec, execution)
            elif builder == "time_bin_anomaly":
                seed = _state_seed(
                    domain,
                    str(family_id),
                    spec,
                    execution,
                    time_binned=True,
                )
            elif builder == "part_to_whole":
                seed = _state_seed(
                    domain,
                    str(family_id),
                    spec,
                    execution,
                    time_binned=False,
                )
            elif builder == "cloud_api_result_comparison":
                seed = _cloud_seed(domain, str(family_id), spec, execution)
            elif builder == "dns_diversity_mapping":
                seed = _dns_seed(domain, str(family_id), spec, execution)
            else:
                raise ScenarioGenerationError(f"unknown_family_builder:{builder}")
            if seed is not None:
                seeds.append(seed)
    return sorted(seeds, key=lambda item: (item.family, item.domain_key, item.composition_id))


def _render(template: Any, context: dict[str, Any]) -> str:
    return " ".join(str(template).format(**context).split())


def _synonym_context(context: dict[str, Any], synonyms: dict[str, Any]) -> dict[str, Any]:
    mutated = copy.deepcopy(context)
    for key, value in list(context.items()):
        if not key.endswith("_role"):
            continue
        label_key = key[: -len("_role")] + "_label"
        synonym = str(synonyms.get(str(value), "")).strip()
        if synonym and label_key in mutated:
            mutated[label_key] = synonym
    return mutated


def _negative_platform(seed: ScenarioSeed, library: dict[str, Any]) -> str:
    mapping = library.get("negative_platforms", {})
    if not isinstance(mapping, dict):
        return "unrelated"
    platform = str(seed.domain_summary.get("platform", "generic"))
    return str(mapping.get(platform, mapping.get("generic", "unrelated")))


def _promote_colliding_groups(records: list[dict[str, Any]]) -> None:
    """Keep identical questions out of less restrictive sibling splits."""
    changed = True
    while changed:
        changed = False
        group_split = {str(row["group_id"]): str(row["split"]) for row in records}
        groups_by_question: dict[str, set[str]] = {}
        for row in records:
            fingerprint = str(row["fingerprints"]["question_sha256"])
            groups_by_question.setdefault(fingerprint, set()).add(str(row["group_id"]))
        promoted: dict[str, str] = {}
        for groups in groups_by_question.values():
            target = max(
                (group_split[group] for group in groups),
                key=SPLIT_RESTRICTION.__getitem__,
            )
            for group in groups:
                if SPLIT_RESTRICTION[target] > SPLIT_RESTRICTION[group_split[group]]:
                    promoted[group] = target
        if not promoted:
            break
        for row in records:
            group_id = str(row["group_id"])
            if group_id not in promoted:
                continue
            row["split"] = promoted[group_id]
            row["learning_eligible"] = False
            changed = True


def materialize_scenarios(
    seeds: list[ScenarioSeed],
    library: dict[str, Any],
) -> list[dict[str, Any]]:
    assignment = library.get("assignment", {})
    if not isinstance(assignment, dict):
        raise ScenarioGenerationError("assignment_configuration_required")
    seed_value = int(assignment.get("seed", 0))
    train_percent = int(assignment.get("train_percent", 70))
    dev_percent = int(assignment.get("dev_percent", 15))
    holdout_percent = int(assignment.get("holdout_percent", 15))
    if train_percent + dev_percent + holdout_percent != 100:
        raise ScenarioGenerationError("assignment_percentages_must_total_100")
    mutations = library.get("mutations", [])
    if not isinstance(mutations, list) or "base" not in mutations:
        raise ScenarioGenerationError("base_mutation_required")
    families = library.get("families", {})
    synonyms = library.get("field_synonyms", {})
    if not isinstance(families, dict) or not isinstance(synonyms, dict):
        raise ScenarioGenerationError("family_and_synonym_configuration_required")

    records: list[dict[str, Any]] = []
    for seed in seeds:
        spec = families[seed.family]
        split = assign_split(
            seed.domain_key,
            seed.composition_id,
            seed=seed_value,
            train_percent=train_percent,
            dev_percent=dev_percent,
        )
        group_id = "composition_" + _sha256_value(
            {"domain": seed.domain_key, "composition": seed.composition_id}
        )[:16]
        for mutation in mutations:
            mutation_name = str(mutation)
            plan = copy.deepcopy(seed.plan)
            context = copy.deepcopy(seed.context)
            template_key = "question"
            negative_platform = ""
            if mutation_name == "paraphrase":
                template_key = "paraphrase"
            elif mutation_name == "time_shift":
                shifted = library.get("time_windows", {}).get("shifted", {})
                plan["execution"]["earliest"] = str(shifted.get("earliest", "-7d"))
                plan["execution"]["latest"] = str(shifted.get("latest", "now"))
            elif mutation_name == "scope_removal":
                template_key = "scope_free"
            elif mutation_name == "field_synonym":
                context = _synonym_context(context, synonyms)
            elif mutation_name == "negative_platform":
                negative_platform = _negative_platform(seed, library)
            elif mutation_name != "base":
                raise ScenarioGenerationError(f"unknown_mutation:{mutation_name}")

            question = _render(spec.get(template_key, spec.get("question", "")), context)
            base_earliest = str(plan["execution"].get("earliest", DEFAULT_UNBOUNDED_EARLIEST))
            if base_earliest == DEFAULT_UNBOUNDED_EARLIEST:
                question = question.replace("last 24 hours", "last 7 days")
            if mutation_name == "time_shift":
                shifted_question = question.replace("last 24 hours", "last 7 days")
                if shifted_question != question:
                    question = shifted_question
                elif "last 7 days" not in question.casefold():
                    question = f"{question} Use the last 7 days."
            if negative_platform:
                question = f"Exclude {negative_platform} sources. {question}"
            reference_spl = compile_analytical_plan(plan)
            scenario_id = "scenario_" + _sha256_value(
                {
                    "group_id": group_id,
                    "mutation": mutation_name,
                    "question": question,
                    "plan": plan,
                }
            )[:20]
            record = {
                "id": scenario_id,
                "group_id": group_id,
                "family": seed.family,
                "split": split,
                "mutation": mutation_name,
                "learning_eligible": split == "train",
                "question": question,
                "domain": seed.domain_summary,
                "reference_plan": plan,
                "reference_spl": reference_spl,
                "expected_constraints": {
                    "dataset_locks": [
                        {
                            "index": item["index"],
                            "sourcetype": item.get("sourcetype", ""),
                        }
                        for item in plan["datasets"]
                    ],
                    "explicit_scope_in_question": mutation_name != "scope_removal",
                    "forbidden_platform": negative_platform,
                    "required_output_fields": plan["analysis"]["output_fields"],
                },
                "provenance": {
                    "source": "environment_metadata",
                    "metadata_fields": list(seed.metadata_fields),
                    "composition_id": seed.composition_id,
                    "initial_hash_split": split,
                    "generator_version": GENERATOR_VERSION,
                    "analytical_plan_version": ANALYTICAL_PLAN_VERSION,
                    "spl_plan_compiler_version": COMPILER_VERSION,
                },
                "fingerprints": {
                    "question_sha256": _sha256_value(question),
                    "reference_plan_sha256": _sha256_value(plan),
                    "reference_spl_sha256": _sha256_value(reference_spl),
                },
            }
            records.append(record)
    _promote_colliding_groups(records)
    return sorted(records, key=lambda item: (item["split"], item["family"], item["group_id"], item["mutation"]))


def _artifact_payload(
    split: str,
    scenarios: list[dict[str, Any]],
    *,
    profile_hash: str,
    library_hash: str,
) -> dict[str, Any]:
    selected = [item for item in scenarios if item["split"] == split]
    return {
        "schema_version": ARTIFACT_SCHEMA_VERSION,
        "generator_version": GENERATOR_VERSION,
        "split": split,
        "learning_eligible": split == "train",
        "protected_eval21_generation_input": False,
        "source": {
            "profile_sha256": profile_hash,
            "composition_library_sha256": library_hash,
        },
        "scenario_count": len(selected),
        "family_counts": {
            family: sum(1 for item in selected if item["family"] == family)
            for family in sorted({item["family"] for item in selected})
        },
        "scenarios": selected,
    }


def build_artifacts(
    *,
    profile_path: str | Path = DEFAULT_PROFILE_PATH,
    library_path: str | Path = DEFAULT_LIBRARY_PATH,
    manifest_path: str | Path = DEFAULT_MANIFEST_PATH,
) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    profile_candidate = Path(profile_path)
    library_candidate = Path(library_path)
    manifest_candidate = Path(manifest_path)
    _assert_generation_input_allowed(profile_candidate, manifest_path=manifest_candidate)
    _assert_generation_input_allowed(library_candidate, manifest_path=manifest_candidate)
    profile, profile_raw = _read_json_object(profile_candidate)
    library, library_raw = _read_yaml_object(library_candidate)
    if str(library.get("generator_version", "")) != GENERATOR_VERSION:
        raise ScenarioGenerationError("composition_library_generator_version_mismatch")

    domains = derive_domains(profile, library)
    seeds = build_scenario_seeds(profile, library)
    scenarios = materialize_scenarios(seeds, library)
    if not scenarios:
        raise ScenarioGenerationError("no_compatible_scenarios")
    assert_no_holdout_leakage(
        scenarios,
        asset_name="generated_profile_scenarios",
        manifest_path=manifest_candidate,
    )

    profile_hash = _sha256_bytes(profile_raw)
    library_hash = _sha256_bytes(library_raw)
    artifacts = {
        split: _artifact_payload(
            split,
            scenarios,
            profile_hash=profile_hash,
            library_hash=library_hash,
        )
        for split in SPLITS
    }
    groups_by_split = {
        split: sorted({item["group_id"] for item in scenarios if item["split"] == split})
        for split in SPLITS
    }
    promoted_groups = {
        str(item["group_id"])
        for item in scenarios
        if item["split"] != item["provenance"]["initial_hash_split"]
    }
    manifest = {
        "schema_version": ARTIFACT_SCHEMA_VERSION,
        "generator_version": GENERATOR_VERSION,
        "assignment": copy.deepcopy(library["assignment"]),
        "assignment_key": "sha256(seed:domain_id:composition_id)",
        "collision_policy": "promote-identical-question-lineages-to-most-restrictive-split",
        "collision_promoted_group_count": len(promoted_groups),
        "mutation_lineage_is_split_atomic": True,
        "protected_eval21_generation_input": False,
        "learning_eligible_splits": ["train"],
        "denied_learning_splits": ["dev", "holdout"],
        "source": {
            "profile_sha256": profile_hash,
            "composition_library_sha256": library_hash,
        },
        "domain_count": len(domains),
        "composition_group_count": len(seeds),
        "scenario_count": len(scenarios),
        "families": sorted({item["family"] for item in scenarios}),
        "mutations": [str(item) for item in library["mutations"]],
        "split_counts": {split: artifacts[split]["scenario_count"] for split in SPLITS},
        "split_group_counts": {split: len(groups_by_split[split]) for split in SPLITS},
        "groups_by_split": groups_by_split,
        "artifacts": {split: f"{split}.json" for split in SPLITS},
    }
    return artifacts, manifest


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    path.write_text(text, encoding="utf-8")


def generate_artifacts(
    *,
    profile_path: str | Path = DEFAULT_PROFILE_PATH,
    library_path: str | Path = DEFAULT_LIBRARY_PATH,
    output_dir: str | Path = DEFAULT_OUTPUT_DIR,
    manifest_path: str | Path = DEFAULT_MANIFEST_PATH,
) -> dict[str, Any]:
    artifacts, manifest = build_artifacts(
        profile_path=profile_path,
        library_path=library_path,
        manifest_path=manifest_path,
    )
    destination = Path(output_dir)
    for split, payload in artifacts.items():
        _write_json(destination / f"{split}.json", payload)
    _write_json(destination / "manifest.json", manifest)
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate deterministic profile-derived compositional SPL scenarios"
    )
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE_PATH)
    parser.add_argument("--library", type=Path, default=DEFAULT_LIBRARY_PATH)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--split-manifest", type=Path, default=DEFAULT_MANIFEST_PATH)
    args = parser.parse_args()
    manifest = generate_artifacts(
        profile_path=args.profile,
        library_path=args.library,
        output_dir=args.out_dir,
        manifest_path=args.split_manifest,
    )
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
