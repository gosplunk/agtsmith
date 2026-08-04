#!/usr/bin/env python3
"""Apply field discovery coalesce hints into constrained WritePlan slots."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from spl_query_schema import AnalyticalPlan, FieldNormalization, WritePlan

ROLE_GROUP_ALIASES: dict[str, tuple[str, ...]] = {
    "user": ("user", "user_name", "username", "actor", "failed_user"),
    "src_ip": ("src_ip", "src", "srcip", "clientip", "ip", "sourceip", "remote_ip"),
    "dest_ip": ("dest_ip", "destinationip", "destination_ip", "dest"),
    "host": ("host", "computer", "dest"),
    "status": ("status", "status_code", "sc_status"),
    "action": ("action", "eventname", "event_name"),
    "operation": ("operation", "eventname", "event_name", "action"),
    "process": ("process", "process_name", "image"),
    "uri": ("uri", "uri_path", "url", "url_path"),
    "user_agent": ("useragent", "user_agent", "http_user_agent"),
}


def _coalesce_hints(field_bind: dict[str, Any]) -> dict[str, str]:
    raw = field_bind.get("coalesce_hints", {})
    if not isinstance(raw, dict):
        return {}
    out: dict[str, str] = {}
    for role, expr in raw.items():
        text = str(expr or "").strip()
        if text:
            out[str(role).strip()] = text
    return out


def apply_field_bind_slots(
    plan: WritePlan,
    field_bind: dict[str, Any] | None,
    *,
    intent: str = "",
    field_strategy: dict[str, Any] | None = None,
) -> WritePlan:
    """Inject only trusted coalesce expressions before aggregation."""
    source = field_bind if isinstance(field_bind, dict) else {}
    if isinstance(field_strategy, dict):
        source = {"coalesce_hints": field_strategy.get("trusted_coalesce_hints", {})}
    if not source:
        return plan
    hints = _coalesce_hints(source)
    if not hints:
        return plan

    updated = deepcopy(plan)
    existing_evals = {
        seg.lower()
        for seg in updated.extra_pipeline
        if isinstance(seg, str) and seg.lower().startswith("eval ")
    }
    new_evals: list[str] = []

    for role, expr in hints.items():
        targets = ROLE_GROUP_ALIASES.get(role, (role,))
        matched_fields: list[str] = []
        for field_name in updated.group_by:
            if field_name.lower() in {t.lower() for t in targets}:
                matched_fields.append(field_name)
        if not matched_fields and role in {"user", "src_ip", "host"}:
            # Prefer canonical output field names for common roles when group_by empty.
            canonical = {"user": "user", "src_ip": "src_ip", "host": "host"}.get(role, role)
            if canonical not in updated.group_by:
                updated.group_by.append(canonical)
                matched_fields = [canonical]
        for field_name in matched_fields:
            eval_seg = f"eval {field_name}={expr}"
            if eval_seg.lower() not in existing_evals:
                new_evals.append(eval_seg)
                existing_evals.add(eval_seg.lower())

    if new_evals:
        updated.extra_pipeline = new_evals + list(updated.extra_pipeline)
    return updated


def group_by_from_role_mappings(
    field_bind: dict[str, Any] | None,
    *,
    intent: str = "",
    field_strategy: dict[str, Any] | None = None,
) -> list[str]:
    """Suggest group-by fields, preferring live-trusted strategy mappings."""
    source = field_bind if isinstance(field_bind, dict) else {}
    if isinstance(field_strategy, dict):
        source = {"role_mappings": field_strategy.get("trusted_role_mappings", {})}
    if not source:
        return []
    mappings = source.get("role_mappings", {})
    if not isinstance(mappings, dict):
        return []
    fields: list[str] = []
    for role in ("user", "src_ip", "host", "status", "method", "uri", "user_agent", "action"):
        names = mappings.get(role, [])
        if isinstance(names, list) and names:
            pick = str(names[0]).strip()
            if pick and pick not in fields:
                fields.append(pick)
    return fields[:6]


def apply_analytical_field_bindings(
    plan: AnalyticalPlan,
    field_strategy: dict[str, Any] | None,
) -> AnalyticalPlan:
    """Bind verified native aliases while preserving declared fallbacks."""
    strategy = field_strategy if isinstance(field_strategy, dict) else {}
    roles = strategy.get("roles", {}) if isinstance(strategy.get("roles"), dict) else {}
    updated = deepcopy(plan)
    normalizations = {item.output: item for item in updated.normalizations}
    referenced = set(updated.dimensions)
    referenced.update(updated.output_fields)
    for measure in updated.measures:
        field_name = str(measure.get("field", "")).strip()
        if field_name:
            referenced.add(field_name)
        condition = measure.get("condition")
        if isinstance(condition, dict):
            referenced.add(str(condition.get("field", "")).strip())
    for branch in updated.datasets:
        for predicate in branch.filters:
            referenced.add(str(predicate.get("field", "")).strip())

    for role, data in roles.items():
        if not isinstance(data, dict):
            continue
        role_name = str(role).strip()
        aliases = ROLE_GROUP_ALIASES.get(role_name, (role_name,))
        output = (
            role_name
            if any(name.casefold() == role_name.casefold() for name in referenced)
            else next(
                (
                    name
                    for name in referenced
                    if name.casefold() in {item.casefold() for item in aliases}
                ),
                role_name,
            )
        )
        trusted = [
            str(item).strip()
            for item in data.get("trusted_fields", [])
            if str(item).strip()
        ]
        if not trusted or output not in referenced:
            continue
        existing = normalizations.get(output)
        if existing and existing.kind in {"rex", "spath"} and strategy.get("raw_parse_required"):
            continue
        replacement = FieldNormalization(
            output=output,
            kind="native" if len(trusted) == 1 else "coalesce",
            fields=trusted,
        )
        if existing:
            index = updated.normalizations.index(existing)
            updated.normalizations[index] = replacement
        else:
            updated.normalizations.append(replacement)
        normalizations[output] = replacement

    referenced_fields = set(updated.dimensions)
    referenced_fields.update(updated.output_fields)
    for measure in updated.measures:
        if str(measure.get("field", "")).strip():
            referenced_fields.add(str(measure["field"]).strip())
        condition = measure.get("condition")
        if isinstance(condition, dict) and str(condition.get("field", "")).strip():
            referenced_fields.add(str(condition["field"]).strip())
    for intersection in updated.intersections:
        referenced_fields.update(
            str(item).strip()
            for item in intersection.get("fields", [])
            if str(item).strip()
        )
    for canonical in ("src_ip", "dest_ip"):
        if any(
            name.casefold() == canonical.casefold()
            for name in referenced_fields
        ) and not any(
            item.output.casefold() == canonical.casefold()
            for item in updated.normalizations
        ):
            aliases = {
                item.casefold()
                for item in ROLE_GROUP_ALIASES[canonical]
            }
            source = next(
                (
                    item.output
                    for item in updated.normalizations
                    if item.output.casefold() in aliases
                    or any(field.casefold() in aliases for field in item.fields)
                ),
                "",
            )
            if source:
                replacement = FieldNormalization(
                    output=canonical,
                    kind="native",
                    fields=[source],
                )
                updated.normalizations.append(replacement)
                normalizations[canonical] = replacement

    def bound_field(field_name: Any) -> str:
        name = str(field_name or "").strip()
        if not name:
            return name
        exact = next(
            (
                item.output
                for item in updated.normalizations
                if item.output.casefold() == name.casefold()
            ),
            "",
        )
        if exact:
            return exact
        return name

    updated.dimensions = [bound_field(item) for item in updated.dimensions]
    for measure in updated.measures:
        if str(measure.get("field", "")).strip():
            measure["field"] = bound_field(measure["field"])
        condition = measure.get("condition")
        if isinstance(condition, dict) and str(condition.get("field", "")).strip():
            condition["field"] = bound_field(condition["field"])
    for intersection in updated.intersections:
        intersection["fields"] = [
            bound_field(item) for item in intersection.get("fields", [])
        ]
    for branch in updated.datasets:
        for predicate in branch.filters:
            if str(predicate.get("field", "")).strip():
                predicate["field"] = bound_field(predicate["field"])
    return updated
