#!/usr/bin/env python3
"""Pre-writer field discovery: live Splunk sampling + role mapping for SPL hints."""

from __future__ import annotations

import re
import time
from typing import Any

from build_environment_profile import _extract_field_inventory, _field_summary_query, _interesting_field_examples
from environment_profile import KNOWN_SOURCETYPE_SEMANTICS, load_environment_profile
from minimal_question_to_answer import map_question_to_template
from question_intelligence import infer_time_window
from spl_field_binding import bind_fields_for_plan


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

ROLE_PATTERNS: dict[str, tuple[str, ...]] = {
    "user": (
        r"^(user(name)?|account|uid|subjectusername|targetusername|caller_user_name|"
        r"src_user|dest_user|failed_user|pam_user|user_name)$",
    ),
    "src_ip": (
        r"^(src(_ip)?|clientip|ip(address)?|source_network_address|sourceipaddress|rhost|"
        r"failed_src_ip|srcip|remote_ip)$",
    ),
    "host": (r"^(host(name)?|computer|dest|dvc|device)$",),
    "status": (r"^(status(_code)?|sc_status|http_status|response_code)$",),
    "event_code": (r"^(event(code|id)|event_id)$",),
    "process": (r"^(process(_name)?|image|commandline|parent_process)$",),
    "action": (r"^(action|eventname|activity|operation)$",),
    "uri": (r"^(uri(_path)?|url|request|path)$",),
    "user_agent": (r"^(useragent|user_agent|http_user_agent)$",),
}

INTENT_ROLE_NEEDS: dict[str, tuple[str, ...]] = {
    "linux_auth_failures": ("user", "src_ip", "host"),
    "windows_auth_failures": ("user", "src_ip", "host", "event_code"),
    "failed_login_activity": ("user", "src_ip", "host"),
    "apache_access_top_ips": ("src_ip", "status", "uri", "user_agent"),
    "apache_404_spike": ("src_ip", "status", "uri"),
    "linux_privilege_escalation": ("user", "host", "process"),
    "linux_privilege_escalation_activity": ("user", "host", "process"),
    "aws_cloudtrail_activity": ("user", "action", "src_ip"),
    "windows_sysmon_process_creation": ("process", "user", "host"),
    "internal_auth_failures": ("user", "src_ip", "host"),
    "splunk_admin_activity": ("user", "action", "src_ip"),
}


def _match_role(field_name: str) -> str | None:
    name = str(field_name or "").strip()
    if not name or name.startswith("_"):
        return None
    lower = name.lower()
    for role, patterns in ROLE_PATTERNS.items():
        for pattern in patterns:
            if re.match(pattern, lower, flags=re.I):
                return role
    return None


def _infer_roles_from_fields(
    fields: list[dict[str, Any]],
    *,
    intent: str = "",
    requested_roles: set[str] | None = None,
) -> dict[str, list[str]]:
    requested = {
        str(role).strip()
        for role in (requested_roles or set())
        if str(role).strip()
    }
    roles: dict[str, list[str]] = {}
    for row in fields:
        if not isinstance(row, dict):
            continue
        field = str(row.get("field", "")).strip()
        role = _match_role(field)
        # ``dest`` is inherently ambiguous: auth records sometimes use it as
        # a host-like field, while network/composition plans use it as the
        # destination IP. Let the typed plan disambiguate it at the trust
        # boundary instead of authorizing the same live field for both roles.
        if field.casefold() == "dest":
            if "dest_ip" in requested:
                role = "dest_ip"
            elif "host" in requested:
                role = "host"
        if not role:
            continue
        bucket = roles.setdefault(role, [])
        if field not in bucket:
            bucket.append(field)
    needs = INTENT_ROLE_NEEDS.get(intent, ())
    for role in needs:
        roles.setdefault(role, [])
    return roles


def _requested_plan_roles(
    planner_output: dict[str, Any],
    *,
    question: str = "",
) -> set[str]:
    """Extract explicit field-role requests without treating output aliases as fields."""
    plan = planner_output.get("analytical_plan", {}) if isinstance(planner_output, dict) else {}
    analysis = plan.get("analysis", {}) if isinstance(plan, dict) else {}
    if not isinstance(analysis, dict):
        return set()
    fields: list[str] = [
        str(item).strip()
        for item in analysis.get("dimensions", [])
        if str(item).strip()
    ]
    for measure in analysis.get("measures", []):
        if not isinstance(measure, dict):
            continue
        field = str(measure.get("field", "")).strip()
        if field:
            fields.append(field)
        condition = measure.get("condition")
        if isinstance(condition, dict):
            condition_field = str(condition.get("field", "")).strip()
            if condition_field:
                fields.append(condition_field)
    for intersection in analysis.get("intersections", []):
        if not isinstance(intersection, dict):
            continue
        values = intersection.get("fields", [])
        if isinstance(values, list):
            fields.extend(str(item).strip() for item in values if str(item).strip())

    roles: set[str] = set()
    for field in fields:
        if field.casefold() == "dest":
            roles.add("dest_ip")
        else:
            role = _match_role(field)
            if role:
                roles.add(role)
    question_l = str(question or "").casefold()
    if re.search(r"\b(?:dest|destination)(?:_ip)?\b", question_l):
        roles.add("dest_ip")
    if re.search(r"\bhost(?:name)?\b", question_l):
        roles.add("host")
    return roles


def _profile_field_rows(profile: dict[str, Any], sourcetype: str) -> list[dict[str, Any]]:
    inv = profile.get("sourcetype_field_inventory", {}) if isinstance(profile, dict) else {}
    if not isinstance(inv, dict):
        return []
    block = inv.get(sourcetype, {})
    if isinstance(block, dict):
        rows = block.get("fields", [])
        if isinstance(rows, list):
            return [r for r in rows if isinstance(r, dict)]
    if isinstance(block, list):
        return [r for r in block if isinstance(r, dict)]
    return []


def _sample_raw_snippet(
    index_expr: str,
    sourcetype: str,
    *,
    earliest_time: str = "-7d",
    latest_time: str = "now",
) -> str:
    from minimal_question_to_answer import run_splunk_query_args

    if not sourcetype:
        return ""
    query = f"search {index_expr} sourcetype=\"{sourcetype}\" | head 1 | table _raw"
    try:
        data = run_splunk_query_args(
            {
                "query": query,
                "earliest_time": earliest_time,
                "latest_time": latest_time,
                "row_limit": 1,
            },
            intent="field_discovery_raw_sample",
            summary_hint="raw sample",
        )
        rows = data.get("structured", {}).get("results", []) if isinstance(data, dict) else []
        if isinstance(rows, list) and rows:
            raw = str(rows[0].get("_raw", "")).strip()
            return " ".join(raw.split())[:320]
    except Exception:
        return ""
    return ""


def _live_field_inventory(
    sourcetype: str,
    indexes: list[str],
    *,
    sample_size: int = 25,
    earliest_time: str = "-7d",
    latest_time: str = "now",
) -> tuple[list[dict[str, Any]], str]:
    from minimal_question_to_answer import run_splunk_query_args

    if not sourcetype or not indexes:
        return [], "missing_sourcetype_or_indexes"
    query_args = {
        "query": _field_summary_query(indexes, sourcetype, sample_size),
        "earliest_time": earliest_time,
        "latest_time": latest_time,
        "row_limit": sample_size,
    }
    try:
        data = run_splunk_query_args(
            query_args,
            intent="field_discovery_inventory",
            summary_hint="field discovery inventory",
        )
        fields = _extract_field_inventory(data)
        return fields, ""
    except Exception as exc:
        return [], f"{type(exc).__name__}:{exc}"


def _semantic_aliases(sourcetype: str) -> dict[str, list[str]]:
    sem = KNOWN_SOURCETYPE_SEMANTICS.get(sourcetype, {})
    if not isinstance(sem, dict):
        sem = {}
    for key, val in KNOWN_SOURCETYPE_SEMANTICS.items():
        if key.lower() == sourcetype.lower() and isinstance(val, dict):
            sem = val
            break
    aliases = sem.get("field_aliases", {}) if isinstance(sem.get("field_aliases"), dict) else {}
    out: dict[str, list[str]] = {}
    for role, names in aliases.items():
        if isinstance(names, list):
            out[str(role)] = [str(n).strip() for n in names if str(n).strip()]
    return out


def _merge_role_mappings(
    inferred: dict[str, list[str]],
    semantic: dict[str, list[str]],
    discovered_fields: list[str],
) -> dict[str, list[str]]:
    merged: dict[str, list[str]] = {}
    discovered_l = {f.lower() for f in discovered_fields}
    for role in set(inferred.keys()) | set(semantic.keys()):
        candidates: list[str] = []
        for source in (inferred.get(role, []), semantic.get(role, [])):
            for name in source:
                if name not in candidates:
                    candidates.append(name)
        present = [name for name in candidates if name.lower() in discovered_l]
        merged[role] = present or candidates[:4]
    return merged


def _coalesce_hints(role_mappings: dict[str, list[str]]) -> dict[str, str]:
    hints: dict[str, str] = {}
    for role, fields in role_mappings.items():
        cleaned = [f for f in fields if str(f).strip()]
        if len(cleaned) >= 2:
            hints[role] = f"coalesce({','.join(cleaned)})"
        elif len(cleaned) == 1:
            hints[role] = cleaned[0]
    return hints


def discover_fields_for_plan(
    question: str,
    planner_output: dict[str, Any],
    *,
    profile: dict[str, Any] | None = None,
    bound: dict[str, Any] | None = None,
    live_probe: bool = True,
    include_raw_sample: bool = True,
    sample_size: int = 25,
    use_llm_roles: bool = False,
    llm_model: str = "",
) -> dict[str, Any]:
    """Discover live fields and map them to semantic roles for writer hints."""
    started = time.time()
    profile = profile if isinstance(profile, dict) else load_environment_profile()
    bound = bound if isinstance(bound, dict) else bind_fields_for_plan(question, planner_output, profile=profile)
    earliest_time, latest_time = infer_time_window(question)
    intent = str(bound.get("intent", "")).strip() or map_question_to_template(question).intent
    sourcetype = str(bound.get("sourcetype", "")).strip()
    index_expr = str(bound.get("index_expr", "index=* NOT index=_*")).strip()

    if not sourcetype:
        try:
            from sourcetype_cards import cards_for_question

            cards = cards_for_question(question, intent=intent, max_cards=1)
            if cards:
                sourcetype = str(cards[0].get("sourcetype", "")).strip()
                if sourcetype and index_expr == "index=* NOT index=_*":
                    index_expr = _index_expr_for_sourcetype(profile, sourcetype)
        except Exception:
            pass

    st_to_idx = profile.get("sourcetype_to_indexes", {}) if isinstance(profile, dict) else {}
    indexes = [str(i).strip() for i in st_to_idx.get(sourcetype, []) if str(i).strip()] if sourcetype else []
    if not indexes and sourcetype:
        m = re.search(r"index=([^\s|)]+)", index_expr)
        if m:
            indexes = [m.group(1).strip('"')]

    profile_rows = _profile_field_rows(profile, sourcetype) if sourcetype else []
    profile_fields = [str(r.get("field", "")).strip() for r in profile_rows if str(r.get("field", "")).strip()]

    live_fields: list[dict[str, Any]] = []
    probe_error = ""
    if live_probe and sourcetype and indexes:
        live_fields, probe_error = _live_field_inventory(
            sourcetype,
            indexes,
            sample_size=sample_size,
            earliest_time=earliest_time,
            latest_time=latest_time,
        )

    discovered_fields = [
        str(r.get("field", "")).strip()
        for r in (live_fields or profile_rows)
        if isinstance(r, dict) and str(r.get("field", "")).strip()
    ]
    interesting = _interesting_field_examples(live_fields or profile_rows, limit=12)
    inferred_roles = _infer_roles_from_fields(
        live_fields or profile_rows,
        intent=intent,
        requested_roles=_requested_plan_roles(planner_output, question=question),
    )
    semantic_aliases = _semantic_aliases(sourcetype)
    role_mappings = _merge_role_mappings(inferred_roles, semantic_aliases, discovered_fields)
    coalesce_hints = _coalesce_hints(role_mappings)

    raw_sample = ""
    if include_raw_sample and sourcetype and live_probe and not probe_error:
        raw_sample = _sample_raw_snippet(
            index_expr,
            sourcetype,
            earliest_time=earliest_time,
            latest_time=latest_time,
        )

    llm_roles: dict[str, Any] = {}
    if use_llm_roles and discovered_fields:
        llm_roles = _llm_map_roles(
            question=question,
            intent=intent,
            sourcetype=sourcetype,
            fields=interesting,
            model=llm_model,
        )
        if isinstance(llm_roles.get("role_mappings"), dict):
            for role, names in llm_roles["role_mappings"].items():
                if isinstance(names, list) and names:
                    role_mappings[str(role)] = [str(n).strip() for n in names if str(n).strip()]
            coalesce_hints = _coalesce_hints(role_mappings)

    profile_only = set(profile_fields)
    live_only = {str(r.get("field", "")).strip() for r in live_fields if str(r.get("field", "")).strip()}
    new_vs_profile = sorted(live_only - profile_only)

    needs = INTENT_ROLE_NEEDS.get(intent, ())
    roles_satisfied = sum(1 for role in needs if role_mappings.get(role))

    duration_ms = int((time.time() - started) * 1000)
    return {
        "intent": intent,
        "sourcetype": sourcetype,
        "index_expr": index_expr,
        "indexes": indexes,
        "earliest_time": earliest_time,
        "latest_time": latest_time,
        "live_probe": live_probe,
        "probe_error": probe_error,
        "field_count": len(discovered_fields),
        "discovered_fields": discovered_fields[:20],
        "interesting_fields": interesting,
        "role_mappings": role_mappings,
        "coalesce_hints": coalesce_hints,
        "semantic_aliases": semantic_aliases,
        "raw_sample": raw_sample,
        "profile_field_count": len(profile_fields),
        "new_fields_vs_profile": new_vs_profile[:12],
        "roles_needed": list(needs),
        "roles_satisfied": roles_satisfied,
        "roles_satisfied_ratio": round(roles_satisfied / len(needs), 3) if needs else 1.0,
        "llm_roles": llm_roles,
        "duration_ms": duration_ms,
        "source": "live_mcp" if live_fields else ("profile" if profile_fields else "none"),
    }


def enrich_field_bind_with_discovery(
    bound: dict[str, Any],
    discovery: dict[str, Any],
) -> dict[str, Any]:
    """Merge discovery output into field_bind payload for writer prompts."""
    merged = dict(bound or {})
    disc_fields = discovery.get("discovered_fields", [])
    if isinstance(disc_fields, list) and disc_fields:
        hints = list(merged.get("field_hints", [])) if isinstance(merged.get("field_hints"), list) else []
        for field in disc_fields:
            if field not in hints:
                hints.append(field)
        merged["field_hints"] = hints[:16]
    if discovery.get("coalesce_hints"):
        merged["coalesce_hints"] = discovery.get("coalesce_hints")
    if discovery.get("role_mappings"):
        merged["role_mappings"] = discovery.get("role_mappings")
    if discovery.get("raw_sample"):
        merged["raw_sample_snippet"] = discovery.get("raw_sample")
    if discovery.get("interesting_fields"):
        merged["interesting_field_examples"] = discovery.get("interesting_fields")
    if discovery.get("earliest_time"):
        merged["earliest_time"] = discovery.get("earliest_time")
    if discovery.get("latest_time"):
        merged["latest_time"] = discovery.get("latest_time")
    merged["field_discovery"] = {
        "source": discovery.get("source"),
        "field_count": discovery.get("field_count"),
        "roles_satisfied_ratio": discovery.get("roles_satisfied_ratio"),
        "new_fields_vs_profile": discovery.get("new_fields_vs_profile", [])[:8],
        "earliest_time": discovery.get("earliest_time"),
        "latest_time": discovery.get("latest_time"),
        "duration_ms": discovery.get("duration_ms"),
    }
    merged["source"] = "field_discovery"
    return merged


def should_run_field_discovery(
    bound: dict[str, Any],
    *,
    profile: dict[str, Any] | None = None,
    force: bool = False,
) -> tuple[bool, str]:
    """Return whether live MCP field discovery should run before writer."""
    if force:
        return True, "forced"
    sourcetype = str(bound.get("sourcetype", "")).strip()
    if not sourcetype:
        return True, "missing_sourcetype"
    hints = bound.get("field_hints", [])
    hint_count = len(hints) if isinstance(hints, list) else 0
    profile = profile if isinstance(profile, dict) else load_environment_profile()
    inv = profile.get("sourcetype_field_inventory", {}) if isinstance(profile, dict) else {}
    block = inv.get(sourcetype, {}) if isinstance(inv, dict) else {}
    fields = block.get("fields", []) if isinstance(block, dict) else block
    field_count = len(fields) if isinstance(fields, list) else 0
    if field_count == 0:
        return True, "cold_profile_inventory"
    if hint_count == 0:
        return True, "no_field_hints"
    intent = str(bound.get("intent", "")).strip()
    needs = INTENT_ROLE_NEEDS.get(intent, ())
    if needs:
        inferred = _infer_roles_from_fields(
            [{"field": h} for h in hints if str(h).strip()],
            intent=intent,
        )
        satisfied = sum(1 for role in needs if inferred.get(role))
        if needs and satisfied < len(needs):
            return True, f"roles_unsatisfied:{satisfied}/{len(needs)}"
    return False, "profile_sufficient"


def _llm_map_roles(
    *,
    question: str,
    intent: str,
    sourcetype: str,
    fields: list[dict[str, Any]],
    model: str,
) -> dict[str, Any]:
    try:
        from langgraph_multi_model_soc import _call_ollama_json
        from runtime_config import DEFAULT_MODEL_QUERY_PLANNER, get_model_assignment
    except Exception as exc:
        return {"error": f"import:{exc}"}

    chosen = model.strip() or get_model_assignment("OLLAMA_MODEL_QUERY_PLANNER", DEFAULT_MODEL_QUERY_PLANNER)
    system = (
        "You map Splunk discovered fields to semantic roles for SPL authoring. "
        "Return strict JSON: role_mappings (object role->field names), notes (array). "
        "Roles: user, src_ip, host, status, event_code, process, action, uri, user_agent. "
        "Only use field names from the provided list."
    )
    payload = {
        "question": question,
        "intent": intent,
        "sourcetype": sourcetype,
        "discovered_fields": fields[:16],
    }
    try:
        return _call_ollama_json(model=chosen, system_prompt=system, user_payload=payload, timeout=60.0)
    except Exception as exc:
        return {"error": f"{type(exc).__name__}:{exc}"}
