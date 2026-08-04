#!/usr/bin/env python3
"""Provenance-aware field capability resolution and fields-first SPL rewriting."""

from __future__ import annotations

import re
import time
from collections.abc import Callable, Iterable
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any

from apache_intent import APACHE_INTENTS, requested_apache_roles
from environment_profile import KNOWN_SOURCETYPE_SEMANTICS, load_environment_profile
from minimal_question_to_answer import map_question_to_template, template_to_query_args
from question_intelligence import infer_time_window
from query_templates import TEMPLATES, split_field_extractions

PROFILE_FRESHNESS_SECONDS = 24 * 60 * 60
LIVE_CACHE_TTL_SECONDS = 5 * 60
LIVE_SAMPLE_SIZE = 50

FieldVerifier = Callable[[str, str, str, str], Any]

ROLE_FIELDS: dict[str, tuple[str, ...]] = {
    "user": (
        "user",
        "username",
        "user_name",
        "account",
        "uid",
        "subjectusername",
        "targetusername",
        "caller_user_name",
        "src_user",
        "dest_user",
        "failed_user",
        "useridentity.arn",
        "userid",
        "userprincipalname",
    ),
    "src_ip": (
        "src_ip",
        "src",
        "srcip",
        "clientip",
        "ip",
        "ipaddress",
        "source_network_address",
        "sourceipaddress",
        "rhost",
        "failed_src_ip",
        "remote_ip",
    ),
    "dest_ip": ("dest_ip", "dest", "destip", "destinationip", "destination_ip"),
    "dest_port": ("dest_port", "destport", "destinationport", "destination_port"),
    "host": ("host", "hostname", "computer", "dvc", "device"),
    "status": ("status", "status_code", "sc_status", "http_status", "response_code", "loginstatus"),
    "event_code": ("eventcode", "eventid", "event_id"),
    "process": ("process", "process_name", "image", "commandline", "parent_process"),
    "action": ("action", "eventname", "event_name", "activity", "operation"),
    "uri": ("uri", "uri_path", "url", "request", "path", "site"),
    "user_agent": ("useragent", "user_agent", "http_user_agent"),
    "method": ("method", "http_method", "verb"),
    "protocol": ("protocol", "protocol_num"),
}

INTENT_ROLE_NEEDS: dict[str, tuple[str, ...]] = {
    "linux_auth_failures": ("user", "src_ip", "host"),
    "windows_auth_failures": ("user", "src_ip", "host", "event_code"),
    "failed_login_activity": ("user", "src_ip", "host"),
    "apache_access_top_ips": ("src_ip", "status", "method"),
    "apache_suspicious_activity": ("src_ip", "status", "method", "uri", "user_agent"),
    "apache_404_spike": ("src_ip", "status", "uri"),
    "apache_404_scanning": ("src_ip", "status", "method", "uri", "user_agent"),
    "apache_suspicious_user_agents": ("src_ip", "user_agent"),
    "apache_sensitive_path_probing": ("src_ip", "status", "method", "uri", "user_agent"),
    "linux_privilege_escalation": ("user", "host", "process"),
    "linux_privilege_escalation_activity": ("user", "host", "process"),
    "aws_cloudtrail_activity": ("user", "action", "src_ip"),
    "windows_sysmon_process_creation": ("process", "user", "host"),
    "internal_auth_failures": ("user", "src_ip", "host"),
    "splunk_admin_activity": ("user", "action", "src_ip"),
    "stream_http_activity": ("method", "status", "src_ip"),
    "osquery_process_activity": ("host", "process"),
    "aws_vpc_flow_activity": ("src_ip", "dest_ip", "dest_port", "protocol", "action"),
    "aad_signin_activity": ("user", "src_ip", "status"),
    "stream_dns_activity": ("src_ip", "dest_ip"),
    "o365_management_activity": ("user", "action", "src_ip"),
}

STRUCTURED_JSON_INTENTS = frozenset(
    {
        "aws_cloudtrail_activity",
        "stream_http_activity",
        "osquery_process_activity",
        "aad_signin_activity",
        "stream_dns_activity",
        "o365_management_activity",
        "windows_credential_access_activity",
        "windows_sysmon_network_activity",
    }
)

# These intents describe positional/raw records. Their canonical rex is evidence,
# not an optimization that can be removed based on similarly named fields.
RAW_PARSE_REQUIRED_INTENTS = frozenset(
    template.intent for template in TEMPLATES if template.raw_parse_required
)

_LIVE_FIELD_CACHE: dict[tuple[str, str, str, str, object | None], tuple[float, set[str], str]] = {}


def clear_field_verification_cache() -> None:
    """Clear the short-lived live verification cache (primarily for tests)."""
    _LIVE_FIELD_CACHE.clear()


def _iso_datetime(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _profile_domain_block(profile: dict[str, Any], index: str, sourcetype: str) -> dict[str, Any]:
    """Return only exact index+sourcetype inventory; never widen across indexes."""
    inventory = profile.get("index_sourcetype_field_inventory", {}) if isinstance(profile, dict) else {}
    if not isinstance(inventory, dict):
        return {}
    index_block = inventory.get(index, {})
    if not isinstance(index_block, dict):
        return {}
    direct = index_block.get(sourcetype, {})
    if isinstance(direct, dict):
        return direct
    sourcetype_l = sourcetype.lower()
    for name, block in index_block.items():
        if str(name).lower() == sourcetype_l and isinstance(block, dict):
            return block
    return {}


def _profile_field_row(block: dict[str, Any], field: str) -> dict[str, Any]:
    field_l = field.lower()
    rows = block.get("fields", []) if isinstance(block, dict) else []
    if not isinstance(rows, list):
        return {}
    for row in rows:
        if isinstance(row, dict) and str(row.get("field", "")).strip().lower() == field_l:
            return row
    return {}


def field_exists(
    index: str,
    sourcetype: str,
    field: str,
    *,
    profile: dict[str, Any] | None = None,
    live_fields: Iterable[str] | None = None,
    now: datetime | None = None,
    freshness_seconds: int = PROFILE_FRESHNESS_SECONDS,
) -> dict[str, Any]:
    """Return scoped field evidence; ``exists`` is true only for live evidence."""
    profile = profile if isinstance(profile, dict) else {}
    now = now or datetime.now(timezone.utc)
    block = _profile_domain_block(profile, index, sourcetype)
    row = _profile_field_row(block, field)
    timestamp = _iso_datetime(block.get("timestamp_utc"))
    age_seconds = (now - timestamp).total_seconds() if timestamp else None
    fresh = age_seconds is not None and 0 <= age_seconds <= max(0, freshness_seconds)
    try:
        count = int(row.get("count", 0) or 0)
    except (TypeError, ValueError):
        count = 0
    samples = row.get("sample_values", []) if isinstance(row, dict) else []
    populated = count > 0 and isinstance(samples, list) and any(str(item).strip() for item in samples)
    candidate = bool(row) and fresh and populated

    live_lookup = {str(item).strip().lower() for item in live_fields or [] if str(item).strip()}
    trusted = field.lower() in live_lookup if live_fields is not None else False
    if trusted:
        level = "trusted"
        source = "live_index_sourcetype_probe"
    elif candidate:
        level = "candidate"
        source = "fresh_index_sourcetype_profile"
    elif row:
        level = "hint"
        source = "stale_or_sparse_index_sourcetype_profile"
    else:
        level = "absent"
        source = "none"
    return {
        "index": index,
        "sourcetype": sourcetype,
        "field": field,
        "exists": trusted,
        "trusted": trusted,
        "candidate": candidate,
        "evidence_level": level,
        "source": source,
        "profile_fresh": fresh,
        "profile_populated": populated,
        "profile_age_seconds": int(age_seconds) if age_seconds is not None else None,
    }


def _safe_spl_literal(value: str) -> str:
    return str(value or "").replace("\\", "\\\\").replace('"', '\\"')


def _extract_live_field_names(data: Any) -> set[str]:
    if isinstance(data, (set, tuple, list)):
        rows = data
    elif isinstance(data, dict):
        rows = (data.get("structured", {}) or {}).get("results", [])
    else:
        rows = []
    names: set[str] = set()
    if isinstance(rows, (set, tuple, list)):
        for row in rows:
            if isinstance(row, dict):
                name = str(row.get("field", "")).strip()
            else:
                name = str(row).strip()
            if name:
                names.add(name)
    return names


def _default_live_verifier(index: str, sourcetype: str, earliest_time: str, latest_time: str) -> dict[str, Any]:
    from minimal_question_to_answer import run_splunk_query_args

    query = (
        f'search index="{_safe_spl_literal(index)}" sourcetype="{_safe_spl_literal(sourcetype)}" '
        f"| head {LIVE_SAMPLE_SIZE} | fields * | fieldsummary maxvals=1"
    )
    return run_splunk_query_args(
        {
            "query": query,
            "earliest_time": earliest_time,
            "latest_time": latest_time,
            "row_limit": 200,
        },
        intent="field_strategy_verification",
        summary_hint="bounded field capability verification",
    )


def _verify_domain_fields(
    index: str,
    sourcetype: str,
    earliest_time: str,
    latest_time: str,
    *,
    verifier: FieldVerifier | None,
    cache_ttl_seconds: int,
) -> tuple[set[str], str, bool]:
    # Custom verifiers are isolated so deterministic benchmark/test evidence
    # cannot contaminate another case that happens to share the same domain/window.
    key = (index, sourcetype, earliest_time, latest_time, verifier)
    cached = _LIVE_FIELD_CACHE.get(key)
    now_mono = time.monotonic()
    if cached and now_mono - cached[0] <= max(0, cache_ttl_seconds):
        return set(cached[1]), cached[2], True
    try:
        data = (verifier or _default_live_verifier)(index, sourcetype, earliest_time, latest_time)
        fields = _extract_live_field_names(data)
        error = ""
    except Exception as exc:
        fields = set()
        error = f"{type(exc).__name__}:{exc}"
    _LIVE_FIELD_CACHE[key] = (now_mono, set(fields), error)
    return fields, error, False


def _indexes_from_bound(bound: dict[str, Any]) -> list[str]:
    explicit = bound.get("indexes", [])
    if isinstance(explicit, list):
        cleaned = [str(item).strip() for item in explicit if str(item).strip() and "*" not in str(item)]
        if cleaned:
            return list(dict.fromkeys(cleaned))
    expr = str(bound.get("index_expr", ""))
    found = [
        next(part for part in match if part).strip()
        for match in re.findall(
            r'index\s*=\s*(?:"([^"]+)"|\'([^\']+)\'|([^\s|()]+))',
            expr,
            flags=re.IGNORECASE,
        )
    ]
    return list(dict.fromkeys(name for name in found if name and "*" not in name and not name.startswith("_")))


def _semantic_aliases(sourcetype: str) -> dict[str, list[str]]:
    block: dict[str, Any] = {}
    for name, value in KNOWN_SOURCETYPE_SEMANTICS.items():
        if str(name).lower() == sourcetype.lower() and isinstance(value, dict):
            block = value
            break
    aliases = block.get("field_aliases", {}) if isinstance(block.get("field_aliases"), dict) else {}
    return {
        str(role): [str(field).strip() for field in fields if str(field).strip()]
        for role, fields in aliases.items()
        if isinstance(fields, list)
    }


def _role_for_field(field: str) -> str | None:
    field_l = str(field or "").strip().lower()
    if not field_l or field_l.startswith("_"):
        return None
    for role, names in ROLE_FIELDS.items():
        if field_l in {name.lower() for name in names}:
            return role
    return None


def _canonical_query(question: str, planner_output: dict[str, Any]) -> str:
    explicit = str(planner_output.get("canonical_template_query", "")).strip()
    if explicit:
        return explicit
    mapped = map_question_to_template(question)
    return str(template_to_query_args(mapped, question).get("query", ""))


def _extraction_segments(query: str) -> list[str]:
    _native, fallbacks = split_field_extractions(query)
    return list(fallbacks)


def _rex_capture_names(segment: str) -> list[str]:
    return list(dict.fromkeys(re.findall(r"\?<([A-Za-z_][A-Za-z0-9_.]*)>", str(segment or ""))))


def _looks_structured_json(intent: str, sourcetype: str, raw_sample: str) -> bool:
    sample = str(raw_sample or "").lstrip()
    return (
        intent in STRUCTURED_JSON_INTENTS
        or sample.startswith("{")
        or sample.startswith("[{")
        or any(token in sourcetype.lower() for token in ("json", "cloudtrail", "o365", "aad", "stream:"))
    )


def resolve_field_strategy(
    question: str,
    planner_output: dict[str, Any],
    *,
    field_bind_output: dict[str, Any] | None = None,
    field_discovery_output: dict[str, Any] | None = None,
    profile: dict[str, Any] | None = None,
    verifier: FieldVerifier | None = None,
    cache_ttl_seconds: int = LIVE_CACHE_TTL_SECONDS,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Resolve each required role using exact-domain provenance and one live probe per domain."""
    started = time.monotonic()
    bound = dict(field_bind_output or {})
    discovery = dict(field_discovery_output or {})
    profile = profile if isinstance(profile, dict) else load_environment_profile()
    intent = str(bound.get("intent") or planner_output.get("intent") or map_question_to_template(question).intent).strip()
    sourcetype = str(bound.get("sourcetype", "")).strip()
    indexes = _indexes_from_bound(bound)
    analytical_plan = (
        planner_output.get("analytical_plan", {})
        if isinstance(planner_output.get("analytical_plan"), dict)
        else {}
    )
    # Field verification must inspect the same time slice that the question
    # contract gives the eventual query. This also prevents stale 24-hour
    # planner fallbacks from hiding fields that only appear in the 7-day probe.
    earliest_time, latest_time = infer_time_window(question)
    canonical_query = _canonical_query(question, planner_output)
    extraction_segments = _extraction_segments(canonical_query)
    rex_segments = [
        segment for segment in extraction_segments if re.match(r"^rex\b", segment, flags=re.IGNORECASE)
    ]
    capture_names = [name for segment in rex_segments for name in _rex_capture_names(segment)]

    needs = list(INTENT_ROLE_NEEDS.get(intent, ()))
    for role in analytical_plan_required_roles(analytical_plan):
        if role not in needs:
            needs.append(role)
    if intent in APACHE_INTENTS:
        for role in requested_apache_roles(question):
            if role not in needs:
                needs.append(role)
    for capture in capture_names:
        role = _role_for_field(capture)
        if role and role not in needs:
            needs.append(role)

    candidate_by_role: dict[str, list[str]] = {role: [] for role in needs}
    mappings = discovery.get("role_mappings", bound.get("role_mappings", {}))
    if isinstance(mappings, dict):
        for role, names in mappings.items():
            if role not in candidate_by_role or not isinstance(names, list):
                continue
            candidate_by_role[role].extend(str(name).strip() for name in names if str(name).strip())
    semantic = _semantic_aliases(sourcetype)
    for role in needs:
        candidate_by_role[role].extend(semantic.get(role, []))
        candidate_by_role[role].extend(ROLE_FIELDS.get(role, ()))
        candidate_by_role[role] = list(dict.fromkeys(candidate_by_role[role]))

    domain_results: list[dict[str, Any]] = []
    domain_field_sets: dict[str, set[str]] = {}
    trusted_spellings: dict[str, str] = {}
    for index in indexes:
        live_fields, error, cache_hit = _verify_domain_fields(
            index,
            sourcetype,
            earliest_time,
            latest_time,
            verifier=verifier,
            cache_ttl_seconds=cache_ttl_seconds,
        )
        domain_field_sets[index] = set(live_fields)
        for name in live_fields:
            trusted_spellings.setdefault(name.lower(), name)
        domain_results.append(
            {
                "index": index,
                "sourcetype": sourcetype,
                "live_field_count": len(live_fields),
                "probe_error": error,
                "cache_hit": cache_hit,
                "source": "live_index_sourcetype_probe",
            }
        )
    successful_domains = [
        {name.lower() for name in fields}
        for index, fields in domain_field_sets.items()
        if not next((row.get("probe_error") for row in domain_results if row["index"] == index), "")
    ]
    trusted_across_domains = (
        set.intersection(*successful_domains)
        if successful_domains and len(successful_domains) == len(indexes)
        else set()
    )

    structured_json = _looks_structured_json(
        intent,
        sourcetype,
        str(discovery.get("raw_sample") or bound.get("raw_sample_snippet") or ""),
    )
    roles: dict[str, dict[str, Any]] = {}
    evidence: list[dict[str, Any]] = []
    for role in needs:
        candidates = candidate_by_role.get(role, [])
        verified = [
            trusted_spellings[name.lower()]
            for name in candidates
            if name.lower() in trusted_across_domains
        ]
        verified = list(dict.fromkeys(verified))
        role_evidence: list[dict[str, Any]] = []
        for index in indexes:
            domain_live = domain_field_sets.get(index, set())
            for candidate in candidates:
                item = field_exists(
                    index,
                    sourcetype,
                    candidate,
                    profile=profile,
                    live_fields=domain_live,
                    now=now,
                )
                if item["evidence_level"] != "absent":
                    role_evidence.append(item)
                    evidence.append(item)

        if intent in RAW_PARSE_REQUIRED_INTENTS:
            classification = "regex_fallback"
        elif len(verified) > 1:
            classification = "alias_coalesce"
        elif len(verified) == 1:
            classification = "native"
        elif structured_json:
            classification = "json"
        elif rex_segments:
            classification = "regex_fallback"
        else:
            classification = "unresolved"
        roles[role] = {
            "classification": classification,
            "trusted_fields": verified,
            "candidate_fields": [
                item["field"] for item in role_evidence if item.get("candidate") and not item.get("trusted")
            ],
            "hint_fields": candidates[:12],
            "coalesce_expression": f"coalesce({','.join(verified)})" if len(verified) > 1 else (verified[0] if verified else ""),
            "evidence": role_evidence,
        }

    trusted_fields = list(dict.fromkeys(name for role in roles.values() for name in role["trusted_fields"]))
    fallback_kind = "rex" if intent in RAW_PARSE_REQUIRED_INTENTS else ("spath" if structured_json else "rex")
    return {
        "intent": intent,
        "sourcetype": sourcetype,
        "indexes": indexes,
        "time_window": {"earliest_time": earliest_time, "latest_time": latest_time},
        "roles": roles,
        "trusted_fields": trusted_fields,
        "trusted_role_mappings": {
            role: data["trusted_fields"] for role, data in roles.items() if data["trusted_fields"]
        },
        "trusted_coalesce_hints": {
            role: data["coalesce_expression"]
            for role, data in roles.items()
            if data["classification"] == "alias_coalesce" and data["coalesce_expression"]
        },
        "forbid_unnecessary_extraction": bool(trusted_fields) and intent not in RAW_PARSE_REQUIRED_INTENTS,
        "raw_parse_required": intent in RAW_PARSE_REQUIRED_INTENTS,
        "structured_json": structured_json,
        "fallback_kind": fallback_kind,
        "fallback_extractions": extraction_segments,
        "domain_verifications": domain_results,
        "evidence": evidence,
        "duration_ms": int((time.monotonic() - started) * 1000),
    }


def _split_pipeline(query: str) -> list[str]:
    """Split on top-level pipes while preserving quoted rex expressions."""
    parts: list[str] = []
    current: list[str] = []
    quote = ""
    escaped = False
    bracket_depth = 0
    for char in str(query or ""):
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


def _field_referenced(text: str, field: str) -> bool:
    return bool(re.search(rf"(?<![A-Za-z0-9_.]){re.escape(field)}(?![A-Za-z0-9_.])", text, flags=re.IGNORECASE))


def _native_replacement(capture: str, strategy: dict[str, Any]) -> str:
    trusted = [str(item) for item in strategy.get("trusted_fields", [])]
    for name in trusted:
        if name.lower() == capture.lower():
            return ""
    role = _role_for_field(capture)
    role_data = (strategy.get("roles", {}) or {}).get(role, {}) if role else {}
    fields = [str(item) for item in role_data.get("trusted_fields", [])]
    if not fields:
        return ""
    expression = fields[0] if len(fields) == 1 else f"coalesce({','.join(fields)})"
    return f"eval {capture}={expression}"


def _spath_output_names(segment: str) -> list[str]:
    names = re.findall(
        r"\boutput\s*=\s*(?:\"([^\"]+)\"|'([^']+)'|([A-Za-z_][A-Za-z0-9_.]*))",
        str(segment or ""),
        flags=re.IGNORECASE,
    )
    outputs = [next(part for part in match if part) for match in names]
    if outputs:
        return list(dict.fromkeys(outputs))
    paths = re.findall(
        r"\bpath\s*=\s*(?:\"([^\"]+)\"|'([^']+)'|([A-Za-z_][A-Za-z0-9_.{}]*))",
        str(segment or ""),
        flags=re.IGNORECASE,
    )
    for match in paths:
        path = next(part for part in match if part)
        leaf = path.rstrip("{}").rsplit(".", 1)[-1]
        if leaf:
            outputs.append(leaf)
    return list(dict.fromkeys(outputs))


def _all_required_roles_trusted(strategy: dict[str, Any]) -> bool:
    roles = strategy.get("roles", {}) if isinstance(strategy.get("roles"), dict) else {}
    return bool(roles) and all(
        isinstance(data, dict) and bool(data.get("trusted_fields"))
        for data in roles.values()
    )


def rewrite_query_fields_first(query: str, strategy: dict[str, Any]) -> tuple[str, list[str]]:
    """Use extraction stages only for roles without trusted native evidence."""
    if not query or strategy.get("raw_parse_required"):
        return query, ["preserved_raw_required_extraction"] if strategy.get("raw_parse_required") else []
    parts = _split_pipeline(query)
    if len(parts) < 2:
        return query, []
    actions: list[str] = []
    rewritten: list[str] = [parts[0]]
    has_spath = any(re.match(r"^spath\b", part, flags=re.IGNORECASE) for part in parts[1:])
    spath_added = False
    for index, segment in enumerate(parts[1:], start=1):
        is_rex = bool(re.match(r"^rex\b", segment, flags=re.IGNORECASE))
        is_spath = bool(re.match(r"^spath\b", segment, flags=re.IGNORECASE))
        if not (is_rex or is_spath):
            rewritten.append(segment)
            continue
        captures = _rex_capture_names(segment) if is_rex else _spath_output_names(segment)
        downstream = " | ".join(parts[index + 1 :])
        required = [capture for capture in captures if _field_referenced(downstream, capture)]
        replacements: list[str] = []
        removable = bool(required or captures) or (is_spath and _all_required_roles_trusted(strategy))
        for capture in required:
            replacement = _native_replacement(capture, strategy)
            trusted_exact = any(
                str(name).lower() == capture.lower() for name in strategy.get("trusted_fields", [])
            )
            if not trusted_exact and not replacement:
                removable = False
                break
            if replacement and replacement.lower() != f"eval {capture.lower()}={capture.lower()}":
                replacements.append(replacement)
        if removable:
            rewritten.extend(list(dict.fromkeys(replacements)))
            command = "rex" if is_rex else "spath"
            actions.append(f"removed_redundant_{command}:{','.join(required or captures)}")
        elif is_rex and strategy.get("structured_json"):
            if not has_spath and not spath_added:
                rewritten.append("spath input=_raw")
                spath_added = True
            actions.append(f"replaced_rex_with_spath:{','.join(required or captures)}")
        else:
            rewritten.append(segment)
            command = "rex" if is_rex else "spath"
            actions.append(f"preserved_{command}_fallback:{','.join(required or captures)}")
    normalized = " | ".join(part.strip().lstrip("|").strip() for part in rewritten if part.strip())
    return normalized.strip(), actions


def apply_field_policy_to_plan(
    plan: dict[str, Any],
    strategy: dict[str, Any] | None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Apply the shared deterministic fields-first policy to a candidate tool plan."""
    updated = deepcopy(plan or {})
    strategy = strategy if isinstance(strategy, dict) else {}
    if str(updated.get("selected_tool", "")).strip() != "splunk_run_query":
        return updated, {"changed": False, "actions": ["non_query_passthrough"]}
    args = updated.get("tool_args", {}) if isinstance(updated.get("tool_args"), dict) else {}
    original = str(args.get("query", "")).strip()
    rewritten, actions = rewrite_query_fields_first(original, strategy)
    if rewritten != original:
        args = dict(args)
        args["query"] = rewritten
        updated["tool_args"] = args
        reason = str(updated.get("reason", "")).strip()
        updated["reason"] = ";".join(part for part in (reason, "fields_first_policy") if part)
    policy = {
        "changed": rewritten != original,
        "actions": actions,
        "original_query": original,
        "rewritten_query": rewritten,
        "strategy_summary": {
            "intent": strategy.get("intent", ""),
            "trusted_fields": strategy.get("trusted_fields", []),
            "raw_parse_required": bool(strategy.get("raw_parse_required")),
            "fallback_kind": strategy.get("fallback_kind", ""),
        },
    }
    return updated, policy


def strategy_prompt_payload(strategy: dict[str, Any] | None) -> dict[str, Any]:
    """Return the bounded authoritative strategy subset safe for writer prompts."""
    strategy = strategy if isinstance(strategy, dict) else {}
    return {
        "intent": strategy.get("intent", ""),
        "indexes": strategy.get("indexes", []),
        "sourcetype": strategy.get("sourcetype", ""),
        "trusted_native_fields": strategy.get("trusted_fields", []),
        "trusted_role_mappings": strategy.get("trusted_role_mappings", {}),
        "trusted_coalesce_hints": strategy.get("trusted_coalesce_hints", {}),
        "role_classifications": {
            role: data.get("classification", "unresolved")
            for role, data in (strategy.get("roles", {}) or {}).items()
            if isinstance(data, dict)
        },
        "forbid_unnecessary_extraction": bool(strategy.get("forbid_unnecessary_extraction")),
        "raw_parse_required": bool(strategy.get("raw_parse_required")),
        "fallback_kind": strategy.get("fallback_kind", ""),
    }


def analytical_plan_required_roles(plan: Any) -> list[str]:
    """Infer canonical field roles needed by an AnalyticalPlan."""
    if hasattr(plan, "to_dict"):
        payload = plan.to_dict()
    else:
        payload = dict(plan) if isinstance(plan, dict) else {}
    analysis = payload.get("analysis", {}) if isinstance(payload.get("analysis"), dict) else {}
    names: list[str] = []
    names.extend(str(item) for item in analysis.get("dimensions", []) if str(item).strip())
    names.extend(str(item) for item in analysis.get("output_fields", []) if str(item).strip())
    for measure in analysis.get("measures", []):
        if not isinstance(measure, dict):
            continue
        names.append(str(measure.get("field", "")))
        condition = measure.get("condition")
        if isinstance(condition, dict):
            names.append(str(condition.get("field", "")))
    for branch in payload.get("datasets", []):
        if not isinstance(branch, dict):
            continue
        for predicate in branch.get("filters", []):
            if isinstance(predicate, dict):
                names.append(str(predicate.get("field", "")))
    roles: list[str] = []
    for name in names:
        role = _role_for_field(name)
        if role and role not in roles:
            roles.append(role)
    return roles


def field_strategy_for_analytical_plan(
    plan: Any,
    strategy: dict[str, Any] | None,
) -> dict[str, Any]:
    """Return the bounded strategy subset relevant to one AnalyticalPlan."""
    strategy = strategy if isinstance(strategy, dict) else {}
    required = analytical_plan_required_roles(plan)
    roles = strategy.get("roles", {}) if isinstance(strategy.get("roles"), dict) else {}
    return {
        **strategy_prompt_payload(strategy),
        "required_roles": required,
        "roles": {
            role: deepcopy(roles[role])
            for role in required
            if role in roles and isinstance(roles[role], dict)
        },
    }
