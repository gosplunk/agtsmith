#!/usr/bin/env python3
"""Deterministic, budgeted candidate ranking and live evidence scoring."""

from __future__ import annotations

import hashlib
import json
import os
import time
from copy import deepcopy
from typing import Any, Callable

MAX_CANDIDATES = 3
MAX_PROBES = 2
PROBE_ROW_LIMIT = 5
PROBE_TIMEOUT_SECONDS = 15.0
TOTAL_PROBE_BUDGET_SECONDS = 45.0
MAX_GLOBAL_QUERY_EXECUTIONS = 5

ProbeRunner = Callable[[dict[str, Any], float], dict[str, Any]]

_FIELD_ALIASES = {
    "clientip": "src_ip",
    "client_ip": "src_ip",
    "sourceip": "src_ip",
    "source_ip": "src_ip",
    "sourceaddress": "src_ip",
    "source_address": "src_ip",
    "username": "user",
    "user_name": "user",
    "account": "user",
    "account_name": "user",
    "hostname": "host",
    "dest_host": "host",
    "outcome": "action",
    "result": "action",
}


def _bounded_env_int(name: str, default: int, maximum: int) -> int:
    try:
        value = int(str(os.getenv(name, default)).strip())
    except (TypeError, ValueError):
        value = default
    return max(0, min(maximum, value))


def _bounded_env_float(name: str, default: float, maximum: float) -> float:
    try:
        value = float(str(os.getenv(name, default)).strip())
    except (TypeError, ValueError):
        value = default
    return max(0.0, min(maximum, value))


def new_query_budget() -> dict[str, Any]:
    """Create the shared evidence/execution query budget."""
    limit = _bounded_env_int(
        "AGTSMITH_MAX_EVIDENCE_QUERIES",
        MAX_GLOBAL_QUERY_EXECUTIONS,
        MAX_GLOBAL_QUERY_EXECUTIONS,
    )
    return {
        "version": "1.0",
        "limit": limit,
        "used": 0,
        "remaining": limit,
        "events": [],
        "exhausted": limit == 0,
    }


def reserve_query(
    budget: dict[str, Any] | None,
    *,
    purpose: str,
    candidate_id: str = "",
) -> tuple[bool, dict[str, Any]]:
    """Reserve one live query before execution and record minimal telemetry."""
    updated = deepcopy(budget) if isinstance(budget, dict) else new_query_budget()
    limit = max(0, min(MAX_GLOBAL_QUERY_EXECUTIONS, int(updated.get("limit", 0) or 0)))
    used = max(0, int(updated.get("used", 0) or 0))
    if used >= limit:
        updated.update({"limit": limit, "used": used, "remaining": 0, "exhausted": True})
        return False, updated
    used += 1
    events = list(updated.get("events", [])) if isinstance(updated.get("events"), list) else []
    events.append(
        {
            "ordinal": used,
            "purpose": str(purpose),
            "candidate_id": str(candidate_id),
        }
    )
    updated.update(
        {
            "limit": limit,
            "used": used,
            "remaining": max(0, limit - used),
            "events": events,
            "exhausted": used >= limit,
        }
    )
    return True, updated


def _fingerprint(candidate: dict[str, Any]) -> str:
    args = candidate.get("tool_args", {}) if isinstance(candidate.get("tool_args"), dict) else {}
    payload = {
        "tool": str(candidate.get("selected_tool", "")),
        "intent": str(candidate.get("intent", "")),
        "args": args,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def _canonical_field(value: Any) -> str:
    field = str(value or "").strip().casefold()
    return _FIELD_ALIASES.get(field, field)


def _rows(splunk_data: dict[str, Any]) -> tuple[list[dict[str, Any]], int]:
    structured = splunk_data.get("structured", {}) if isinstance(splunk_data, dict) else {}
    raw_rows = structured.get("results", []) if isinstance(structured, dict) else []
    rows = [dict(row) for row in raw_rows if isinstance(row, dict)] if isinstance(raw_rows, list) else []
    total = structured.get("total_rows") if isinstance(structured, dict) else None
    return rows, total if isinstance(total, int) else len(rows)


def score_live_evidence(
    coverage_report: dict[str, Any] | None,
    splunk_data: dict[str, Any],
) -> dict[str, Any]:
    """Score returned row schema and reject semantically unrelated nonzero rows."""
    report = coverage_report if isinstance(coverage_report, dict) else {}
    spec = report.get("spec", {}) if isinstance(report.get("spec"), dict) else {}
    required = {
        _canonical_field(item)
        for item in spec.get("output_fields", [])
        if str(item).strip()
    }
    rows, total_rows = _rows(splunk_data)
    actual = {
        _canonical_field(field)
        for row in rows
        for field in row
        if str(field).strip()
    }
    matched = required & actual
    schema_score = 1.0 if not required else round(len(matched) / len(required), 4)
    missing = sorted(required - actual)

    if not rows and total_rows <= 0:
        status = "zero_result_unclassified"
        evidence_score = 0.35
        accepted = True
        rejected = False
        reason = "zero_rows_require_base_data_diagnostic"
    elif required and not matched:
        status = "unrelated_nonzero"
        evidence_score = 0.0
        accepted = False
        rejected = True
        reason = "nonzero_rows_have_no_requested_output_fields"
    elif missing:
        status = "missing_required_fields"
        evidence_score = round(0.55 * schema_score, 4)
        accepted = False
        rejected = True
        reason = "nonzero_rows_omit_requested_output_fields"
    else:
        status = "related_nonzero"
        evidence_score = 1.0
        accepted = True
        rejected = False
        reason = "result_schema_satisfies_coverage_spec"

    return {
        "status": status,
        "score": evidence_score,
        "schema_score": schema_score,
        "required_fields": sorted(required),
        "actual_fields": sorted(actual),
        "matched_fields": sorted(matched),
        "missing_fields": missing,
        "rows_returned": len(rows),
        "total_rows": total_rows,
        "accepted": accepted,
        "rejected": rejected,
        "reason": reason,
    }


def confidence_cap_for_evidence(evidence: dict[str, Any] | None) -> float:
    status = str((evidence or {}).get("status", "not_scored"))
    return {
        "related_nonzero": 0.95,
        "zero_result_unclassified": 0.55,
        "valid_zero_result": 0.55,
        "no_base_data": 0.35,
        "missing_required_fields": 0.45,
        "unrelated_nonzero": 0.25,
        "probe_timeout": 0.35,
        "probe_error": 0.30,
        "budget_exhausted": 0.30,
    }.get(status, 0.60)


def _static_report(candidate: dict[str, Any]) -> dict[str, Any]:
    report = candidate.get("semantic_coverage", {})
    return report if isinstance(report, dict) else {}


def _source_priority(source: str) -> int:
    source_l = str(source or "").casefold()
    if "analytical_plan" in source_l or "primary" in source_l:
        return 3
    if "repair" in source_l:
        return 2
    if "fallback" in source_l or "template" in source_l or "oracle" in source_l:
        return 1
    return 0


def _rank_key(candidate: dict[str, Any]) -> tuple[Any, ...]:
    report = _static_report(candidate)
    hard_failures = report.get("hard_failures", []) if isinstance(report.get("hard_failures"), list) else []
    evidence = candidate.get("live_evidence", {})
    evidence = evidence if isinstance(evidence, dict) else {}
    return (
        1 if not hard_failures and bool(report.get("passed", True)) else 0,
        1 if not evidence.get("rejected", False) else 0,
        float(report.get("static_score", candidate.get("static_score", 0.0)) or 0.0),
        float(evidence.get("score", 0.0) or 0.0),
        float(evidence.get("schema_score", 0.0) or 0.0),
        _source_priority(str(candidate.get("candidate_source", candidate.get("source", "")))),
        str(candidate.get("candidate_id", "")),
    )


def _probe_candidate(
    candidate: dict[str, Any],
    *,
    probe_runner: ProbeRunner,
    timeout_seconds: float,
) -> dict[str, Any]:
    started = time.monotonic()
    args = deepcopy(candidate.get("tool_args", {}))
    args["row_limit"] = min(PROBE_ROW_LIMIT, max(1, int(args.get("row_limit", PROBE_ROW_LIMIT) or PROBE_ROW_LIMIT)))
    try:
        data = probe_runner(args, timeout_seconds)
        evidence = score_live_evidence(_static_report(candidate), data)
        evidence["duration_ms"] = int((time.monotonic() - started) * 1000)
        return evidence
    except Exception as exc:
        elapsed_ms = int((time.monotonic() - started) * 1000)
        timeout = isinstance(exc, TimeoutError) or "timeout" in type(exc).__name__.casefold()
        return {
            "status": "probe_timeout" if timeout else "probe_error",
            "score": 0.0,
            "schema_score": 0.0,
            "accepted": False,
            "rejected": True,
            "reason": f"{type(exc).__name__}:{exc}",
            "duration_ms": elapsed_ms,
            "rows_returned": 0,
        }


def select_semantic_candidate(
    *,
    candidates: list[dict[str, Any]],
    mode: str,
    probe_runner: ProbeRunner,
    query_budget: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Collect at most three candidates, probe two, and rank deterministically."""
    candidate_limit = _bounded_env_int("AGTSMITH_MAX_SEMANTIC_CANDIDATES", MAX_CANDIDATES, MAX_CANDIDATES)
    probe_limit = _bounded_env_int("AGTSMITH_MAX_SEMANTIC_PROBES", MAX_PROBES, MAX_PROBES)
    per_probe_timeout = _bounded_env_float(
        "AGTSMITH_SEMANTIC_PROBE_TIMEOUT_SEC",
        PROBE_TIMEOUT_SECONDS,
        PROBE_TIMEOUT_SECONDS,
    )
    total_probe_budget = _bounded_env_float(
        "AGTSMITH_TOTAL_PROBE_BUDGET_SEC",
        TOTAL_PROBE_BUDGET_SECONDS,
        TOTAL_PROBE_BUDGET_SECONDS,
    )
    budget = deepcopy(query_budget) if isinstance(query_budget, dict) else new_query_budget()

    collected: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in candidates:
        if not isinstance(raw, dict) or len(collected) >= candidate_limit:
            continue
        candidate = deepcopy(raw)
        candidate_id = _fingerprint(candidate)
        if candidate_id in seen:
            continue
        seen.add(candidate_id)
        candidate["candidate_id"] = candidate_id
        candidate.setdefault("candidate_source", candidate.get("source", "unknown"))
        candidate.setdefault("live_evidence", {"status": "not_probed", "score": 0.0})
        collected.append(candidate)

    static_ranked = sorted(collected, key=_rank_key, reverse=True)
    probe_started = time.monotonic()
    probes_used = 0
    for candidate in static_ranked:
        if probes_used >= probe_limit:
            break
        report = _static_report(candidate)
        if report.get("hard_failures") or not report.get("passed", True):
            continue
        if str(candidate.get("selected_tool", "")) != "splunk_run_query":
            continue
        elapsed = time.monotonic() - probe_started
        remaining = total_probe_budget - elapsed
        if remaining <= 0:
            break
        reserved, budget = reserve_query(
            budget,
            purpose="semantic_candidate_probe",
            candidate_id=str(candidate["candidate_id"]),
        )
        if not reserved:
            candidate["live_evidence"] = {
                "status": "budget_exhausted",
                "score": 0.0,
                "accepted": False,
                "rejected": True,
                "reason": "global_query_budget_exhausted",
            }
            break
        candidate["live_evidence"] = _probe_candidate(
            candidate,
            probe_runner=probe_runner,
            timeout_seconds=min(per_probe_timeout, remaining),
        )
        probes_used += 1

    ranked = sorted(static_ranked, key=_rank_key, reverse=True)
    original_id = collected[0]["candidate_id"] if collected else ""
    best = ranked[0] if ranked else None
    mode_l = str(mode or "observe").strip().casefold()
    shadow_selected_id = str((best or {}).get("candidate_id", ""))
    selected = next((item for item in collected if item["candidate_id"] == original_id), best)
    blocked = False
    if mode_l in {"prefer", "enforce"}:
        selected = best
    if mode_l == "enforce":
        evidence = (selected or {}).get("live_evidence", {})
        selected_report = _static_report(selected or {})
        compatibility_allowed = not selected_report.get("compatibility_candidate") or bool(
            (selected or {}).get("fallback_only")
        )
        blocked = not bool(
            selected
            and selected_report.get("passed", False)
            and compatibility_allowed
            and (
                str(selected.get("selected_tool", "")) != "splunk_run_query"
                or (isinstance(evidence, dict) and evidence.get("accepted", False))
            )
        )

    telemetry = [
        {
            "candidate_id": item["candidate_id"],
            "source": item.get("candidate_source", item.get("source", "")),
            "static_score": float(_static_report(item).get("static_score", 0.0) or 0.0),
            "hard_failures": list(_static_report(item).get("hard_failures", [])),
            "evidence_status": (item.get("live_evidence", {}) or {}).get("status", "not_probed"),
            "evidence_score": float((item.get("live_evidence", {}) or {}).get("score", 0.0) or 0.0),
            "schema_score": float((item.get("live_evidence", {}) or {}).get("schema_score", 0.0) or 0.0),
            "rows_returned": int((item.get("live_evidence", {}) or {}).get("rows_returned", 0) or 0),
        }
        for item in ranked
    ]
    return {
        "version": "1.0",
        "mode": mode_l,
        "limits": {
            "max_candidates": candidate_limit,
            "max_probes": probe_limit,
            "probe_row_limit": PROBE_ROW_LIMIT,
            "probe_timeout_seconds": per_probe_timeout,
            "total_probe_budget_seconds": total_probe_budget,
            "max_global_queries": int(budget.get("limit", 0) or 0),
        },
        "candidate_count": len(collected),
        "probes_used": probes_used,
        "probe_elapsed_ms": int((time.monotonic() - probe_started) * 1000),
        "selected_candidate": deepcopy(selected) if selected else {},
        "selected_candidate_id": str((selected or {}).get("candidate_id", "")),
        "shadow_selected_candidate_id": shadow_selected_id,
        "observe_preserved_original": mode_l == "observe",
        "blocked": blocked,
        "ranked_candidates": ranked,
        "telemetry": telemetry,
        "query_budget": budget,
        "confidence_cap": confidence_cap_for_evidence(
            (selected or {}).get("live_evidence", {}) if selected else {}
        ),
    }
