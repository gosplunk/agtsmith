#!/usr/bin/env python3
"""Short probe: field discovery agent vs baseline field_bind for writer SPL quality."""

from __future__ import annotations

import argparse
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from evaluate_spl_writer_models import generate_candidate, score_candidate
from minimal_question_to_answer import map_question_to_template, template_to_query_args
from question_intelligence import infer_time_window
from spl_field_binding import bind_fields_for_plan
from spl_field_discovery import discover_fields_for_plan, enrich_field_bind_with_discovery
from spl_writer_prompt import build_writer_system_prompt, build_writer_user_payload

PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUT_DEFAULT = PROJECT_ROOT / "artifacts/benchmark/field_discovery_probe_latest.json"

PROBE_CASES: list[dict[str, Any]] = [
    {
        "id": "linux_auth_failures_24h",
        "question": "Show failed SSH login activity in the last 24 hours on my linux systems. Identify the top source IPs, usernames targeted, ports used, and which host is being targeted most.",
        "expected_intent": "linux_auth_failures",
        "required_terms": ["index=linux", "auth.log", "stats", "user", "src_ip"],
    },
    {
        "id": "windows_failed_logons_24h",
        "question": "Show failed login activity in the last 24 hours in windows.",
        "expected_intent": "windows_auth_failures",
        "required_terms": ["4625", "stats", "user"],
    },
    {
        "id": "apache_access_top_ips",
        "question": "Investigate suspicious web access activity in access_combined over the last 24 hours. Show top client IPs, status codes, methods, and likely scanning behavior.",
        "expected_intent": "apache_access_top_ips",
        "required_terms": ["access_combined", "clientip", "stats", "status"],
    },
    {
        "id": "aws_cloudtrail_activity",
        "question": "Show AWS CloudTrail activity in the last 24 hours including event names and users.",
        "expected_intent": "aws_cloudtrail_activity",
        "required_terms": ["cloudtrail", "eventname", "stats"],
    },
    {
        "id": "internal_audit_failures",
        "question": "Show _audit auth failures today.",
        "expected_intent": "internal_auth_failures",
        "required_terms": ["index=_audit", "stats"],
    },
    {
        "id": "linux_priv_esc_cold",
        "question": "Investigate failed privilege escalation attempts on my linux systems over the last day.",
        "expected_intent": "linux_privilege_escalation",
        "required_terms": ["index=linux", "sudo", "stats"],
        "simulate_cold_profile": True,
    },
]


def _planner_stub(question: str, intent: str) -> dict[str, Any]:
    mapped = map_question_to_template(question)
    use_intent = intent or mapped.intent
    tool_args = template_to_query_args(mapped, question)
    return {
        "intent": use_intent,
        "selected_tool": "splunk_run_query",
        "tool_args": tool_args,
        "confidence": 0.7,
        "reason": "probe_planner_stub",
    }


def _cold_profile(profile: dict[str, Any], sourcetype: str) -> dict[str, Any]:
    """Simulate stale/missing field inventory for one sourcetype."""
    copy = json.loads(json.dumps(profile))
    inv = copy.get("sourcetype_field_inventory", {})
    if isinstance(inv, dict) and sourcetype in inv:
        inv[sourcetype] = {"fields": [], "field_count": 0, "simulated_cold": True}
        copy["sourcetype_field_inventory"] = inv
    return copy


def _generate_with_field_bind(
    *,
    model: str,
    question: str,
    planner: dict[str, Any],
    field_bind: dict[str, Any],
) -> dict[str, Any]:
    from langgraph_multi_model_soc import _call_ollama_json
    from spl_query_schema import constrained_mode_enabled, parse_write_plan, validate_write_plan, write_plan_to_tool_args

    intent = str(planner.get("intent", "")).strip()
    system = build_writer_system_prompt(intent=intent)
    user_payload = build_writer_user_payload(
        question=question,
        planner_output=planner,
        field_bind_output=field_bind,
    )
    writer_output = _call_ollama_json(model=model, system_prompt=system, user_payload=user_payload, timeout=120.0)
    if constrained_mode_enabled():
        plan = parse_write_plan(writer_output)
        if plan is not None:
            if field_bind.get("index_expr") and plan.index_expr in {"", "index=* NOT index=_*"}:
                plan.index_expr = str(field_bind.get("index_expr"))
            if field_bind.get("sourcetype") and not plan.sourcetype:
                plan.sourcetype = str(field_bind.get("sourcetype"))
            ok, _reason = validate_write_plan(plan)
            if ok:
                writer_output = {**writer_output, **write_plan_to_tool_args(plan, intent=intent)}
    tool_args = writer_output.get("tool_args", {}) if isinstance(writer_output.get("tool_args"), dict) else {}
    query = str(tool_args.get("query", writer_output.get("query", ""))).strip()
    inferred_earliest, inferred_latest = infer_time_window(question)
    return {
        "query": query,
        "earliest_time": tool_args.get("earliest_time", writer_output.get("earliest_time", inferred_earliest)),
        "latest_time": tool_args.get("latest_time", writer_output.get("latest_time", inferred_latest)),
        "row_limit": tool_args.get("row_limit", writer_output.get("row_limit", 10)),
    }


def _uses_discovered_fields(query: str, discovery: dict[str, Any]) -> list[str]:
    lower = query.lower()
    hits: list[str] = []
    for hint in discovery.get("coalesce_hints", {}).values():
        for token in str(hint).replace("coalesce(", "").replace(")", "").split(","):
            token = token.strip()
            if token and token.lower() in lower:
                hits.append(token)
    for role_fields in discovery.get("role_mappings", {}).values():
        if not isinstance(role_fields, list):
            continue
        for field in role_fields:
            if str(field).lower() in lower:
                hits.append(str(field))
    return sorted(set(hits))


def run_probe(*, model: str, writer_compare: bool, use_llm_roles: bool) -> dict[str, Any]:
    from environment_profile import load_environment_profile

    profile = load_environment_profile()
    results: list[dict[str, Any]] = []
    baseline_scores: list[int] = []
    discovery_scores: list[int] = []
    role_ratios: list[float] = []

    for idx, case in enumerate(PROBE_CASES, start=1):
        question = str(case["question"])
        intent = str(case.get("expected_intent", ""))
        planner = _planner_stub(question, intent)
        case_profile = profile
        if case.get("simulate_cold_profile"):
            bound_pre = bind_fields_for_plan(question, planner, profile=profile)
            st = str(bound_pre.get("sourcetype", "")).strip()
            if st:
                case_profile = _cold_profile(profile, st)

        bound = bind_fields_for_plan(question, planner, profile=case_profile)
        print(f"[{idx}/{len(PROBE_CASES)}] discover: {case['id']}")
        discovery = discover_fields_for_plan(
            question,
            planner,
            profile=case_profile,
            bound=bound,
            live_probe=True,
            use_llm_roles=use_llm_roles,
            llm_model=model,
        )
        enriched = enrich_field_bind_with_discovery(bound, discovery)
        role_ratios.append(float(discovery.get("roles_satisfied_ratio", 0.0)))

        row: dict[str, Any] = {
            "id": case["id"],
            "question": question,
            "expected_intent": intent,
            "baseline_field_hints": bound.get("field_hints", []),
            "discovery_source": discovery.get("source"),
            "discovery_field_count": discovery.get("field_count"),
            "new_fields_vs_profile": discovery.get("new_fields_vs_profile", []),
            "role_mappings": discovery.get("role_mappings"),
            "coalesce_hints": discovery.get("coalesce_hints"),
            "roles_satisfied_ratio": discovery.get("roles_satisfied_ratio"),
            "probe_error": discovery.get("probe_error"),
            "discovery_duration_ms": discovery.get("duration_ms"),
            "raw_sample_len": len(str(discovery.get("raw_sample", ""))),
        }

        eval_case = {
            "required_terms": case.get("required_terms", []),
            "forbidden_terms": case.get("forbidden_terms", []),
            "expected_intent": intent,
        }

        if writer_compare:
            print(f"  writer baseline...")
            baseline_candidate = _generate_with_field_bind(model=model, question=question, planner=planner, field_bind=bound)
            baseline_score, baseline_notes = score_candidate(baseline_candidate, eval_case)
            print(f"  writer discovery...")
            discovery_candidate = _generate_with_field_bind(
                model=model, question=question, planner=planner, field_bind=enriched
            )
            discovery_score, discovery_notes = score_candidate(discovery_candidate, eval_case)
            baseline_scores.append(baseline_score)
            discovery_scores.append(discovery_score)
            row.update(
                {
                    "baseline_query": baseline_candidate.get("query", ""),
                    "baseline_score": baseline_score,
                    "baseline_notes": baseline_notes,
                    "discovery_query": discovery_candidate.get("query", ""),
                    "discovery_score": discovery_score,
                    "discovery_notes": discovery_notes,
                    "score_delta": discovery_score - baseline_score,
                    "discovery_field_usage": _uses_discovered_fields(discovery_candidate.get("query", ""), discovery),
                }
            )
        results.append(row)

    summary = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "model": model,
        "case_count": len(PROBE_CASES),
        "writer_compare": writer_compare,
        "use_llm_roles": use_llm_roles,
        "avg_roles_satisfied_ratio": round(sum(role_ratios) / len(role_ratios), 3) if role_ratios else 0.0,
        "discovery_live_success": sum(1 for r in results if r.get("discovery_source") == "live_mcp"),
        "cases_with_new_fields": sum(1 for r in results if r.get("new_fields_vs_profile")),
    }
    if writer_compare and baseline_scores:
        summary["baseline_avg_score"] = round(sum(baseline_scores) / len(baseline_scores), 2)
        summary["discovery_avg_score"] = round(sum(discovery_scores) / len(discovery_scores), 2)
        summary["avg_score_delta"] = round(
            sum(d - b for d, b in zip(discovery_scores, baseline_scores)) / len(baseline_scores),
            2,
        )
        summary["discovery_wins"] = sum(
            1 for r in results if int(r.get("score_delta", 0)) > 0
        )
        summary["baseline_wins"] = sum(
            1 for r in results if int(r.get("score_delta", 0)) < 0
        )
        summary["ties"] = sum(1 for r in results if int(r.get("score_delta", 0)) == 0)

    payload = {"summary": summary, "results": results}
    OUT_DEFAULT.parent.mkdir(parents=True, exist_ok=True)
    OUT_DEFAULT.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description="Probe field discovery agent")
    parser.add_argument("--model", default="granite4:3b")
    parser.add_argument("--no-writer", action="store_true", help="Skip writer A/B (discovery only)")
    parser.add_argument("--llm-roles", action="store_true", help="Use LLM for role mapping")
    args = parser.parse_args()
    run_probe(model=args.model, writer_compare=not args.no_writer, use_llm_roles=args.llm_roles)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
