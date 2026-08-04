#!/usr/bin/env python3
"""Benchmark SPL quality on simulated unknown/cold environments."""

from __future__ import annotations

import argparse
import copy
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from evaluate_spl_writer_models import score_candidate
from minimal_question_to_answer import map_question_to_template
from spl_field_binding import bind_fields_for_plan
from spl_field_discovery import discover_fields_for_plan, enrich_field_bind_with_discovery
from spl_write_plan_slots import apply_field_bind_slots, group_by_from_role_mappings
from spl_query_schema import constrained_mode_enabled, parse_write_plan, validate_write_plan, write_plan_to_tool_args

PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUT_DEFAULT = PROJECT_ROOT / "artifacts/benchmark/unknown_env_benchmark_latest.json"


def _load_cases(path: Path) -> list[dict[str, Any]]:
    rows = json.loads(path.read_text(encoding="utf-8"))
    return [r for r in rows if isinstance(r, dict)]


def _cold_profile(profile: dict[str, Any], sourcetype: str, *, strip: bool) -> dict[str, Any]:
    copy_profile = copy.deepcopy(profile)
    if not strip or not sourcetype:
        return copy_profile
    inv = copy_profile.get("sourcetype_field_inventory", {})
    if isinstance(inv, dict) and sourcetype in inv:
        inv[sourcetype] = {"fields": [], "field_count": 0, "simulated_unknown_env": True}
        copy_profile["sourcetype_field_inventory"] = inv
    return copy_profile


def _planner_stub(question: str, intent: str) -> dict[str, Any]:
    mapped = map_question_to_template(question)
    use_intent = intent or mapped.intent
    return {
        "intent": use_intent,
        "selected_tool": "splunk_run_query",
        "tool_args": {},
        "confidence": 0.7,
    }


def _generate_with_slots(
    *,
    model: str,
    question: str,
    planner: dict[str, Any],
    field_bind: dict[str, Any],
) -> dict[str, Any]:
    from langgraph_multi_model_soc import _call_ollama_json
    from spl_writer_prompt import build_writer_system_prompt, build_writer_user_payload

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
            if not plan.group_by:
                plan.group_by = group_by_from_role_mappings(field_bind, intent=intent)
            plan = apply_field_bind_slots(plan, field_bind, intent=intent)
            ok, _reason = validate_write_plan(plan)
            if ok:
                writer_output = {**writer_output, **write_plan_to_tool_args(plan, intent=intent)}
    tool_args = writer_output.get("tool_args", {}) if isinstance(writer_output.get("tool_args"), dict) else {}
    return {
        "query": str(tool_args.get("query", writer_output.get("query", ""))).strip(),
        "earliest_time": tool_args.get("earliest_time", "-7d"),
        "latest_time": tool_args.get("latest_time", "now"),
        "row_limit": tool_args.get("row_limit", 10),
    }


def _roles_satisfied(discovery: dict[str, Any], required: list[str]) -> tuple[int, int]:
    mappings = discovery.get("role_mappings", {}) if isinstance(discovery.get("role_mappings"), dict) else {}
    if not required:
        return 0, 0
    hit = sum(1 for role in required if mappings.get(role))
    return hit, len(required)


def _oracle_profile(case: dict[str, Any]) -> dict[str, Any]:
    """Build exact-domain profile evidence without trusting static timestamps."""
    inventory: dict[str, dict[str, dict[str, Any]]] = {}
    for domain in case.get("profile_domains", []):
        if not isinstance(domain, dict):
            continue
        index = str(domain.get("index", "")).strip()
        sourcetype = str(domain.get("sourcetype", "")).strip()
        if not index or not sourcetype:
            continue
        try:
            age_seconds = max(0, int(domain.get("age_seconds", 0) or 0))
        except (TypeError, ValueError):
            age_seconds = 0
        timestamp = datetime.fromtimestamp(
            datetime.now(timezone.utc).timestamp() - age_seconds,
            tz=timezone.utc,
        ).isoformat()
        inventory.setdefault(index, {})[sourcetype] = {
            "timestamp_utc": timestamp,
            "fields": [
                row
                for row in domain.get("fields", [])
                if isinstance(row, dict) and str(row.get("field", "")).strip()
            ],
        }
    return {"index_sourcetype_field_inventory": inventory}


def evaluate_field_strategy_oracle(case: dict[str, Any]) -> dict[str, Any]:
    """Evaluate one deterministic negative/oracle fields-first case."""
    from spl_field_strategy import (
        clear_field_verification_cache,
        resolve_field_strategy,
        rewrite_query_fields_first,
    )

    clear_field_verification_cache()
    query = str(case.get("canonical_query", "")).strip()
    index_expr = str(case.get("index_expr", "")).strip()
    sourcetype = str(case.get("sourcetype", "")).strip()
    live_fields_by_index = case.get("live_fields_by_index", {})
    if not isinstance(live_fields_by_index, dict):
        live_fields_by_index = {}

    def verifier(index: str, _sourcetype: str, _earliest: str, _latest: str) -> set[str]:
        fields = live_fields_by_index.get(index, [])
        return {str(field) for field in fields if str(field).strip()} if isinstance(fields, list) else set()

    planner = {
        "intent": str(case.get("expected_intent", "")),
        "canonical_template_query": query,
        "tool_args": {
            "earliest_time": str(case.get("earliest_time", "-7d")),
            "latest_time": str(case.get("latest_time", "now")),
        },
    }
    strategy = resolve_field_strategy(
        str(case.get("question", "")),
        planner,
        field_bind_output={
            "intent": planner["intent"],
            "index_expr": index_expr,
            "sourcetype": sourcetype,
            "role_mappings": case.get("role_mappings", {}),
        },
        profile=_oracle_profile(case),
        verifier=verifier,
    )
    rewritten, actions = rewrite_query_fields_first(query, strategy)

    findings: list[str] = []
    for pattern in case.get("required_patterns", []):
        if not re.search(str(pattern), rewritten, flags=re.IGNORECASE):
            findings.append(f"missing_required_pattern:{pattern}")
    for pattern in case.get("forbidden_patterns", []):
        if re.search(str(pattern), rewritten, flags=re.IGNORECASE):
            findings.append(f"matched_forbidden_pattern:{pattern}")
    expected_trusted = {
        str(field).lower() for field in case.get("expected_trusted_fields", []) if str(field).strip()
    }
    actual_trusted = {
        str(field).lower() for field in strategy.get("trusted_fields", []) if str(field).strip()
    }
    if actual_trusted != expected_trusted:
        findings.append(
            "trusted_fields_mismatch:"
            f"expected={sorted(expected_trusted)},actual={sorted(actual_trusted)}"
        )
    for prefix in case.get("required_action_prefixes", []):
        if not any(str(action).startswith(str(prefix)) for action in actions):
            findings.append(f"missing_action_prefix:{prefix}")

    return {
        "id": str(case.get("id", "")),
        "benchmark_mode": "field_strategy_oracle",
        "passed": not findings,
        "findings": findings,
        "rewritten_query": rewritten,
        "actions": actions,
        "trusted_fields": strategy.get("trusted_fields", []),
        "role_classifications": {
            role: data.get("classification")
            for role, data in (strategy.get("roles", {}) or {}).items()
            if isinstance(data, dict)
        },
        "domain_verifications": strategy.get("domain_verifications", []),
    }


def run_benchmark(*, model: str, cases_path: Path, live_discovery: bool) -> dict[str, Any]:
    from environment_profile import load_environment_profile

    profile = load_environment_profile()
    cases = _load_cases(cases_path)
    results: list[dict[str, Any]] = []
    baseline_scores: list[int] = []
    discovery_scores: list[int] = []
    role_hits_baseline = 0
    role_total = 0
    role_hits_discovery = 0
    oracle_results: list[dict[str, Any]] = []

    for idx, case in enumerate(cases, start=1):
        if str(case.get("benchmark_mode", "")).strip() == "field_strategy_oracle":
            print(f"[{idx}/{len(cases)}] {case['id']} (field strategy oracle)")
            oracle = evaluate_field_strategy_oracle(case)
            oracle_results.append(oracle)
            results.append(oracle)
            continue
        question = str(case["question"])
        intent = str(case.get("expected_intent", ""))
        sourcetype = str(case.get("sourcetype", "")).strip()
        strip = bool(case.get("strip_sourcetype_inventory", True))
        case_profile = _cold_profile(profile, sourcetype, strip=strip)
        planner = _planner_stub(question, intent)

        print(f"[{idx}/{len(cases)}] {case['id']}")
        bound = bind_fields_for_plan(question, planner, profile=case_profile)
        baseline_candidate = _generate_with_slots(model=model, question=question, planner=planner, field_bind=bound)
        eval_case = {
            "required_terms": case.get("required_terms", []),
            "forbidden_terms": case.get("forbidden_terms", []),
            "expected_intent": intent,
        }
        baseline_score, baseline_notes = score_candidate(baseline_candidate, eval_case)
        baseline_scores.append(baseline_score)

        discovery = discover_fields_for_plan(
            question,
            planner,
            profile=case_profile,
            bound=bound,
            live_probe=live_discovery,
        )
        enriched = enrich_field_bind_with_discovery(bound, discovery)
        discovery_candidate = _generate_with_slots(
            model=model, question=question, planner=planner, field_bind=enriched
        )
        discovery_score, discovery_notes = score_candidate(discovery_candidate, eval_case)
        discovery_scores.append(discovery_score)

        req_roles = list(case.get("required_roles", []))
        if req_roles:
            role_total += len(req_roles)
            empty_disc = {"role_mappings": {}}
            role_hits_baseline += _roles_satisfied(empty_disc, req_roles)[0]
            role_hits_discovery += _roles_satisfied(discovery, req_roles)[0]

        results.append(
            {
                "id": case["id"],
                "question": question,
                "baseline_score": baseline_score,
                "discovery_score": discovery_score,
                "score_delta": discovery_score - baseline_score,
                "discovery_field_count": discovery.get("field_count", 0),
                "discovery_source": discovery.get("source"),
                "coalesce_hints": discovery.get("coalesce_hints", {}),
                "roles_satisfied_ratio": discovery.get("roles_satisfied_ratio"),
                "baseline_query": baseline_candidate.get("query", "")[:400],
                "discovery_query": discovery_candidate.get("query", "")[:400],
                "baseline_notes": baseline_notes[:4],
                "discovery_notes": discovery_notes[:4],
            }
        )

    summary = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "model": model,
        "case_count": len(cases),
        "model_case_count": len(cases) - len(oracle_results),
        "field_strategy_oracle_count": len(oracle_results),
        "field_strategy_oracle_passed": sum(1 for row in oracle_results if row.get("passed")),
        "live_discovery": live_discovery,
        "baseline_avg_score": round(sum(baseline_scores) / len(baseline_scores), 2) if baseline_scores else 0,
        "discovery_avg_score": round(sum(discovery_scores) / len(discovery_scores), 2) if discovery_scores else 0,
        "avg_score_delta": round(
            sum(d - b for d, b in zip(discovery_scores, baseline_scores)) / len(baseline_scores),
            2,
        )
        if baseline_scores
        else 0,
        "discovery_wins": sum(
            1 for row in results if "score_delta" in row and row["score_delta"] > 0
        ),
        "role_mapping_hits_discovery": role_hits_discovery,
        "role_mapping_total": role_total,
    }
    payload = {"summary": summary, "results": results}
    OUT_DEFAULT.parent.mkdir(parents=True, exist_ok=True)
    OUT_DEFAULT.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description="Unknown environment SPL benchmark")
    parser.add_argument("--cases", default=str(PROJECT_ROOT / "benchmarks/unknown_env_cases.json"))
    parser.add_argument("--model", default="granite4:3b")
    parser.add_argument("--no-live", action="store_true", help="Skip live MCP fieldsummary probes")
    args = parser.parse_args()
    payload = run_benchmark(model=args.model, cases_path=Path(args.cases), live_discovery=not args.no_live)
    summary = payload.get("summary", {})
    return (
        0
        if summary.get("field_strategy_oracle_passed", 0)
        == summary.get("field_strategy_oracle_count", 0)
        else 1
    )


if __name__ == "__main__":
    raise SystemExit(main())
