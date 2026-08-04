#!/usr/bin/env python3
"""Compare canonical MCP SPL, Data Domains profile, template, and multi-model paths."""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from environment_profile import indexes_with_data_in_window, load_environment_profile, profile_inventory_structured_results
from minimal_question_to_answer import map_question_to_template, run_splunk_query_args, template_to_query_args, try_profile_inventory_answer
from query_policy import validate_query_args
from score_result_equivalence import (
    entity_recall as _shared_entity_recall,
    jaccard as _shared_jaccard,
    score_result_equivalence,
)
from spl_offline_docs_rag import build_offline_docs_context, offline_docs_index_available


@dataclass(frozen=True)
class AccuracyCase:
    id: str
    category: str
    question: str
    expected_intent: str
    canonical_spl: str
    earliest_time: str
    latest_time: str
    compare_fields: tuple[str, ...]
    profile_window: str
    min_jaccard: float
    entity_fields: tuple[str, ...]
    min_entity_recall: float
    fields_first: bool = False
    offline_verified_fields: tuple[str, ...] = ()


def _load_cases(path: Path) -> list[AccuracyCase]:
    rows = json.loads(path.read_text(encoding="utf-8"))
    cases: list[AccuracyCase] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        compare_fields = tuple(str(x) for x in row.get("compare_fields", []))
        entity_fields_raw = row.get("entity_fields")
        if entity_fields_raw:
            entity_fields = tuple(str(x) for x in entity_fields_raw)
        else:
            entity_fields = tuple(f for f in compare_fields if f != "count")
        cases.append(
            AccuracyCase(
                id=str(row["id"]),
                category=str(row.get("category", "")),
                question=str(row["question"]),
                expected_intent=str(row.get("expected_intent", "")),
                canonical_spl=str(row["canonical_spl"]),
                earliest_time=str(row.get("earliest_time", "-24h")),
                latest_time=str(row.get("latest_time", "now")),
                compare_fields=compare_fields,
                profile_window=str(row.get("profile_window", "")),
                min_jaccard=float(row.get("min_jaccard", 0.9)),
                entity_fields=entity_fields,
                min_entity_recall=float(row.get("min_entity_recall", 0.9)),
                fields_first=bool(row.get("fields_first", False)),
                offline_verified_fields=tuple(
                    str(field)
                    for field in row.get("offline_verified_fields", [])
                    if str(field).strip()
                ),
            )
        )
    return cases


def _rows(data: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not isinstance(data, dict):
        return []
    structured = data.get("structured", data)
    if not isinstance(structured, dict):
        return []
    results = structured.get("results", [])
    if not isinstance(results, list):
        return []
    return [row for row in results if isinstance(row, dict)]


def _row_keys(rows: list[dict[str, Any]], fields: tuple[str, ...]) -> set[str]:
    keys: set[str] = set()
    for row in rows:
        parts = []
        for field in fields:
            parts.append(str(row.get(field, "")).strip().lower())
        if any(parts):
            keys.add("|".join(parts))
    return keys


def _jaccard(a: set[str], b: set[str]) -> float:
    return _shared_jaccard(a, b)


def _entity_recall(candidate: set[str], reference: set[str]) -> float:
    return _shared_entity_recall(candidate, reference)


def _aggregate_count(rows: list[dict[str, Any]]) -> int:
    total = 0
    for row in rows:
        try:
            total += int(row.get("count", 0))
        except Exception:
            continue
    return total


def _run_canonical(case: AccuracyCase, *, row_limit: int, offline: bool) -> dict[str, Any]:
    query = case.canonical_spl.strip()
    if not query:
        template = map_question_to_template(case.question)
        query = str(template_to_query_args(template, case.question).get("query", "")).strip()
    args = {
        "query": query,
        "earliest_time": case.earliest_time,
        "latest_time": case.latest_time,
        "row_limit": row_limit,
    }
    if offline:
        return {"structured": {"results": [], "total_rows": 0}, "offline": True, "mapped_query": args}
    return run_splunk_query_args(args, intent=case.expected_intent, summary_hint="canonical ground truth")


def _run_template(
    case: AccuracyCase,
    *,
    profile: dict[str, Any],
    row_limit: int,
    offline: bool,
) -> dict[str, Any]:
    template = map_question_to_template(case.question)
    args = template_to_query_args(template, case.question)
    args["row_limit"] = row_limit
    field_strategy: dict[str, Any] = {}
    field_policy: dict[str, Any] = {}
    if case.fields_first:
        from spl_field_binding import bind_fields_for_plan
        from spl_field_strategy import apply_field_policy_to_plan, resolve_field_strategy

        planner = {
            "intent": template.intent,
            "canonical_template_query": str(args.get("query", "")),
            "tool_args": args,
        }
        bound = bind_fields_for_plan(case.question, planner, profile=profile)
        verifier = (
            (lambda *_args: set(case.offline_verified_fields))
            if offline
            else None
        )
        field_strategy = resolve_field_strategy(
            case.question,
            planner,
            field_bind_output=bound,
            profile=profile,
            verifier=verifier,
        )
        plan, field_policy = apply_field_policy_to_plan(
            {
                "selected_tool": "splunk_run_query",
                "intent": template.intent,
                "tool_args": args,
            },
            field_strategy,
        )
        args = plan.get("tool_args", args)
    if offline:
        return {
            "intent": template.intent,
            "structured": {"results": [], "total_rows": 0},
            "offline": True,
            "mapped_query": args,
            "field_strategy_trusted_fields": field_strategy.get("trusted_fields", []),
            "field_policy_actions": field_policy.get("actions", []),
        }
    result = run_splunk_query_args(args, intent=template.intent, summary_hint=template.summary_hint)
    result["field_strategy_trusted_fields"] = field_strategy.get("trusted_fields", [])
    result["field_policy_actions"] = field_policy.get("actions", [])
    return result


def _run_multi_model(case: AccuracyCase, *, row_limit: int, offline: bool) -> dict[str, Any]:
    if offline:
        template = map_question_to_template(case.question)
        args = template_to_query_args(template, case.question)
        args["row_limit"] = row_limit
        return {
            "intent": template.intent,
            "structured": {"results": [], "total_rows": 0},
            "offline": True,
            "mapped_query": args,
            "source": "multi_model_offline",
        }
    from langgraph_multi_model_soc import run_multi_model_soc

    payload = run_multi_model_soc(case.question)
    result = payload.get("result", {}) if isinstance(payload, dict) else {}
    if not isinstance(result, dict):
        result = {}

    intent = str(result.get("intent") or case.expected_intent)
    query_args = result.get("query_args", {})
    if isinstance(query_args, dict) and str(query_args.get("query", "")).strip():
        mapped_query = {
            **query_args,
            "row_limit": row_limit,
            "earliest_time": case.earliest_time,
            "latest_time": case.latest_time,
        }
        executed = run_splunk_query_args(mapped_query, intent=intent, summary_hint="multi-model pipeline")
        executed["mapped_query"] = mapped_query
        executed["source"] = "multi_model"
        return executed

    generated_spl = str(result.get("generated_spl", "")).strip()
    if generated_spl:
        mapped_query = {
            "query": generated_spl,
            "earliest_time": case.earliest_time,
            "latest_time": case.latest_time,
            "row_limit": row_limit,
        }
        executed = run_splunk_query_args(mapped_query, intent=intent, summary_hint="multi-model pipeline")
        executed["mapped_query"] = mapped_query
        executed["source"] = "multi_model"
        return executed

    final_plan = result.get("final_plan", {}) or result.get("query_writer_output", {}) or {}
    tool_args = final_plan.get("tool_args", {}) if isinstance(final_plan, dict) else {}
    if not isinstance(tool_args, dict):
        tool_args = {}
    intent = str(final_plan.get("intent", intent or case.expected_intent))
    if str(final_plan.get("selected_tool", "")) != "splunk_run_query" or not tool_args.get("query"):
        return {
            "intent": intent,
            "structured": {"results": [], "total_rows": 0},
            "mapped_query": tool_args,
            "source": "multi_model_non_query",
            "final_plan": final_plan,
        }
    tool_args = {**tool_args, "row_limit": row_limit, "earliest_time": case.earliest_time, "latest_time": case.latest_time}
    executed = run_splunk_query_args(tool_args, intent=intent, summary_hint="multi-model pipeline")
    executed["mapped_query"] = tool_args
    executed["source"] = "multi_model"
    executed["final_plan"] = final_plan
    return executed


def _run_profile(case: AccuracyCase, profile: dict[str, Any]) -> dict[str, Any]:
    if case.profile_window:
        rows = indexes_with_data_in_window(profile, earliest=case.profile_window)
        return {"structured": {"results": rows, "total_rows": len(rows)}, "source": "index_activity"}
    template = map_question_to_template(case.question)
    profile_answer = try_profile_inventory_answer(case.question, template)
    if profile_answer is not None:
        return profile_answer
    structured = profile_inventory_structured_results(case.question, profile)
    if structured:
        return {"structured": structured, "source": "profile_inventory"}
    return {"structured": {"results": [], "total_rows": 0}, "source": "profile_unavailable"}


def _rag_meta(question: str, *, intent: str) -> dict[str, Any]:
    available = offline_docs_index_available()
    ctx = build_offline_docs_context(question, intent=intent, max_topics=3, max_chars=800) if available else ""
    titles: list[str] = []
    for line in ctx.splitlines():
        if line.startswith("title="):
            titles.append(line.split("=", 1)[-1].strip())
    return {"offline_docs_available": available, "matched_titles": titles}


def _score_rows(
    *,
    case: AccuracyCase,
    candidate_rows: list[dict[str, Any]],
    reference_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    shared = score_result_equivalence(
        candidate_rows=candidate_rows,
        reference_rows=reference_rows,
        compare_fields=case.compare_fields,
        entity_fields=case.entity_fields,
    )
    return {
        **shared,
        "count_delta_pct": round(
            abs(_aggregate_count(candidate_rows) - _aggregate_count(reference_rows))
            / max(1, _aggregate_count(reference_rows)),
            4,
        )
        if reference_rows and "count" in case.compare_fields
        else None,
    }


def _passes_score(score: dict[str, Any], *, case: AccuracyCase) -> bool:
    if score.get("entity_recall", 0) >= case.min_entity_recall:
        return True
    return float(score.get("jaccard", 0)) >= case.min_jaccard


def evaluate_case(
    case: AccuracyCase,
    *,
    profile: dict[str, Any],
    row_limit: int,
    offline: bool,
    include_multi_model: bool = False,
) -> dict[str, Any]:
    template = map_question_to_template(case.question)
    canonical = _run_canonical(case, row_limit=row_limit, offline=offline)
    pipeline = _run_template(case, profile=profile, row_limit=row_limit, offline=offline)
    profile_data = _run_profile(case, profile)
    multi_model = _run_multi_model(case, row_limit=row_limit, offline=offline) if include_multi_model else None

    canonical_rows = _rows(canonical)
    pipeline_rows = _rows(pipeline)
    profile_rows = _rows(profile_data)
    multi_rows = _rows(multi_model) if multi_model else []

    pipeline_args = pipeline.get("mapped_query", {}) if isinstance(pipeline.get("mapped_query"), dict) else {}
    policy_ok, policy_reason = validate_query_args(pipeline_args, question=case.question)
    pipeline_query = str(pipeline_args.get("query", ""))
    fields_first_findings: list[str] = []
    if case.fields_first:
        if not pipeline.get("field_strategy_trusted_fields"):
            fields_first_findings.append("fields_first_no_trusted_native_fields")
        if "| rex " in pipeline_query.lower() or "| spath " in pipeline_query.lower():
            fields_first_findings.append("fields_first_extraction_not_removed")
        if not any(
            str(action).startswith("removed_redundant_")
            for action in pipeline.get("field_policy_actions", [])
        ):
            fields_first_findings.append("fields_first_policy_removal_not_observed")

    pipeline_score = _score_rows(case=case, candidate_rows=pipeline_rows, reference_rows=canonical_rows)
    profile_score = (
        _score_rows(case=case, candidate_rows=profile_rows, reference_rows=canonical_rows)
        if case.profile_window
        else None
    )
    multi_score = (
        _score_rows(case=case, candidate_rows=multi_rows, reference_rows=canonical_rows)
        if include_multi_model
        else None
    )

    if offline:
        findings: list[str] = list(fields_first_findings)
        if template.intent != case.expected_intent:
            findings.append(f"intent_mismatch:{template.intent}->{case.expected_intent}")
        if not policy_ok:
            findings.append(f"policy_fail:{policy_reason}")
        passed = not findings
        return {
            "id": case.id,
            "category": case.category,
            "question": case.question,
            "expected_intent": case.expected_intent,
            "actual_intent": template.intent,
            "passed": passed,
            "findings": findings,
            "pipeline_score": pipeline_score,
            "profile_score": profile_score,
            "multi_model_score": multi_score,
            "canonical_rows": 0,
            "pipeline_rows": 0,
            "profile_rows": len(profile_rows),
            "multi_model_rows": 0,
            "pipeline_query": pipeline_args.get("query", ""),
            "field_strategy_trusted_fields": pipeline.get("field_strategy_trusted_fields", []),
            "field_policy_actions": pipeline.get("field_policy_actions", []),
            "policy_ok": policy_ok,
            "policy_reason": policy_reason,
            "rag": _rag_meta(case.question, intent=template.intent),
            "offline": True,
        }

    findings = list(fields_first_findings)
    if template.intent != case.expected_intent:
        findings.append(f"intent_mismatch:{template.intent}->{case.expected_intent}")
    if not policy_ok:
        findings.append(f"policy_fail:{policy_reason}")
    if not _passes_score(pipeline_score, case=case):
        findings.append(
            f"pipeline_entity_recall:{pipeline_score.get('entity_recall')}<{case.min_entity_recall}"
        )
    if profile_score is not None and not _passes_score(profile_score, case=case):
        findings.append(
            f"profile_entity_recall:{profile_score.get('entity_recall')}<{case.min_entity_recall}"
        )
    if multi_score is not None and not _passes_score(multi_score, case=case):
        findings.append(
            f"multi_model_entity_recall:{multi_score.get('entity_recall')}<{case.min_entity_recall}"
        )

    passed = not findings
    multi_args = multi_model.get("mapped_query", {}) if isinstance(multi_model, dict) else {}
    return {
        "id": case.id,
        "category": case.category,
        "question": case.question,
        "expected_intent": case.expected_intent,
        "actual_intent": template.intent,
        "passed": passed,
        "findings": findings,
        "pipeline_score": pipeline_score,
        "profile_score": profile_score,
        "multi_model_score": multi_score,
        "pipeline_jaccard": pipeline_score.get("jaccard"),
        "profile_jaccard": profile_score.get("jaccard") if profile_score else None,
        "canonical_rows": len(canonical_rows),
        "pipeline_rows": len(pipeline_rows),
        "profile_rows": len(profile_rows),
        "multi_model_rows": len(multi_rows),
        "pipeline_query": pipeline_args.get("query", ""),
        "field_strategy_trusted_fields": pipeline.get("field_strategy_trusted_fields", []),
        "field_policy_actions": pipeline.get("field_policy_actions", []),
        "multi_model_query": multi_args.get("query", "") if isinstance(multi_args, dict) else "",
        "policy_ok": policy_ok,
        "policy_reason": policy_reason,
        "rag": _rag_meta(case.question, intent=template.intent),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Operational SPL accuracy harness")
    parser.add_argument("--cases", default="benchmarks/operational_spl_accuracy.json")
    parser.add_argument("--out-dir", default="artifacts/benchmark/operational_spl_accuracy")
    parser.add_argument("--row-limit", type=int, default=50)
    parser.add_argument("--offline", action="store_true", help="Skip live MCP execution")
    parser.add_argument("--multi-model", action="store_true", help="Also run full multi-model LangGraph pipeline")
    args = parser.parse_args()

    cases = _load_cases(Path(args.cases))
    profile = load_environment_profile()
    results = [
        evaluate_case(
            case,
            profile=profile,
            row_limit=max(1, args.row_limit),
            offline=bool(args.offline),
            include_multi_model=bool(args.multi_model),
        )
        for case in cases
    ]
    passed = sum(1 for row in results if row.get("passed"))
    report = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "offline": bool(args.offline),
        "multi_model": bool(args.multi_model),
        "case_count": len(results),
        "passed_count": passed,
        "pass_rate_pct": round((passed / len(results)) * 100, 2) if results else 0.0,
        "results": results,
    }
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    latest = out_dir / "latest.json"
    latest.write_text(json.dumps(report, indent=2), encoding="utf-8")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    history = out_dir / f"run_{stamp}.json"
    history.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({"out": str(latest), "passed": passed, "total": len(results)}, indent=2))
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
