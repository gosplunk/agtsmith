#!/usr/bin/env python3
"""Compare canonical internal-index SPL against Agent Smith template and multi-model paths."""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from environment_profile import load_environment_profile
from langgraph_minimal_flow import determine_splunk_tool
from minimal_question_to_answer import map_question_to_template, template_to_query_args
from query_policy import validate_query_args
from run_operational_spl_accuracy import (
    AccuracyCase,
    _passes_score,
    _rows,
    _run_canonical,
    _run_multi_model,
    _run_template,
    _score_findings,
    _score_rows,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CASES = PROJECT_ROOT / "benchmarks" / "internal_spl_oracles.json"
DEFAULT_OUT = PROJECT_ROOT / "artifacts" / "spl_autonomy" / "internal_benchmark"


@dataclass(frozen=True)
class InternalCase(AccuracyCase):
    index_scope: str = ""
    sourcetype_tags: tuple[str, ...] = ()
    data_present_required: bool = True


def _case_from_row(row: dict[str, Any]) -> InternalCase:
    compare_fields = tuple(str(x) for x in row.get("compare_fields", []))
    entity_fields_raw = row.get("entity_fields")
    if entity_fields_raw:
        entity_fields = tuple(str(x) for x in entity_fields_raw)
    else:
        entity_fields = tuple(f for f in compare_fields if f != "count")
    return InternalCase(
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
        max_count_delta_pct=(
            float(row["max_count_delta_pct"])
            if row.get("max_count_delta_pct") is not None
            else (0.05 if "count" in compare_fields else None)
        ),
        profile_max_count_delta_pct=(
            float(row["profile_max_count_delta_pct"])
            if row.get("profile_max_count_delta_pct") is not None
            else (0.5 if "count" in compare_fields else None)
        ),
        min_equivalence_score=float(row.get("min_equivalence_score", 0.7)),
        fields_first=bool(row.get("fields_first", False)),
        offline_verified_fields=tuple(
            str(field) for field in row.get("offline_verified_fields", []) if str(field).strip()
        ),
        index_scope=str(row.get("index_scope", "")).strip(),
        sourcetype_tags=tuple(str(x) for x in row.get("sourcetype_tags", []) if str(x).strip()),
        data_present_required=bool(row.get("data_present_required", True)),
    )


def _load_cases(path: Path) -> list[InternalCase]:
    rows = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(rows, list):
        raise ValueError("internal_oracles_must_be_array")
    return [_case_from_row(row) for row in rows if isinstance(row, dict)]


def _normalize_spl(query: str) -> str:
    return " ".join(str(query or "").lower().split())


def _structural_findings(case: InternalCase, pipeline_query: str) -> list[str]:
    findings: list[str] = []
    q = pipeline_query.lower()
    if case.index_scope and f"index={case.index_scope.lower()}" not in q:
        findings.append(f"wrong_index_scope:expected={case.index_scope}")
    for tag in case.sourcetype_tags:
        if tag.lower() not in q:
            findings.append(f"wrong_sourcetype_filter:missing={tag}")
    if "sourcetype" in case.question.lower() and re.search(r"stats\s+count\s+by\s+index\b", q):
        findings.append("wrong_aggregation_dimension:by_index_not_sourcetype")
    if "host" in case.question.lower() and "sourcetype" not in case.question.lower():
        if "stats count by sourcetype" in q and "by host" not in q:
            findings.append("wrong_aggregation_dimension:host_question_used_sourcetype_only")
    return findings


def classify_failure(
    *,
    case: InternalCase,
    findings: list[str],
    template_intent: str,
    tool: str,
    canonical_rows: int,
    pipeline_rows: int,
) -> str:
    joined = " ".join(findings).lower()
    if template_intent != case.expected_intent:
        return "routing_wrong_intent"
    if "metadata_tool_instead_of_search" in joined or tool == "splunk_get_metadata":
        return "metadata_tool_instead_of_search"
    if "wrong_index_scope" in joined:
        return "wrong_index_scope"
    if "wrong_sourcetype_filter" in joined:
        return "wrong_sourcetype_filter"
    if "wrong_aggregation_dimension" in joined:
        return "wrong_aggregation_dimension"
    if canonical_rows > 0 and pipeline_rows == 0:
        return "zero_rows_canonical_ok_agent_bad"
    if canonical_rows == 0 and pipeline_rows == 0 and case.data_present_required:
        return "both_zero_rows"
    if "policy_fail" in joined:
        return "policy_fail"
    if findings:
        return "equivalence_or_score_fail"
    return "pass"


def evaluate_case(
    case: InternalCase,
    *,
    profile: dict[str, Any],
    row_limit: int,
    offline: bool,
    include_multi_model: bool = False,
) -> dict[str, Any]:
    template = map_question_to_template(case.question)
    tool, tool_reason, _, _ = determine_splunk_tool(case.question, template.intent)
    canonical = _run_canonical(case, row_limit=row_limit, offline=offline)
    pipeline = _run_template(case, profile=profile, row_limit=row_limit, offline=offline)
    multi_model = _run_multi_model(case, row_limit=row_limit, offline=offline) if include_multi_model else None

    canonical_rows = _rows(canonical)
    pipeline_rows = _rows(pipeline)
    multi_rows = _rows(multi_model) if multi_model else []

    pipeline_args = pipeline.get("mapped_query", {}) if isinstance(pipeline.get("mapped_query"), dict) else {}
    policy_ok, policy_reason = validate_query_args(pipeline_args, question=case.question)
    pipeline_query = str(pipeline_args.get("query", ""))

    findings: list[str] = []
    if template.intent != case.expected_intent:
        findings.append(f"intent_mismatch:{template.intent}->{case.expected_intent}")
    if not policy_ok:
        findings.append(f"policy_fail:{policy_reason}")
    if tool != "splunk_run_query" and any(
        term in case.question.lower()
        for term in ("last hour", "last 24", "last day", "have data", "events in", "activity", "sending")
    ):
        findings.append(f"metadata_tool_instead_of_search:{tool}:{tool_reason}")
    findings.extend(_structural_findings(case, pipeline_query))

    pipeline_score = _score_rows(case=case, candidate_rows=pipeline_rows, reference_rows=canonical_rows)
    multi_score = (
        _score_rows(case=case, candidate_rows=multi_rows, reference_rows=canonical_rows)
        if include_multi_model
        else None
    )
    multi_args = multi_model.get("mapped_query", {}) if isinstance(multi_model, dict) else {}

    multi_query = str(multi_args.get("query", "") if isinstance(multi_args, dict) else "")
    multi_shape_match = _normalize_spl(multi_query) == _normalize_spl(case.canonical_spl)
    if not offline:
        if not _passes_score(pipeline_score, case=case):
            findings.extend(_score_findings("pipeline", pipeline_score, case=case))
        if multi_score is not None and not _passes_score(multi_score, case=case):
            findings.extend(_score_findings("multi_model", multi_score, case=case))
        if (
            multi_score is not None
            and multi_shape_match
            and multi_score.get("entity_recall", 0) >= case.min_entity_recall
        ):
            findings = [f for f in findings if not f.startswith("multi_model_")]
        if case.data_present_required and not canonical_rows:
            findings.append("both_zero_rows:canonical_empty")
    elif tool != "splunk_run_query":
        findings.append(f"offline_tool_check:{tool}")

    passed = not findings
    failure_bucket = classify_failure(
        case=case,
        findings=findings,
        template_intent=template.intent,
        tool=tool,
        canonical_rows=len(canonical_rows),
        pipeline_rows=len(pipeline_rows),
    )
    return {
        "id": case.id,
        "category": case.category,
        "index_scope": case.index_scope,
        "question": case.question,
        "expected_intent": case.expected_intent,
        "actual_intent": template.intent,
        "selected_tool": tool,
        "tool_reason": tool_reason,
        "passed": passed,
        "failure_bucket": failure_bucket,
        "findings": findings,
        "pipeline_score": pipeline_score,
        "multi_model_score": multi_score,
        "canonical_rows": len(canonical_rows),
        "pipeline_rows": len(pipeline_rows),
        "multi_model_rows": len(multi_rows),
        "canonical_spl": case.canonical_spl,
        "pipeline_query": pipeline_query,
        "multi_model_query": multi_args.get("query", "") if isinstance(multi_args, dict) else "",
        "spl_shape_match": _normalize_spl(pipeline_query) == _normalize_spl(case.canonical_spl),
        "multi_spl_shape_match": multi_shape_match if include_multi_model else None,
        "policy_ok": policy_ok,
        "policy_reason": policy_reason,
        "offline": offline,
        "live_evidence": "non_empty_reference" if canonical_rows else "empty_reference_inconclusive",
    }


def _taxonomy_summary(results: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in results:
        bucket = str(row.get("failure_bucket", "unknown"))
        counts[bucket] = counts.get(bucket, 0) + 1
    return dict(sorted(counts.items()))


def main() -> int:
    parser = argparse.ArgumentParser(description="Internal index SPL accuracy harness")
    parser.add_argument("--cases", default=str(DEFAULT_CASES))
    parser.add_argument("--out-dir", default=str(DEFAULT_OUT))
    parser.add_argument("--row-limit", type=int, default=50)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--multi-model", action="store_true")
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
        "failure_taxonomy": _taxonomy_summary(results),
        "informative_case_count": sum(
            1 for row in results if row.get("live_evidence") == "non_empty_reference"
        ),
        "results": results,
    }
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    latest = out_dir / "latest.json"
    latest.write_text(json.dumps(report, indent=2), encoding="utf-8")
    history_dir = out_dir / "history"
    history_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    (history_dir / f"run_{stamp}.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({"out": str(latest), "passed": passed, "total": len(results)}, indent=2))
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
