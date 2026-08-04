#!/usr/bin/env python3
"""Classify benchmark failures and propose pending local-learning candidates."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from holdout_firewall import holdout_leak_reasons
from local_learning import BROAD_INTENTS, _candidate, _upsert_candidates, load_environment_profile
from minimal_question_to_answer import map_question_to_template, template_to_query_args

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MIN_PASS_SCORE = 85


def classify_failure(row: dict[str, Any]) -> str:
    return str(row.get("failure_class", "unknown")).strip() or "unknown"


def _template_query_for_question(question: str) -> str:
    template = map_question_to_template(question)
    args = template_to_query_args(template, question)
    return str(args.get("query", "")).strip()


def _failure_has_live_mcp_evidence(row: dict[str, Any]) -> bool:
    if bool(row.get("live_mcp_verified")):
        return True
    if bool(row.get("mcp_executed")):
        return True
    try:
        if int(row.get("rows_returned", 0)) > 0:
            return True
    except Exception:
        pass
    failure_class = classify_failure(row)
    if failure_class in {
        "intent_contract_failure",
        "query_antipattern",
        "policy_failure",
        "platform_coherence",
        "environment_failure",
        "sourcetype_coherence",
    }:
        return True
    return False


def propose_candidate_from_failure(row: dict[str, Any], *, min_pass_score: int = DEFAULT_MIN_PASS_SCORE) -> dict[str, Any] | None:
    if holdout_leak_reasons(row):
        return None
    try:
        score = int(row.get("score", 0))
    except Exception:
        score = 0
    if score >= min_pass_score:
        return None

    failure_class = classify_failure(row)
    if not _failure_has_live_mcp_evidence(row) and failure_class in {"empty_result", "field_coverage_gap", "row_count_low"}:
        return None
    intent = str(row.get("expected_intent") or row.get("actual_intent") or row.get("intent") or "").strip()
    question = str(row.get("question", "")).strip()
    query = str(row.get("query", "")).strip()
    case_id = str(row.get("id", "")).strip()
    if not intent or not question:
        return None

    env = load_environment_profile()
    env_evidence = {
        "preferred_sources": env.get("preferred_sources", []) if isinstance(env, dict) else [],
        "preferred_sourcetypes": env.get("preferred_sourcetypes", []) if isinstance(env, dict) else [],
        "available_fields": env.get("available_fields", []) if isinstance(env, dict) else [],
    }

    if failure_class in {"intent_contract_failure", "query_antipattern", "policy_failure"}:
        template_query = _template_query_for_question(question) or query
        if not template_query:
            return None
        return _candidate(
            intent=intent,
            kind="spl_pattern_asset",
            proposal={
                "query_template": template_query,
                "required_sourcetypes": [],
                "use_when": f"Benchmark failure {case_id or intent}: {failure_class}",
                "avoid_when": [f"failure_class:{failure_class}"],
            },
            reason=f"spl_improvement_loop:{failure_class}:{case_id or intent}",
            supporting_question=question,
            supporting_spl=query or template_query,
            environment_evidence=env_evidence,
        )

    if failure_class == "field_coverage_gap":
        missing = [
            item.split(":", 1)[1]
            for item in row.get("findings", [])
            if isinstance(item, str) and item.startswith("missing_result_fields:")
        ]
        fields = [part.strip() for chunk in missing for part in chunk.split(",") if part.strip()]
        if not fields:
            return None
        return _candidate(
            intent=intent,
            kind="preferred_fields",
            proposal={"preferred_fields": fields[:8]},
            reason=f"spl_improvement_loop:{failure_class}:{case_id or intent}",
            supporting_question=question,
            supporting_spl=query,
            environment_evidence=env_evidence,
        )

    if failure_class == "empty_result" and intent in BROAD_INTENTS:
        return _candidate(
            intent=intent,
            kind="post_result_pivot_hint",
            proposal={
                "cross_platform_pivot_hint": (
                    "Zero rows on a cross-platform auth intent: verify platform coverage, widen the time window, "
                    "and pivot by host or sourcetype before narrowing sources."
                )
            },
            reason=f"spl_improvement_loop:{failure_class}:{case_id or intent}",
            supporting_question=question,
            supporting_spl=query,
            environment_evidence=env_evidence,
        )

    return None


def process_benchmark_report(report_path: Path, *, min_pass_score: int = DEFAULT_MIN_PASS_SCORE) -> dict[str, Any]:
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    results = payload.get("results", [])
    if not isinstance(results, list):
        results = []

    candidates: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    holdout_rejected = 0
    for row in results:
        if not isinstance(row, dict):
            continue
        if holdout_leak_reasons(row):
            holdout_rejected += 1
            continue
        candidate = propose_candidate_from_failure(row, min_pass_score=min_pass_score)
        if not candidate:
            continue
        rec_id = str(candidate.get("id", "")).strip()
        if rec_id and rec_id in seen_ids:
            continue
        if rec_id:
            seen_ids.add(rec_id)
        candidates.append(candidate)

    upsert = _upsert_candidates(candidates) if candidates else {"created": 0, "stale_marked": 0, "total": 0}
    return {
        "source_report": str(report_path),
        "candidates_proposed": len(candidates),
        "holdout_rejected_count": holdout_rejected,
        "candidate_ids": [str(item.get("id", "")) for item in candidates],
        "upsert": upsert,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Propose pending learning candidates from benchmark failures")
    parser.add_argument(
        "--report",
        default="artifacts/benchmark/spl_hardening_benchmark_latest.json",
        help="Benchmark JSON report to analyze",
    )
    parser.add_argument("--min-pass-score", type=int, default=DEFAULT_MIN_PASS_SCORE)
    args = parser.parse_args()

    report_path = Path(args.report)
    if not report_path.is_file():
        print(f"SKIP spl-improvement-loop: report not found at {report_path}")
        return 0

    outcome = process_benchmark_report(report_path, min_pass_score=args.min_pass_score)
    print(json.dumps(outcome, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
