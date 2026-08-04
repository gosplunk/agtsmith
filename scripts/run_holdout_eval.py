#!/usr/bin/env python3
"""Reproduce or explicitly execute the protected eval21 holdout.

Baseline replay is the default. Live execution must be requested explicitly so
the holdout cannot accidentally become a prompt-tuning feedback loop.
"""

from __future__ import annotations

import argparse
import json
import statistics
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from holdout_firewall import load_split_manifest, protected_sha256
from score_result_equivalence import score_result_equivalence
from spl_autonomy_manifest import build_manifest
from spl_plan_compiler import COMPILER_VERSION
from spl_query_schema import ANALYTICAL_PLAN_VERSION

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CASES = PROJECT_ROOT / "benchmarks" / "holdout_eval21_cases.json"
DEFAULT_BASELINE = PROJECT_ROOT / "benchmarks" / "holdout_eval21_baseline.json"
DEFAULT_SPLIT_MANIFEST = PROJECT_ROOT / "benchmarks" / "scenario_splits" / "manifest.json"


def _load_object(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"expected_json_object:{path}")
    return payload


def _case_fingerprints(cases: list[dict[str, Any]]) -> list[dict[str, str]]:
    return [
        {
            "id": str(case.get("id", "")),
            "question_sha256": protected_sha256(case.get("question", "")),
            "reference_spl_sha256": protected_sha256(case.get("reference_spl", "")),
        }
        for case in cases
    ]


def reproduce_baseline(
    *,
    cases_path: Path = DEFAULT_CASES,
    baseline_path: Path = DEFAULT_BASELINE,
) -> dict[str, Any]:
    corpus = _load_object(cases_path)
    baseline = _load_object(baseline_path)
    cases = [row for row in corpus.get("cases", []) if isinstance(row, dict)]
    rows = [row for row in baseline.get("cases", []) if isinstance(row, dict)]
    case_ids = [str(row.get("id", "")) for row in cases]
    baseline_ids = [str(row.get("id", "")) for row in rows]
    if len(cases) != 21 or len(set(case_ids)) != 21:
        raise ValueError("holdout_corpus_must_contain_21_unique_cases")
    if case_ids != baseline_ids:
        raise ValueError("holdout_baseline_case_order_or_ids_changed")
    fingerprints = _case_fingerprints(cases)
    expected_fingerprints = load_split_manifest(DEFAULT_SPLIT_MANIFEST).get("case_fingerprints", {})
    actual_fingerprints = {
        row["id"]: [row["question_sha256"], row["reference_spl_sha256"]]
        for row in fingerprints
    }
    if actual_fingerprints != expected_fingerprints:
        raise ValueError("holdout_case_fingerprint_mismatch")

    scores = [int(row.get("score", 0)) for row in rows]
    counts = {
        classification: sum(1 for row in rows if row.get("classification") == classification)
        for classification in ("pass", "partial", "fail")
    }
    reproduced = {
        "average": round(statistics.mean(scores), 1),
        **counts,
    }
    expected = baseline.get("aggregate", {})
    if reproduced != expected:
        raise ValueError(f"baseline_mismatch:expected={expected}:actual={reproduced}")
    return {
        "mode": "baseline_replay",
        "reproduced": True,
        "case_count": len(cases),
        "aggregate": reproduced,
        "rubric": baseline.get("rubric", {}),
        "execution": baseline.get("execution", {}),
        "case_fingerprints": fingerprints,
    }


def _structured_rows(payload: dict[str, Any]) -> list[dict[str, Any]]:
    structured = payload.get("structured", {})
    results = structured.get("results", []) if isinstance(structured, dict) else []
    return [row for row in results if isinstance(row, dict)] if isinstance(results, list) else []


def run_live_holdout(
    *,
    cases_path: Path = DEFAULT_CASES,
) -> dict[str, Any]:
    from langgraph_multi_model_soc import run_multi_model_soc
    from minimal_question_to_answer import run_splunk_query_args

    corpus = _load_object(cases_path)
    defaults = corpus.get("default_window", {})
    cases = [row for row in corpus.get("cases", []) if isinstance(row, dict)]
    results: list[dict[str, Any]] = []
    for case in cases:
        earliest = str(case.get("earliest_time", defaults.get("earliest_time", "-7d")))
        latest = str(case.get("latest_time", defaults.get("latest_time", "now")))
        row_limit = int(case.get("row_limit", defaults.get("row_limit", 100)))
        generated_payload = run_multi_model_soc(str(case["question"]), write_artifact=False)
        generated_result = generated_payload.get("result", {}) if isinstance(generated_payload, dict) else {}
        generated_args = generated_result.get("query_args", {}) if isinstance(generated_result, dict) else {}
        generated_args = dict(generated_args) if isinstance(generated_args, dict) else {}
        generated_args.update({"earliest_time": earliest, "latest_time": latest, "row_limit": row_limit})
        reference_args = {
            "query": str(case["reference_spl"]),
            "earliest_time": earliest,
            "latest_time": latest,
            "row_limit": row_limit,
        }
        generated_live = run_splunk_query_args(
            generated_args,
            intent=str(generated_result.get("intent", "custom_query")),
        )
        reference_live = run_splunk_query_args(reference_args, intent="expert_reference")
        generated_rows = _structured_rows(generated_live)
        reference_rows = _structured_rows(reference_live)
        equivalence = score_result_equivalence(
            candidate_rows=generated_rows,
            reference_rows=reference_rows,
            compare_fields=case.get("compare_fields", []),
            entity_fields=case.get("entity_fields", []),
        )
        results.append(
            {
                "id": case["id"],
                "question_sha256": protected_sha256(case["question"]),
                "reference_spl_sha256": protected_sha256(case["reference_spl"]),
                "generated_spl_sha256": protected_sha256(generated_args.get("query", "")),
                "generated_rows": len(generated_rows),
                "reference_rows": len(reference_rows),
                "equivalence": equivalence,
            }
        )
    return {
        "mode": "live_holdout",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        **build_manifest(
            extra={
                "holdout": "eval21",
                "analytical_plan_version": ANALYTICAL_PLAN_VERSION,
                "compiler_version": COMPILER_VERSION,
            }
        ),
        "case_count": len(results),
        "equivalence_average": round(
            statistics.mean(float(row["equivalence"]["equivalence_score"]) for row in results),
            4,
        )
        if results
        else 0.0,
        "results": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Protected eval21 holdout harness")
    parser.add_argument("--cases", type=Path, default=DEFAULT_CASES)
    parser.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE)
    parser.add_argument(
        "--live",
        action="store_true",
        help="Explicitly run generation and MCP; baseline replay is the safe default",
    )
    parser.add_argument(
        "--min-equivalence",
        type=float,
        default=0.0,
        help="Fail a live release gate below this aggregate equivalence (0-1)",
    )
    parser.add_argument("--out", type=Path, help="Optional report path")
    args = parser.parse_args()
    report = (
        run_live_holdout(cases_path=args.cases)
        if args.live
        else reproduce_baseline(cases_path=args.cases, baseline_path=args.baseline)
    )
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    if args.live and float(report.get("equivalence_average", 0.0)) < args.min_equivalence:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
