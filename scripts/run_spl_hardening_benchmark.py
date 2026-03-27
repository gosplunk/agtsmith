#!/usr/bin/env python3
"""Run an MCP-backed SPL hardening benchmark against the current environment."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from botsv3_catalog import BOTSV3_SOURCETYPES
from intent_field_contracts import validate_query_for_intent
from langgraph_multi_model_soc import planner_node, run_multi_model_soc, writer_node
from minimal_question_to_answer import map_question_to_template, run_splunk_query_args, template_to_query_args
from query_policy import validate_query_args


@dataclass(frozen=True)
class Case:
    id: str
    family: str
    question: str
    expected_intent: str
    expected_shape: str
    preferred_indexes: tuple[str, ...]
    preferred_sourcetypes: tuple[str, ...]
    required_query_terms: tuple[str, ...]
    forbidden_query_terms: tuple[str, ...]
    required_result_fields: tuple[str, ...]
    allow_zero_rows: bool
    min_rows: int
    expected_earliest_time: str
    expected_latest_time: str


def _generate_botsv3_inventory_cases() -> list[Case]:
    cases: list[Case] = []
    for sourcetype in BOTSV3_SOURCETYPES:
        slug = re.sub(r"[^a-z0-9]+", "_", sourcetype.lower()).strip("_")
        cases.append(
            Case(
                id=f"botsv3_inventory_{slug}",
                family="botsv3_named_sourcetype_overview",
                question=f"Across the full BOTSv3 dataset, show an overview of sourcetype {sourcetype} by host and source.",
                expected_intent="botsv3_named_sourcetype_overview",
                expected_shape="stats",
                preferred_indexes=("index=botsv3",),
                preferred_sourcetypes=(f"sourcetype={sourcetype}",),
                required_query_terms=("index=botsv3", f"sourcetype={sourcetype}", "stats", "host", "source"),
                forbidden_query_terms=(),
                required_result_fields=("host", "source", "sourcetype", "count"),
                allow_zero_rows=False,
                min_rows=1,
                expected_earliest_time="0",
                expected_latest_time="now",
            )
        )
    return cases


def _load_cases(path: Path) -> list[Case]:
    if path.name == "AUTO_BOTSV3_INVENTORY":
        return _generate_botsv3_inventory_cases()
    raw = json.loads(path.read_text(encoding="utf-8"))
    return [
        Case(
            id=str(row["id"]),
            family=str(row["family"]),
            question=str(row["question"]),
            expected_intent=str(row["expected_intent"]),
            expected_shape=str(row["expected_shape"]),
            preferred_indexes=tuple(row.get("preferred_indexes", [])),
            preferred_sourcetypes=tuple(row.get("preferred_sourcetypes", [])),
            required_query_terms=tuple(row.get("required_query_terms", [])),
            forbidden_query_terms=tuple(row.get("forbidden_query_terms", [])),
            required_result_fields=tuple(row.get("required_result_fields", [])),
            allow_zero_rows=bool(row.get("allow_zero_rows", False)),
            min_rows=int(row.get("min_rows", 0)),
            expected_earliest_time=str(row.get("expected_earliest_time", "")).strip(),
            expected_latest_time=str(row.get("expected_latest_time", "")).strip(),
        )
        for row in raw
    ]


def _extract_shape(query: str) -> str:
    lower = query.lower()
    if "| table " in lower:
        return "table"
    if "| timechart " in lower:
        return "timechart"
    if "earliest(_time)" in lower or "first_seen" in lower:
        return "first_seen"
    if "| stats " in lower:
        return "stats"
    return "unknown"


def _score_preferred_terms(query: str, terms: tuple[str, ...], max_points: int) -> tuple[int, list[str]]:
    if not terms:
        return max_points, []
    lower = query.lower()
    hits = [term for term in terms if term.lower() in lower]
    if not hits:
        return 0, list(terms)
    score = int((len(hits) / len(terms)) * max_points)
    missing = [term for term in terms if term not in hits]
    return score, missing


def _field_coverage(results: list[dict[str, Any]], required_fields: tuple[str, ...]) -> tuple[int, list[str]]:
    if not required_fields:
        return 10, []
    if not results:
        return 0, list(required_fields)
    top_keys = {str(key) for key in results[0].keys()}
    missing = [field for field in required_fields if field not in top_keys]
    hit_count = len(required_fields) - len(missing)
    return int((hit_count / max(1, len(required_fields))) * 10), missing


def _score_case(
    case: Case,
    *,
    actual_intent: str,
    query_args: dict[str, Any],
    policy_ok: bool,
    policy_reason: str,
    structured: dict[str, Any] | None,
    error: str,
) -> dict[str, Any]:
    query = str(query_args.get("query", "")).strip()
    lower = query.lower()
    findings: list[str] = []
    score = 0
    contract_ok, contract_reason = validate_query_for_intent(actual_intent, query_args)
    actual_earliest = str(query_args.get("earliest_time", "")).strip()
    actual_latest = str(query_args.get("latest_time", "")).strip()

    if actual_intent == case.expected_intent:
        score += 20
    else:
        findings.append(f"intent_mismatch:{actual_intent}->{case.expected_intent}")

    if policy_ok:
        score += 15
    else:
        findings.append(f"policy_fail:{policy_reason}")

    required_hits = sum(1 for term in case.required_query_terms if term.lower() in lower)
    if case.required_query_terms:
        score += int((required_hits / len(case.required_query_terms)) * 20)
        if required_hits < len(case.required_query_terms):
            findings.append(f"required_query_terms:{required_hits}/{len(case.required_query_terms)}")
    else:
        score += 20

    forbidden_present = [term for term in case.forbidden_query_terms if term.lower() in lower]
    if forbidden_present:
        findings.append("forbidden_terms_present:" + ",".join(forbidden_present))
    else:
        score += 10

    index_score, missing_indexes = _score_preferred_terms(query, case.preferred_indexes, 5)
    sourcetype_score, missing_sourcetypes = _score_preferred_terms(query, case.preferred_sourcetypes, 5)
    score += index_score + sourcetype_score
    if missing_indexes:
        findings.append("preferred_indexes_missing:" + ",".join(missing_indexes))
    if missing_sourcetypes:
        findings.append("preferred_sourcetypes_missing:" + ",".join(missing_sourcetypes))

    actual_shape = _extract_shape(query)
    if actual_shape == case.expected_shape:
        score += 10
    else:
        findings.append(f"shape_mismatch:{actual_shape}->{case.expected_shape}")

    if contract_ok:
        score += 5
    else:
        findings.append(f"intent_contract_fail:{contract_reason}")

    if case.expected_earliest_time:
        if actual_earliest == case.expected_earliest_time:
            score += 5
        else:
            findings.append(f"time_mismatch_earliest:{actual_earliest}->{case.expected_earliest_time}")
    if case.expected_latest_time:
        if actual_latest == case.expected_latest_time:
            score += 5
        else:
            findings.append(f"time_mismatch_latest:{actual_latest}->{case.expected_latest_time}")

    results: list[dict[str, Any]] = []
    total_rows = 0
    if structured and isinstance(structured, dict):
        maybe_results = structured.get("results", [])
        if isinstance(maybe_results, list):
            results = [row for row in maybe_results if isinstance(row, dict)]
        total_rows = int(structured.get("total_rows", len(results)) or 0)

    if error:
        findings.append(f"execution_error:{error}")
    else:
        if total_rows >= case.min_rows:
            score += 15
        elif case.allow_zero_rows and total_rows == 0:
            score += 8
            findings.append("zero_rows_allowed")
        else:
            findings.append(f"row_count_below_expectation:{total_rows}<{case.min_rows}")

        if total_rows > 0:
            field_score, missing_fields = _field_coverage(results, case.required_result_fields)
            score += field_score
            if missing_fields:
                findings.append("missing_result_fields:" + ",".join(missing_fields))
        else:
            score += 10 if case.allow_zero_rows else 0
            if not case.allow_zero_rows:
                score = min(score, 79)

    failure_class = "pass"
    if error:
        failure_class = "execution_error"
    elif not policy_ok:
        failure_class = "policy_failure"
    elif not contract_ok:
        failure_class = "intent_contract_failure"
    elif actual_intent != case.expected_intent:
        failure_class = "intent_mismatch"
    elif forbidden_present:
        failure_class = "query_antipattern"
    elif total_rows == 0 and not case.allow_zero_rows:
        failure_class = "empty_result"
    elif any(item.startswith("missing_result_fields:") for item in findings):
        failure_class = "field_coverage_gap"
    elif actual_shape != case.expected_shape:
        failure_class = "shape_mismatch"
    elif any(item.startswith("time_mismatch_") for item in findings):
        failure_class = "time_window_mismatch"

    return {
        "score": max(0, min(100, score)),
        "query_shape": actual_shape,
        "rows_returned": total_rows,
        "results_preview": results[:3],
        "findings": findings,
        "failure_class": failure_class,
        "intent_contract_ok": contract_ok,
        "intent_contract_reason": contract_reason,
    }


def _build_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# SPL Hardening Benchmark",
        "",
        f"- Timestamp (UTC): `{report['timestamp_utc']}`",
        f"- Cases: `{report['case_count']}`",
        f"- Average score: `{report['summary']['avg_score']}`",
        f"- Pass rate (>=85): `{report['summary']['pass_rate_pct']}%`",
        f"- Failures (<85): `{report['summary']['failing_case_count']}`",
        "",
        "## Family Scores",
    ]
    for family, data in report["summary"]["family_scores"].items():
        lines.append(f"- family=`{family}` avg_score=`{data['avg_score']}` cases=`{data['case_count']}`")
    lines.append("")
    lines.append("## Failure Classes")
    for failure_class, count in report["summary"]["failure_classes"].items():
        lines.append(f"- `{failure_class}`: `{count}`")
    lines.append("")
    if report["summary"].get("comparison"):
        cmp = report["summary"]["comparison"]
        lines.append("## Comparison To Previous Run")
        lines.append(f"- previous_avg_score: `{cmp['previous_avg_score']}`")
        lines.append(f"- current_avg_score: `{cmp['current_avg_score']}`")
        lines.append(f"- avg_score_delta: `{cmp['avg_score_delta']}`")
        lines.append(f"- previous_pass_rate_pct: `{cmp['previous_pass_rate_pct']}`")
        lines.append(f"- current_pass_rate_pct: `{cmp['current_pass_rate_pct']}`")
        lines.append(f"- pass_rate_delta_pct: `{cmp['pass_rate_delta_pct']}`")
        if cmp.get("changed_cases"):
            lines.append("- changed_cases:")
            for case in cmp["changed_cases"]:
                lines.append(
                    f"  - `{case['id']}` old=`{case['previous_score']}` new=`{case['current_score']}` delta=`{case['delta']}`"
                )
        lines.append("")

    lines.append("## Cases")
    for row in report["results"]:
        lines.append(f"### {row['id']}")
        lines.append(f"- family: `{row['family']}`")
        lines.append(f"- question: {row['question']}")
        lines.append(f"- intent: expected=`{row['expected_intent']}` actual=`{row['actual_intent']}`")
        lines.append(f"- score: `{row['score']}`")
        lines.append(f"- failure_class: `{row['failure_class']}`")
        lines.append(f"- rows_returned: `{row['rows_returned']}`")
        lines.append(f"- query_shape: `{row['query_shape']}`")
        lines.append(f"- query: `{row['query']}`")
        if row["findings"]:
            lines.append("- findings:")
            for finding in row["findings"]:
                lines.append(f"  - `{finding}`")
        lines.append("")
    return "\n".join(lines) + "\n"


def _slugify(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_") or "scope"


def _bounded_scope(prefix: str, values: list[str]) -> str:
    raw = prefix + "_" + "_".join(_slugify(value) for value in values if value.strip())
    if len(raw) <= 120:
        return raw
    digest = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:12]
    head = raw[:90].rstrip("_")
    return f"{head}_{digest}"


def main() -> int:
    parser = argparse.ArgumentParser(description="Run MCP-backed SPL hardening benchmark")
    parser.add_argument("--cases", default="benchmarks/spl_cases.json")
    parser.add_argument("--out-dir", default="artifacts/benchmark")
    parser.add_argument("--min-pass-score", type=int, default=85)
    parser.add_argument("--case-limit", type=int, default=0)
    parser.add_argument("--family", action="append", default=[], help="Restrict to one or more benchmark families")
    parser.add_argument("--case-id", action="append", default=[], help="Restrict to one or more specific case ids")
    parser.add_argument("--use-planner", action="store_true", help="Use the live planner path instead of deterministic template routing")
    parser.add_argument("--use-full-pipeline", action="store_true", help="Use the full run_multi_model_soc pipeline")
    args = parser.parse_args()

    cases = _load_cases(Path(args.cases))
    if args.family:
        allow_families = {value.strip() for value in args.family if value.strip()}
        cases = [case for case in cases if case.family in allow_families]
    if args.case_id:
        allow_ids = {value.strip() for value in args.case_id if value.strip()}
        cases = [case for case in cases if case.id in allow_ids]
    if args.case_limit > 0:
        cases = cases[: args.case_limit]
    if not cases:
        raise SystemExit("no_cases_selected")

    scope = "all"
    if args.case_id:
        scope = _bounded_scope("case", args.case_id)
    elif args.family:
        scope = _bounded_scope("family", args.family)
    elif args.case_limit > 0:
        scope = f"limit_{args.case_limit}"

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    history_dir = out_dir / "history"
    history_dir.mkdir(parents=True, exist_ok=True)
    failures_jsonl = out_dir / "spl_hardening_failures_latest.jsonl"
    failure_rows: list[str] = []
    results: list[dict[str, Any]] = []

    for idx, case in enumerate(cases, start=1):
        print(f"[benchmark] {idx}/{len(cases)} case={case.id}")
        if args.use_full_pipeline:
            payload = run_multi_model_soc(case.question, write_artifact=False)
            result = payload.get("result", {}) if isinstance(payload, dict) else {}
            plan = result.get("final_adjudication", {}) if isinstance(result.get("final_adjudication", {}), dict) else {}
            actual_intent = str(result.get("intent", plan.get("selected_intent", ""))).strip() or "unknown"
            actual_tool = str(result.get("selected_tool", plan.get("selected_tool", ""))).strip()
            query_args = result.get("query_args", plan.get("selected_args", {}))
            if not isinstance(query_args, dict):
                query_args = {}
            if actual_tool == "splunk_get_indexes":
                query_args = {}
            summary_hint = str(result.get("search_strategy_summary", "")).strip() or "Summarize key findings and suggest a next investigative check."
            structured = {
                "results": result.get("spl_results_preview", []),
                "total_rows": result.get("rows_returned", 0),
            }
            error = ""
            validation_reason = str(result.get("validation_reason", "")).strip()
            policy_ok = validation_reason.startswith("plan_valid")
            policy_reason = str(result.get("validation_reason", ""))
            if not policy_ok:
                error = policy_reason or "validation_failed"
        elif args.use_planner:
            planner_state = planner_node({"question": case.question})
            writer_state = writer_node({"question": case.question, "planner_output": planner_state.get("planner_output", {})})
            writer_output = writer_state.get("writer_output", {}) or {}
            actual_intent = str(writer_output.get("intent", "")).strip() or "unknown"
            query_args = writer_output.get("tool_args", {}) if isinstance(writer_output.get("tool_args", {}), dict) else {}
            summary_hint = "Summarize key findings and suggest a next investigative check."
            structured: dict[str, Any] | None = None
            error = ""
            policy_ok, policy_reason = validate_query_args(query_args, question=case.question)
        else:
            template = map_question_to_template(case.question)
            actual_intent = template.intent
            query_args = template_to_query_args(template, case.question)
            summary_hint = template.summary_hint
            structured = None
            error = ""
            policy_ok, policy_reason = validate_query_args(query_args, question=case.question)

        if not args.use_full_pipeline:
            if policy_ok:
                try:
                    run = run_splunk_query_args(query_args, intent=actual_intent, summary_hint=summary_hint)
                    maybe_structured = run.get("structured", {})
                    if isinstance(maybe_structured, dict):
                        structured = maybe_structured
                except Exception as exc:
                    error = f"{type(exc).__name__}:{exc}"
            else:
                error = policy_reason

        score = _score_case(
            case,
            actual_intent=actual_intent,
            query_args=query_args,
            policy_ok=policy_ok,
            policy_reason=policy_reason,
            structured=structured,
            error=error,
        )
        row = {
            "id": case.id,
            "family": case.family,
            "question": case.question,
            "expected_intent": case.expected_intent,
            "actual_intent": actual_intent,
            "query": query_args.get("query", ""),
            "earliest_time": query_args.get("earliest_time", ""),
            "latest_time": query_args.get("latest_time", ""),
            "row_limit": query_args.get("row_limit", ""),
            "policy_ok": policy_ok,
            "policy_reason": policy_reason,
            **score,
        }
        results.append(row)
        if row["score"] < args.min_pass_score:
            failure_rows.append(json.dumps(row, ensure_ascii=True))

    scores = [int(row["score"]) for row in results]
    family_buckets: dict[str, list[int]] = defaultdict(list)
    for row in results:
        family_buckets[row["family"]].append(int(row["score"]))
    family_scores = {
        family: {"avg_score": round(statistics.mean(vals), 2), "case_count": len(vals)}
        for family, vals in sorted(family_buckets.items())
    }
    failure_classes = Counter(row["failure_class"] for row in results if row["failure_class"] != "pass")
    failing_cases = [row for row in results if row["score"] < args.min_pass_score]

    previous_report_path = out_dir / f"spl_hardening_benchmark_latest_{scope}.json"
    previous_report: dict[str, Any] | None = None
    if previous_report_path.exists():
        try:
            previous_report = json.loads(previous_report_path.read_text(encoding="utf-8"))
        except Exception:
            previous_report = None

    report = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "scope": scope,
        "case_count": len(results),
        "summary": {
            "avg_score": round(statistics.mean(scores), 2) if scores else 0.0,
            "median_score": round(statistics.median(scores), 2) if scores else 0.0,
            "min_pass_score": args.min_pass_score,
            "pass_rate_pct": round((sum(1 for score in scores if score >= args.min_pass_score) / len(scores)) * 100, 2)
            if scores
            else 0.0,
            "failing_case_count": len(failing_cases),
            "family_scores": family_scores,
            "failure_classes": dict(sorted(failure_classes.items())),
            "top_fix_targets": [row["id"] for row in sorted(failing_cases, key=lambda item: item["score"])[:5]],
        },
        "results": results,
    }

    if previous_report and isinstance(previous_report, dict):
        previous_results = {row["id"]: row for row in previous_report.get("results", []) if isinstance(row, dict) and "id" in row}
        changed_cases: list[dict[str, Any]] = []
        for row in results:
            prev = previous_results.get(row["id"])
            if not prev:
                continue
            previous_score = int(prev.get("score", 0))
            current_score = int(row["score"])
            if previous_score != current_score:
                changed_cases.append(
                    {
                        "id": row["id"],
                        "previous_score": previous_score,
                        "current_score": current_score,
                        "delta": current_score - previous_score,
                    }
                )
        report["summary"]["comparison"] = {
            "previous_avg_score": previous_report.get("summary", {}).get("avg_score", 0.0),
            "current_avg_score": report["summary"]["avg_score"],
            "avg_score_delta": round(report["summary"]["avg_score"] - float(previous_report.get("summary", {}).get("avg_score", 0.0)), 2),
            "previous_pass_rate_pct": previous_report.get("summary", {}).get("pass_rate_pct", 0.0),
            "current_pass_rate_pct": report["summary"]["pass_rate_pct"],
            "pass_rate_delta_pct": round(
                report["summary"]["pass_rate_pct"] - float(previous_report.get("summary", {}).get("pass_rate_pct", 0.0)),
                2,
            ),
            "changed_cases": sorted(changed_cases, key=lambda item: item["delta"]),
        }

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_json = out_dir / f"spl_hardening_benchmark_{stamp}.json"
    out_md = out_dir / f"spl_hardening_benchmark_{stamp}.md"
    latest_json = out_dir / "spl_hardening_benchmark_latest.json"
    latest_md = out_dir / "spl_hardening_benchmark_latest.md"
    latest_scope_json = out_dir / f"spl_hardening_benchmark_latest_{scope}.json"
    latest_scope_md = out_dir / f"spl_hardening_benchmark_latest_{scope}.md"
    history_json = history_dir / f"spl_hardening_benchmark_{stamp}.json"
    history_md = history_dir / f"spl_hardening_benchmark_{stamp}.md"

    payload = json.dumps(report, indent=2)
    out_json.write_text(payload, encoding="utf-8")
    latest_scope_json.write_text(payload, encoding="utf-8")
    if scope == "all":
        latest_json.write_text(payload, encoding="utf-8")
    history_json.write_text(payload, encoding="utf-8")
    markdown = _build_markdown(report)
    out_md.write_text(markdown, encoding="utf-8")
    latest_scope_md.write_text(markdown, encoding="utf-8")
    if scope == "all":
        latest_md.write_text(markdown, encoding="utf-8")
    history_md.write_text(markdown, encoding="utf-8")
    if scope == "all":
        failures_jsonl.write_text("\n".join(failure_rows) + ("\n" if failure_rows else ""), encoding="utf-8")

    print("=== SPL Hardening Benchmark ===")
    print(f"cases={len(results)}")
    print(f"avg_score={report['summary']['avg_score']}")
    print(f"pass_rate_pct={report['summary']['pass_rate_pct']}")
    print(f"failing_case_count={report['summary']['failing_case_count']}")
    print(f"json={out_json}")
    print(f"md={out_md}")
    print(f"latest_scope_json={latest_scope_json}")
    print(f"latest_scope_md={latest_scope_md}")
    if scope == "all":
        print(f"latest_json={latest_json}")
        print(f"latest_md={latest_md}")
    print(f"history_json={history_json}")
    print(f"history_md={history_md}")
    if scope == "all":
        print(f"failures_jsonl={failures_jsonl}")
    if report["summary"]["top_fix_targets"]:
        print("top_fix_targets=" + ",".join(report["summary"]["top_fix_targets"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
