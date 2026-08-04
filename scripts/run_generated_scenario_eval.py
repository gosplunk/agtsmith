#!/usr/bin/env python3
"""Evaluate generated train/dev compositions without opening protected holdouts.

Static evaluation covers every scenario deterministically. Live evaluation runs
the selected rollout mode through the full multi-model graph and compares its
MCP result with the compiled reference plan for the same train/dev scenario.
"""

from __future__ import annotations

import argparse
import json
import multiprocessing as mp
import os
from queue import Empty
import statistics
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from query_policy import validate_query_args
from question_intelligence import validate_query_dataset_locks
from score_result_equivalence import score_result_equivalence
from spl_autonomy_manifest import build_manifest
from spl_plan_compiler import COMPILER_VERSION, compile_analytical_plan
from spl_query_schema import ANALYTICAL_PLAN_VERSION
from spl_semantic_coverage import evaluate_semantic_coverage

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SCENARIO_DIR = PROJECT_ROOT / "benchmarks" / "scenario_splits" / "generated"
DEFAULT_OUT_ROOT = PROJECT_ROOT / "artifacts" / "benchmark" / "generated_scenarios"
ALLOWED_SPLITS = {"train", "dev"}
ROLLOUT_MODES = {"observe", "prefer", "enforce"}
EVALUATOR_VERSION = "1.0"
DEFAULT_MIN_EVIDENCE_CASES = 12
DEFAULT_MIN_EVIDENCE_PLATFORMS = 3
DEFAULT_MIN_EVIDENCE_PER_PLATFORM = 2
DEFAULT_LIVE_MCP_REQUEST_TIMEOUT_SECONDS = 30.0
DEFAULT_LIVE_OLLAMA_REQUEST_TIMEOUT_SECONDS = 45.0
DEFAULT_LIVE_CASE_TIMEOUT_SECONDS = 120.0
DEFAULT_LIVE_RUN_TIMEOUT_SECONDS = 900.0
DEFAULT_LIVE_CONCURRENCY = 2
DEFAULT_REFERENCE_PREFLIGHT_CONCURRENCY = 1


def _bounded_worker(
    fn: Any,
    result_queue: Any,
) -> None:
    try:
        result_queue.put(("ok", fn()))
    except BaseException as exc:
        result_queue.put(
            (
                "error",
                type(exc).__name__,
                str(exc).replace("\r", " ").replace("\n", " ")[:500],
            )
        )


def _run_bounded(fn: Any, timeout_seconds: float) -> dict[str, Any]:
    """Run one live operation in a killable child process."""
    bounded_timeout = max(0.1, float(timeout_seconds))
    started = time.monotonic()
    context = mp.get_context("fork")
    result_queue = context.Queue(maxsize=1)
    process = context.Process(
        target=_bounded_worker,
        args=(fn, result_queue),
        daemon=True,
    )
    process.start()
    process.join(bounded_timeout)
    if process.is_alive():
        process.terminate()
        process.join(2.0)
        if process.is_alive() and hasattr(process, "kill"):
            process.kill()
            process.join(1.0)
        result_queue.close()
        return {
            "status": "timeout",
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "timeout_seconds": bounded_timeout,
        }
    try:
        payload = result_queue.get(timeout=1.0)
    except Empty:
        payload = (
            "error",
            "WorkerExit",
            f"bounded worker exited with code {process.exitcode}",
        )
    finally:
        result_queue.close()
    elapsed = round(time.monotonic() - started, 3)
    if payload[0] == "ok":
        return {
            "status": "ok",
            "value": payload[1],
            "elapsed_seconds": elapsed,
        }
    return {
        "status": "error",
        "error_type": str(payload[1]),
        "error": str(payload[2]),
        "elapsed_seconds": elapsed,
    }


def _terminate_bounded_process(process: Any) -> None:
    """Stop an isolated worker without leaving a child behind."""
    if not process.is_alive():
        process.join(0.1)
        return
    process.terminate()
    process.join(2.0)
    if process.is_alive() and hasattr(process, "kill"):
        process.kill()
        process.join(1.0)


def _run_bounded_many(
    jobs: list[tuple[str, Any]],
    *,
    timeout_seconds: float,
    max_concurrency: int = DEFAULT_LIVE_CONCURRENCY,
    run_deadline: float | None = None,
    run_started: float | None = None,
) -> dict[str, dict[str, Any]]:
    """Run isolated jobs with bounded concurrency and killable budgets.

    Each job remains in its own process, so cancellation cannot poison another
    case's module globals, MCP timeout telemetry, or Ollama client state.
    """
    bounded_timeout = max(0.1, float(timeout_seconds))
    concurrency = max(1, int(max_concurrency))
    pending = list(jobs)
    active: dict[str, dict[str, Any]] = {}
    results: dict[str, dict[str, Any]] = {}

    def deadline_result(*, scope: str, elapsed: float, budget: float) -> dict[str, Any]:
        result: dict[str, Any] = {
            "status": "timeout",
            "scope": scope,
            "elapsed_seconds": round(max(0.0, elapsed), 3),
            "timeout_seconds": round(max(0.0, budget), 3),
        }
        if run_started is not None:
            result["run_elapsed_seconds"] = round(
                max(0.0, time.monotonic() - run_started),
                3,
            )
        return result

    while pending or active:
        while pending and len(active) < concurrency:
            job_id, fn = pending.pop(0)
            now = time.monotonic()
            remaining = (
                run_deadline - now
                if run_deadline is not None
                else bounded_timeout
            )
            if remaining <= 0:
                results[job_id] = deadline_result(
                    scope="run",
                    elapsed=0.0,
                    budget=0.0,
                )
                continue
            budget = min(bounded_timeout, remaining)
            context = mp.get_context("fork")
            result_queue = context.Queue(maxsize=1)
            process = context.Process(
                target=_bounded_worker,
                args=(fn, result_queue),
                daemon=True,
            )
            started = time.monotonic()
            process.start()
            active[job_id] = {
                "process": process,
                "result_queue": result_queue,
                "started": started,
                "deadline": started + budget,
                "budget": budget,
            }

        now = time.monotonic()
        for job_id, state in list(active.items()):
            process = state["process"]
            timed_out = process.is_alive() and (
                now >= state["deadline"]
                or (run_deadline is not None and now >= run_deadline)
            )
            if process.is_alive() and not timed_out:
                continue
            if timed_out:
                _terminate_bounded_process(process)
                scope = (
                    "run"
                    if run_deadline is not None and now >= run_deadline
                    else "case"
                )
                results[job_id] = deadline_result(
                    scope=scope,
                    elapsed=now - state["started"],
                    budget=state["budget"],
                )
            else:
                process.join(0.1)
                try:
                    payload = state["result_queue"].get(timeout=1.0)
                except Empty:
                    payload = (
                        "error",
                        "WorkerExit",
                        f"bounded worker exited with code {process.exitcode}",
                    )
                elapsed = round(time.monotonic() - state["started"], 3)
                if payload[0] == "ok":
                    results[job_id] = {
                        "status": "ok",
                        "value": payload[1],
                        "elapsed_seconds": elapsed,
                    }
                else:
                    results[job_id] = {
                        "status": "error",
                        "error_type": str(payload[1]),
                        "error": str(payload[2]),
                        "elapsed_seconds": elapsed,
                    }
            state["result_queue"].close()
            del active[job_id]
        if active:
            time.sleep(0.02)
    return results


def _timeout_result(
    scenario: dict[str, Any],
    *,
    stage: str,
    scope: str,
    timeout_seconds: float,
    elapsed_seconds: float,
    run_elapsed_seconds: float | None = None,
) -> dict[str, Any]:
    """Return a failed case without inventing semantic/equivalence scores."""
    platform = str(scenario.get("domain", {}).get("platform", "unknown"))
    result = {
        "id": scenario["id"],
        "group_id": scenario["group_id"],
        "family": scenario["family"],
        "mutation": scenario["mutation"],
        "platform": platform,
        "passed": False,
        "findings": [
            f"mcp_timeout:{stage}:{scope}",
            "equivalence_not_scored:live_execution_timeout",
        ],
        "failure_class": "mcp_reliability",
        "elapsed_seconds": round(elapsed_seconds, 3),
        "timeout": {
            "timed_out": True,
            "scope": scope,
            "stage": stage,
            "case_id": str(scenario["id"]),
            "platform": platform,
            "timeout_seconds": round(timeout_seconds, 3),
            "elapsed_seconds": round(elapsed_seconds, 3),
        },
        "candidate_source": "",
        "dataset_routing_ok": False,
        "legacy_dataset_routing_ok": False,
        "semantic_coverage_passed": False,
        "semantic_coverage_score": None,
        "semantic_hard_failures": [],
        "candidate_rows": 0,
        "reference_rows": 0,
        "equivalence": {
            "evidence_available": False,
            "equivalence_score": None,
            "status": "not_scored_timeout",
        },
        "candidate_scores": [],
        "query_budget": {},
    }
    if run_elapsed_seconds is not None:
        result["timeout"]["run_elapsed_seconds"] = round(
            max(0.0, run_elapsed_seconds),
            3,
        )
    return result


def _worker_failure_result(
    scenario: dict[str, Any],
    *,
    stage: str,
    error_type: str,
    error: str,
    elapsed_seconds: float,
) -> dict[str, Any]:
    """Return a failed case when an isolated live worker exits unexpectedly."""
    result = _timeout_result(
        scenario,
        stage=stage,
        scope="worker",
        timeout_seconds=0.0,
        elapsed_seconds=elapsed_seconds,
    )
    result["findings"] = [
        f"mcp_pipeline_failure:{stage}:{error_type}",
        "equivalence_not_scored:live_worker_failure",
    ]
    result["timeout"] = {
        "timed_out": False,
        "scope": "worker",
        "stage": stage,
        "case_id": str(scenario["id"]),
        "platform": result["platform"],
        "error_type": error_type,
        "error": error,
        "elapsed_seconds": round(elapsed_seconds, 3),
    }
    result["equivalence"]["status"] = "not_scored_worker_failure"
    return result


def _load_scenarios(path: Path, split: str) -> list[dict[str, Any]]:
    if split not in ALLOWED_SPLITS:
        raise ValueError("generated_scenario_eval_allows_train_or_dev_only")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("split") != split:
        raise ValueError(f"scenario_split_mismatch:{split}")
    rows = payload.get("scenarios", [])
    if not isinstance(rows, list):
        raise ValueError("scenario_rows_required")
    scenarios = [dict(row) for row in rows if isinstance(row, dict)]
    if any(str(row.get("split", "")) != split for row in scenarios):
        raise ValueError(f"mixed_scenario_split:{split}")
    return scenarios


def _query_args(scenario: dict[str, Any], query: str) -> dict[str, Any]:
    execution = scenario["reference_plan"]["execution"]
    return {
        "query": query,
        "earliest_time": execution["earliest"],
        "latest_time": execution["latest"],
        "row_limit": execution["row_limit"],
    }


def _failure_class(findings: list[str]) -> str:
    if not findings:
        return "none"
    prefixes = (
        ("compile", "compilation"),
        ("policy", "safety"),
        ("dataset", "routing"),
        ("shadow_analytical", "semantic_coverage"),
        ("semantic", "semantic_coverage"),
        ("mcp", "mcp_reliability"),
        ("ollama", "mcp_reliability"),
        ("equivalence", "result_equivalence"),
    )
    for prefix, classification in prefixes:
        if any(finding.startswith(prefix) for finding in findings):
            return classification
    return "other"


def _static_result(scenario: dict[str, Any]) -> dict[str, Any]:
    findings: list[str] = []
    plan = scenario["reference_plan"]
    reference_spl = str(scenario["reference_spl"])
    try:
        compiled = compile_analytical_plan(plan)
    except Exception as exc:
        compiled = ""
        findings.append(f"compile_error:{type(exc).__name__}:{exc}")
    if compiled != reference_spl:
        findings.append("compile_parity_mismatch")
    args = _query_args(scenario, compiled or reference_spl)
    policy_ok, policy_reason = validate_query_args(args, question=str(scenario["question"]))
    if not policy_ok:
        findings.append(f"policy_failure:{policy_reason}")
    dataset_ok, dataset_reason = validate_query_dataset_locks(
        str(scenario["question"]),
        str(args["query"]),
    )
    if not dataset_ok:
        findings.append(f"dataset_lock_failure:{dataset_reason}")
    try:
        coverage = evaluate_semantic_coverage(
            question=str(scenario["question"]),
            analytical_plan=plan,
            query_args=args,
            safety_ok=policy_ok,
            safety_reason=policy_reason,
        )
    except Exception as exc:
        coverage = {"passed": False, "score": 0.0, "error": f"{type(exc).__name__}:{exc}"}
    if not coverage.get("passed"):
        findings.append("semantic_coverage_failure")
    return {
        "id": scenario["id"],
        "group_id": scenario["group_id"],
        "family": scenario["family"],
        "mutation": scenario["mutation"],
        "platform": scenario.get("domain", {}).get("platform", "unknown"),
        "passed": not findings,
        "findings": findings,
        "failure_class": _failure_class(findings),
        "policy_ok": policy_ok,
        "dataset_routing_ok": dataset_ok,
        "semantic_coverage_passed": bool(coverage.get("passed")),
        "semantic_coverage_score": float(
            coverage.get(
                "static_score",
                coverage.get("overall_score", coverage.get("score", 0.0)),
            )
            or 0.0
        ),
        "semantic_hard_failures": [
            str(item)
            for item in coverage.get("hard_failures", [])
            if str(item).strip()
        ],
    }


def _rows_from_output(output: dict[str, Any]) -> list[dict[str, Any]]:
    rows = output.get("spl_results_preview", [])
    return [dict(row) for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []


def _reference_rows(scenario: dict[str, Any]) -> list[dict[str, Any]]:
    from minimal_question_to_answer import run_splunk_query_args

    payload = run_splunk_query_args(
        _query_args(scenario, str(scenario["reference_spl"])),
        intent="generated_scenario_reference",
        summary_hint="generated train/dev reference",
    )
    structured = payload.get("structured", {})
    rows = structured.get("results", []) if isinstance(structured, dict) else []
    return [dict(row) for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []


def _reference_preflight(
    scenarios: list[dict[str, Any]],
    *,
    case_timeout_seconds: float = DEFAULT_LIVE_CASE_TIMEOUT_SECONDS,
    run_deadline: float | None = None,
    max_concurrency: int = DEFAULT_LIVE_CONCURRENCY,
    run_started: float | None = None,
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, Any]]:
    rows_by_id: dict[str, list[dict[str, Any]]] = {}
    cases: list[dict[str, Any]] = []
    jobs = [
        (
            str(scenario["id"]),
            (lambda scenario=scenario: _reference_rows(scenario)),
        )
        for scenario in scenarios
    ]
    bounded_results = _run_bounded_many(
        jobs,
        timeout_seconds=case_timeout_seconds,
        max_concurrency=max_concurrency,
        run_deadline=run_deadline,
        run_started=run_started,
    )
    for scenario in scenarios:
        scenario_id = str(scenario["id"])
        rows: list[dict[str, Any]] = []
        error = ""
        failure: dict[str, Any] | None = None
        bounded = bounded_results[scenario_id]
        elapsed_seconds = float(bounded.get("elapsed_seconds", 0.0) or 0.0)
        if bounded["status"] == "ok":
            rows = bounded["value"]
        elif bounded["status"] == "timeout":
            failure = {
                "scope": str(bounded.get("scope", "case")),
                "stage": "reference_preflight",
                "timeout_seconds": float(bounded.get("timeout_seconds", 0.0) or 0.0),
            }
            error = f"mcp_timeout:reference_preflight:{failure['scope']}"
        else:
            error_type = str(bounded.get("error_type", "WorkerError"))
            if "timeout" in error_type.casefold():
                failure = {
                    "scope": "request",
                    "stage": "reference_preflight",
                    "timeout_seconds": case_timeout_seconds,
                }
                error = "mcp_timeout:reference_preflight:request"
            else:
                error = (
                    f"mcp_reference_failure:{error_type}:"
                    f"{bounded.get('error', '')}"
                )
        rows_by_id[scenario_id] = rows
        case = {
            "id": scenario_id,
            "family": str(scenario.get("family", "")),
            "mutation": str(scenario.get("mutation", "")),
            "platform": str(scenario.get("domain", {}).get("platform", "unknown")),
            "row_count": len(rows),
            "equivalence_eligible": bool(rows) and not error,
            "error": error,
            "elapsed_seconds": round(elapsed_seconds, 3),
        }
        if failure is not None:
            case["timeout"] = {
                "timed_out": True,
                "scope": failure["scope"],
                "stage": failure["stage"],
                "case_id": scenario_id,
                "platform": case["platform"],
                "timeout_seconds": failure["timeout_seconds"],
                "elapsed_seconds": case["elapsed_seconds"],
            }
            if "run_elapsed_seconds" in bounded:
                case["timeout"]["run_elapsed_seconds"] = bounded["run_elapsed_seconds"]
        cases.append(case)
    eligible = [row for row in cases if row["equivalence_eligible"]]
    platform_counts = {
        platform: sum(
            1
            for row in eligible
            if row["platform"] == platform
        )
        for platform in sorted(
            {
                row["platform"]
                for row in eligible
            }
        )
    }
    return rows_by_id, {
        "case_count": len(cases),
        "eligible_count": len(eligible),
        "structural_only_count": len(cases) - len(eligible),
        "error_count": sum(1 for row in cases if row["error"]),
        "timeout_count": sum(1 for row in cases if row.get("timeout", {}).get("timed_out")),
        "reliability_pct": _pct(
            sum(1 for row in cases if not row["error"]),
            len(cases),
        ),
        "eligible_platform_counts": platform_counts,
        "eligible_platform_count": len(platform_counts),
        "cases": cases,
    }


def _candidate_source(output: dict[str, Any]) -> str:
    candidates = output.get("semantic_candidates", {})
    if not isinstance(candidates, dict):
        return ""
    selected_id = str(candidates.get("selected_candidate_id", ""))
    for row in candidates.get("ranked_candidates", []):
        if isinstance(row, dict) and str(row.get("candidate_id", "")) == selected_id:
            return str(row.get("candidate_source", row.get("source", "")))
    return ""


def _live_result(
    scenario: dict[str, Any],
    mode: str,
    *,
    reference_rows: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    from langgraph_multi_model_soc import run_multi_model_soc
    from minimal_question_to_answer import (
        get_mcp_timeout_events,
        reset_mcp_timeout_events,
    )
    from ollama_client import get_ollama_timeout_events, reset_ollama_timeout_events

    started = time.monotonic()
    findings: list[str] = []
    output: dict[str, Any] = {}
    candidate_plan: dict[str, Any] = {}
    reset_mcp_timeout_events()
    reset_ollama_timeout_events()
    if reference_rows is None:
        reference_rows = []
        try:
            reference_rows = _reference_rows(scenario)
        except Exception as exc:
            findings.append(f"mcp_reference_failure:{type(exc).__name__}:{exc}")
    try:
        payload = run_multi_model_soc(str(scenario["question"]), write_artifact=False)
        candidate = payload.get("result", {}) if isinstance(payload, dict) else {}
        output = dict(candidate) if isinstance(candidate, dict) else {}
    except Exception as exc:
        findings.append(f"mcp_pipeline_failure:{type(exc).__name__}:{exc}")

    raw_timeout_events = [
        *get_mcp_timeout_events(),
        *get_ollama_timeout_events(),
    ]
    timeout_events = [
        {
            **event,
            "timed_out": True,
            "case_id": str(scenario["id"]),
            "platform": str(scenario.get("domain", {}).get("platform", "unknown")),
            "stage": "live_pipeline",
        }
        for event in raw_timeout_events
    ]
    for event in timeout_events:
        source = "ollama" if "model" in event else "mcp"
        target = str(event.get("model") or event.get("tool_name") or "unknown")
        findings.append(f"{source}_timeout:{target}")

    candidate_rows = _rows_from_output(output)
    query_args = output.get("query_args", {})
    query_args = dict(query_args) if isinstance(query_args, dict) else {}
    query = str(query_args.get("query", ""))
    legacy_routing_ok, legacy_routing_reason = validate_query_dataset_locks(
        str(scenario["question"]),
        query,
    )
    if not query:
        findings.append("mcp_pipeline_missing_query")

    coverage = output.get("semantic_coverage", {})
    coverage = dict(coverage) if isinstance(coverage, dict) else {}
    source = _candidate_source(output)
    planner = output.get("planner", {})
    planner_output = planner.get("output", {}) if isinstance(planner, dict) else {}
    planner_output = planner_output if isinstance(planner_output, dict) else {}
    planner_status = planner_output.get("analytical_plan_status", {})
    planner_status = planner_status if isinstance(planner_status, dict) else {}
    if mode == "observe":
        shadow = planner_output.get("analytical_plan_execution", {})
        shadow = shadow if isinstance(shadow, dict) else {}
        shadow_coverage = shadow.get("semantic_coverage", {})
        if isinstance(shadow_coverage, dict) and shadow.get("observed"):
            coverage = dict(shadow_coverage)
            source = "shadow_analytical_plan"
            observed_candidate = shadow.get("observed_candidate", {})
            observed_candidate = (
                observed_candidate
                if isinstance(observed_candidate, dict)
                else {}
            )
            observed_plan = observed_candidate.get("analytical_plan", {})
            if isinstance(observed_plan, dict):
                candidate_plan = observed_plan
            observed_args = observed_candidate.get("tool_args", {})
            observed_args = (
                dict(observed_args)
                if isinstance(observed_args, dict)
                else {}
            )
            if observed_args.get("query"):
                from minimal_question_to_answer import run_splunk_query_args

                try:
                    shadow_payload = run_splunk_query_args(
                        observed_args,
                        intent="generated_scenario_shadow_candidate",
                        summary_hint="generated train/dev shadow candidate",
                    )
                    structured = shadow_payload.get("structured", {})
                    shadow_rows = (
                        structured.get("results", [])
                        if isinstance(structured, dict)
                        else []
                    )
                    candidate_rows = [
                        dict(row)
                        for row in shadow_rows
                        if isinstance(row, dict)
                    ] if isinstance(shadow_rows, list) else []
                    query_args = observed_args
                    query = str(observed_args.get("query", ""))
                except Exception as exc:
                    findings.append(
                        f"mcp_shadow_failure:{type(exc).__name__}:{exc}"
                    )
        else:
            # Observe mode evaluates the shadow typed path itself. A healthy
            # legacy execution cannot hide a missing or invalid shadow plan.
            coverage = {}
            source = ""
            findings.append("shadow_analytical_plan_unavailable")
        shadow_hard = coverage.get("hard_failures", [])
        shadow_hard = shadow_hard if isinstance(shadow_hard, list) else []
        routing_ok = not any(str(item).startswith("dataset:") for item in shadow_hard)
        routing_reason = (
            "shadow_dataset_locks_ok"
            if routing_ok
            else next(
                str(item)
                for item in shadow_hard
                if str(item).startswith("dataset:")
            )
        )
    else:
        routing_ok, routing_reason = legacy_routing_ok, legacy_routing_reason
    if not routing_ok:
        findings.append(f"dataset_lock_failure:{routing_reason}")

    if not candidate_plan:
        for plan_source in (
            output.get("writer", {}).get("output", {})
            if isinstance(output.get("writer"), dict)
            else {},
            output.get("final_adjudication", {}),
        ):
            if not isinstance(plan_source, dict):
                continue
            raw_plan = plan_source.get("analytical_plan", {})
            if isinstance(raw_plan, dict):
                candidate_plan = raw_plan
                break

    semantic_passed = bool(coverage.get("passed"))
    if not semantic_passed:
        findings.append("semantic_coverage_failure")

    plan = scenario["reference_plan"]
    compare_fields = [
        str(field)
        for field in plan["analysis"].get("output_fields", [])
        if str(field).strip()
    ]
    entity_fields = [
        str(field)
        for field in plan["analysis"].get("dimensions", [])
        if str(field).strip()
    ]
    equivalence = score_result_equivalence(
        candidate_rows=candidate_rows,
        reference_rows=reference_rows,
        compare_fields=compare_fields,
        entity_fields=entity_fields,
        reference_plan=plan,
        candidate_plan=candidate_plan,
    )
    equivalence_evidence_available = bool(reference_rows)
    equivalence["evidence_available"] = equivalence_evidence_available
    equivalence_score = float(equivalence["equivalence_score"])
    if not equivalence_evidence_available:
        findings.append("equivalence_evidence_unavailable:both_results_empty")
    elif equivalence_score < 0.75:
        findings.append(f"equivalence_below_gate:{equivalence_score:.4f}")

    if mode == "enforce" and source in {"", "legacy", "compatibility"}:
        findings.append(f"semantic_enforce_source_invalid:{source or 'missing'}")
    return {
        "id": scenario["id"],
        "group_id": scenario["group_id"],
        "family": scenario["family"],
        "mutation": scenario["mutation"],
        "platform": scenario.get("domain", {}).get("platform", "unknown"),
        "passed": not findings,
        "findings": findings,
        "failure_class": _failure_class(findings),
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "candidate_source": source,
        "planner_plan_status": {
            "present": bool(planner_status.get("present")),
            "valid": bool(planner_status.get("valid")),
            "repair_attempted": bool(planner_status.get("repair_attempted")),
            "repair_succeeded": bool(planner_status.get("repair_succeeded")),
            "errors": [
                str(item)
                for item in planner_status.get(
                    "repair_errors",
                    planner_status.get("errors", []),
                )
                if str(item).strip()
            ],
        },
        "dataset_routing_ok": routing_ok,
        "legacy_dataset_routing_ok": legacy_routing_ok,
        "semantic_coverage_passed": semantic_passed,
        "semantic_coverage_score": float(
            coverage.get(
                "static_score",
                coverage.get("overall_score", coverage.get("score", 0.0)),
            )
            or 0.0
        ),
        "semantic_hard_failures": [
            str(item)
            for item in coverage.get("hard_failures", [])
            if str(item).strip()
        ],
        "candidate_rows": len(candidate_rows),
        "reference_rows": len(reference_rows),
        "equivalence": equivalence,
        "candidate_scores": (
            output.get("semantic_candidates", {}).get("ranked_candidates", [])
            if isinstance(output.get("semantic_candidates"), dict)
            else []
        ),
        "query_budget": output.get("query_budget", {}),
        "timeout_events": timeout_events,
    }


def _pct(numerator: int, denominator: int) -> float:
    return round(100.0 * numerator / denominator, 2) if denominator else 0.0


def _mutation_retention(results: list[dict[str, Any]]) -> float:
    mutated = [row for row in results if row.get("mutation") != "base"]
    if not mutated:
        return 100.0
    return _pct(sum(1 for row in mutated if row.get("passed")), len(mutated))


def _aggregate(
    results: list[dict[str, Any]],
    *,
    split: str,
    execution: str,
    mode: str,
    reference_preflight: dict[str, Any] | None = None,
    min_evidence_cases: int = DEFAULT_MIN_EVIDENCE_CASES,
    min_evidence_platforms: int = DEFAULT_MIN_EVIDENCE_PLATFORMS,
    min_evidence_per_platform: int = DEFAULT_MIN_EVIDENCE_PER_PLATFORM,
) -> dict[str, Any]:
    total = len(results)
    equivalence_scores = [
        float(row.get("equivalence", {}).get("equivalence_score", 0.0))
        for row in results
        if isinstance(row.get("equivalence"), dict)
        and row.get("equivalence", {}).get("evidence_available")
    ]
    equivalence_evidence_count = sum(
        1
        for row in results
        if isinstance(row.get("equivalence"), dict)
        and row.get("equivalence", {}).get("evidence_available")
    )
    platforms = sorted({str(row.get("platform", "unknown")) for row in results})
    platform_pass_rates = {
        platform: _pct(
            sum(1 for row in results if row.get("platform") == platform and row.get("passed")),
            sum(1 for row in results if row.get("platform") == platform),
        )
        for platform in platforms
    }
    summary = {
        "split": split,
        "execution": execution,
        "mode": mode,
        "case_count": total,
        "passed_count": sum(1 for row in results if row.get("passed")),
        "pass_rate_pct": _pct(sum(1 for row in results if row.get("passed")), total),
        "routing_accuracy_pct": _pct(
            sum(1 for row in results if row.get("dataset_routing_ok")),
            total,
        ),
        "semantic_coverage_pct": _pct(
            sum(1 for row in results if row.get("semantic_coverage_passed")),
            total,
        ),
        "mutation_retention_pct": _mutation_retention(results),
        "platform_pass_rates_pct": platform_pass_rates,
        "minimum_platform_pass_rate_pct": min(platform_pass_rates.values(), default=0.0),
        "equivalence_average": (
            round(statistics.mean(equivalence_scores), 4) if equivalence_scores else None
        ),
        "equivalence_evidence_count": equivalence_evidence_count,
        "equivalence_evidence_pct": _pct(equivalence_evidence_count, total),
        "failure_classes": {
            failure_class: sum(
                1 for row in results if row.get("failure_class") == failure_class
            )
            for failure_class in sorted(
                {
                    str(row.get("failure_class"))
                    for row in results
                    if row.get("failure_class") != "none"
                }
            )
        },
    }
    gates = {
        "routing_accuracy_at_least_95": summary["routing_accuracy_pct"] >= 95.0,
        "semantic_coverage_at_least_90": summary["semantic_coverage_pct"] >= 90.0,
        "mutation_retention_at_least_80": summary["mutation_retention_pct"] >= 80.0,
        "no_platform_below_60": summary["minimum_platform_pass_rate_pct"] >= 60.0,
    }
    if execution == "live":
        preflight = (
            reference_preflight
            if isinstance(reference_preflight, dict)
            else {}
        )
        platform_evidence = preflight.get("eligible_platform_counts", {})
        platform_evidence = (
            platform_evidence
            if isinstance(platform_evidence, dict)
            else {}
        )
        diverse_platforms = sum(
            1
            for count in platform_evidence.values()
            if int(count) >= max(1, min_evidence_per_platform)
        )
        summary["reference_preflight_case_count"] = int(
            preflight.get("case_count", total)
        )
        summary["reference_eligible_count"] = int(
            preflight.get("eligible_count", equivalence_evidence_count)
        )
        summary["reference_structural_only_count"] = int(
            preflight.get("structural_only_count", 0)
        )
        summary["reference_preflight_reliability_pct"] = float(
            preflight.get("reliability_pct", 100.0 if total else 0.0)
        )
        summary["evidence_platform_counts"] = platform_evidence
        summary["diverse_evidence_platform_count"] = diverse_platforms
        summary["minimum_evidence_requirements"] = {
            "cases": min_evidence_cases,
            "platforms": min_evidence_platforms,
            "per_platform": min_evidence_per_platform,
        }
        gates["equivalence_evidence_at_least_95"] = (
            summary["equivalence_evidence_pct"] >= 95.0
        )
        gates["reference_evidence_case_minimum"] = (
            summary["reference_eligible_count"] >= min_evidence_cases
        )
        gates["reference_evidence_platform_diversity"] = (
            diverse_platforms >= min_evidence_platforms
        )
        gates["reference_preflight_reliability_at_least_95"] = (
            summary["reference_preflight_reliability_pct"] >= 95.0
        )
        gates["equivalence_at_least_75"] = bool(
            summary["equivalence_evidence_count"] > 0
            and summary["equivalence_average"] is not None
            and summary["equivalence_average"] >= 0.75
        )
        gates["mcp_reliability_at_least_95"] = (
            _pct(
                sum(
                    1
                    for row in results
                    if not any(
                        str(item).startswith(("mcp_", "ollama_"))
                        for item in row.get("findings", [])
                    )
                ),
                total,
            )
            >= 95.0
        )
    summary["gates"] = gates
    summary["gate_passed"] = all(gates.values())
    return summary


def run_evaluation(
    *,
    split: str,
    execution: str,
    mode: str,
    scenario_dir: Path = DEFAULT_SCENARIO_DIR,
    out_root: Path = DEFAULT_OUT_ROOT,
    max_cases: int = 0,
    case_ids: tuple[str, ...] = (),
    reference_preflight_only: bool = False,
    min_evidence_cases: int = DEFAULT_MIN_EVIDENCE_CASES,
    min_evidence_platforms: int = DEFAULT_MIN_EVIDENCE_PLATFORMS,
    min_evidence_per_platform: int = DEFAULT_MIN_EVIDENCE_PER_PLATFORM,
    mcp_request_timeout_seconds: float = DEFAULT_LIVE_MCP_REQUEST_TIMEOUT_SECONDS,
    ollama_request_timeout_seconds: float = DEFAULT_LIVE_OLLAMA_REQUEST_TIMEOUT_SECONDS,
    case_timeout_seconds: float = DEFAULT_LIVE_CASE_TIMEOUT_SECONDS,
    run_timeout_seconds: float = DEFAULT_LIVE_RUN_TIMEOUT_SECONDS,
    live_concurrency: int = DEFAULT_LIVE_CONCURRENCY,
    reference_preflight_concurrency: int = DEFAULT_REFERENCE_PREFLIGHT_CONCURRENCY,
) -> dict[str, Any]:
    if execution not in {"static", "live"}:
        raise ValueError("execution_must_be_static_or_live")
    if mode not in ROLLOUT_MODES:
        raise ValueError(f"invalid_rollout_mode:{mode}")
    scenarios = _load_scenarios(scenario_dir / f"{split}.json", split)
    if case_ids:
        requested = set(case_ids)
        scenarios = [
            scenario
            for scenario in scenarios
            if str(scenario.get("id", "")) in requested
        ]
        missing = requested - {
            str(scenario.get("id", ""))
            for scenario in scenarios
        }
        if missing:
            raise ValueError(
                f"unknown_train_dev_case_ids:{','.join(sorted(missing))}"
            )
    if max_cases > 0:
        scenarios = scenarios[:max_cases]
    if reference_preflight_only and execution != "live":
        raise ValueError("reference_preflight_requires_live_execution")
    reference_rows_by_id: dict[str, list[dict[str, Any]]] = {}
    reference_preflight: dict[str, Any] | None = None
    live_started = time.monotonic() if execution == "live" else None
    run_deadline = (
        live_started + max(0.1, float(run_timeout_seconds))
        if live_started is not None
        else None
    )
    live_env_names = (
        "AGTSMITH_MCP_REQUEST_TIMEOUT_SEC",
        "AGTSMITH_OLLAMA_REQUEST_TIMEOUT_SEC",
    )
    previous_live_env = {name: os.environ.get(name) for name in live_env_names}
    if execution == "live":
        os.environ[live_env_names[0]] = str(max(0.1, float(mcp_request_timeout_seconds)))
        os.environ[live_env_names[1]] = str(
            max(0.1, float(ollama_request_timeout_seconds))
        )

    previous_mode = os.environ.get("AGTSMITH_ANALYTICAL_PLANNER_MODE")
    os.environ["AGTSMITH_ANALYTICAL_PLANNER_MODE"] = mode
    try:
        timeout_preflight_ids: dict[str, dict[str, Any]] = {}
        if execution == "live":
            reference_rows_by_id, reference_preflight = _reference_preflight(
                scenarios,
                case_timeout_seconds=max(0.1, float(case_timeout_seconds)),
                run_deadline=run_deadline,
                max_concurrency=max(1, int(reference_preflight_concurrency)),
                run_started=live_started,
            )
            eligible_ids = {
                str(row["id"])
                for row in reference_preflight["cases"]
                if row["equivalence_eligible"]
            }
            timeout_preflight_ids = {
                str(row["id"]): dict(row["timeout"])
                for row in reference_preflight["cases"]
                if isinstance(row.get("timeout"), dict)
                and row["timeout"].get("timed_out")
            }
            scenarios = [
                scenario
                for scenario in scenarios
                if str(scenario["id"]) in eligible_ids
                or str(scenario["id"]) in timeout_preflight_ids
            ]

        if reference_preflight_only:
            results = []
        elif execution != "live":
            results = [_static_result(scenario) for scenario in scenarios]
        else:
            live_jobs = []
            for scenario in scenarios:
                scenario_id = str(scenario["id"])
                preflight_timeout = timeout_preflight_ids.get(scenario_id)
                if preflight_timeout is not None:
                    continue
                live_jobs.append(
                    (
                        scenario_id,
                        lambda scenario=scenario, scenario_id=scenario_id: _live_result(
                            scenario,
                            mode,
                            reference_rows=reference_rows_by_id[scenario_id],
                        ),
                    )
                )
            bounded_live_results = _run_bounded_many(
                live_jobs,
                timeout_seconds=max(0.1, float(case_timeout_seconds)),
                max_concurrency=max(1, int(live_concurrency)),
                run_deadline=run_deadline,
                run_started=live_started,
            )
            results = []
            for scenario in scenarios:
                scenario_id = str(scenario["id"])
                preflight_timeout = timeout_preflight_ids.get(scenario_id)
                if preflight_timeout is not None:
                    results.append(
                        _timeout_result(
                            scenario,
                            stage=str(preflight_timeout.get("stage", "reference_preflight")),
                            scope=str(preflight_timeout.get("scope", "case")),
                            timeout_seconds=float(
                                preflight_timeout.get("timeout_seconds", 0.0) or 0.0
                            ),
                            elapsed_seconds=float(
                                preflight_timeout.get("elapsed_seconds", 0.0) or 0.0
                            ),
                            run_elapsed_seconds=(
                                float(preflight_timeout["run_elapsed_seconds"])
                                if "run_elapsed_seconds" in preflight_timeout
                                else None
                            ),
                        )
                    )
                    continue
                bounded = bounded_live_results[scenario_id]
                if bounded["status"] == "ok":
                    results.append(bounded["value"])
                elif bounded["status"] == "timeout":
                    results.append(
                        _timeout_result(
                            scenario,
                            stage="live_pipeline",
                            scope=str(bounded.get("scope", "case")),
                            timeout_seconds=float(
                                bounded.get("timeout_seconds", 0.0) or 0.0
                            ),
                            elapsed_seconds=float(
                                bounded.get("elapsed_seconds", 0.0) or 0.0
                            ),
                            run_elapsed_seconds=(
                                float(bounded["run_elapsed_seconds"])
                                if "run_elapsed_seconds" in bounded
                                else None
                            ),
                        )
                    )
                elif "timeout" in str(bounded.get("error_type", "")).casefold():
                    results.append(
                        _timeout_result(
                            scenario,
                            stage="live_pipeline",
                            scope="request",
                            timeout_seconds=float(case_timeout_seconds),
                            elapsed_seconds=float(bounded["elapsed_seconds"]),
                            run_elapsed_seconds=(
                                float(bounded["run_elapsed_seconds"])
                                if "run_elapsed_seconds" in bounded
                                else None
                            ),
                        )
                    )
                else:
                    results.append(
                        _worker_failure_result(
                            scenario,
                            stage="live_pipeline",
                            error_type=str(bounded.get("error_type", "WorkerError")),
                            error=str(bounded.get("error", "")),
                            elapsed_seconds=float(bounded.get("elapsed_seconds", 0.0)),
                        )
                    )
    finally:
        if previous_mode is None:
            os.environ.pop("AGTSMITH_ANALYTICAL_PLANNER_MODE", None)
        else:
            os.environ["AGTSMITH_ANALYTICAL_PLANNER_MODE"] = previous_mode
        for name, previous in previous_live_env.items():
            if previous is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = previous
    summary = _aggregate(
        results,
        split=split,
        execution=execution,
        mode=mode,
        reference_preflight=reference_preflight,
        min_evidence_cases=min_evidence_cases,
        min_evidence_platforms=min_evidence_platforms,
        min_evidence_per_platform=min_evidence_per_platform,
    )
    if reference_preflight_only:
        summary = {
            "split": split,
            "execution": "reference_preflight",
            "mode": mode,
            **{
                key: value
                for key, value in summary.items()
                if key.startswith("reference_")
                or key.startswith("evidence_")
                or key.startswith("diverse_")
                or key == "minimum_evidence_requirements"
            },
        }
        summary["gates"] = {
            "reference_evidence_case_minimum": (
                summary["reference_eligible_count"] >= min_evidence_cases
            ),
            "reference_evidence_platform_diversity": (
                summary["diverse_evidence_platform_count"]
                >= min_evidence_platforms
            ),
            "reference_preflight_reliability_at_least_95": (
                summary["reference_preflight_reliability_pct"] >= 95.0
            ),
        }
        summary["gate_passed"] = all(summary["gates"].values())
    manifest_profile = os.getenv("AGTSMITH_ENVIRONMENT_PROFILE_PATH")
    if manifest_profile and not Path(manifest_profile).is_absolute():
        manifest_profile = str((PROJECT_ROOT / manifest_profile).resolve())
    report = {
        "schema_version": 1,
        "evaluator_version": EVALUATOR_VERSION,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        **build_manifest(
            env_profile_path=manifest_profile,
            extra={
                "analytical_plan_version": ANALYTICAL_PLAN_VERSION,
                "compiler_version": COMPILER_VERSION,
                "rollout_mode": mode,
                "scenario_split": split,
                "live_budgets": {
                    "mcp_request_timeout_seconds": float(mcp_request_timeout_seconds),
                    "ollama_request_timeout_seconds": float(
                        ollama_request_timeout_seconds
                    ),
                    "case_timeout_seconds": float(case_timeout_seconds),
                    "run_timeout_seconds": float(run_timeout_seconds),
                    "live_concurrency": max(1, int(live_concurrency)),
                    "reference_preflight_concurrency": max(
                        1,
                        int(reference_preflight_concurrency),
                    ),
                },
            }
        ),
        "summary": summary,
        "reference_preflight": reference_preflight,
        "results": results,
    }
    output_execution = "reference_preflight" if reference_preflight_only else execution
    out_dir = out_root / output_execution / mode / split
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "latest.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    (out_dir / f"run_{stamp}.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Generated train/dev scenario evaluator")
    parser.add_argument("--split", choices=sorted(ALLOWED_SPLITS), default="dev")
    parser.add_argument("--execution", choices=("static", "live"), default="static")
    parser.add_argument("--mode", choices=sorted(ROLLOUT_MODES), default="observe")
    parser.add_argument("--scenario-dir", type=Path, default=DEFAULT_SCENARIO_DIR)
    parser.add_argument("--out-root", type=Path, default=DEFAULT_OUT_ROOT)
    parser.add_argument("--max-cases", type=int, default=0)
    parser.add_argument(
        "--reference-preflight-only",
        action="store_true",
        help="Execute deterministic references only and classify evidence eligibility",
    )
    parser.add_argument(
        "--min-evidence-cases",
        type=int,
        default=DEFAULT_MIN_EVIDENCE_CASES,
    )
    parser.add_argument(
        "--min-evidence-platforms",
        type=int,
        default=DEFAULT_MIN_EVIDENCE_PLATFORMS,
    )
    parser.add_argument(
        "--min-evidence-per-platform",
        type=int,
        default=DEFAULT_MIN_EVIDENCE_PER_PLATFORM,
    )
    parser.add_argument(
        "--case-id",
        action="append",
        default=[],
        help="Run only the named train/dev case; repeatable",
    )
    parser.add_argument(
        "--mcp-request-timeout-sec",
        type=float,
        default=DEFAULT_LIVE_MCP_REQUEST_TIMEOUT_SECONDS,
        help="Total MCP request budget, including retries, for live execution",
    )
    parser.add_argument(
        "--ollama-request-timeout-sec",
        type=float,
        default=DEFAULT_LIVE_OLLAMA_REQUEST_TIMEOUT_SECONDS,
        help="Per-request Ollama budget for live execution",
    )
    parser.add_argument(
        "--case-timeout-sec",
        type=float,
        default=DEFAULT_LIVE_CASE_TIMEOUT_SECONDS,
        help="Killable budget for one live case, including all graph stages",
    )
    parser.add_argument(
        "--run-timeout-sec",
        type=float,
        default=DEFAULT_LIVE_RUN_TIMEOUT_SECONDS,
        help="Whole live run budget, including reference preflight",
    )
    parser.add_argument(
        "--live-concurrency",
        type=int,
        default=DEFAULT_LIVE_CONCURRENCY,
        help="Maximum number of isolated live pipeline cases in flight",
    )
    parser.add_argument(
        "--reference-preflight-concurrency",
        type=int,
        default=DEFAULT_REFERENCE_PREFLIGHT_CONCURRENCY,
        help="Maximum number of deterministic reference queries in flight",
    )
    args = parser.parse_args()
    report = run_evaluation(
        split=args.split,
        execution=args.execution,
        mode=args.mode,
        scenario_dir=args.scenario_dir,
        out_root=args.out_root,
        max_cases=max(0, args.max_cases),
        case_ids=tuple(args.case_id),
        reference_preflight_only=args.reference_preflight_only,
        min_evidence_cases=max(1, args.min_evidence_cases),
        min_evidence_platforms=max(1, args.min_evidence_platforms),
        min_evidence_per_platform=max(1, args.min_evidence_per_platform),
        mcp_request_timeout_seconds=max(0.1, args.mcp_request_timeout_sec),
        ollama_request_timeout_seconds=max(0.1, args.ollama_request_timeout_sec),
        case_timeout_seconds=max(0.1, args.case_timeout_sec),
        run_timeout_seconds=max(0.1, args.run_timeout_sec),
        live_concurrency=max(1, args.live_concurrency),
        reference_preflight_concurrency=max(
            1,
            args.reference_preflight_concurrency,
        ),
    )
    print(json.dumps(report["summary"], indent=2, sort_keys=True))
    return 0 if report["summary"]["gate_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
