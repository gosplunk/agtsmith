#!/usr/bin/env python3
"""Tests for train/dev-only rollout scenario evaluation."""

from __future__ import annotations

import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from run_generated_scenario_eval import (  # noqa: E402
    DEFAULT_SCENARIO_DIR,
    _aggregate,
    _load_scenarios,
    _run_bounded,
    _run_bounded_many,
    _static_result,
    _timeout_result,
    run_evaluation,
)
from minimal_question_to_answer import MCPRequestTimeout, _run_mcp_tool  # noqa: E402


class GeneratedScenarioEvalTests(unittest.TestCase):
    def test_bounded_worker_terminates_hung_operation(self) -> None:
        started = time.monotonic()
        result = _run_bounded(lambda: time.sleep(2.0), 0.1)
        self.assertEqual(result["status"], "timeout")
        self.assertLess(time.monotonic() - started, 1.5)

    def test_bounded_many_runs_isolated_jobs_concurrently(self) -> None:
        started = time.monotonic()
        results = _run_bounded_many(
            [
                ("one", lambda: (time.sleep(0.2), "one")[1]),
                ("two", lambda: (time.sleep(0.2), "two")[1]),
            ],
            timeout_seconds=1.0,
            max_concurrency=2,
        )
        self.assertLess(time.monotonic() - started, 0.65)
        self.assertEqual(results["one"]["status"], "ok")
        self.assertEqual(results["one"]["value"], "one")
        self.assertEqual(results["two"]["status"], "ok")
        self.assertEqual(results["two"]["value"], "two")

    def test_bounded_many_cancels_only_expired_job(self) -> None:
        results = _run_bounded_many(
            [
                ("slow", lambda: time.sleep(2.0)),
                ("fast", lambda: "fast"),
            ],
            timeout_seconds=0.1,
            max_concurrency=2,
        )
        self.assertEqual(results["slow"]["status"], "timeout")
        self.assertEqual(results["slow"]["scope"], "case")
        self.assertEqual(results["fast"]["status"], "ok")
        self.assertEqual(results["fast"]["value"], "fast")
        self.assertLess(results["slow"]["elapsed_seconds"], 0.75)

    def test_run_deadline_records_actual_wait_not_full_budget(self) -> None:
        started = time.monotonic()
        results = _run_bounded_many(
            [("not_started", lambda: "never")],
            timeout_seconds=10.0,
            max_concurrency=1,
            run_deadline=started - 0.1,
            run_started=started - 0.2,
        )
        self.assertEqual(results["not_started"]["status"], "timeout")
        self.assertEqual(results["not_started"]["scope"], "run")
        self.assertEqual(results["not_started"]["elapsed_seconds"], 0.0)
        self.assertEqual(results["not_started"]["timeout_seconds"], 0.0)
        self.assertGreaterEqual(results["not_started"]["run_elapsed_seconds"], 0.2)

    def test_timeout_result_records_context_without_scores(self) -> None:
        scenario = {
            "id": "dev-timeout",
            "group_id": "group",
            "family": "linux_auth_failures",
            "mutation": "base",
            "domain": {"platform": "linux"},
        }
        result = _timeout_result(
            scenario,
            stage="live_pipeline",
            scope="case",
            timeout_seconds=12.0,
            elapsed_seconds=12.1,
        )
        self.assertFalse(result["passed"])
        self.assertEqual(result["failure_class"], "mcp_reliability")
        self.assertEqual(result["timeout"]["case_id"], "dev-timeout")
        self.assertEqual(result["timeout"]["platform"], "linux")
        self.assertEqual(result["timeout"]["stage"], "live_pipeline")
        self.assertIsNone(result["equivalence"]["equivalence_score"])
        self.assertFalse(result["equivalence"]["evidence_available"])

    def test_mcp_retries_share_one_total_timeout_budget(self) -> None:
        with mock.patch(
            "minimal_question_to_answer.mcp_call",
            side_effect=httpx.ReadTimeout("simulated slow MCP call"),
        ) as mcp_call:
            with self.assertRaises(MCPRequestTimeout):
                _run_mcp_tool(
                    "splunk_run_query",
                    {},
                    max_attempts=3,
                    retry_backoff_seconds=0.01,
                    timeout_seconds=0.1,
                )
        self.assertLessEqual(mcp_call.call_count, 3)

    def test_live_run_records_reference_timeout_case(self) -> None:
        scenario = {
            "id": "dev-reference-timeout",
            "group_id": "group",
            "family": "linux_auth_failures",
            "mutation": "base",
            "domain": {"platform": "linux"},
        }
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch(
                "run_generated_scenario_eval._load_scenarios",
                return_value=[scenario],
            ), mock.patch(
                "run_generated_scenario_eval._reference_rows",
                side_effect=lambda _scenario: time.sleep(2.0),
            ):
                report = run_evaluation(
                    split="dev",
                    execution="live",
                    mode="observe",
                    out_root=Path(tmp),
                    case_timeout_seconds=0.1,
                    run_timeout_seconds=0.5,
                    min_evidence_cases=1,
                    min_evidence_platforms=1,
                    min_evidence_per_platform=1,
                )
        self.assertEqual(report["summary"]["case_count"], 1)
        self.assertEqual(report["summary"]["failure_classes"], {"mcp_reliability": 1})
        self.assertEqual(report["results"][0]["timeout"]["stage"], "reference_preflight")
        self.assertIsNone(report["results"][0]["equivalence"]["equivalence_score"])

    def test_protected_splits_cannot_be_loaded(self) -> None:
        with self.assertRaisesRegex(ValueError, "train_or_dev_only"):
            _load_scenarios(DEFAULT_SCENARIO_DIR / "holdout.json", "holdout")

    def test_checked_in_train_and_dev_reference_plans_pass_static_gate(self) -> None:
        for split in ("train", "dev"):
            scenarios = _load_scenarios(DEFAULT_SCENARIO_DIR / f"{split}.json", split)
            results = [_static_result(scenario) for scenario in scenarios]
            summary = _aggregate(
                results,
                split=split,
                execution="static",
                mode="observe",
            )
            with self.subTest(split=split):
                self.assertTrue(summary["gate_passed"])
                self.assertGreaterEqual(summary["routing_accuracy_pct"], 95.0)
                self.assertGreaterEqual(summary["semantic_coverage_pct"], 90.0)
                self.assertGreaterEqual(summary["mutation_retention_pct"], 80.0)

    def test_both_empty_live_results_are_not_equivalence_evidence(self) -> None:
        summary = _aggregate(
            [
                {
                    "passed": False,
                    "platform": "web",
                    "mutation": "base",
                    "dataset_routing_ok": True,
                    "semantic_coverage_passed": True,
                    "failure_class": "result_equivalence",
                    "findings": ["equivalence_evidence_unavailable:both_results_empty"],
                    "equivalence": {
                        "equivalence_score": 1.0,
                        "evidence_available": False,
                    },
                }
            ],
            split="dev",
            execution="live",
            mode="observe",
        )
        self.assertIsNone(summary["equivalence_average"])
        self.assertEqual(summary["equivalence_evidence_count"], 0)
        self.assertEqual(summary["equivalence_evidence_pct"], 0.0)
        self.assertFalse(summary["gates"]["equivalence_evidence_at_least_95"])
        self.assertFalse(summary["gates"]["equivalence_at_least_75"])
        self.assertFalse(summary["gate_passed"])


if __name__ == "__main__":
    unittest.main()
