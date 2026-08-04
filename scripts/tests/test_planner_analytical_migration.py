#!/usr/bin/env python3
"""Focused tests for observe/prefer AnalyticalPlan planner migration."""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import langgraph_multi_model_soc as mm  # noqa: E402
from question_intelligence import (  # noqa: E402
    extract_explicit_dataset_locks,
    extract_explicit_sourcetypes,
    infer_analytical_shape_hints,
    validate_query_dataset_locks,
)
from spl_plan_migration import (  # noqa: E402
    analytical_planner_mode,
    bind_analytical_plan,
    compile_bound_analytical_plan,
    normalize_analytical_plan_candidate,
    validate_planner_analytical_plan,
)


def _plan(*, index: str = "locked", sourcetype: str = "access_combined") -> dict:
    return {
        "version": "1.0",
        "datasets": [{"index": index, "sourcetype": sourcetype}],
        "normalizations": [],
        "analysis": {
            "dimensions": ["src_ip"],
            "measures": [{"name": "events", "function": "count"}],
            "post_aggregation_predicates": [],
            "ratios": [],
            "intersections": [],
            "ranking": [{"field": "events", "direction": "desc", "limit": 10}],
            "output_fields": ["src_ip", "events"],
        },
        "execution": {
            "earliest": "-24h",
            "latest": "now",
            "row_limit": 20,
            "materialization": "bounded",
        },
    }


class PlannerAnalyticalMigrationTests(unittest.TestCase):
    def test_question_hints_preserve_explicit_locks_without_output_word_filters(self) -> None:
        question = (
            "In index=locked sourcetype=access_combined show top 5 counts by client IP "
            "where status>=500 every 10 minutes"
        )
        self.assertEqual(
            extract_explicit_dataset_locks(question),
            {"indexes": ["locked"], "sourcetypes": ["access_combined"]},
        )
        hints = infer_analytical_shape_hints(question)
        self.assertEqual(hints["ranking"]["limit"], 5)
        self.assertEqual(hints["time_bin"], "10m")
        self.assertIn("src_ip", hints["dimensions"])
        self.assertEqual(hints["filters"], [{"field": "status", "operator": "gte", "value": 500}])
        self.assertFalse(any(item.get("value") in {"counts", "values"} for item in hints["filters"]))

    def test_explicit_dataset_locks_are_hard_contract_failures(self) -> None:
        question = "Analyze index=locked sourcetype=access_combined by client IP"
        status = validate_planner_analytical_plan(question, _plan(index="other"))
        self.assertFalse(status["valid"])
        self.assertTrue(
            any(error.startswith("explicit_index_lock_violation") for error in status["errors"])
        )

    def test_multi_sourcetype_locks_preserve_both_branches(self) -> None:
        question = (
            "Correlate index auth sourcetype linux_secure with index web "
            "sourcetype proxy:access by shared source."
        )
        plan = _plan(index="auth", sourcetype="linux_secure")
        plan["datasets"].append({"index": "web", "sourcetype": "proxy:access"})
        self.assertEqual(
            extract_explicit_sourcetypes(question),
            ["linux_secure", "proxy:access"],
        )
        status = validate_planner_analytical_plan(question, plan)
        self.assertTrue(status["valid"], status["errors"])
        candidate = compile_bound_analytical_plan(question, plan)
        query = candidate["tool_args"]["query"]
        self.assertIn('sourcetype="linux_secure"', query)
        self.assertIn('sourcetype="proxy:access"', query)
        self.assertEqual(validate_query_dataset_locks(question, query), (True, "dataset_locks_ok"))

        single_question = "Analyze index auth sourcetype linux_secure by source."
        self.assertFalse(
            validate_planner_analytical_plan(
                single_question,
                plan,
            )["valid"]
        )

    def test_structural_normalization_uses_plan_vocabulary(self) -> None:
        plan = _plan(index="*")
        plan["analysis"]["measures"] = [
            {"name": "events", "function": "count", "field": "_time"},
            {"name": "distinct_hosts", "function": "cardinality", "field": "host"},
            {
                "name": "failed_events",
                "function": "count",
                "condition": {"field": "state", "operator": "neq", "value": "success"},
            },
        ]
        plan["analysis"]["ratios"] = [
            {
                "name": "failure_pct",
                "numerator": "failures",
                "denominator": "all_events",
                "scale": 100,
            }
        ]
        plan["analysis"]["ranking"] = [
            {"field": "failure_rate", "direction": "descending", "limit": 500}
        ]
        plan["analysis"]["output_fields"] = [
            "src_ip",
            "events",
            "distinct_host_cardinality",
            "failure_percentage",
        ]

        normalized = normalize_analytical_plan_candidate("Analyze activity", plan)
        measures = normalized["analysis"]["measures"]
        self.assertEqual(measures[0]["function"], "count")
        self.assertNotIn("field", measures[0])
        self.assertEqual(measures[1]["function"], "dc")
        self.assertEqual(normalized["analysis"]["ratios"][0]["numerator"], "failed_events")
        self.assertEqual(normalized["analysis"]["ratios"][0]["denominator"], "events")
        self.assertEqual(normalized["analysis"]["ranking"][0]["field"], "failure_pct")
        self.assertEqual(normalized["analysis"]["ranking"][0]["direction"], "desc")
        self.assertEqual(normalized["analysis"]["ranking"][0]["limit"], 200)
        self.assertIn("distinct_hosts", normalized["analysis"]["output_fields"])
        self.assertIn("failure_pct", normalized["analysis"]["output_fields"])

    def test_repaired_plan_can_enforce_authoritative_dataset_locks(self) -> None:
        question = "Analyze index=locked sourcetype=access_combined by client IP"
        status = validate_planner_analytical_plan(
            question,
            _plan(index="wrong", sourcetype="wrong:source"),
            enforce_dataset_locks=True,
        )
        self.assertTrue(status["valid"], status["errors"])
        self.assertEqual(status["plan"]["datasets"][0]["index"], "locked")
        self.assertEqual(status["plan"]["datasets"][0]["sourcetype"], "access_combined")

    def test_unresolved_platform_wildcard_is_normalized_to_empty_scope(self) -> None:
        plan = _plan(index="*", sourcetype="")
        plan["datasets"][0]["platform"] = "*"
        normalized = normalize_analytical_plan_candidate("Analyze activity", plan)
        self.assertEqual(normalized["datasets"][0]["platform"], "")
        plan["datasets"][0]["platform"] = None
        normalized = normalize_analytical_plan_candidate("Analyze activity", plan)
        self.assertEqual(normalized["datasets"][0]["platform"], "")

    def test_explicit_question_window_overrides_model_default(self) -> None:
        plan = _plan(index="main", sourcetype="netstat")
        plan["execution"]["earliest"] = "-24h"
        plan["execution"]["latest"] = "now"

        normalized = normalize_analytical_plan_candidate(
            "For index main sourcetype netstat, show activity during the last 7 days.",
            plan,
        )

        self.assertEqual(normalized["execution"]["earliest"], "-7d")
        self.assertEqual(normalized["execution"]["latest"], "now")

    def test_unbounded_question_preserves_model_window(self) -> None:
        plan = _plan(index="main", sourcetype="netstat")
        plan["execution"]["earliest"] = "-7d"

        normalized = normalize_analytical_plan_candidate("Show activity.", plan)

        self.assertEqual(normalized["execution"]["earliest"], "-7d")

    def test_unbounded_question_replaces_legacy_model_default(self) -> None:
        plan = _plan(index="main", sourcetype="netstat")
        plan["execution"]["earliest"] = "-24h"

        normalized = normalize_analytical_plan_candidate("Show activity.", plan)

        self.assertEqual(normalized["execution"]["earliest"], "-7d")

    def test_explicit_last_24_hours_survives_typed_plan_normalization(self) -> None:
        plan = _plan(index="main", sourcetype="netstat")
        plan["execution"]["earliest"] = "-7d"

        normalized = normalize_analytical_plan_candidate(
            "Show activity during the last 24 hours.",
            plan,
        )

        self.assertEqual(normalized["execution"]["earliest"], "-24h")

    def test_structural_normalization_recovers_common_schema_aliases(self) -> None:
        plan = _plan(index="web/proxy:access", sourcetype="")
        plan["analysis"]["measures"] = [
            {"name": "events", "function": "count", "field": "src_ip"},
            {"name": "system_cardinality", "function": "cardinality", "field": ""},
            {"name": "present_events", "function": "exists", "field": "system"},
        ]
        plan["analysis"]["intersections"] = [
            {"name": "shared_values", "fields": ["system"]}
        ]
        normalized = normalize_analytical_plan_candidate("Analyze the system values", plan)
        self.assertEqual(normalized["datasets"][0]["index"], "web")
        self.assertEqual(normalized["datasets"][0]["sourcetype"], "proxy:access")
        self.assertNotIn("field", normalized["analysis"]["measures"][0])
        self.assertEqual(normalized["analysis"]["measures"][1]["function"], "dc")
        self.assertEqual(normalized["analysis"]["measures"][1]["field"], "system")
        self.assertEqual(normalized["analysis"]["measures"][2]["function"], "count")
        self.assertEqual(
            normalized["analysis"]["measures"][2]["condition"]["operator"],
            "exists",
        )
        self.assertEqual(normalized["analysis"]["intersections"], [])

    def test_intersection_aliases_bind_to_values_source_fields(self) -> None:
        plan = _plan(index="main", sourcetype="netstat")
        plan["analysis"]["measures"] = [
            {"name": "events", "function": "count"},
            {"name": "host_values", "function": "values", "field": "host"},
            {"name": "resolver_values", "function": "values", "field": "resolver"},
        ]
        plan["analysis"]["intersections"] = [
            {
                "name": "intersection_events",
                "fields": ["host_values", "resolver_values"],
            }
        ]

        normalized = normalize_analytical_plan_candidate(
            "For index main sourcetype netstat, collect host and resolver values "
            "and count events where both are present.",
            plan,
        )

        self.assertEqual(
            normalized["analysis"]["intersections"][0]["fields"],
            ["host", "resolver"],
        )
        query = compile_bound_analytical_plan(
            "For index main sourcetype netstat, collect host and resolver values "
            "and count events where both are present.",
            normalized,
        )["tool_args"]["query"]
        self.assertIn(
            "count(eval(isnotnull(host) AND isnotnull(resolver))) "
            "as intersection_events",
            query,
        )
        self.assertNotIn("isnotnull(host_values)", query)
        self.assertNotIn("isnotnull(resolver_values)", query)

    def test_intersection_unknown_fields_are_not_fuzzy_rewritten(self) -> None:
        plan = _plan(index="main", sourcetype="netstat")
        plan["analysis"]["measures"] = [
            {"name": "host_values", "function": "values", "field": "host"},
            {"name": "resolver_values", "function": "values", "field": "resolver"},
        ]
        plan["analysis"]["intersections"] = [
            {"name": "intersection_events", "fields": ["host_value_set", "resolver"]}
        ]

        normalized = normalize_analytical_plan_candidate("Analyze activity", plan)

        self.assertEqual(
            normalized["analysis"]["intersections"][0]["fields"],
            ["host_value_set", "resolver"],
        )

    def test_structural_normalization_recovers_polarized_comparison_conditions(self) -> None:
        plan = _plan(index="*")
        plan["analysis"]["measures"] = [
            {"name": "good_events", "function": "count"},
            {"name": "bad_events", "function": "count"},
        ]
        normalized = normalize_analytical_plan_candidate(
            "Compare good versus non-good outcomes by operation.",
            plan,
        )
        measures = normalized["analysis"]["measures"]
        self.assertEqual(
            measures[0]["condition"],
            {"field": "outcome", "operator": "eq", "value": "success"},
        )
        self.assertEqual(
            measures[1]["condition"],
            {"field": "outcome", "operator": "neq", "value": "success"},
        )

    def test_environment_and_trusted_field_binding_precede_compilation(self) -> None:
        plan = _plan(index="*")
        candidate = compile_bound_analytical_plan(
            "Show requests by client IP",
            plan,
            intent="unknown_composition",
            field_bind={"index_expr": "index=linux", "sourcetype": "access_combined"},
            field_strategy={
                "roles": {
                    "src_ip": {
                        "trusted_fields": ["clientip", "src"],
                        "classification": "alias_coalesce",
                    }
                },
                "raw_parse_required": False,
            },
        )
        query = candidate["tool_args"]["query"]
        self.assertIn('index="linux"', query)
        self.assertIn('sourcetype="access_combined"', query)
        self.assertIn("eval src_ip=coalesce(clientip,src)", query)
        self.assertEqual(candidate["source"], "analytical_plan_compiler")

    def test_profile_binding_does_not_cross_host_and_destination_roles(self) -> None:
        plan = _plan(index="main", sourcetype="netstat")
        plan["analysis"]["dimensions"] = ["src_ip", "host"]
        plan["analysis"]["measures"] = [
            {"name": "host_values", "function": "values", "field": "host"},
            {"name": "dest_values", "function": "values", "field": "dest"},
        ]
        plan["analysis"]["intersections"] = [
            {"name": "intersection_events", "fields": ["host", "dest"]}
        ]

        bound = bind_analytical_plan(
            "For index main sourcetype netstat, group by src and collect host and dest.",
            plan,
            field_bind={
                "profile_native_fields": ["src", "host", "dest"],
                "sourcetype": "netstat",
                "index_expr": "index=main",
            },
        )
        normalizations = {
            item.output: item.fields for item in bound.normalizations
        }

        self.assertEqual(normalizations["host"], ["host"])
        self.assertEqual(normalizations["dest"], ["dest"])
        self.assertNotIn(["host", "dest"], normalizations.values())

    def test_invalid_plan_gets_exactly_one_structured_repair(self) -> None:
        question = "Analyze index=locked sourcetype=access_combined by client IP"
        normalized = {
            "selected_tool": "splunk_run_query",
            "intent": "unknown",
            "analytical_plan": _plan(index="wrong"),
        }
        with patch.object(mm, "_call_ollama_json", return_value={"analytical_plan": _plan()}) as repair:
            output = mm._process_planner_analytical_plan(
                question,
                normalized,
                planner_model="planner-test",
            )
        repair.assert_called_once()
        self.assertTrue(output["analytical_plan_status"]["valid"])
        self.assertTrue(output["analytical_plan_status"]["repair_attempted"])
        self.assertTrue(output["analytical_plan_status"]["repair_succeeded"])
        self.assertEqual(output["analytical_plan"]["datasets"][0]["index"], "locked")

    def test_missing_plan_gets_exactly_one_structured_repair(self) -> None:
        question = "Analyze index=locked sourcetype=access_combined by client IP"
        normalized = {
            "selected_tool": "splunk_run_query",
            "intent": "unknown",
        }
        with patch.object(
            mm,
            "_call_ollama_json",
            return_value={"analytical_plan": _plan()},
        ) as repair:
            output = mm._process_planner_analytical_plan(
                question,
                normalized,
                planner_model="planner-test",
            )
        repair.assert_called_once()
        self.assertTrue(output["analytical_plan_status"]["repair_attempted"])
        self.assertTrue(output["analytical_plan_status"]["repair_succeeded"])
        self.assertEqual(output["analytical_plan"]["datasets"][0]["index"], "locked")

    def test_observe_keeps_legacy_path_and_prefer_selects_valid_compiled_plan(self) -> None:
        state = {
            "question": "Show requests by client IP",
            "planner_output": {
                "intent": "apache_access_top_ips",
                "confidence": 0.9,
                "analytical_plan": _plan(index="linux"),
                "analytical_plan_status": {"valid": True, "errors": []},
            },
            "field_bind_output": {"index_expr": "index=linux", "sourcetype": "access_combined"},
            "field_strategy_output": {},
        }
        with (
            patch.dict(os.environ, {"AGTSMITH_ANALYTICAL_PLANNER_MODE": "observe"}),
            patch.object(mm, "validate_query_args", return_value=(True, "ok")),
            patch.object(mm, "validate_query_against_environment", return_value=(True, "ok")),
        ):
            candidate, diagnostics = mm._preferred_analytical_candidate(state)
            self.assertIsNone(candidate)
            self.assertEqual(diagnostics["fallback_reason"], "observe_mode_legacy_execution")
            self.assertTrue(diagnostics["observed"])
            self.assertTrue(diagnostics["semantic_coverage"]["passed"])
            self.assertEqual(analytical_planner_mode(), "observe")

        with (
            patch.dict(os.environ, {"AGTSMITH_ANALYTICAL_PLANNER_MODE": "prefer"}),
            patch.object(mm, "validate_query_args", return_value=(True, "ok")),
            patch.object(mm, "validate_query_against_environment", return_value=(True, "ok")),
        ):
            candidate, diagnostics = mm._preferred_analytical_candidate(state)
        self.assertIsNotNone(candidate)
        self.assertTrue(diagnostics["selected"])
        self.assertEqual(candidate["source"], "analytical_plan_compiler")

        with patch.dict(os.environ, {"AGTSMITH_ANALYTICAL_PLANNER_MODE": "enforce"}):
            self.assertEqual(analytical_planner_mode(), "enforce")

    def test_prefer_compiled_candidate_bypasses_legacy_spl_reviewers(self) -> None:
        state = {
            "question": "Show requests by client IP",
            "planner_output": {
                "analytical_plan_execution": {"mode": "prefer", "selected": True},
            },
            "writer_output": {"source": "analytical_plan_compiler"},
        }
        self.assertEqual(mm.route_after_writer(state), "validate_final_plan")

    def test_prefer_falls_back_when_binding_or_environment_validation_fails(self) -> None:
        state = {
            "question": "Show requests by client IP",
            "planner_output": {
                "intent": "apache_access_top_ips",
                "analytical_plan": _plan(index="linux"),
                "analytical_plan_status": {"valid": True, "errors": []},
            },
            "field_bind_output": {},
            "field_strategy_output": {},
        }
        with (
            patch.dict(os.environ, {"AGTSMITH_ANALYTICAL_PLANNER_MODE": "prefer"}),
            patch.object(mm, "validate_query_args", return_value=(True, "ok")),
            patch.object(mm, "validate_query_against_environment", return_value=(False, "unknown_index")),
        ):
            candidate, diagnostics = mm._preferred_analytical_candidate(state)
        self.assertIsNone(candidate)
        self.assertEqual(
            diagnostics["fallback_reason"],
            "analytical_plan_bind_or_compile_failed",
        )

    def test_failed_preferred_candidate_uses_legacy_fallback_not_raw_spl_repair(self) -> None:
        state = {
            "supported": True,
            "question": "Show failed Splunk logins today.",
            "planner_output": {
                "analytical_plan_execution": {"mode": "prefer", "selected": True},
            },
            "writer_output": {
                "selected_tool": "splunk_run_query",
                "intent": "internal_auth_failures",
                "source": "analytical_plan_compiler",
                "tool_args": {
                    "query": "search index=_audit | stats count",
                    "earliest_time": "@d",
                    "latest_time": "now",
                    "row_limit": 10,
                },
            },
        }
        with (
            patch.object(
                mm,
                "validate_query_args",
                side_effect=[(False, "forced_typed_failure"), (True, "ok")],
            ),
            patch.object(mm, "validate_query_for_intent", return_value=(True, "ok")),
            patch.object(mm, "validate_platform_sourcetype_coherence", return_value=(True, "ok")),
            patch.object(mm, "validate_intent_platform_scope", return_value=(True, "ok")),
            patch.object(mm, "normalize_query_index_aliases", side_effect=lambda query, _profile: query),
            patch.object(mm, "validate_query_against_environment", return_value=(True, "ok")),
            patch("spl_structure_validate.validate_structure", return_value=(True, "ok")),
            patch(
                "spl_domain_knowledge.validate_query_against_domain_knowledge",
                return_value=(True, "ok"),
            ),
            patch.object(mm, "attempt_query_repair_once") as raw_repair,
        ):
            output = mm.validate_final_plan_node(state)
        raw_repair.assert_not_called()
        self.assertTrue(output["validation_ok"])
        self.assertTrue(output["query_repair"]["analytical_plan_fallback_applied"])
        self.assertEqual(output["final_plan"]["source"], "fallback")

    def test_prefer_semantic_failure_gets_one_structured_plan_repair(self) -> None:
        invalid_shape = _plan(index="linux")
        invalid_shape["analysis"]["ranking"] = []
        repaired = _plan(index="linux")
        state = {
            "question": "Show top 10 requests by client IP",
            "planner_output": {
                "intent": "apache_access_top_ips",
                "confidence": 0.9,
                "analytical_plan": invalid_shape,
                "analytical_plan_status": {
                    "valid": True,
                    "errors": [],
                    "repair_attempted": False,
                    "dataset_locks": {"indexes": [], "sourcetypes": []},
                },
            },
            "field_bind_output": {"index_expr": "index=linux", "sourcetype": "access_combined"},
            "field_strategy_output": {},
        }
        with (
            patch.dict(os.environ, {"AGTSMITH_ANALYTICAL_PLANNER_MODE": "prefer"}),
            patch.object(mm, "validate_query_args", return_value=(True, "ok")),
            patch.object(mm, "validate_query_against_environment", return_value=(True, "ok")),
            patch.object(mm, "_call_ollama_json", return_value={"analytical_plan": repaired}) as repair,
        ):
            candidate, diagnostics = mm._preferred_analytical_candidate(state)
        repair.assert_called_once()
        payload = repair.call_args.kwargs["user_payload"]
        self.assertIn("semantic_repair_feedback", payload)
        self.assertNotIn("query", payload)
        self.assertTrue(diagnostics["repair_attempted"])
        self.assertTrue(diagnostics["repair_succeeded"])
        self.assertTrue(diagnostics["selected"])
        self.assertIsNotNone(candidate)
        self.assertTrue(candidate["semantic_coverage"]["passed"])

    def test_post_field_policy_semantic_gate_observes_or_blocks_by_mode(self) -> None:
        plan = _plan(index="linux")
        state = {
            "supported": True,
            "validation_ok": True,
            "validation_reason": "field_policy_valid",
            "question": "Show top 10 requests by client IP",
            "planner_output": {
                "analytical_plan": plan,
                "analytical_plan_status": {"valid": True},
            },
            "final_plan": {
                "selected_tool": "splunk_run_query",
                "intent": "apache_access_top_ips",
                "source": "analytical_plan_compiler",
                "analytical_plan": plan,
                "tool_args": {
                    "query": 'search index="linux" sourcetype="access_combined" | stats count as events',
                    "earliest_time": "-24h",
                    "latest_time": "now",
                    "row_limit": 20,
                },
            },
            "field_strategy_output": {},
        }
        with patch.dict(os.environ, {"AGTSMITH_ANALYTICAL_PLANNER_MODE": "observe"}):
            observed = mm.semantic_gate_node(state)
        self.assertTrue(observed["validation_ok"])
        self.assertFalse(observed["semantic_coverage_output"]["passed"])
        self.assertEqual(observed["semantic_coverage_output"]["decision"], "observe_only")

        with patch.dict(os.environ, {"AGTSMITH_ANALYTICAL_PLANNER_MODE": "prefer"}):
            blocked = mm.semantic_gate_node(state)
        self.assertFalse(blocked["validation_ok"])
        self.assertEqual(blocked["validation_reason"], "semantic_coverage_failed")
        self.assertFalse(
            blocked["query_repair"]["semantic_plan_repair_feedback"]["raw_spl_repair_allowed"]
        )

    def test_semantic_gate_is_wired_between_field_policy_and_execution(self) -> None:
        graph = mm.describe_multi_model_graph()
        node_ids = {item["id"] for item in graph["active"]["nodes"]}
        edges = {
            (item["from"], item["to"])
            for item in graph["active"]["edges"]
        }
        self.assertIn("semantic_gate", node_ids)
        self.assertIn("semantic_candidate_select", node_ids)
        self.assertIn(("field_policy", "semantic_gate"), edges)
        self.assertIn(("semantic_gate", "semantic_candidate_select"), edges)
        self.assertIn(("semantic_candidate_select", "run_tool"), edges)

    def test_post_execution_retries_one_ranked_candidate_after_unrelated_rows(self) -> None:
        plan = {
            "selected_tool": "splunk_run_query",
            "intent": "unknown_composition",
            "source": "analytical_plan_compiler",
            "tool_args": {
                "query": 'search index="locked" | stats count as events by src_ip',
                "earliest_time": "-24h",
                "latest_time": "now",
                "row_limit": 20,
            },
        }
        alternate = {
            **plan,
            "candidate_id": "alternate",
            "candidate_source": "structured_plan_repair",
            "live_evidence": {
                "status": "related_nonzero",
                "accepted": True,
                "rejected": False,
            },
            "semantic_coverage": {
                "passed": True,
                "spec": {"output_fields": ["src_ip", "events"]},
            },
        }
        state = {
            "supported": True,
            "validation_ok": True,
            "validation_reason": "semantic_coverage_passed",
            "question": "Show events by source IP",
            "final_plan": plan,
            "splunk_data": {
                "structured": {
                    "total_rows": 1,
                    "results": [{"unrelated": "value"}],
                }
            },
            "semantic_coverage_output": {
                "passed": True,
                "spec": {"output_fields": ["src_ip", "events"]},
            },
            "semantic_candidate_output": {
                "selected_candidate_id": "primary",
                "ranked_candidates": [alternate],
            },
            "query_budget_output": {
                "version": "1.0",
                "limit": 5,
                "used": 3,
                "remaining": 2,
                "events": [],
                "exhausted": False,
            },
            "confidence_cap": 0.95,
        }
        with (
            patch.dict(os.environ, {"AGTSMITH_ANALYTICAL_PLANNER_MODE": "prefer"}),
            patch.object(
                mm,
                "run_splunk_query_args",
                return_value={
                    "structured": {
                        "total_rows": 1,
                        "results": [{"src_ip": "192.0.2.9", "events": "7"}],
                    }
                },
            ) as retry,
        ):
            output = mm.post_execution_node(state)
        retry.assert_called_once()
        self.assertTrue(output["validation_ok"])
        self.assertEqual(output["final_plan"]["source"], "analytical_plan_compiler")
        self.assertEqual(
            output["semantic_coverage_output"]["live_evidence"]["status"],
            "related_nonzero",
        )
        self.assertTrue(
            output["semantic_coverage_output"]["post_execution_semantic_retry"]["applied"]
        )
        self.assertEqual(output["query_budget_output"]["used"], 4)

    def test_post_execution_blocks_unrelated_nonzero_without_valid_alternate(self) -> None:
        state = {
            "supported": True,
            "validation_ok": True,
            "validation_reason": "semantic_coverage_passed",
            "question": "Show events by source IP",
            "final_plan": {
                "selected_tool": "splunk_run_query",
                "intent": "unknown_composition",
                "tool_args": {
                    "query": 'search index="locked" | stats count as events by src_ip',
                    "earliest_time": "-24h",
                    "latest_time": "now",
                    "row_limit": 20,
                },
            },
            "splunk_data": {
                "structured": {
                    "total_rows": 1,
                    "results": [{"unrelated": "value"}],
                }
            },
            "semantic_coverage_output": {
                "passed": True,
                "spec": {"output_fields": ["src_ip", "events"]},
            },
            "semantic_candidate_output": {
                "selected_candidate_id": "primary",
                "ranked_candidates": [],
            },
            "query_budget_output": {
                "version": "1.0",
                "limit": 5,
                "used": 3,
                "remaining": 2,
                "events": [],
                "exhausted": False,
            },
            "confidence_cap": 0.95,
        }
        with patch.dict(os.environ, {"AGTSMITH_ANALYTICAL_PLANNER_MODE": "prefer"}):
            output = mm.post_execution_node(state)
        self.assertFalse(output["validation_ok"])
        self.assertFalse(output["supported"])
        self.assertIn("unrelated_nonzero", output["validation_reason"])
        self.assertLessEqual(output["confidence_cap"], 0.25)


if __name__ == "__main__":
    unittest.main()
