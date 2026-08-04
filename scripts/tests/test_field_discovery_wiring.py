#!/usr/bin/env python3
"""LangGraph wiring tests for field discovery node."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from langgraph_multi_model_soc import (  # noqa: E402
    field_discovery_node,
    field_policy_node,
    field_strategy_node,
    route_after_field_policy,
    route_after_validation,
)


class FieldDiscoveryWiringTests(unittest.TestCase):
    @patch("spl_field_discovery.discover_fields_for_plan")
    @patch("spl_field_discovery.should_run_field_discovery")
    def test_node_enriches_field_bind_when_triggered(self, mock_should, mock_discover) -> None:
        mock_should.return_value = (True, "no_field_hints")
        mock_discover.return_value = {
            "discovered_fields": ["clientip", "status"],
            "coalesce_hints": {"src_ip": "clientip"},
            "role_mappings": {"src_ip": ["clientip"]},
            "source": "live_mcp",
            "field_count": 2,
            "roles_satisfied_ratio": 1.0,
            "duration_ms": 50,
        }
        state = {
            "question": "apache access",
            "planner_output": {"intent": "apache_access_top_ips"},
            "field_bind_output": {"sourcetype": "access_combined", "field_hints": []},
            "stage_logs": [],
        }
        out = field_discovery_node(state)
        bound = out.get("field_bind_output", {})
        self.assertIn("clientip", bound.get("field_hints", []))
        self.assertFalse(out.get("field_discovery_output", {}).get("skipped", True))

    @patch("spl_plan_migration.analytical_planner_mode", return_value="observe")
    @patch("spl_field_discovery.discover_fields_for_plan")
    @patch("spl_field_discovery.should_run_field_discovery")
    def test_typed_observe_skips_redundant_raw_sample_probe(
        self,
        mock_should,
        mock_discover,
        _mock_mode,
    ) -> None:
        mock_should.return_value = (True, "no_field_hints")
        mock_discover.return_value = {
            "discovered_fields": ["clientip"],
            "source": "live_mcp",
            "field_count": 1,
            "duration_ms": 10,
        }
        field_discovery_node(
            {
                "question": "apache access",
                "planner_output": {
                    "intent": "apache_access_top_ips",
                    "analytical_plan_status": {"valid": True},
                },
                "field_bind_output": {"sourcetype": "access_combined"},
                "stage_logs": [],
            }
        )
        self.assertFalse(mock_discover.call_args.kwargs["include_raw_sample"])

    @patch("spl_field_discovery.should_run_field_discovery")
    def test_node_skips_when_profile_sufficient(self, mock_should) -> None:
        mock_should.return_value = (False, "profile_sufficient")
        state = {
            "question": "apache access",
            "planner_output": {"intent": "apache_access_top_ips"},
            "field_bind_output": {"field_hints": ["clientip"], "sourcetype": "access_combined"},
            "stage_logs": [],
        }
        out = field_discovery_node(state)
        self.assertTrue(out.get("field_discovery_output", {}).get("skipped"))

    @patch("spl_field_strategy.resolve_field_strategy")
    def test_field_strategy_node_persists_provenance_output(self, mock_resolve) -> None:
        mock_resolve.return_value = {
            "trusted_fields": ["clientip", "status"],
            "domain_verifications": [{"index": "linux", "sourcetype": "access_combined"}],
            "roles": {"src_ip": {"classification": "native"}},
        }
        out = field_strategy_node(
            {
                "question": "apache access",
                "planner_output": {"intent": "apache_access_top_ips"},
                "field_bind_output": {"index_expr": "index=linux", "sourcetype": "access_combined"},
                "field_discovery_output": {},
                "stage_logs": [],
            }
        )
        self.assertEqual(out["field_strategy_output"]["trusted_fields"], ["clientip", "status"])
        self.assertIn("field_strategy_duration_ms", out)

    @patch("langgraph_multi_model_soc._validate_field_policy_plan")
    @patch("spl_field_strategy.apply_field_policy_to_plan")
    def test_field_policy_runs_after_validation_and_before_semantic_gate(
        self,
        mock_apply,
        mock_validate,
    ) -> None:
        rewritten = {
            "selected_tool": "splunk_run_query",
            "intent": "apache_access_top_ips",
            "tool_args": {
                "query": "search index=linux sourcetype=access_combined | stats count by clientip",
                "earliest_time": "-24h",
                "latest_time": "now",
                "row_limit": 20,
            },
        }
        mock_apply.return_value = (rewritten, {"changed": True, "actions": ["removed_redundant_rex"]})
        mock_validate.return_value = (True, "field_policy_valid")
        out = field_policy_node(
            {
                "supported": True,
                "validation_ok": True,
                "question": "apache access",
                "final_plan": rewritten,
                "field_strategy_output": {"trusted_fields": ["clientip"]},
                "stage_logs": [],
            }
        )
        self.assertTrue(out["validation_ok"])
        self.assertTrue(out["field_policy_output"]["changed"])
        self.assertEqual(route_after_validation({"validation_ok": True}), "field_policy")
        self.assertEqual(route_after_field_policy(out), "semantic_gate")


if __name__ == "__main__":
    unittest.main()
