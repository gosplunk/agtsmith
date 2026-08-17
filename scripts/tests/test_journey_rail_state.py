#!/usr/bin/env python3
"""Tests for honest runtime-rail journey state."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from investigation_progress import journey_rail_state_from_result


class JourneyRailStateTests(unittest.TestCase):
    def test_deterministic_mcp_short_path(self) -> None:
        state = journey_rail_state_from_result(
            {"selected_tool": "splunk_get_indexes", "intent": "top_indexes"},
            pipeline_effective="deterministic",
            spl_run_time_ms=842,
            run_wall_ms=910,
            packaging_skipped=True,
        )
        self.assertTrue(state["short_path"])
        self.assertEqual(state["writer_path_mode"], "deterministic")
        self.assertIn("writer", state["completed_nodes"])
        self.assertIn("run_tool", state["completed_nodes"])
        self.assertIn("planner", state["skipped_nodes"])
        self.assertIn("security_review", state["skipped_nodes"])
        self.assertEqual(state["timings_ms"]["run_tool"], 842)
        self.assertNotIn("security_review", state["timings_ms"])
        self.assertNotIn("planner", state["completed_nodes"])

    def test_library_graph_run_uses_stage_timings(self) -> None:
        state = journey_rail_state_from_result(
            {
                "selected_tool": "splunk_run_query",
                "review_profile": "metadata",
                "skipped_nodes": ["security_review", "peer_review", "peer_review_2", "spl_validate"],
                "node_timings_ms": {
                    "guardrail": 12,
                    "planner": 2400,
                    "writer": 3,
                    "run_tool": 680,
                    "summarize": 0,
                },
                "stage_logs": [
                    {"stage": "writer", "model": "saved_query_library", "duration_ms": 3},
                    {"stage": "execution", "duration_ms": 680},
                ],
                "query_writer_output": {"source": "saved_query_library"},
            },
            pipeline_effective="assisted",
            packaging_skipped=True,
        )
        self.assertFalse(state["short_path"])
        self.assertEqual(state["writer_path_mode"], "library")
        self.assertIn("writer", state["completed_nodes"])
        self.assertIn("run_tool", state["completed_nodes"])
        self.assertIn("security_review", state["skipped_nodes"])
        self.assertNotIn("security_review", state["timings_ms"])
        self.assertNotIn("peer_review", state["completed_nodes"])

    def test_partial_final_payload_does_not_fabricate_zero_timings(self) -> None:
        state = journey_rail_state_from_result(
            {
                "review_profile": "metadata",
                "node_timings_ms": {"planner": 250},
                "stage_logs": [{"stage": "field_bind", "duration_ms": 30}],
            },
            pipeline_effective="assisted",
            packaging_skipped=True,
        )
        self.assertEqual(state["timings_ms"]["planner"], 250)
        self.assertEqual(state["timings_ms"]["field_bind"], 30)
        self.assertNotIn("guardrail", state["timings_ms"])
        self.assertNotIn("security_review", state["timings_ms"])


if __name__ == "__main__":
    unittest.main()
