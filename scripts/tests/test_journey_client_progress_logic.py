#!/usr/bin/env python3
"""Simulate runtime-rail journey client logic for SSE stage events."""

from __future__ import annotations

import unittest


JOURNEY = [
    "guardrail",
    "planner",
    "field_bind",
    "field_discovery",
    "field_strategy",
    "domain_knowledge",
    "writer",
    "spl_validate",
    "security_review",
    "peer_review",
    "peer_review_2",
    "validate_final_plan",
    "field_policy",
    "semantic_gate",
    "semantic_candidate_select",
    "run_tool",
    "post_execution",
    "evidence_review",
    "summarize",
    "finalize",
    "package_response",
]


class JourneyClientSimulator:
    def __init__(self) -> None:
        self.active_node = ""
        self.completed_nodes: set[str] = set()
        self.skipped_nodes: set[str] = set()
        self.stage_timings_sec: dict[str, float] = {}
        self.stage_start_at: dict[str, float] = {}
        self.now_ms = 0.0
        self.completed_through = -1

    def journey_index(self, node: str) -> int:
        try:
            return JOURNEY.index(node)
        except ValueError:
            return -1

    def finalize_active_stage_timing(self, elapsed_sec: float = 1.0) -> None:
        if not self.active_node:
            return
        self.stage_timings_sec[self.active_node] = max(
            self.stage_timings_sec.get(self.active_node, 0.0),
            elapsed_sec,
        )
        self.stage_start_at.pop(self.active_node, None)

    def apply_measured_stage_seconds(self, node: str, duration_ms: float | None) -> None:
        if not node or node in self.skipped_nodes:
            return
        measured_ms = float(duration_ms) if duration_ms is not None else float("nan")
        if measured_ms != measured_ms or measured_ms <= 0:
            return
        self.stage_timings_sec[node] = max(
            self.stage_timings_sec.get(node, 0.0),
            measured_ms / 1000.0,
        )
        self.stage_start_at.pop(node, None)

    def record_stage_complete(self, node: str, duration_ms: float | None = None) -> None:
        if not node or node in self.skipped_nodes:
            return
        measured_ms = float(duration_ms) if duration_ms is not None else float("nan")
        has_measured = measured_ms == measured_ms and measured_ms > 0
        if self.active_node == node:
            if has_measured:
                self.apply_measured_stage_seconds(node, measured_ms)
            else:
                self.finalize_active_stage_timing(elapsed_sec=2.5)
            self.active_node = ""
        elif has_measured:
            self.apply_measured_stage_seconds(node, measured_ms)
        self.completed_nodes.add(node)
        idx = self.journey_index(node)
        if idx >= 0:
            self.completed_through = max(self.completed_through, idx)

    def activate_journey_node(self, node: str) -> None:
        if not node or node in self.skipped_nodes or node in self.completed_nodes:
            return
        if self.active_node and self.active_node != node:
            self.finalize_active_stage_timing(elapsed_sec=0.5)
            self.completed_nodes.add(self.active_node)
        self.active_node = node
        self.stage_start_at[node] = self.now_ms

    def mark_skipped(self, node: str) -> None:
        if not node:
            return
        self.skipped_nodes.add(node)
        self.stage_timings_sec.pop(node, None)
        self.stage_start_at.pop(node, None)

    def handle_event(self, event: dict) -> None:
        if event.get("skipped"):
            node = str(event.get("node") or "")
            if self.active_node == node:
                self.finalize_active_stage_timing(elapsed_sec=0.1)
                self.active_node = ""
            self.mark_skipped(node)
            return
        node = str(event.get("node") or "")
        phase = str(event.get("phase") or "enter").lower()
        if phase == "complete":
            self.record_stage_complete(node, event.get("duration_ms"))
        else:
            self.activate_journey_node(node)


class JourneyClientProgressLogicTests(unittest.TestCase):
    def test_metadata_profile_advances_past_skipped_review_nodes(self) -> None:
        sim = JourneyClientSimulator()
        events = [
            {"node": "guardrail", "phase": "enter"},
            {"node": "guardrail", "phase": "complete", "duration_ms": 4},
            {"node": "planner", "phase": "enter"},
            {"node": "spl_validate", "skipped": True},
            {"node": "security_review", "skipped": True},
            {"node": "peer_review", "skipped": True},
            {"node": "peer_review_2", "skipped": True},
            {"node": "planner", "phase": "complete", "duration_ms": 160000},
            {"node": "field_bind", "phase": "enter"},
            {"node": "field_bind", "phase": "complete", "duration_ms": 35},
        ]
        for event in events:
            sim.handle_event(event)

        self.assertEqual(sim.active_node, "")
        self.assertIn("field_bind", sim.completed_nodes)
        self.assertAlmostEqual(sim.stage_timings_sec["planner"], 160.0)
        self.assertAlmostEqual(sim.stage_timings_sec["field_bind"], 0.035)
        self.assertIn("spl_validate", sim.skipped_nodes)

    def test_zero_duration_falls_back_to_wall_clock(self) -> None:
        sim = JourneyClientSimulator()
        sim.handle_event({"node": "planner", "phase": "enter"})
        sim.record_stage_complete("planner", 0)
        self.assertGreater(sim.stage_timings_sec.get("planner", 0.0), 0.0)


if __name__ == "__main__":
    unittest.main()
