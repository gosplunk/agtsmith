#!/usr/bin/env python3
"""Tests for honest investigation progress mapping."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from investigation_progress import (  # noqa: E402
    JOURNEY_UI_STEPS,
    LANE_EVIDENCE_Y,
    LANE_MERGE_X,
    LANE_META_Y,
    LANE_SEC_DROP_X,
    LANE_TOP_Y,
    MULTI_MODEL_NODE_PROGRESS,
    PLAYBOOK_EDGES,
    PLAYBOOK_FLOW_NODES,
    PLAYBOOK_LAYOUT,
    PLAYBOOK_NODE_BRANCH,
    PLAYBOOK_NODE_GAP,
    PLAYBOOK_NODE_ICONS,
    PLAYBOOK_PROCESS_W,
    PLAYBOOK_DECISION_R,
    PLAYBOOK_NODE_TIPS,
    PROFILE_DEC_WRITER_X,
    classify_review_profile,
    is_inventory_question,
    is_security_question,
    journey_completion_from_workflow,
    journey_step_index,
    journey_state_for_progress_pct,
    journey_timings_ms_from_result,
    progress_for_multi_model_node,
    progress_for_stage_log,
    requires_security_review,
    should_skip_inventory_llm_review,
    should_skip_security_review,
    skipped_nodes_for_profile,
    synthetic_stage_event_for_progress,
)


class InvestigationProgressTests(unittest.TestCase):
    def test_finalize_is_near_complete_not_mid_pipeline(self) -> None:
        finalize = progress_for_multi_model_node("finalize")
        summarize = progress_for_multi_model_node("summarize")
        run_tool = progress_for_multi_model_node("run_tool")
        self.assertGreater(finalize["pct"], summarize["pct"])
        self.assertGreater(summarize["pct"], run_tool["pct"])
        self.assertGreaterEqual(finalize["pct"], 98)

    def test_no_node_reports_fake_ninety_three_cap(self) -> None:
        pcts = [int(entry["pct"]) for entry in MULTI_MODEL_NODE_PROGRESS.values()]
        self.assertNotIn(93, pcts)
        self.assertLess(max(pcts), 100)

    def test_stage_log_execution_maps_to_splunk_retrieval(self) -> None:
        execution = progress_for_stage_log("execution")
        self.assertEqual(execution["pct"], progress_for_multi_model_node("run_tool")["pct"])
        self.assertIn("Splunk", execution["title"])

    def test_unknown_stage_falls_back_to_starting_progress(self) -> None:
        unknown = progress_for_stage_log("not_a_real_stage")
        self.assertEqual(unknown["pct"], 2)


    def test_journey_ui_steps_match_runtime_rail_order(self) -> None:
        labels = [step["label"] for step in JOURNEY_UI_STEPS]
        self.assertEqual(
            labels,
            [
                "Guardrail",
                "Planner",
                "SPL Writer",
                "Security Review",
                "Splunk Query",
                "Evidence Review",
                "Summarize",
                "Graph close",
                "Deliver",
            ],
        )

    def test_journey_step_index_maps_graph_nodes(self) -> None:
        self.assertEqual(journey_step_index("writer"), 2)
        self.assertEqual(journey_step_index("unknown"), -1)

    def test_journey_state_for_progress_pct_advances_active_node(self) -> None:
        active, completed = journey_state_for_progress_pct(30)
        self.assertEqual(active, "writer")
        self.assertEqual(completed, 1)

    def test_synthetic_stage_event_for_llm_assisted_progress(self) -> None:
        event = synthetic_stage_event_for_progress(77, label="Executing reviewed Splunk MCP query...")
        self.assertEqual(event["node"], "run_tool")
        self.assertEqual(event["progress_pct"], 77)
        self.assertEqual(event["source"], "llm_assisted")
        self.assertIn("Splunk", event["title"])

    def test_journey_completion_from_workflow_marks_all_steps(self) -> None:
        workflow = [{"stage": "planner"}, {"stage": "query_writer"}, {"stage": "summary"}]
        active, completed = journey_completion_from_workflow(workflow)
        self.assertEqual(active, JOURNEY_UI_STEPS[-1]["node"])
        self.assertEqual(completed, len(JOURNEY_UI_STEPS) - 1)

    def test_journey_state_at_finalize_marks_summarize_complete(self) -> None:
        active, completed = journey_state_for_progress_pct(98)
        self.assertEqual(active, "finalize")
        self.assertEqual(completed, journey_step_index("summarize"))

    def test_package_response_progress_is_near_complete(self) -> None:
        packaging = progress_for_multi_model_node("package_response")
        finalize = progress_for_multi_model_node("finalize")
        self.assertGreater(packaging["pct"], finalize["pct"])
        self.assertIn("MCP", packaging["label"])

    def test_journey_completion_without_workflow_stays_idle(self) -> None:
        active, completed = journey_completion_from_workflow(None)
        self.assertEqual(active, "")
        self.assertEqual(completed, -1)

    def test_journey_timings_ms_from_node_timings_rolls_up_security_review(self) -> None:
        timings = journey_timings_ms_from_result(
            {
                "node_timings_ms": {
                    "guardrail": 100,
                    "planner": 200,
                    "writer": 300,
                    "security_review": 400,
                    "peer_review_1": 500,
                    "peer_review_2": 600,
                    "validation": 50,
                    "run_tool": 700,
                    "evidence_review": 800,
                    "summarize": 900,
                }
            }
        )
        self.assertEqual(timings["security_review"], 1500)
        self.assertEqual(timings["run_tool"], 750)
        self.assertEqual(timings["summarize"], 900)

    def test_journey_timings_ms_falls_back_to_stage_logs(self) -> None:
        timings = journey_timings_ms_from_result(
            {
                "stage_logs": [
                    {"stage": "reviewer", "duration_ms": 120},
                    {"stage": "peer_review_1", "duration_ms": 80},
                    {"stage": "execution", "duration_ms": 450},
                ]
            }
        )
        self.assertEqual(timings["security_review"], 200)
        self.assertEqual(timings["run_tool"], 450)

    def test_should_skip_security_review_for_index_inventory(self) -> None:
        self.assertTrue(
            should_skip_security_review(intent="top_indexes", selected_tool="splunk_run_query")
        )
        self.assertTrue(
            should_skip_security_review(
                question="Which indexes have data in the last hour?",
                intent="unknown",
                selected_tool="splunk_run_query",
            )
        )
        self.assertTrue(
            should_skip_security_review(intent="failed_login_activity", selected_tool="splunk_get_indexes")
        )
        self.assertFalse(
            should_skip_security_review(intent="failed_login_activity", selected_tool="splunk_run_query")
        )

    def test_is_inventory_question_detects_default_index_prompt(self) -> None:
        self.assertTrue(is_inventory_question("Which indexes have data in the last hour?"))
        self.assertFalse(is_inventory_question("Show failed login activity in the last 24 hours"))

    def test_should_skip_inventory_llm_review_alias(self) -> None:
        self.assertTrue(
            should_skip_inventory_llm_review(
                question="List sourcetypes metadata for the last day",
            )
        )

    def test_journey_skipped_nodes_from_result_filters_unknown(self) -> None:
        from investigation_progress import journey_skipped_nodes_from_result

        nodes = journey_skipped_nodes_from_result(
            {"skipped_nodes": ["security_review", "not_a_step", "security_review"]}
        )
        self.assertEqual(nodes, ["security_review"])

    def test_journey_skipped_nodes_from_result_includes_packaging_when_flagged(self) -> None:
        from investigation_progress import journey_skipped_nodes_from_result

        nodes = journey_skipped_nodes_from_result({"packaging_skipped": True})
        self.assertEqual(nodes, ["package_response"])

        nodes = journey_skipped_nodes_from_result(
            {"skipped_nodes": ["security_review"], "packaging_skipped": True}
        )
        self.assertEqual(nodes, ["security_review", "package_response"])

    def test_skipped_stage_event_payload_marks_status(self) -> None:
        from investigation_progress import skipped_stage_event_payload

        event = skipped_stage_event_payload("security_review")
        self.assertTrue(event["skipped"])
        self.assertEqual(event["status"], "skipped")
        self.assertEqual(event["node"], "security_review")
        self.assertEqual(event["label"], "skipped")

    def test_classify_review_profile_metadata_from_template(self) -> None:
        self.assertEqual(
            classify_review_profile(
                "Which indexes have data?",
                template_intent="top_indexes",
                planner_intent="unknown",
            ),
            "metadata",
        )

    def test_classify_review_profile_security_from_question(self) -> None:
        self.assertEqual(
            classify_review_profile(
                "Show failed login activity in the last 24 hours",
                template_intent="unknown",
            ),
            "security",
        )

    def test_classify_review_profile_operational_default(self) -> None:
        self.assertEqual(
            classify_review_profile(
                "Show sourcetype counts for index main",
                template_intent="apache_access_top_ips",
            ),
            "operational",
        )

    def test_is_security_question_detects_failed_login(self) -> None:
        self.assertTrue(is_security_question("Show failed login activity in the last 24 hours"))
        self.assertFalse(is_security_question("Which indexes have data in the last hour?"))

    def test_skipped_nodes_for_profile(self) -> None:
        self.assertEqual(skipped_nodes_for_profile("security"), [])
        self.assertEqual(skipped_nodes_for_profile("operational"), ["security_review"])
        self.assertTrue(requires_security_review("security"))
        self.assertFalse(requires_security_review("metadata"))

    def test_playbook_flowchart_data_covers_decisions_and_profiles(self) -> None:
        flow_ids = {str(item["id"]) for item in PLAYBOOK_FLOW_NODES}
        self.assertIn("dec_guardrail", flow_ids)
        self.assertIn("dec_writer", flow_ids)
        writer_dec = next(item for item in PLAYBOOK_FLOW_NODES if item["id"] == "dec_writer")
        self.assertEqual(writer_dec.get("label"), "Profile?")
        self.assertIn("dec_security", flow_ids)
        self.assertIn("dec_validate", flow_ids)
        self.assertIn("dec_evidence", flow_ids)
        decision_nodes = [item for item in PLAYBOOK_FLOW_NODES if item.get("kind") == "decision"]
        self.assertGreaterEqual(len(decision_nodes), 5)
        for node_id in flow_ids:
            self.assertIn(node_id, PLAYBOOK_LAYOUT)
        edge_endpoints = set()
        for edge in PLAYBOOK_EDGES:
            edge_endpoints.add(edge["from"])
            edge_endpoints.add(edge["to"])
        self.assertTrue(edge_endpoints.issubset(flow_ids))
        writer_edges = [edge for edge in PLAYBOOK_EDGES if edge.get("from") == "dec_writer"]
        profiles = {tuple(edge.get("profiles", [])) for edge in writer_edges}
        self.assertIn(("operational",), profiles)
        self.assertIn(("metadata",), profiles)
        self.assertIn(("security",), profiles)

    def test_playbook_layout_is_compact_multi_lane(self) -> None:
        xs = [pos["x"] for pos in PLAYBOOK_LAYOUT.values()]
        ys = [pos["y"] for pos in PLAYBOOK_LAYOUT.values()]
        self.assertGreaterEqual(max(xs) - min(xs), 600)
        self.assertLessEqual(max(xs) - min(xs), 1100)
        self.assertLessEqual(max(ys) - min(ys), 680)
        guardrail_icon = PLAYBOOK_NODE_ICONS.get("guardrail", "")
        self.assertTrue(guardrail_icon.startswith("M"), msg="icons must be SVG path data")
        self.assertNotIn("🛡", guardrail_icon)
        self.assertIn("security_review", PLAYBOOK_NODE_ICONS)
        planner_icon = PLAYBOOK_NODE_ICONS.get("planner", "")
        self.assertIn("h-4.18", planner_icon, msg="planner should use clipboard icon")
        run_tool_icon = PLAYBOOK_NODE_ICONS.get("run_tool", "")
        self.assertIn("13.62", run_tool_icon, msg="run_tool should use terminal icon")
        labeled = [edge for edge in PLAYBOOK_EDGES if edge.get("label")]
        self.assertTrue(all("label_short" in edge for edge in labeled))
        self.assertTrue(all("label_at" in edge for edge in labeled))
        trunk_edges = [edge for edge in PLAYBOOK_EDGES if edge.get("branch") == "trunk"]
        self.assertGreaterEqual(len(trunk_edges), 6)

    def test_playbook_routing_lanes_and_single_block_label(self) -> None:
        sec_nodes = ("security_review", "dec_security", "peer_review", "peer_review_2")
        for node_id in sec_nodes:
            self.assertEqual(PLAYBOOK_LAYOUT[node_id]["x"], LANE_SEC_DROP_X)
        blocked_block_labels = [
            edge
            for edge in PLAYBOOK_EDGES
            if edge.get("branch") == "blocked" and edge.get("label_short") == "BLOCK"
        ]
        self.assertEqual(len(blocked_block_labels), 1)
        sec_edge = next(
            edge for edge in PLAYBOOK_EDGES if edge["from"] == "dec_writer" and edge["to"] == "security_review"
        )
        self.assertEqual(PLAYBOOK_LAYOUT["dec_writer"]["y"], 36)
        self.assertEqual(PLAYBOOK_LAYOUT["dec_writer"]["x"], LANE_SEC_DROP_X)
        self.assertEqual(sec_edge.get("anchor_from"), "bottom")
        self.assertEqual(sec_edge.get("anchor_to"), "top")
        meta_edge = next(
            edge
            for edge in PLAYBOOK_EDGES
            if edge["from"] == "dec_writer" and edge["to"] == "validate_final_plan"
        )
        self.assertEqual(meta_edge["waypoints"][0]["x"], PROFILE_DEC_WRITER_X)
        self.assertEqual(meta_edge["waypoints"][-1]["y"], LANE_META_Y)
        spl_merge = next(
            edge for edge in PLAYBOOK_EDGES if edge["from"] == "spl_validate" and edge["to"] == "validate_final_plan"
        )
        self.assertEqual(spl_merge["waypoints"][-2]["x"], LANE_MERGE_X)
        evidence_edges = [
            edge for edge in PLAYBOOK_EDGES if edge.get("from") == "dec_evidence" and edge.get("waypoints")
        ]
        self.assertEqual(len(evidence_edges), 3)
        self.assertEqual(evidence_edges[1]["waypoints"][0]["y"], LANE_EVIDENCE_Y)

    def test_playbook_spine_nodes_do_not_overlap(self) -> None:
        spine = [
            "ingest_question",
            "guardrail",
            "dec_guardrail",
            "planner",
            "writer",
            "dec_writer",
        ]

        def _half_width(node_id: str) -> int:
            return (
                PLAYBOOK_DECISION_R
                if node_id.startswith("dec_")
                else PLAYBOOK_PROCESS_W // 2
            )

        for left_id, right_id in zip(spine, spine[1:]):
            left_x = PLAYBOOK_LAYOUT[left_id]["x"]
            right_x = PLAYBOOK_LAYOUT[right_id]["x"]
            gap = right_x - left_x - _half_width(left_id) - _half_width(right_id)
            self.assertGreaterEqual(
                gap,
                PLAYBOOK_NODE_GAP - 1,
                msg=f"{left_id} overlaps {right_id} (gap={gap})",
            )

    def test_playbook_node_branch_covers_flow_nodes(self) -> None:
        for node in PLAYBOOK_FLOW_NODES:
            node_id = str(node["id"])
            self.assertIn(node_id, PLAYBOOK_NODE_BRANCH, msg=node_id)
        self.assertEqual(PLAYBOOK_NODE_BRANCH["spl_validate"], "operational")
        self.assertEqual(PLAYBOOK_NODE_BRANCH["peer_review"], "metadata")
        self.assertEqual(PLAYBOOK_NODE_BRANCH["security_review"], "security")
        self.assertEqual(PLAYBOOK_NODE_BRANCH["dec_guardrail"], "gate")

    def test_playbook_node_tips_cover_flow_nodes(self) -> None:
        for node in PLAYBOOK_FLOW_NODES:
            node_id = str(node["id"])
            self.assertIn(node_id, PLAYBOOK_NODE_TIPS, msg=node_id)
            self.assertTrue(len(PLAYBOOK_NODE_TIPS[node_id]) >= 12, msg=node_id)

    def test_playbook_process_nodes_no_horizontal_overlap(self) -> None:
        """Every process node pair on the same row must have NODE_GAP between bounds."""
        process_half = PLAYBOOK_PROCESS_W // 2
        by_row: dict[int, list[tuple[str, int]]] = {}
        for node in PLAYBOOK_FLOW_NODES:
            if node.get("kind") != "process":
                continue
            node_id = str(node["id"])
            pos = PLAYBOOK_LAYOUT[node_id]
            by_row.setdefault(int(pos["y"]), []).append((node_id, int(pos["x"])))
        for row_y, items in by_row.items():
            items.sort(key=lambda item: item[1])
            for (left_id, left_x), (right_id, right_x) in zip(items, items[1:]):
                gap = right_x - left_x - process_half - process_half
                self.assertGreaterEqual(
                    gap,
                    PLAYBOOK_NODE_GAP - 1,
                    msg=f"row y={row_y}: {left_id} overlaps {right_id} (gap={gap})",
                )


if __name__ == "__main__":
    unittest.main()
