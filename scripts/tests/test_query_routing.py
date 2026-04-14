#!/usr/bin/env python3
"""Regression tests for environment-agnostic deterministic query routing."""

from __future__ import annotations

import sys
from pathlib import Path
import types
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

langgraph = types.ModuleType("langgraph")
graph = types.ModuleType("langgraph.graph")
graph.END = "END"
graph.START = "START"
graph.StateGraph = object
langgraph.graph = graph
sys.modules.setdefault("langgraph", langgraph)
sys.modules.setdefault("langgraph.graph", graph)

from langgraph_minimal_flow import determine_splunk_tool
from minimal_question_to_answer import map_question_to_template


class QueryRoutingTests(unittest.TestCase):
    def test_failed_privilege_escalation_prefers_failure_template(self) -> None:
        template = map_question_to_template("Show failed sudo or su activity on linux in the last 24 hours.")
        self.assertEqual(template.intent, "linux_privilege_escalation")

    def test_privilege_escalation_behavior_prefers_activity_template(self) -> None:
        template = map_question_to_template("Show sudo activity on linux and preserve context for root sessions.")
        self.assertEqual(template.intent, "linux_privilege_escalation_activity")

    def test_new_privilege_escalation_behavior_prefers_first_seen_template(self) -> None:
        template = map_question_to_template("Show newly observed sudo or su behavior in the last 24 hours on linux.")
        self.assertEqual(template.intent, "linux_privilege_escalation_first_seen")

    def test_apache_logon_attempts_prefer_access_template(self) -> None:
        template = map_question_to_template("Investigate weird logon attempts on my apache web server.")
        self.assertEqual(template.intent, "apache_access_top_ips")

    def test_sources_metadata_uses_metadata_tool(self) -> None:
        template = map_question_to_template("Show sources metadata for the last 24 hours.")
        tool, _reason, metadata_args, _mode = determine_splunk_tool("Show sources metadata for the last 24 hours.", template.intent)
        self.assertEqual(tool, "splunk_get_metadata")
        self.assertEqual(metadata_args.get("type"), "sources")

    def test_demo_botsv3_phrase_does_not_misroute_aad_signin_questions(self) -> None:
        template = map_question_to_template(
            "Show Azure AD sign-in activity by user, IP, and application using the public BOTSv3 demo dataset across all time."
        )
        self.assertEqual(template.intent, "aad_signin_activity")


if __name__ == "__main__":
    unittest.main()
