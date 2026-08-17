#!/usr/bin/env python3
"""Tests for strict MCP deterministic routing."""

from __future__ import annotations

import unittest

import mcp_deterministic_routing as mdr


class McpDeterministicRoutingTests(unittest.TestCase):
    def test_index_access_question_is_eligible(self) -> None:
        payload = mdr.classify_mcp_deterministic_eligibility("What indexes do I have access to?")
        self.assertTrue(payload["eligible"])
        self.assertEqual(payload["selected_tool"], "splunk_get_indexes")
        self.assertEqual(payload["category"], "index_inventory")

    def test_top_events_question_is_not_eligible(self) -> None:
        payload = mdr.classify_mcp_deterministic_eligibility("Which indexes had the most events in 24h?")
        self.assertFalse(payload["eligible"])
        self.assertIn("disqualified:most events", payload["reason"])

    def test_failed_login_is_not_eligible(self) -> None:
        payload = mdr.classify_mcp_deterministic_eligibility("Show failed login activity in the last 24 hours")
        self.assertFalse(payload["eligible"])

    def test_splunk_version_is_eligible(self) -> None:
        payload = mdr.classify_mcp_deterministic_eligibility("What is the Splunk version?")
        self.assertTrue(payload["eligible"])
        self.assertEqual(payload["selected_tool"], "splunk_get_info")

    def test_list_hosts_is_eligible(self) -> None:
        payload = mdr.classify_mcp_deterministic_eligibility("List hosts in my environment")
        self.assertTrue(payload["eligible"])
        self.assertEqual(payload["selected_tool"], "splunk_get_metadata")

    def test_auto_route_from_assisted(self) -> None:
        pipeline, meta = mdr.resolve_mcp_chat_pipeline("Show indexes available", "assisted")
        self.assertEqual(pipeline, "deterministic")
        self.assertTrue(meta["auto_routed"])

    def test_manual_assisted_not_downgraded(self) -> None:
        pipeline, meta = mdr.resolve_mcp_chat_pipeline("Show failed login activity", "assisted")
        self.assertEqual(pipeline, "assisted")
        self.assertFalse(meta["auto_routed"])

    def test_indexes_with_recent_data_is_not_eligible(self) -> None:
        payload = mdr.classify_mcp_deterministic_eligibility(
            "What indexes had data in the last 15 minutes?"
        )
        self.assertFalse(payload["eligible"])
        self.assertIn("disqualified:", payload["reason"])

    def test_indexes_with_data_volume_requires_llm(self) -> None:
        pipeline, meta = mdr.resolve_mcp_chat_pipeline(
            "What indexes had data in the last 15 minutes?",
            "assisted",
        )
        self.assertEqual(pipeline, "assisted")
        self.assertFalse(meta["auto_routed"])


if __name__ == "__main__":
    raise SystemExit(unittest.main())
