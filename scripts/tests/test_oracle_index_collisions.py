#!/usr/bin/env python3
"""Oracle index/metadata collision tests."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from spl_domain_knowledge import match_patterns, resolve_domain_knowledge  # noqa: E402


class OracleIndexCollisionTests(unittest.TestCase):
    def test_how_many_indexes_beats_volume_pattern(self) -> None:
        question = "how many indexes do I have in this splunk environment?"
        resolution = resolve_domain_knowledge(question)
        self.assertIsNotNone(resolution)
        assert resolution is not None
        self.assertEqual(resolution.pattern_id, "index_count_cardinality")
        self.assertIn("dc(index)", resolution.query.lower())

    def test_busiest_indexes_beats_count_pattern(self) -> None:
        question = "Which indexes had the most events in the last 24 hours?"
        resolution = resolve_domain_knowledge(question, intent="top_indexes")
        self.assertIsNotNone(resolution)
        assert resolution is not None
        self.assertIn(
            resolution.pattern_id,
            {"index_volume_ranking", "template_top_indexes"},
        )
        self.assertIn("count by index", resolution.query.lower())

    def test_list_indexes_uses_metadata_tool(self) -> None:
        question = "what indexes are in my environment?"
        resolution = resolve_domain_knowledge(question)
        self.assertIsNotNone(resolution)
        assert resolution is not None
        self.assertEqual(resolution.pattern_id, "index_inventory_list")
        self.assertEqual(resolution.preferred_tool, "splunk_get_indexes")

    def test_list_indexes_pattern_does_not_win_when_time_window_present(self) -> None:
        # index_inventory_list's "what indexes"/"which indexes do i" triggers are
        # substrings of many time-bound questions. Its preferred_tool
        # (splunk_get_indexes) cannot filter by time at all, so it must never win
        # once the question asks about data/events in a specific window -- the
        # real search-capable pattern (splunk_run_query) must be selected instead.
        for question in (
            "What indexes have had events in the last hour?",
            "Which indexes have data in the last hour?",
            "What indexes had data in the last 15 minutes?",
            "Which indexes had data in the last 15 minutes?",
        ):
            resolution = resolve_domain_knowledge(question)
            self.assertIsNotNone(resolution, question)
            assert resolution is not None
            self.assertNotEqual(resolution.pattern_id, "index_inventory_list", question)
            self.assertEqual(resolution.preferred_tool, "splunk_run_query", question)

    def test_pure_inventory_question_still_uses_metadata_tool(self) -> None:
        resolution = resolve_domain_knowledge("What indexes do I have access to?")
        self.assertIsNotNone(resolution)
        assert resolution is not None
        self.assertEqual(resolution.pattern_id, "index_inventory_list")
        self.assertEqual(resolution.preferred_tool, "splunk_get_indexes")

    def test_collision_margin_between_count_and_volume(self) -> None:
        count_q = "how many indexes do I have?"
        volume_q = "show busiest indexes over the last 7 days"
        count_matches = match_patterns(count_q)
        volume_matches = match_patterns(volume_q, intent="top_indexes")
        self.assertTrue(count_matches)
        self.assertTrue(volume_matches)
        self.assertEqual(count_matches[0][0].id, "index_count_cardinality")
        self.assertIn(volume_matches[0][0].id, {"index_volume_ranking", "template_top_indexes"})


if __name__ == "__main__":
    unittest.main()
