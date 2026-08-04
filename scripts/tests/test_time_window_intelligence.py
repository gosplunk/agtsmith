#!/usr/bin/env python3
"""Unit tests for natural-language and Splunk-style time window parsing."""

from __future__ import annotations

import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from question_intelligence import (
    apply_question_time_window,
    infer_time_window,
    question_has_explicit_relative_window,
    question_requests_all_time,
    spl_time_values_equivalent,
)


class TimeWindowIntelligenceTests(unittest.TestCase):
    def _assert_window(self, question: str, earliest: str, latest: str = "now") -> None:
        got_e, got_l = infer_time_window(question)
        self.assertEqual(got_e, earliest, msg=f"earliest mismatch for: {question!r}")
        self.assertEqual(got_l, latest, msg=f"latest mismatch for: {question!r}")

    def test_relative_counts(self) -> None:
        cases = (
            ("failed logons in the last 7 days", "-7d"),
            ("activity within the last 15 minutes", "-15m"),
            ("alerts over the last 2 hours", "-2h"),
            ("events during the last 3 weeks", "-3w"),
            ("signins for the last 6 months", "-6mon"),
            ("audit logs in the last 2 quarters", "-2q"),
            ("changes in the last 1 year", "-1y"),
            ("traffic 45 days ago", "-45d"),
            ("since 30 days ago", "-30d"),
            ("since 4 hours ago", "-4h"),
        )
        for question, earliest in cases:
            with self.subTest(question=question):
                self._assert_window(question, earliest)

    def test_named_windows(self) -> None:
        cases = (
            ("failed logons today", "@d"),
            ("failed logons yesterday", "-1d@d", "@d"),
            ("this week auth failures", "@w0"),
            ("this month logons", "@mon"),
            ("this quarter activity", "@q"),
            ("this year incidents", "@y"),
            ("last 24 hours failures", "-24h"),
            ("last 90 days activity", "-90d"),
            ("year to date alerts", "@y"),
            ("ytd failed logons", "@y"),
            ("previous calendar week", "-7d@w0", "@w0"),
            ("previous month activity", "-1mon@mon", "@mon"),
        )
        for case in cases:
            question = case[0]
            earliest = case[1]
            latest = case[2] if len(case) > 2 else "now"
            with self.subTest(question=question):
                self._assert_window(question, earliest, latest)

    def test_since_and_until_anchors(self) -> None:
        self._assert_window("failed logons since yesterday", "-1d@d")
        self._assert_window("activity since start of month", "@mon")
        self._assert_window("events since 2024-06-01", "2024-06-01")
        self._assert_window("alerts since 6/1/2024", "6/1/2024")
        self._assert_window("logons since monday", "@w1")
        self._assert_window("events until yesterday", "-30d", "@d")
        self._assert_window("activity from yesterday to today", "-1d@d")

    def test_splunk_literal_modifiers(self) -> None:
        self._assert_window("search index=windows earliest=-7d latest=now", "-7d")
        self._assert_window("run query earliest_time=-30d@d", "-30d@d")

    def test_all_time_phrases(self) -> None:
        cases = (
            "were there any failed logons at any point ever in windows?",
            "show all history of admin logons",
            "any failed logons ever recorded on windows",
            "search full retention for 4625 events",
        )
        for question in cases:
            with self.subTest(question=question):
                self.assertTrue(question_requests_all_time(question))
                self._assert_window(question, "0")

    def test_explicit_window_beats_all_time_heuristic(self) -> None:
        question = "were there any failed logons ever in windows in the last 24 hours?"
        self.assertFalse(question_requests_all_time(question))
        self.assertTrue(question_has_explicit_relative_window(question))
        self._assert_window(question, "-24h")

    def test_apply_question_time_window_overrides_planner_default(self) -> None:
        tool_args = {"earliest_time": "-24h", "latest_time": "now"}
        apply_question_time_window("failed logons in the last 7 days", tool_args)
        self.assertEqual(tool_args["earliest_time"], "-7d")

    def test_default_when_unspecified(self) -> None:
        self._assert_window("show me windows process activity", "-7d")

    def test_explicit_last_24_hours_does_not_use_default(self) -> None:
        self._assert_window("show me windows process activity in the last 24 hours", "-24h")

    def test_explicit_last_7_days_matches_default_but_remains_explicit(self) -> None:
        question = "show me windows process activity in the last 7 days"
        self.assertTrue(question_has_explicit_relative_window(question))
        self._assert_window(question, "-7d")

    def test_partial_literal_preserves_explicit_latest(self) -> None:
        self._assert_window("search index=main earliest_time=-24h", "-24h")
        self._assert_window("search index=main latest_time=now", "-7d")

    def test_apply_replaces_planner_fallback_for_unbounded_question(self) -> None:
        tool_args = {"earliest_time": "-24h", "latest_time": "now"}
        apply_question_time_window("show me windows process activity", tool_args)
        self.assertEqual(tool_args, {"earliest_time": "-7d", "latest_time": "now"})

    def test_rolling_relative_time_equivalence(self) -> None:
        for left, right in (
            ("-1d", "-24h"),
            ("now-1d", "-24h"),
            ("-2d", "-48h"),
            ("-1w", "-168h"),
        ):
            with self.subTest(left=left, right=right):
                self.assertTrue(spl_time_values_equivalent(left, right))

    def test_snapped_and_rolling_windows_are_not_equivalent(self) -> None:
        self.assertFalse(spl_time_values_equivalent("-1d@d", "-24h"))
        self.assertFalse(spl_time_values_equivalent("@d", "-24h"))


if __name__ == "__main__":
    unittest.main()
