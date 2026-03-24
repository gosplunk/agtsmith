#!/usr/bin/env python3
"""Unit tests for question-family routing and time-window extraction."""

from __future__ import annotations

import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from minimal_question_to_answer import map_question_to_template, template_to_query_args
from question_intelligence import infer_time_window


class QuestionRoutingTests(unittest.TestCase):
    def test_time_window_extracts_last_7_days(self) -> None:
        earliest, latest = infer_time_window("Show failed login activity in the last 7 days on my windows or linux machines")
        self.assertEqual(earliest, "-7d")
        self.assertEqual(latest, "now")

    def test_windows_or_linux_failed_login_builds_mixed_query(self) -> None:
        question = "Show failed login activity in the last 7 days on my windows or linux machines"
        template = map_question_to_template(question)
        self.assertEqual(template.intent, "failed_login_activity")
        args = template_to_query_args(template, question)
        query = str(args.get("query", ""))
        self.assertIn("index=linux", query)
        self.assertIn("index=windows", query)
        self.assertIn("EventCode=4625", query)
        self.assertIn("failed password", query)
        self.assertEqual(args.get("earliest_time"), "-7d")
        self.assertEqual(args.get("latest_time"), "now")

    def test_windows_specific_failed_login_uses_windows_intent(self) -> None:
        question = "Show failed login activity in the last 24 hours in windows"
        template = map_question_to_template(question)
        self.assertEqual(template.intent, "windows_auth_failures")
        args = template_to_query_args(template, question)
        self.assertIn("index=windows", str(args.get("query", "")))


if __name__ == "__main__":
    unittest.main()
