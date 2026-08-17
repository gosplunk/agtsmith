#!/usr/bin/env python3
"""Unit tests for the optional edge-model question classifier."""

from __future__ import annotations

import json
import sys
from pathlib import Path
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import edge_question_classifier as eqc


class EdgeQuestionClassifierTests(unittest.TestCase):
    def setUp(self) -> None:
        eqc._cached_query_hint.cache_clear()

    def test_disabled_by_default_returns_empty(self) -> None:
        with mock.patch.dict("os.environ", {"EDGE_LLM_ENABLED": "0"}, clear=False):
            self.assertEqual(eqc.classify_question("Show failed Windows logons"), {})
            self.assertEqual(eqc.question_query_hint("Show failed Windows logons"), "")

    def test_classify_question_parses_and_sanitizes_response(self) -> None:
        env = {
            "EDGE_LLM_ENABLED": "1",
            "EDGE_LLM_HOST": "http://127.0.0.1:11434",
            "EDGE_LLM_MODEL": "gemma3:1b",
        }
        raw_response = json.dumps(
            {
                "platform": "O365",
                "activity": "Failed_Login",
                "data_category": "identity",
                "entities": ["jdoe@example.com"],
                "time_hint": "last 24 hours",
                "extra_unexpected_key": "ignored",
            }
        )
        with mock.patch.dict("os.environ", env, clear=False), mock.patch.object(
            eqc, "_post_json", return_value={"response": raw_response}
        ) as mocked:
            result = eqc.classify_question("unsuccessful sign-ins to Office 365 in the last day")
        self.assertTrue(mocked.called)
        self.assertEqual(result["platform"], "o365")
        self.assertEqual(result["activity"], "failed_login")
        self.assertEqual(result["data_category"], "identity")
        self.assertEqual(result["entities"], ["jdoe@example.com"])
        self.assertEqual(result["time_hint"], "last 24 hours")
        self.assertNotIn("extra_unexpected_key", result)

    def test_classify_question_handles_markdown_fenced_json(self) -> None:
        env = {"EDGE_LLM_ENABLED": "1", "EDGE_LLM_HOST": "http://127.0.0.1:11434", "EDGE_LLM_MODEL": "gemma3:1b"}
        fenced = '```json\n{"platform": "windows", "activity": "failed_login"}\n```'
        with mock.patch.dict("os.environ", env, clear=False), mock.patch.object(
            eqc, "_post_json", return_value={"response": fenced}
        ):
            result = eqc.classify_question("weird logon attempts on the domain controller")
        self.assertEqual(result.get("platform"), "windows")
        self.assertEqual(result.get("activity"), "failed_login")

    def test_classify_question_degrades_on_network_error(self) -> None:
        env = {"EDGE_LLM_ENABLED": "1", "EDGE_LLM_HOST": "http://127.0.0.1:11434", "EDGE_LLM_MODEL": "gemma3:1b"}
        with mock.patch.dict("os.environ", env, clear=False), mock.patch.object(
            eqc, "_post_json", side_effect=OSError("connection refused")
        ):
            result = eqc.classify_question("anything")
        self.assertEqual(result, {})

    def test_classify_question_ignores_unknown_placeholder_values(self) -> None:
        env = {"EDGE_LLM_ENABLED": "1", "EDGE_LLM_HOST": "http://127.0.0.1:11434", "EDGE_LLM_MODEL": "gemma3:1b"}
        raw_response = json.dumps({"platform": "unknown", "activity": "unspecified", "time_hint": "last week"})
        with mock.patch.dict("os.environ", env, clear=False), mock.patch.object(
            eqc, "_post_json", return_value={"response": raw_response}
        ):
            result = eqc.classify_question("some question")
        self.assertNotIn("platform", result)
        self.assertNotIn("activity", result)
        self.assertEqual(result.get("time_hint"), "last week")

    def test_classification_to_query_hint_formats_populated_fields_only(self) -> None:
        hint = eqc.classification_to_query_hint(
            {"platform": "o365", "activity": "failed_login", "entities": ["jdoe"], "data_category": ""}
        )
        self.assertEqual(hint, "platform=o365 activity=failed_login entities=jdoe")

    def test_classification_to_query_hint_empty_for_empty_input(self) -> None:
        self.assertEqual(eqc.classification_to_query_hint({}), "")
        self.assertEqual(eqc.classification_to_query_hint(None), "")  # type: ignore[arg-type]

    def test_question_query_hint_end_to_end(self) -> None:
        env = {"EDGE_LLM_ENABLED": "1", "EDGE_LLM_HOST": "http://127.0.0.1:11434", "EDGE_LLM_MODEL": "gemma3:1b"}
        raw_response = json.dumps({"platform": "apache", "activity": "web_error"})
        with mock.patch.dict("os.environ", env, clear=False), mock.patch.object(
            eqc, "_post_json", return_value={"response": raw_response}
        ):
            hint = eqc.question_query_hint("spikes in apache error logs", use_cache=False)
        self.assertEqual(hint, "platform=apache activity=web_error")


if __name__ == "__main__":
    unittest.main()
