#!/usr/bin/env python3
"""Tests for template override modes in LangGraph validation."""

from __future__ import annotations

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import langgraph_multi_model_soc as mm


class TemplateOverrideTests(unittest.TestCase):
    def test_template_override_default_is_fallback(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(mm._template_override_mode(), "fallback")

    def test_enforce_alignment_skips_template_when_fallback_mode(self) -> None:
        question = "Show failed login activity in the last 24 hours on my linux systems"
        plan = {
            "selected_tool": "splunk_run_query",
            "intent": "linux_auth_failures",
            "tool_args": {"query": "search index=linux | stats count"},
            "reason": "writer_model",
        }
        with mock.patch.dict(os.environ, {"AGTSMITH_TEMPLATE_OVERRIDE": "fallback"}, clear=False):
            aligned = mm._enforce_question_alignment(question, plan)
        self.assertEqual(aligned.get("reason"), "writer_model")

    def test_enforce_alignment_forces_template_when_always_mode(self) -> None:
        question = "Show failed login activity in the last 24 hours on my linux systems"
        plan = {
            "selected_tool": "splunk_run_query",
            "intent": "linux_auth_failures",
            "tool_args": {"query": "search index=linux | stats count"},
            "reason": "writer_model",
        }
        with mock.patch.dict(os.environ, {"AGTSMITH_TEMPLATE_OVERRIDE": "always"}, clear=False):
            aligned = mm._enforce_question_alignment(question, plan)
        self.assertTrue(str(aligned.get("reason", "")).startswith("question_alignment_override:template:"))


if __name__ == "__main__":
    unittest.main()
