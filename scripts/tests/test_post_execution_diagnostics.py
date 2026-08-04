#!/usr/bin/env python3
"""Tests for post-execution diagnostics."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from post_execution_diagnostics import (  # noqa: E402
    _extract_linux_branch,
    _extract_windows_append,
    _query_with_fallback_extractions,
    run_post_execution_diagnostics,
)


class PostExecutionDiagnosticsTests(unittest.TestCase):
    def test_extract_linux_branch_strips_stats(self) -> None:
        query = (
            'search index=linux sourcetype=auth.log "Failed password" '
            "| stats count by host"
        )
        branch = _extract_linux_branch(query)
        self.assertNotIn("| stats", branch)
        self.assertIn("index=linux", branch)

    def test_extract_windows_append(self) -> None:
        query = (
            'search index=linux sourcetype=auth.log "Failed password" '
            "| append [ search index=windows sourcetype=XmlWinEventLog EventCode=4625 ] "
            "| stats count by platform"
        )
        win = _extract_windows_append(query)
        self.assertIn("index=windows", win)
        self.assertIn("4625", win)

    def test_skips_when_rows_present(self) -> None:
        out = run_post_execution_diagnostics(
            question="test",
            plan={"selected_tool": "splunk_run_query", "intent": "linux_auth_failures", "tool_args": {}},
            splunk_data={"structured": {"total_rows": 5, "results": [{}, {}]}},
        )
        self.assertTrue(out.get("skipped"))
        self.assertEqual(out.get("reason"), "rows_present")

    def test_rejects_unrelated_nonzero_result_schema(self) -> None:
        out = run_post_execution_diagnostics(
            question="show requests by client IP",
            plan={
                "selected_tool": "splunk_run_query",
                "intent": "apache_access_top_ips",
                "tool_args": {"query": "search index=linux | stats count by src_ip"},
            },
            splunk_data={
                "structured": {
                    "total_rows": 1,
                    "results": [{"unexpected_field": "not evidence"}],
                }
            },
            coverage_report={"spec": {"output_fields": ["src_ip", "events"]}},
        )
        self.assertTrue(out["live_evidence"]["rejected"])
        self.assertEqual(out["live_evidence"]["status"], "unrelated_nonzero")

    @patch("post_execution_diagnostics._run_diag_query")
    def test_runs_auth_diagnostics_on_zero_rows(self, mock_diag) -> None:
        mock_diag.return_value = {"label": "linux_branch", "rows_returned": 0, "ok": False}
        query = (
            'search index=linux sourcetype=auth.log "Failed password" '
            "| append [ search index=windows sourcetype=XmlWinEventLog EventCode=4625 ] "
            "| stats count by platform"
        )
        out = run_post_execution_diagnostics(
            question="failed logons",
            plan={
                "selected_tool": "splunk_run_query",
                "intent": "failed_login_activity",
                "tool_args": {"query": query, "earliest_time": "-24h", "latest_time": "now"},
            },
            splunk_data={"structured": {"total_rows": 0, "results": []}},
        )
        self.assertFalse(out.get("skipped"))
        self.assertGreaterEqual(len(out.get("diagnostics", [])), 1)

    def test_inserts_only_missing_extraction_fallbacks(self) -> None:
        query = (
            "search index=linux sourcetype=access_combined "
            "| stats count by clientip status method"
        )
        fallback = (
            'rex field=_raw "^(?<clientip>\\S+).* (?<status>\\d{3})"',
        )
        rendered = _query_with_fallback_extractions(query, list(fallback))
        self.assertIn(f"| {fallback[0]} | stats", rendered)

    @patch("post_execution_diagnostics._run_diag_query")
    def test_does_not_retry_when_base_events_are_empty(self, mock_diag) -> None:
        mock_diag.return_value = {
            "label": "base_events",
            "rows_returned": 0,
            "ok": False,
        }
        out = run_post_execution_diagnostics(
            question="top Apache clients",
            plan={
                "selected_tool": "splunk_run_query",
                "intent": "apache_access_top_ips",
                "tool_args": {
                    "query": "search index=linux sourcetype=access_combined | stats count by clientip status method"
                },
            },
            splunk_data={"structured": {"total_rows": 0, "results": []}},
            field_strategy={
                "roles": {
                    "src_ip": {"trusted_fields": ["clientip"]},
                    "status": {"trusted_fields": ["status"]},
                    "method": {"trusted_fields": ["method"]},
                },
                "fallback_extractions": [
                    'rex field=_raw "^(?<clientip>\\S+).* (?<status>\\d{3})"'
                ],
            },
        )
        self.assertFalse(out["retry_applied"])
        self.assertEqual(out["retry_reason"], "base_events_empty")
        self.assertEqual(out["live_evidence"]["status"], "no_base_data")
        self.assertEqual(mock_diag.call_count, 1)

    @patch("minimal_question_to_answer.run_splunk_query_args")
    @patch("post_execution_diagnostics._run_diag_query")
    def test_retries_extraction_when_base_exists_but_native_fields_empty(
        self,
        mock_diag,
        mock_run,
    ) -> None:
        def diag_result(_query, *, tool_args, label, query_budget=None):
            ok = label in {"base_events", "extraction_fallback_probe"}
            return {
                "label": label,
                "query": tool_args.get("query", ""),
                "rows_returned": 1 if ok else 0,
                "ok": ok,
                "_splunk_data": (
                    {"structured": {"total_rows": 1, "results": [{"count": "3"}]}}
                    if label == "extraction_fallback_probe"
                    else {}
                ),
            }

        mock_diag.side_effect = diag_result
        mock_run.return_value = {"structured": {"total_rows": 1, "results": [{"count": "3"}]}}
        out = run_post_execution_diagnostics(
            question="top Apache clients",
            plan={
                "selected_tool": "splunk_run_query",
                "intent": "apache_access_top_ips",
                "tool_args": {
                    "query": "search index=linux sourcetype=access_combined | stats count by clientip status method",
                    "earliest_time": "-24h",
                    "latest_time": "now",
                },
            },
            splunk_data={"structured": {"total_rows": 0, "results": []}},
            field_strategy={
                "roles": {
                    "src_ip": {"trusted_fields": ["clientip"]},
                    "status": {"trusted_fields": ["status"]},
                    "method": {"trusted_fields": ["method"]},
                },
                "fallback_extractions": [
                    'rex field=_raw "^(?<clientip>\\S+).* (?<status>\\d{3})"'
                ],
            },
        )
        self.assertTrue(out["retry_applied"])
        self.assertEqual(out["retry_reason"], "extraction_fallback_succeeded")
        retry_query = out["retry_plan"]["tool_args"]["query"]
        self.assertIn("| rex field=_raw", retry_query)
        self.assertEqual(
            [call.kwargs["label"] for call in mock_diag.call_args_list],
            ["base_events", "required_native_fields", "extraction_fallback_probe"],
        )

    @patch("post_execution_diagnostics._run_diag_query")
    def test_does_not_retry_when_required_native_fields_are_populated(self, mock_diag) -> None:
        def diag_result(_query, *, tool_args, label, query_budget=None):
            return {
                "label": label,
                "query": tool_args.get("query", ""),
                "rows_returned": 1,
                "ok": True,
            }

        mock_diag.side_effect = diag_result
        out = run_post_execution_diagnostics(
            question="top Apache clients",
            plan={
                "selected_tool": "splunk_run_query",
                "intent": "apache_access_top_ips",
                "tool_args": {
                    "query": "search index=linux sourcetype=access_combined | stats count by clientip status method"
                },
            },
            splunk_data={"structured": {"total_rows": 0, "results": []}},
            field_strategy={
                "roles": {
                    "src_ip": {"trusted_fields": ["clientip"]},
                    "status": {"trusted_fields": ["status"]},
                    "method": {"trusted_fields": ["method"]},
                },
                "fallback_extractions": [
                    'rex field=_raw "^(?<clientip>\\S+).* (?<status>\\d{3})"'
                ],
            },
        )
        self.assertFalse(out["retry_applied"])
        self.assertEqual(out["retry_reason"], "required_native_fields_populated")
        self.assertEqual(mock_diag.call_count, 2)


if __name__ == "__main__":
    unittest.main()
