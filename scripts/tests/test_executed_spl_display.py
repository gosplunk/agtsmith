#!/usr/bin/env python3
"""Tests for executed SPL display resolution (library / deterministic paths)."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from investigation_progress import executed_spl_from_result


class ExecutedSplDisplayTests(unittest.TestCase):
    def test_saved_query_library_writer_output_fallback(self) -> None:
        query = "search index=windows EventCode=4625 user=alice | stats count"
        payload = {
            "selected_tool": "splunk_run_query",
            "query_args": {},
            "query_writer_output": {
                "source": "saved_query_library",
                "tool_args": {"query": query, "earliest_time": "-7d", "latest_time": "now"},
            },
            "rows_returned": 12,
        }
        self.assertEqual(executed_spl_from_result(payload), query)

    def test_selected_spl_details_fallback(self) -> None:
        query = "search index=botsv3 | head 5"
        payload = {
            "selected_tool": "splunk_run_query",
            "selected_spl_details": [{"query": query, "writer_model": "saved_query_library"}],
        }
        self.assertEqual(executed_spl_from_result(payload), query)

    def test_metadata_tool_display(self) -> None:
        payload = {
            "selected_tool": "splunk_get_indexes",
            "query_args": {},
        }
        resolved = executed_spl_from_result(payload)
        self.assertIn("| rest", resolved)
        self.assertIn("/services/data/indexes", resolved)

    def test_generating_command_preserved(self) -> None:
        query = "| rest splunk_server=local /services/data/indexes | table title"
        payload = {
            "selected_tool": "splunk_run_query",
            "query_args": {"query": query},
        }
        self.assertEqual(executed_spl_from_result(payload), query)


if __name__ == "__main__":
    unittest.main()
