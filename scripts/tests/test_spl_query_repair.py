#!/usr/bin/env python3
"""Unit tests for one-pass SPL repair helper."""

from __future__ import annotations

import sys
from pathlib import Path
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from spl_query_repair import attempt_query_repair_once


class SplQueryRepairTests(unittest.TestCase):
    @mock.patch("spl_query_repair.httpx.Client")
    def test_fallback_to_template_when_model_call_fails(self, client_cls: mock.Mock) -> None:
        client = client_cls.return_value.__enter__.return_value
        client.post.side_effect = RuntimeError("simulated_network_error")

        out = attempt_query_repair_once(
            question="Show failed login activity in the last 24 hours",
            failed_query_args={
                "query": 'search index=linux sourcetype="XmlWinEventLog" | stats count',
                "earliest_time": "-24h",
                "latest_time": "now",
                "row_limit": 10,
            },
            failure_reason="environment_sourcetype_not_in_index:XmlWinEventLog",
            model="fake-model",
            timeout=0.1,
        )
        self.assertTrue(out["ok"], out)
        self.assertEqual(out["source"], "template_fallback_repair")
        self.assertIn("query", out["args"])
        self.assertTrue(str(out["args"]["query"]).startswith("search "))


if __name__ == "__main__":
    unittest.main()
