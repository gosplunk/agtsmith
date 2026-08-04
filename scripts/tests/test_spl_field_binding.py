#!/usr/bin/env python3
"""Unit tests for SPL field binding."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from spl_field_binding import bind_fields_for_plan  # noqa: E402


class SplFieldBindingTests(unittest.TestCase):
    def test_bind_uses_profile_index_for_sourcetype(self) -> None:
        profile = {
            "sourcetype_to_indexes": {"linux_secure": ["os"]},
            "sourcetype_field_inventory": {"linux_secure": [{"field": "host"}]},
        }
        bound = bind_fields_for_plan(
            "Show failed logins on Linux hosts",
            {"intent": "failed_logins", "sourcetype": "linux_secure"},
            profile=profile,
        )
        self.assertEqual(bound["sourcetype"], "linux_secure")
        self.assertEqual(bound["index_expr"], "index=os")
        self.assertIn("host", bound["field_hints"])

    def test_bind_reads_nested_current_profile_field_inventory(self) -> None:
        profile = {
            "sourcetype_to_indexes": {"stream:dns": ["botsv3"]},
            "sourcetype_field_inventory": {
                "stream:dns": {
                    "fields": [
                        {"field": "src_ip", "count": 10},
                        {"field": "dest_ip", "count": 10},
                    ]
                }
            },
        }
        bound = bind_fields_for_plan(
            "Show distinct dest_ip values by src_ip",
            {"intent": "stream_dns_activity", "sourcetype": "stream:dns"},
            profile=profile,
        )
        self.assertEqual(bound["index_expr"], "index=botsv3")
        self.assertIn("src_ip", bound["profile_native_fields"])
        self.assertIn("dest_ip", bound["profile_native_fields"])


if __name__ == "__main__":
    unittest.main()
