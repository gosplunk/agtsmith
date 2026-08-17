#!/usr/bin/env python3
"""Unit tests for portable investigation playbooks."""

from __future__ import annotations

import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from investigation_playbooks import (
    playbook_for_intent,
    playbook_query_pivots,
    playbook_recommended_pivots,
    playbook_target_order,
)


class InvestigationPlaybookTests(unittest.TestCase):
    def test_http_intent_maps_to_web_traffic_playbook(self) -> None:
        playbook = playbook_for_intent("stream_http_activity")
        self.assertEqual(playbook["id"], "web_traffic_hunt")
        self.assertEqual(playbook_target_order("stream_http_activity")[:3], ("site", "source_ip", "user_agent"))

    def test_failed_login_recommendations_are_playbook_driven(self) -> None:
        recs = playbook_recommended_pivots(
            "failed_login_activity",
            {"hosts": ["host-a"], "users": ["svc-user"], "source_ips": ["10.1.2.3"]},
        )
        self.assertTrue(recs)
        self.assertNotIn("Pivot to index inventory for broader visibility.", recs)
        self.assertIn("Priority source IP pivot: 10.1.2.3", recs)

    def test_all_operational_intents_have_specific_playbooks(self) -> None:
        expected = {
            "top_indexes": "inventory_ops",
            "metadata_inventory": "inventory_ops",
            "index_sourcetype_volume": "inventory_ops",
            "host_activity_summary": "inventory_ops",
            "index_staleness": "inventory_ops",
            "splunk_internal_health": "platform_ops",
            "splunk_license_usage": "platform_ops",
            "forwarder_connectivity": "platform_ops",
            "web_traffic_summary": "it_ops_web",
            "network_flow_summary": "network_flow_hunt",
            "app_error_spike": "it_ops_errors",
        }
        for intent, playbook_id in expected.items():
            with self.subTest(intent=intent):
                self.assertEqual(playbook_for_intent(intent)["id"], playbook_id)

    def test_inventory_pivot_is_bounded_and_rejects_injection(self) -> None:
        pivots = playbook_query_pivots(
            "metadata_inventory",
            {"indexes": ["linux"], "sourcetypes": ["auth.log"]},
            earliest="-24h",
        )
        self.assertTrue(pivots)
        self.assertTrue(all("earliest=-24h latest=now" in row["query"] for row in pivots))
        self.assertFalse(
            playbook_query_pivots(
                "top_indexes",
                {"indexes": ["main | outputlookup stolen.csv"]},
            )
        )


if __name__ == "__main__":
    unittest.main()
