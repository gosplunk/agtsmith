#!/usr/bin/env python3
"""Unit tests for portable investigation playbooks."""

from __future__ import annotations

import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from investigation_playbooks import playbook_for_intent, playbook_recommended_pivots, playbook_target_order


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


if __name__ == "__main__":
    unittest.main()
