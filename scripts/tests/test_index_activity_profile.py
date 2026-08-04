#!/usr/bin/env python3
"""Tests for index_activity profile helpers."""

from __future__ import annotations

import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from environment_profile import (
    indexes_with_data_in_window,
    profile_can_answer_inventory,
    profile_inventory_structured_results,
    profile_is_fresh,
)


def _fresh_profile(*, windows: dict[str, list[dict[str, object]]] | None = None) -> dict[str, object]:
    ts = datetime.now(timezone.utc).isoformat()
    return {
        "timestamp_utc": ts,
        "index_activity": {
            "timestamp_utc": ts,
            "windows": windows
            or {
                "-1h": [{"index": "linux", "count": 10}, {"index": "main", "count": 3}],
                "-24h": [{"index": "linux", "count": 100}],
            },
        },
    }


class IndexActivityProfileTests(unittest.TestCase):
    def test_indexes_with_data_in_window_filters_zero_counts(self) -> None:
        profile = _fresh_profile(
            windows={"-1h": [{"index": "linux", "count": 5}, {"index": "empty", "count": 0}]}
        )
        rows = indexes_with_data_in_window(profile, earliest="-1h")
        self.assertEqual([row["index"] for row in rows], ["linux"])

    def test_profile_can_answer_inventory_last_hour(self) -> None:
        profile = _fresh_profile()
        can_answer, window = profile_can_answer_inventory(
            "Which indexes have data in the last hour?",
            profile,
        )
        self.assertTrue(can_answer)
        self.assertEqual(window, "-1h")

    def test_profile_inventory_structured_results_shape(self) -> None:
        profile = _fresh_profile()
        structured = profile_inventory_structured_results(
            "Which indexes have data in the last hour?",
            profile,
        )
        self.assertIsNotNone(structured)
        assert structured is not None
        self.assertEqual(structured.get("profile_window"), "-1h")
        self.assertGreaterEqual(int(structured.get("total_rows", 0)), 1)

    def test_profile_is_fresh_respects_age(self) -> None:
        profile = _fresh_profile()
        self.assertTrue(profile_is_fresh(profile, max_age_minutes=60))
        stale_ts = (datetime.now(timezone.utc) - timedelta(hours=3)).isoformat()
        stale_profile = dict(profile)
        stale_profile["timestamp_utc"] = stale_ts
        self.assertFalse(profile_is_fresh(stale_profile, max_age_minutes=60))


if __name__ == "__main__":
    unittest.main()
