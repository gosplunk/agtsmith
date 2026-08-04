#!/usr/bin/env python3
"""Unit tests for sourcetype oracle cards."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from build_sourcetype_cards import build_cards_from_profile  # noqa: E402
from sourcetype_cards import cards_for_question, format_cards_context, load_cards  # noqa: E402


class SourcetypeCardsTests(unittest.TestCase):
    def test_build_cards_from_profile(self) -> None:
        profile = {
            "sourcetype_to_indexes": {"linux_secure": ["os", "main"]},
            "sourcetype_field_inventory": {
                "linux_secure": [{"field": "host", "sample_values": ["web1"]}],
            },
        }
        cards = build_cards_from_profile(profile)
        self.assertEqual(len(cards), 1)
        self.assertEqual(cards[0]["sourcetype"], "linux_secure")
        self.assertIn("index=os", cards[0]["gold_query_fragment"])

    def test_cards_for_question_prefers_matching_sourcetype(self) -> None:
        cards = [
            {
                "sourcetype": "XmlWinEventLog:Security",
                "tags": ["windows"],
                "use_cases": ["failed_logins"],
                "card_text": "Windows security events",
                "indexes": ["wineventlog"],
                "top_fields": ["EventCode"],
                "gold_query_fragment": 'search index=wineventlog sourcetype="XmlWinEventLog:Security"',
                "anti_patterns": [],
            },
            {
                "sourcetype": "linux_secure",
                "tags": ["linux"],
                "use_cases": ["failed_logins"],
                "card_text": "Linux auth events",
                "indexes": ["os"],
                "top_fields": ["host"],
                "gold_query_fragment": 'search index=os sourcetype=linux_secure',
                "anti_patterns": [],
            },
        ]
        chosen = cards_for_question(
            "Show failed Windows login activity",
            intent="failed_logins",
            cards=cards,
            max_cards=1,
        )
        self.assertEqual(chosen[0]["sourcetype"], "XmlWinEventLog:Security")

    def test_load_cards_from_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "cards.json"
            path.write_text(json.dumps([{"sourcetype": "syslog", "card_text": "syslog card"}]), encoding="utf-8")
            load_cards.cache_clear()
            rows = load_cards(path=str(path))
            self.assertEqual(rows[0]["sourcetype"], "syslog")
            ctx = format_cards_context(rows)
            self.assertIn("[SOURCETYPE_CARDS]", ctx)


if __name__ == "__main__":
    unittest.main()
