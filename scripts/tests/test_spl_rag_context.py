#!/usr/bin/env python3
"""Tests for intent-scoped SPL RAG context."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from spl_rag_context import build_resolved_domain_hints, build_spl_rag_context


class SplRagContextTests(unittest.TestCase):
    def test_build_resolved_domain_hints_empty_without_intent(self) -> None:
        self.assertEqual(build_resolved_domain_hints("failed logons", intent=""), "")

    def test_build_spl_rag_context_includes_resolved_domains_when_intent_set(self) -> None:
        profile = {
            "timestamp_utc": "2026-07-28T00:00:00+00:00",
            "indexes": [
                {"index": "linux", "sourcetypes": ["auth.log", "linux_secure"]},
            ],
            "sourcetype_to_indexes": {"auth.log": ["linux"], "linux_secure": ["linux"]},
            "sourcetype_field_inventory": {},
            "index_sourcetype_field_inventory": {
                "linux": {
                    "auth.log": {
                        "interesting_field_examples": [
                            {"field": "user", "sample_values": ["root"], "count": 1}
                        ]
                    }
                }
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            profile_path = Path(tmp) / "profile.json"
            profile_path.write_text(json.dumps(profile), encoding="utf-8")
            with mock.patch("spl_rag_context.SKILLPACK_PATH", Path(tmp) / "missing.json"):
                ctx = build_spl_rag_context(
                    "Show failed SSH login activity in the last 24 hours",
                    intent="linux_auth_failures",
                    max_chars=4000,
                    profile_path=profile_path,
                )
        self.assertIn("[RESOLVED_DOMAINS]", ctx)
        self.assertIn("index=linux", ctx)


if __name__ == "__main__":
    unittest.main()
