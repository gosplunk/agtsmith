#!/usr/bin/env python3
"""Tests for ten-domain registry."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ten_domain_registry import (
    TARGET_PASS_RATE_PCT,
    TEN_DOMAINS,
    lab_domains_for_ids,
    oracle_domains,
    score_snapshot_row,
)


class TenDomainRegistryTests(unittest.TestCase):
    def test_has_ten_domains(self) -> None:
        self.assertEqual(len(TEN_DOMAINS), 10)

    def test_oracle_and_live_mix(self) -> None:
        self.assertEqual(len(oracle_domains()), 3)
        self.assertEqual(len(TEN_DOMAINS) - len(oracle_domains()), 7)

    def test_lab_domain_mapping(self) -> None:
        labs = lab_domains_for_ids(["linux_auth", "stream_dns"])
        self.assertIn("linux_auth", labs)
        self.assertIn("stream_dns", labs)

    def test_score_target(self) -> None:
        ok = score_snapshot_row("linux", pass_rate_pct=90.0, passed=9, total=10)
        bad = score_snapshot_row("linux", pass_rate_pct=89.9, passed=8, total=10)
        self.assertTrue(ok["meets_target"])
        self.assertFalse(bad["meets_target"])
        self.assertEqual(TARGET_PASS_RATE_PCT, 90.0)


if __name__ == "__main__":
    unittest.main()
