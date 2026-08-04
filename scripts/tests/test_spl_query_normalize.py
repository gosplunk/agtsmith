#!/usr/bin/env python3
"""Tests for SPL query normalization."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from spl_query_normalize import drop_invented_sourcetypes, normalize_sourcetype_clauses, normalize_writer_query


class SplQueryNormalizeTests(unittest.TestCase):
    def test_strips_trailing_paren_from_bare_sourcetype(self) -> None:
        query = 'search index=linux (sourcetype=auth.log OR sourcetype=syslog) failed'
        out = normalize_sourcetype_clauses(query)
        self.assertIn('sourcetype="syslog"', out)
        self.assertNotIn("syslog)", out)

    def test_drops_invented_sourcetype(self) -> None:
        profile = {"sourcetype_to_indexes": {"auth.log": ["linux"], "syslog": ["linux"]}}
        query = 'search index=linux (sourcetype=auth.log OR sourcetype=auth-too_small OR sourcetype=syslog) failed'
        out = drop_invented_sourcetypes(query, profile=profile)
        self.assertIn('sourcetype="auth.log"', out)
        self.assertNotIn("auth-too_small", out)

    def test_normalize_writer_query_combined(self) -> None:
        profile = {"sourcetype_to_indexes": {"XmlWinEventLog": ["wineventlog"]}}
        query = "search index=wineventlog sourcetype=XmlWinEventLog) EventCode=4625"
        out = normalize_writer_query(query, profile=profile)
        self.assertIn('sourcetype="XmlWinEventLog"', out)
        self.assertNotIn("XmlWinEventLog)", out)


if __name__ == "__main__":
    unittest.main()
