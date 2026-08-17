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

    def test_preserves_closing_paren_after_bare_sourcetype(self) -> None:
        # Regression: a bare sourcetype token immediately before a closing paren
        # used to swallow the paren entirely, unbalancing the query.
        query = "search index=linux (sourcetype=auth.log OR sourcetype=syslog) failed"
        out = normalize_sourcetype_clauses(query)
        self.assertEqual(out.count("("), out.count(")"))
        self.assertIn('sourcetype="syslog")', out)

    def test_drops_unknown_sourcetype_from_or_list_without_dangling_or(self) -> None:
        # Regression: dropping the unknown alternative in an OR list used to
        # leave a dangling "OR )" / unbalanced parens instead of valid SPL.
        profile = {"sourcetype_to_indexes": {"splunkd": ["_internal"]}}
        query = (
            "search index=_internal (sourcetype=splunkd OR sourcetype=deploymentclient) "
            "| stats count by host sourcetype | sort - count"
        )
        out = drop_invented_sourcetypes(query, profile=profile)
        self.assertIn('sourcetype="splunkd"', out)
        self.assertNotIn("deploymentclient", out)
        self.assertNotIn(" OR )", out)
        self.assertNotIn("OR |", out)
        self.assertEqual(out.count("("), out.count(")"))

    def test_leaves_standalone_unknown_sourcetype_untouched(self) -> None:
        # A lone sourcetype (no OR alternative) has nothing to gracefully
        # degrade to, so it must be left for the structural hard-block.
        profile = {"sourcetype_to_indexes": {"linux_secure": ["os"]}}
        query = "search index=main sourcetype=totally_made_up | stats count"
        out = drop_invented_sourcetypes(query, profile=profile)
        self.assertIn('sourcetype="totally_made_up"', out)

    def test_leaves_all_unknown_or_list_untouched(self) -> None:
        # If every member of an OR list is unknown there's nothing valid to
        # fall back to, so the chain must be left intact for the hard-block.
        profile = {"sourcetype_to_indexes": {"splunkd": ["_internal"]}}
        query = "search index=_internal (sourcetype=unknown1 OR sourcetype=unknown2) | stats count"
        out = drop_invented_sourcetypes(query, profile=profile)
        self.assertIn('sourcetype="unknown1"', out)
        self.assertIn('sourcetype="unknown2"', out)

    def test_dedupes_after_hallucinated_sourcetype_remap(self) -> None:
        profile = {"sourcetype_to_indexes": {"auth.log": ["linux"], "syslog": ["linux"]}}
        query = (
            "search index=linux (sourcetype=auth.log OR sourcetype=auth-too_small "
            "OR sourcetype=syslog) failed"
        )
        out = drop_invented_sourcetypes(query, profile=profile)
        self.assertEqual(out.count('sourcetype="auth.log"'), 1)
        self.assertIn('sourcetype="syslog"', out)


if __name__ == "__main__":
    unittest.main()
