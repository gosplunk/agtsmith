#!/usr/bin/env python3
"""Unit tests for SPL structure validation."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from spl_structure_validate import validate_structure  # noqa: E402


class SplStructureValidateTests(unittest.TestCase):
    def test_rejects_platform_mix(self) -> None:
        profile = {
            "sourcetype_to_indexes": {
                "XmlWinEventLog:Security": ["wineventlog"],
                "auth.log": ["os"],
            }
        }
        query = 'search index=main sourcetype="XmlWinEventLog:Security" auth.log failed'
        ok, reason = validate_structure(query, intent="failed_logins", profile=profile)
        self.assertFalse(ok)
        self.assertEqual(reason, "platform_mix_windows_linux")

    def test_accepts_valid_linux_query(self) -> None:
        profile = {"sourcetype_to_indexes": {"linux_secure": ["os"]}}
        query = 'search index=os sourcetype="linux_secure" failed | stats count by host'
        ok, reason = validate_structure(query, intent="failed_logins", profile=profile)
        self.assertTrue(ok)
        self.assertEqual(reason, "structure_ok")

    def test_rejects_invented_sourcetype(self) -> None:
        profile = {"sourcetype_to_indexes": {"linux_secure": ["os"]}}
        query = 'search index=main sourcetype="totally_made_up" | stats count'
        ok, reason = validate_structure(query, profile=profile)
        self.assertFalse(ok)
        self.assertTrue(reason.startswith("invented_sourcetype"))

    def test_accepts_sourcetype_at_parenthesized_clause_boundary(self) -> None:
        profile = {
            "sourcetype_to_indexes": {
                "auth.log": ["linux"],
                "auth-too_small": ["linux"],
                "syslog": ["linux"],
            }
        }
        query = (
            "search index=linux "
            "(sourcetype=auth.log OR sourcetype=auth-too_small OR sourcetype=syslog) "
            '"Failed password" | stats count by host'
        )
        ok, reason = validate_structure(query, intent="linux_auth_failures", profile=profile)
        self.assertTrue(ok)
        self.assertEqual(reason, "structure_ok")

    def test_cross_platform_mix_allowed(self) -> None:
        query = 'search index=linux sourcetype="auth.log" failed | append [search index=windows sourcetype="XmlWinEventLog" EventCode=4625] | stats count'
        ok, reason = validate_structure(
            query,
            intent="failed_login_activity",
            question="Show failed login evidence on windows and linux today.",
        )
        self.assertTrue(ok, reason)


if __name__ == "__main__":
    unittest.main()
