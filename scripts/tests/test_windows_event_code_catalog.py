#!/usr/bin/env python3
"""Tests for Windows/Sysmon event code catalog."""

from __future__ import annotations

import unittest

from windows_event_code_catalog import (
    benchmark_cases_from_catalog,
    build_event_code_rag_context,
    build_event_code_reviewer_context,
    intents_for_question,
    lookup_by_event_code,
    lookup_by_intent,
    rag_tokens_for_intent,
)


class WindowsEventCodeCatalogTests(unittest.TestCase):
    def test_lookup_by_intent_4625(self) -> None:
        entry = lookup_by_intent("windows_auth_failures")
        self.assertIsNotNone(entry)
        assert entry is not None
        self.assertIn("4625", entry.get("event_codes", []))

    def test_lookup_by_event_code_sysmon_22(self) -> None:
        entry = lookup_by_event_code("22")
        self.assertIsNotNone(entry)
        assert entry is not None
        self.assertEqual(entry.get("intent"), "windows_sysmon_dns_activity")

    def test_intents_for_sysmon_dns_question(self) -> None:
        intents = intents_for_question("Show Windows Sysmon DNS queries in the last 24 hours")
        self.assertIn("windows_sysmon_dns_activity", intents)

    def test_rag_tokens_include_event_code(self) -> None:
        tokens = rag_tokens_for_intent("windows_process_audit_activity")
        self.assertIn("4688", tokens)

    def test_build_event_code_rag_context(self) -> None:
        ctx = build_event_code_rag_context(
            "Show Windows failed logon events",
            intent="windows_auth_failures",
        )
        self.assertIn("4625", ctx)
        self.assertIn("WINDOWS_EVENT_CODE_CATALOG", ctx)

    def test_build_event_code_reviewer_context(self) -> None:
        ctx = build_event_code_reviewer_context(
            question="Show Sysmon network connections",
            intent="windows_sysmon_network_activity",
        )
        self.assertEqual(ctx.get("event_code"), "3")
        self.assertIn("DestinationIp", ctx.get("expected_key_fields", []))

    def test_benchmark_cases_from_catalog(self) -> None:
        cases = benchmark_cases_from_catalog()
        self.assertIn("windows_sysmon_dns_22_24h", cases)
        self.assertGreaterEqual(len(cases), 8)


if __name__ == "__main__":
    unittest.main()
