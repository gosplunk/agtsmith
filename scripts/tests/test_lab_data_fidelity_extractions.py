#!/usr/bin/env python3
"""Tests for lab search-time extraction installation."""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from lab_data.setup_fidelity_extractions import (  # noqa: E402
    PROPS_STANZAS,
    TRANSFORMS_STANZAS,
    _upsert_stanza,
    install,
)


class LabDataFidelityExtractionTests(unittest.TestCase):
    def test_required_sourcetypes_have_source_native_extraction_modes(self) -> None:
        self.assertIn("XmlWinEventLog", PROPS_STANZAS)
        self.assertEqual(PROPS_STANZAS["aws:cloudtrail"]["KV_MODE"], "json")
        self.assertEqual(
            PROPS_STANZAS["o365:management:activity"]["KV_MODE"],
            "json",
        )
        self.assertEqual(PROPS_STANZAS["stream:dns"]["KV_MODE"], "json")
        self.assertIn(
            "agtsmith_xml_eventdata",
            PROPS_STANZAS["XmlWinEventLog"]["REPORT-agtsmith_xml_fields"],
        )

    def test_dynamic_event_data_regex_accepts_realistic_quote_styles(self) -> None:
        pattern = re.compile(TRANSFORMS_STANZAS["agtsmith_xml_eventdata"]["REGEX"])
        for raw in (
            '<Data Name="TargetUserName">alice</Data>',
            "<Data Name='IpAddress'>10.0.0.55</Data>",
        ):
            match = pattern.search(raw)
            self.assertIsNotNone(match)
            self.assertEqual(len(match.groups()), 2)

    def test_upsert_creates_then_updates_stanza_values(self) -> None:
        with (
            mock.patch(
                "lab_data.setup_fidelity_extractions._stanza_exists",
                return_value=False,
            ),
            mock.patch(
                "lab_data.setup_fidelity_extractions._request",
                return_value={},
            ) as request,
        ):
            action = _upsert_stanza(
                "https://127.0.0.1:8089",
                {"Authorization": "REDACTED"},
                "props",
                "XmlWinEventLog",
                {"KV_MODE": "xml"},
            )
        self.assertEqual(action, "created")
        self.assertEqual(request.call_count, 2)
        self.assertEqual(
            request.call_args_list[-1].args[-1],
            {"KV_MODE": "xml"},
        )

    def test_dry_run_does_not_require_credentials_or_write(self) -> None:
        with mock.patch(
            "lab_data.setup_fidelity_extractions._upsert_stanza"
        ) as upsert:
            report = install(dry_run=True)
        self.assertTrue(report["dry_run"])
        self.assertEqual(report["props"]["XmlWinEventLog"], "planned")
        upsert.assert_not_called()


if __name__ == "__main__":
    unittest.main()
