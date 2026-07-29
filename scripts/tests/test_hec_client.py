#!/usr/bin/env python3
"""Tests for HEC payload shape (raw vs structured events)."""

from __future__ import annotations

import json
import unittest
from unittest import mock

from lab_data.hec_client import HecClient, HecConfig


class HecClientPayloadTests(unittest.TestCase):
    def _capture_payload(self, **kwargs) -> dict:
        client = HecClient(HecConfig(url="https://127.0.0.1:8088/services/collector/event", token="test"))
        captured: dict = {}

        def fake_urlopen(req, timeout=30, context=None):
            captured["body"] = json.loads(req.data.decode("utf-8"))
            return mock.Mock(status=200, __enter__=lambda s: s, __exit__=mock.Mock())

        with mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
            client.send_event(**kwargs)
        return captured["body"]

    def test_raw_event_is_string_not_json_wrapper(self) -> None:
        line = '10.0.0.5 - - [28/Jul/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 1234'
        payload = self._capture_payload(
            index="botsv3",
            sourcetype="access_combined",
            host="agtsmith-lab-gen",
            source="/var/log/apache2/access.log",
            time_epoch=1.0,
            event=line,
            fields={"lab_data_source": "agtsmith_generator"},
        )
        self.assertIsInstance(payload["event"], str)
        self.assertEqual(payload["event"], line)
        self.assertEqual(payload["fields"]["lab_data_source"], "agtsmith_generator")

    def test_structured_event_stays_dict(self) -> None:
        event = {"EventCode": "4625", "TargetUserName": "alice"}
        payload = self._capture_payload(
            index="botsv3",
            sourcetype="XmlWinEventLog",
            host="agtsmith-lab-gen",
            source="WinEventLog:Security",
            time_epoch=1.0,
            event=event,
            fields={"lab_data_source": "agtsmith_generator"},
        )
        self.assertIsInstance(payload["event"], dict)
        self.assertEqual(payload["event"]["EventCode"], "4625")
        self.assertEqual(payload["event"]["lab_data_source"], "agtsmith_generator")


if __name__ == "__main__":
    unittest.main()
