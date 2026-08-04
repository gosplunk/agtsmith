#!/usr/bin/env python3
"""Tests for HEC payload shape (raw vs structured events)."""

from __future__ import annotations

import json
import unittest
from unittest import mock

from lab_data.hec_client import HecClient, HecConfig
from lab_data.receivers_client import ReceiversClient, ReceiversConfig


class HecClientPayloadTests(unittest.TestCase):
    def _capture_payload(self, **kwargs) -> dict:
        client = HecClient(HecConfig(url="https://127.0.0.1:8088/services/collector/event", token="test"))
        captured: dict = {}

        def fake_urlopen(req, timeout=30, context=None):
            captured["body"] = json.loads(req.data.decode("utf-8"))
            response = mock.MagicMock(status=200)
            response.read.return_value = b'{"text":"Success","code":0}'
            response.__enter__.return_value = response
            return response

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

    def test_http_200_with_hec_error_code_is_rejected(self) -> None:
        client = HecClient(HecConfig(url="https://127.0.0.1:8088/services/collector/event", token="test"))
        response = mock.MagicMock(status=200)
        response.read.return_value = b'{"text":"Incorrect index","code":7}'
        response.__enter__.return_value = response
        with mock.patch("urllib.request.urlopen", return_value=response):
            with self.assertRaisesRegex(RuntimeError, r"hec_rejected:7:Incorrect index"):
                client.send_event(
                    index="missing",
                    sourcetype="access_combined",
                    host="agtsmith-lab-gen",
                    source="/var/log/apache2/access.log",
                    time_epoch=1.0,
                    event="test",
                )

    def test_receivers_transport_refuses_to_corrupt_raw_xml_with_fields(self) -> None:
        client = ReceiversClient(
            ReceiversConfig(
                base_url="https://127.0.0.1:8089",
                user="",
                password="",
            )
        )
        with self.assertRaisesRegex(
            RuntimeError,
            "receivers_string_fields_unsupported",
        ):
            client.send_event(
                index="botsv3",
                sourcetype="XmlWinEventLog",
                host="WIN-TEST",
                source="XmlWinEventLog:Security",
                time_epoch=1.0,
                event="<Event></Event>",
                fields={"lab_data_source": "agtsmith_generator"},
            )


if __name__ == "__main__":
    unittest.main()
