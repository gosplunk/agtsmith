#!/usr/bin/env python3
"""Regression tests for production-shaped synthetic lab events."""

from __future__ import annotations

import json
import random
import re
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from lab_data.config import load_event_catalog  # noqa: E402
from lab_data_generate import _build_events_for_set, generate  # noqa: E402


class LabDataGenerateTests(unittest.TestCase):
    def setUp(self) -> None:
        catalog = load_event_catalog()
        self.defaults = catalog["defaults"]
        self.event_sets = catalog["event_sets"]

    def _build(self, name: str, *, count: int = 1, seed: int = 42) -> list[dict]:
        rows = _build_events_for_set(
            self.event_sets[name],
            layout_name="expanded_lab",
            count=count,
            hours=1,
            defaults=self.defaults,
            rng=random.Random(seed),
        )
        self.assertEqual(len(rows), count)
        return rows

    def test_all_catalog_events_render_without_placeholders(self) -> None:
        self.assertEqual(len(self.event_sets), 29)
        for name in self.event_sets:
            with self.subTest(event_set=name):
                row = self._build(name)[0]
                rendered = (
                    json.dumps(row["event"], sort_keys=True)
                    if isinstance(row["event"], dict)
                    else str(row["event"])
                )
                self.assertNotRegex(rendered, r"\{[A-Za-z_][A-Za-z0-9_]*\}")
                self.assertEqual(
                    row["fields"],
                    {
                        "lab_data_source": "agtsmith_generator",
                        "lab_data_version": "fidelity_v2",
                    },
                )

    def test_windows_xml_uses_native_system_and_event_data_names(self) -> None:
        event = self._build("win_4625")[0]["event"]
        self.assertIsInstance(event, str)
        for fragment in (
            '<Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}"/>',
            "<EventID>4625</EventID>",
            "<EventRecordID>",
            "<Execution ProcessID=",
            "<Channel>Security</Channel>",
            '<Data Name="TargetUserName">',
            '<Data Name="IpAddress">',
            '<Data Name="IpPort">',
            '<Data Name="Status">0xC000006D</Data>',
            '<Data Name="SubStatus">',
        ):
            self.assertIn(fragment, event)
        self.assertNotIn("Source_Network_Address", event)
        self.assertNotIn("lab_data_source", event)

    def test_xml_semantic_fields_are_not_duplicated_as_hec_fields(self) -> None:
        row = self._build("win_5379")[0]
        event = row["event"]
        self.assertEqual(row["index"], "botsv3")
        self.assertEqual(row["sourcetype"], "XmlWinEventLog")
        self.assertEqual(row["source"], "XmlWinEventLog:Security")
        self.assertIn('<Data Name="TargetName">', event)
        self.assertIn('<Data Name="CountOfCredentialsReturned">', event)
        self.assertNotIn("TargetName", row["fields"])
        self.assertNotIn("EventID", row["fields"])

    def test_security_4688_uses_native_field_names(self) -> None:
        event = self._build("win_4688")[0]["event"]
        for field in ("NewProcessName", "CommandLine", "ParentProcessName", "NewProcessId"):
            self.assertIn(f'<Data Name="{field}">', event)
        for synthetic_name in ("New_Process_Name", "Process_Command_Line", "Creator_Process_Name"):
            self.assertNotIn(synthetic_name, event)

    def test_sysmon_fixtures_include_correlation_fields(self) -> None:
        process = self._build("win_sysmon_process")[0]["event"]
        for field in (
            "UtcTime",
            "ProcessGuid",
            "ProcessId",
            "Image",
            "CommandLine",
            "Hashes",
            "ParentProcessGuid",
            "ParentProcessId",
            "ParentImage",
        ):
            self.assertIn(f'<Data Name="{field}">', process)

        network = self._build("win_sysmon_network")[0]["event"]
        for field in (
            "ProcessGuid",
            "ProcessId",
            "User",
            "Initiated",
            "SourceHostname",
            "DestinationHostname",
            "DestinationPortName",
        ):
            self.assertIn(f'<Data Name="{field}">', network)

    def test_sysmon_dns_status_and_results_are_coherent(self) -> None:
        events = [row["event"] for row in self._build("win_sysmon_dns", count=30)]
        self.assertTrue(any('<Data Name="QueryStatus">0</Data>' in event for event in events))
        self.assertTrue(any('<Data Name="QueryStatus">9003</Data>' in event for event in events))
        for event in events:
            if '<Data Name="QueryStatus">9003</Data>' in event:
                self.assertIn('<Data Name="QueryResults"></Data>', event)
            else:
                self.assertRegex(event, r'<Data Name="QueryResults">type: 1 [^<]+;</Data>')

    def test_raw_log_families_use_source_native_envelopes(self) -> None:
        ssh = self._build("linux_failed_ssh")[0]
        self.assertRegex(
            ssh["event"],
            r"^[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2} [\w-]+ sshd\[\d+\]: ",
        )
        self.assertIn(str(ssh["host"]), ssh["event"])

        syslog = self._build("linux_syslog")[0]
        self.assertRegex(
            syslog["event"],
            r"^<\d+>1 \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z [\w-]+ ",
        )

        apache_error = self._build("apache_error_soc")[0]["event"]
        self.assertRegex(
            apache_error,
            r"^\[[A-Z][a-z]{2} [A-Z][a-z]{2} \d{2} \d{2}:\d{2}:\d{2}\.\d{6} \d{4}\] "
            r"\[[a-z_]+:error\] \[pid \d+:tid \d+\] \[client [^]]+\] AH\d{5}: ",
        )

    def test_linux_privilege_scenarios_cover_realistic_su_and_sudoers_events(
        self,
    ) -> None:
        success = self._build("linux_su_success")[0]
        failure = self._build("linux_su_failure")[0]
        non_sudoer = self._build("linux_non_sudoer")[0]
        for row in (success, failure, non_sudoer):
            self.assertEqual(row["host"], "linux-host-b")
            self.assertRegex(
                row["event"],
                r"^[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2} linux-host-b ",
            )
        self.assertIn("agtsmith_test", success["event"])
        self.assertRegex(
            failure["event"],
            r"(pam_unix\(su:auth\): authentication failure|FAILED SU)",
        )
        self.assertIn("NOT in sudoers", non_sudoer["event"])

    def test_raw_and_structured_timestamps_match_hec_time(self) -> None:
        apache = self._build("apache_access")[0]
        apache_match = re.search(r"\[([^]]+)\]", apache["event"])
        self.assertIsNotNone(apache_match)
        apache_time = datetime.strptime(
            apache_match.group(1),
            "%d/%b/%Y:%H:%M:%S %z",
        ).timestamp()
        self.assertLess(abs(apache_time - apache["time_epoch"]), 1.1)

        windows = self._build("win_4625")[0]
        xml_match = re.search(r'<TimeCreated SystemTime="([^"]+)"/>', windows["event"])
        self.assertIsNotNone(xml_match)
        xml_time = datetime.fromisoformat(xml_match.group(1).replace("Z", "+00:00")).timestamp()
        self.assertLess(abs(xml_time - windows["time_epoch"]), 0.01)

        for name, field in (
            ("stream_dns_query", "timestamp"),
            ("aws_cloudtrail_api", "eventTime"),
            ("o365_management_activity", "CreationTime"),
        ):
            row = self._build(name)[0]
            raw_time = datetime.fromisoformat(row["event"][field].replace("Z", "+00:00")).timestamp()
            self.assertLess(abs(raw_time - row["time_epoch"]), 0.01)

    def test_explicit_time_range_bounds_every_generated_timestamp(self) -> None:
        start_time = 1_700_000_000.0
        end_time = start_time + 3600.0
        rows = _build_events_for_set(
            self.event_sets["stream_dns_query"],
            layout_name="expanded_lab",
            count=100,
            hours=999,
            defaults=self.defaults,
            rng=random.Random(42),
            start_time=start_time,
            end_time=end_time,
        )
        self.assertEqual(len(rows), 100)
        for row in rows:
            self.assertGreaterEqual(row["time_epoch"], start_time)
            self.assertLessEqual(row["time_epoch"], end_time)
            embedded = datetime.fromisoformat(
                row["event"]["timestamp"].replace("Z", "+00:00")
            ).timestamp()
            self.assertLess(abs(embedded - row["time_epoch"]), 0.01)

    def test_generate_reports_selected_explicit_range(self) -> None:
        start_time = 1_700_000_000.0
        end_time = start_time + 7200.0
        with mock.patch("lab_data_generate._pick_transport", return_value="hec"):
            report = generate(
                layout="expanded_lab",
                count=3,
                hours=6,
                event_sets=["linux_failed_ssh"],
                dry_run=True,
                start_time=start_time,
                end_time=end_time,
            )
        self.assertEqual(report["hours"], 2)
        self.assertEqual(
            report["time_range"],
            {
                "mode": "explicit",
                "start_epoch": start_time,
                "end_epoch": end_time,
                "start_utc": "2023-11-14T22:13:20+00:00",
                "end_utc": "2023-11-15T00:13:20+00:00",
                "span_hours": 2,
            },
        )
        for row in report["sample_events"]:
            self.assertGreaterEqual(row["time_epoch"], start_time)
            self.assertLessEqual(row["time_epoch"], end_time)

    def test_explicit_time_range_requires_ordered_finite_bounds(self) -> None:
        for start_time, end_time, reason in (
            (1_700_000_000, None, "explicit_time_range_requires_start_and_end"),
            (float("inf"), 1_700_000_001, "invalid_explicit_time_range"),
            (1_700_000_001, 1_700_000_000, "time_range_start_must_precede_end"),
        ):
            with self.subTest(reason=reason):
                with self.assertRaisesRegex(ValueError, reason):
                    _build_events_for_set(
                        self.event_sets["linux_failed_ssh"],
                        layout_name="expanded_lab",
                        count=1,
                        hours=1,
                        defaults=self.defaults,
                        rng=random.Random(42),
                        start_time=start_time,
                        end_time=end_time,
                    )

    def test_stream_dns_matches_stream_json_shape(self) -> None:
        events = [row["event"] for row in self._build("stream_dns_query", count=30)]
        for event in events:
            self.assertIsInstance(event["query"], list)
            self.assertIsInstance(event["query_type"], list)
            self.assertIn("src_ip", event)
            self.assertIn("dest_ip", event)
            self.assertIn("src_port", event)
            self.assertEqual(event["dest_port"], 53)
            self.assertIn(event["reply_code"], {"NoError", "NXDomain"})
            if event["reply_code"] == "NXDomain":
                self.assertEqual(event["answer"], [])
            else:
                self.assertTrue(event["answer"])

    def test_cloudtrail_scenarios_are_service_action_coherent(self) -> None:
        events = [row["event"] for row in self._build("aws_cloudtrail_api", count=60)]
        allowed = {
            ("iam.amazonaws.com", "ListUsers"),
            ("s3.amazonaws.com", "PutObject"),
            ("ec2.amazonaws.com", "RunInstances"),
        }
        for event in events:
            self.assertIn((event["eventSource"], event["eventName"]), allowed)
            for field in (
                "eventVersion",
                "eventTime",
                "awsRegion",
                "requestID",
                "eventID",
                "eventType",
                "managementEvent",
                "recipientAccountId",
                "eventCategory",
            ):
                self.assertIn(field, event)
            identity = event["userIdentity"]
            self.assertTrue(identity["arn"].endswith("/" + identity["userName"]))
            self.assertFalse(identity["accessKeyId"].startswith(("AKIA", "ASIA")))
            if event["eventName"] == "RunInstances":
                self.assertEqual(event["errorCode"], "Client.UnauthorizedOperation")
                self.assertIn("instancesSet", event["requestParameters"])

    def test_o365_scenarios_do_not_mix_workload_specific_fields(self) -> None:
        events = [row["event"] for row in self._build("o365_management_activity", count=60)]
        allowed = {
            ("SharePoint", "FileDownloaded"),
            ("Exchange", "Set-Mailbox"),
            ("AzureActiveDirectory", "Add member to group."),
        }
        for event in events:
            self.assertIn((event["Workload"], event["Operation"]), allowed)
            for field in (
                "CreationTime",
                "Id",
                "OrganizationId",
                "RecordType",
                "ResultStatus",
                "UserKey",
                "UserType",
                "Version",
                "UserId",
                "CorrelationId",
            ):
                self.assertIn(field, event)
            if event["Workload"] == "SharePoint":
                self.assertIn("SiteUrl", event)
                self.assertIn("SourceFileName", event)
            else:
                self.assertNotIn("SiteUrl", event)
                self.assertNotIn("SourceFileName", event)

    def test_apache_raw_event_matches_access_combined_shape(self) -> None:
        row = self._build("apache_access")[0]
        self.assertEqual(row["index"], "botsv3")
        self.assertEqual(row["sourcetype"], "access_combined")
        self.assertRegex(
            row["event"],
            re.compile(
                r'^\S+ - - \[\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} \+0000\] '
                r'"GET \S+ HTTP/1\.1" 200 \d+ "[^"]*" "[^"]+"$'
            ),
        )

    def test_unresolved_placeholder_is_rejected(self) -> None:
        invalid = {
            "domain": "windows_auth_test",
            "benchmark_case": "invalid",
            "format": "json",
            "source": "test",
            "payload": {"TargetUserName": "{missing_value}"},
            "fields": {},
        }
        with self.assertRaisesRegex(
            ValueError,
            r"event_set_unresolved_placeholders:invalid:missing_value",
        ):
            _build_events_for_set(
                invalid,
                layout_name="expanded_lab",
                count=1,
                hours=1,
                defaults=self.defaults,
                rng=random.Random(42),
            )

    def test_explicit_unknown_or_unmapped_event_set_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "unknown_event_sets:not_real"):
            generate(
                layout="expanded_lab",
                count=1,
                hours=1,
                event_sets=["not_real"],
                dry_run=True,
            )
        with self.assertRaisesRegex(
            ValueError,
            "event_set_domain_not_in_layout:aws_cloudtrail_api:aws_cloudtrail:existing_lab",
        ):
            generate(
                layout="existing_lab",
                count=1,
                hours=1,
                event_sets=["aws_cloudtrail_api"],
                dry_run=True,
            )


if __name__ == "__main__":
    unittest.main()
