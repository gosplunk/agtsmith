#!/usr/bin/env python3
"""Unit tests for field discovery helpers."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from spl_field_discovery import (  # noqa: E402
    _infer_roles_from_fields,
    _requested_plan_roles,
    discover_fields_for_plan,
    enrich_field_bind_with_discovery,
    should_run_field_discovery,
)


class SplFieldDiscoveryTests(unittest.TestCase):
    def test_infer_roles_maps_cloudtrail_fields(self) -> None:
        fields = [
            {"field": "eventName", "count": 10},
            {"field": "sourceIPAddress", "count": 8},
            {"field": "userIdentity.arn", "count": 5},
        ]
        roles = _infer_roles_from_fields(fields, intent="aws_cloudtrail_activity")
        self.assertIn("eventName", roles.get("action", []))
        self.assertIn("sourceIPAddress", roles.get("src_ip", []))

    def test_plan_disambiguates_dest_from_host(self) -> None:
        fields = [{"field": "host"}, {"field": "dest"}]
        roles = _infer_roles_from_fields(
            fields,
            requested_roles={"host", "dest_ip"},
        )
        self.assertEqual(roles["host"], ["host"])
        self.assertEqual(roles["dest_ip"], ["dest"])

    def test_auth_without_destination_plan_keeps_dest_host_compatibility(self) -> None:
        roles = _infer_roles_from_fields(
            [{"field": "dest"}],
            intent="linux_auth_failures",
            requested_roles={"host"},
        )
        self.assertEqual(roles["host"], ["dest"])

    def test_requested_roles_ignore_output_aliases(self) -> None:
        roles = _requested_plan_roles(
            {
                "analytical_plan": {
                    "analysis": {
                        "dimensions": ["src_ip"],
                        "measures": [
                            {
                                "name": "dest_values",
                                "function": "values",
                                "field": "dest",
                            }
                        ],
                        "output_fields": ["src_ip", "dest_values"],
                    }
                }
            }
        )
        self.assertEqual(roles, {"src_ip", "dest_ip"})

    def test_question_disambiguates_destination_even_with_canonical_resolver(self) -> None:
        roles = _requested_plan_roles(
            {"analytical_plan": {"analysis": {}}},
            question="Collect host and dest values for each source.",
        )
        self.assertEqual(roles, {"host", "dest_ip"})

    def test_should_run_on_cold_profile(self) -> None:
        bound = {"sourcetype": "auth.log", "field_hints": [], "intent": "linux_auth_failures"}
        profile = {"sourcetype_field_inventory": {"auth.log": {"fields": []}}}
        run, reason = should_run_field_discovery(bound, profile=profile)
        self.assertTrue(run)
        self.assertIn("cold", reason)

    def test_should_skip_when_profile_has_hints(self) -> None:
        bound = {
            "sourcetype": "access_combined",
            "field_hints": ["clientip", "status", "uri_path", "useragent"],
            "intent": "apache_access_top_ips",
        }
        profile = {
            "sourcetype_field_inventory": {
                "access_combined": {
                    "fields": [
                        {"field": "clientip"},
                        {"field": "status"},
                        {"field": "uri_path"},
                        {"field": "useragent"},
                    ]
                }
            }
        }
        run, reason = should_run_field_discovery(bound, profile=profile)
        self.assertFalse(run)
        self.assertEqual(reason, "profile_sufficient")

    def test_enrich_merges_coalesce_hints(self) -> None:
        bound = {"field_hints": ["clientip"]}
        discovery = {
            "discovered_fields": ["clientip", "status"],
            "coalesce_hints": {"src_ip": "clientip"},
            "role_mappings": {"src_ip": ["clientip"]},
            "source": "live_mcp",
            "field_count": 2,
            "roles_satisfied_ratio": 1.0,
            "duration_ms": 100,
        }
        merged = enrich_field_bind_with_discovery(bound, discovery)
        self.assertIn("status", merged.get("field_hints", []))
        self.assertEqual(merged.get("coalesce_hints", {}).get("src_ip"), "clientip")

    def test_discovery_uses_question_window_for_inventory_and_raw_probe(self) -> None:
        profile = {
            "sourcetype_to_indexes": {"access_combined": ["web"]},
            "sourcetype_field_inventory": {
                "access_combined": {"fields": []},
            },
        }
        with (
            patch(
                "spl_field_discovery._live_field_inventory",
                return_value=([{"field": "clientip", "count": 2}], ""),
            ) as inventory,
            patch(
                "spl_field_discovery._sample_raw_snippet",
                return_value="clientip=192.0.2.1",
            ) as raw_sample,
        ):
            discovery = discover_fields_for_plan(
                "Show Apache access activity in the last 24 hours",
                {"intent": "apache_access_top_ips"},
                profile=profile,
                bound={
                    "intent": "apache_access_top_ips",
                    "sourcetype": "access_combined",
                    "index_expr": "index=web",
                },
                live_probe=True,
            )

        inventory.assert_called_once_with(
            "access_combined",
            ["web"],
            sample_size=25,
            earliest_time="-24h",
            latest_time="now",
        )
        raw_sample.assert_called_once_with(
            "index=web",
            "access_combined",
            earliest_time="-24h",
            latest_time="now",
        )
        self.assertEqual(discovery["earliest_time"], "-24h")
        self.assertEqual(discovery["latest_time"], "now")


if __name__ == "__main__":
    unittest.main()
