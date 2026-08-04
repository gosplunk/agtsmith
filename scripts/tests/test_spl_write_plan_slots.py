#!/usr/bin/env python3
"""Tests for WritePlan slot filling from field discovery."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from spl_query_schema import AnalyticalPlan, WritePlan, materialize_write_plan
from spl_write_plan_slots import (
    apply_analytical_field_bindings,
    apply_field_bind_slots,
    group_by_from_role_mappings,
)


class WritePlanSlotTests(unittest.TestCase):
    def test_injects_eval_from_coalesce_hints(self) -> None:
        plan = WritePlan(
            index_expr="index=soc_linux",
            sourcetype="access_combined",
            group_by=["clientip", "status"],
            aggregation="count",
        )
        field_bind = {
            "coalesce_hints": {"src_ip": "clientip", "status": "status"},
            "role_mappings": {"src_ip": ["clientip"], "status": ["status"]},
        }
        updated = apply_field_bind_slots(plan, field_bind)
        query = materialize_write_plan(updated)
        self.assertIn("eval clientip=clientip", query)
        self.assertIn("stats count", query)

    def test_group_by_from_role_mappings(self) -> None:
        field_bind = {
            "role_mappings": {
                "src_ip": ["clientip"],
                "status": ["status"],
                "user": ["userIdentity.arn"],
            }
        }
        fields = group_by_from_role_mappings(field_bind, intent="aws_cloudtrail_activity")
        self.assertIn("clientip", fields)
        self.assertIn("status", fields)

    def test_strategy_mappings_override_untrusted_field_hints(self) -> None:
        plan = WritePlan(
            index_expr="index=linux",
            sourcetype="access_combined",
            group_by=["clientip"],
            aggregation="count",
        )
        field_bind = {
            "coalesce_hints": {"src_ip": "coalesce(unverified_src,clientip)"},
            "role_mappings": {"src_ip": ["unverified_src"]},
        }
        strategy = {
            "trusted_coalesce_hints": {"src_ip": "coalesce(clientip,src)"},
            "trusted_role_mappings": {"src_ip": ["clientip", "src"]},
        }
        updated = apply_field_bind_slots(plan, field_bind, field_strategy=strategy)
        query = materialize_write_plan(updated)
        self.assertIn("eval clientip=coalesce(clientip,src)", query)
        self.assertNotIn("unverified_src", query)
        self.assertEqual(
            group_by_from_role_mappings(field_bind, field_strategy=strategy),
            ["clientip"],
        )

    def test_binds_verified_fields_into_analytical_plan(self) -> None:
        plan = AnalyticalPlan.from_dict(
            {
                "version": "1.0",
                "datasets": [{"index": "linux", "sourcetype": "access_combined"}],
                "normalizations": [
                    {
                        "output": "src_ip",
                        "kind": "rex",
                        "fields": ["_raw"],
                        "source_field": "_raw",
                        "pattern": "(?<src_ip>\\S+)",
                    }
                ],
                "analysis": {
                    "dimensions": ["src_ip"],
                    "measures": [{"name": "events", "function": "count"}],
                },
            }
        )
        strategy = {
            "roles": {
                "src_ip": {
                    "trusted_fields": ["clientip", "src"],
                    "classification": "alias_coalesce",
                }
            },
            "raw_parse_required": False,
        }
        updated = apply_analytical_field_bindings(plan, strategy)
        self.assertEqual(updated.normalizations[0].kind, "coalesce")
        self.assertEqual(updated.normalizations[0].fields, ["clientip", "src"])
        self.assertEqual(plan.normalizations[0].kind, "rex")

    def test_preserves_required_raw_fallback_binding(self) -> None:
        plan = AnalyticalPlan.from_dict(
            {
                "version": "1.0",
                "datasets": [{"index": "main", "sourcetype": "aws:vpcflow"}],
                "normalizations": [
                    {
                        "output": "src_ip",
                        "kind": "rex",
                        "fields": ["_raw"],
                        "source_field": "_raw",
                        "pattern": "(?<src_ip>\\S+)",
                    }
                ],
                "analysis": {
                    "dimensions": ["src_ip"],
                    "measures": [{"name": "events", "function": "count"}],
                },
            }
        )
        updated = apply_analytical_field_bindings(
            plan,
            {
                "roles": {"src_ip": {"trusted_fields": ["src_ip"]}},
                "raw_parse_required": True,
            },
        )
        self.assertEqual(updated.normalizations[0].kind, "rex")

    def test_binds_operation_role_to_event_name_alias(self) -> None:
        plan = AnalyticalPlan.from_dict(
            {
                "version": "1.0",
                "datasets": [{"index": "aws_prod", "sourcetype": "aws:cloudtrail"}],
                "analysis": {
                    "dimensions": ["operation"],
                    "measures": [
                        {
                            "name": "operation_values",
                            "function": "values",
                            "field": "eventName",
                        }
                    ],
                    "output_fields": ["operation", "operation_values"],
                },
            }
        )
        updated = apply_analytical_field_bindings(
            plan,
            {"roles": {"operation": {"trusted_fields": ["eventName"]}}},
        )
        self.assertEqual(updated.normalizations[0].output, "operation")
        self.assertEqual(updated.normalizations[0].fields, ["eventName"])

    def test_rewrites_ip_role_alias_to_bound_native_output(self) -> None:
        plan = AnalyticalPlan.from_dict(
            {
                "version": "1.0",
                "datasets": [{"index": "main", "sourcetype": "netstat"}],
                "normalizations": [
                    {"output": "dest", "kind": "native", "fields": ["dest"]}
                ],
                "analysis": {
                    "dimensions": ["src_ip"],
                    "measures": [
                        {"name": "dest_values", "function": "values", "field": "dest_ip"}
                    ],
                    "intersections": [
                        {"name": "intersection_events", "fields": ["host", "dest_ip"]}
                    ],
                    "output_fields": ["src_ip", "dest_values", "intersection_events"],
                },
            }
        )
        updated = apply_analytical_field_bindings(plan, {"roles": {}})
        self.assertEqual(updated.measures[0]["field"], "dest_ip")
        self.assertEqual(updated.intersections[0]["fields"][1], "dest_ip")
        self.assertEqual(updated.normalizations[-1].output, "dest_ip")
        self.assertEqual(updated.normalizations[-1].fields, ["dest"])


if __name__ == "__main__":
    unittest.main()
