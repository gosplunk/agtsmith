#!/usr/bin/env python3
"""Tests for edge-LLM MCP pipeline router."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import mcp_deterministic_routing as mdr
import mcp_pipeline_router as mpr


class McpPipelineRouterTests(unittest.TestCase):
    def test_hard_veto_time_window_from_edge(self) -> None:
        router = {
            "route": "deterministic_mcp",
            "mcp_tool": "splunk_get_indexes",
            "needs_event_search": True,
            "needs_time_window": True,
            "confidence": 0.98,
            "reason": "index_inventory",
            "source": "edge_llm",
        }
        vetoed = mpr.apply_pipeline_hard_vetoes(router, "What indexes had data in the last 15 minutes?")
        self.assertTrue(vetoed["vetoed"])
        self.assertEqual(vetoed["route"], "llm_assisted")
        self.assertIn("needs_time_window", vetoed["veto_reasons"])

    def test_hard_veto_low_confidence(self) -> None:
        router = {
            "route": "deterministic_mcp",
            "mcp_tool": "splunk_get_indexes",
            "needs_event_search": False,
            "needs_time_window": False,
            "confidence": 0.5,
            "reason": "maybe_inventory",
            "source": "edge_llm",
        }
        with mock.patch("mcp_pipeline_router.mcp_deterministic_min_confidence", return_value=0.90):
            vetoed = mpr.apply_pipeline_hard_vetoes(router, "What indexes do I have access to?")
        self.assertTrue(vetoed["vetoed"])
        self.assertTrue(any("confidence_below" in v for v in vetoed["veto_reasons"]))

    def test_edge_llm_classify_parses_json(self) -> None:
        payload = {
            "response": json.dumps(
                {
                    "route": "deterministic_mcp",
                    "mcp_tool": "splunk_get_indexes",
                    "needs_event_search": False,
                    "needs_time_window": False,
                    "confidence": 0.95,
                    "reason": "index_inventory",
                }
            )
        }
        with mock.patch("mcp_pipeline_router.get_edge_llm_enabled", return_value=True):
            with mock.patch("mcp_pipeline_router.mcp_pipeline_router_enabled", return_value=True):
                with mock.patch("mcp_pipeline_router.get_edge_llm_model", return_value="gemma3:1b"):
                    with mock.patch("mcp_pipeline_router._post_json", return_value=payload):
                        out = mpr.classify_pipeline_with_edge_llm("What indexes do I have access to?")
        self.assertEqual(out["route"], "deterministic_mcp")
        self.assertEqual(out["mcp_tool"], "splunk_get_indexes")
        self.assertEqual(out["confidence"], 0.95)

    def test_edge_primary_blocks_keyword_upgrade_when_edge_says_llm(self) -> None:
        edge = {
            "route": "llm_assisted",
            "mcp_tool": "none",
            "needs_event_search": False,
            "needs_time_window": False,
            "confidence": 0.99,
            "reason": "custom_spl",
            "source": "edge_llm",
        }
        with mock.patch("mcp_pipeline_router.classify_pipeline_with_edge_llm", return_value=edge):
            pipeline, meta = mpr.resolve_pipeline_route("Show indexes available", "assisted", use_edge_llm=True)
        self.assertEqual(pipeline, "assisted")
        self.assertFalse(meta["auto_routed"])

    def test_edge_unavailable_falls_back_to_keyword(self) -> None:
        with mock.patch("mcp_pipeline_router.classify_pipeline_with_edge_llm", return_value={}):
            pipeline, meta = mpr.resolve_pipeline_route("Show indexes available", "assisted", use_edge_llm=True)
        self.assertEqual(pipeline, "deterministic")
        self.assertTrue(meta["auto_routed"])
        self.assertEqual(meta["router_method"], "edge_llm_unavailable_keyword_fallback")

    def test_resolve_mcp_chat_pipeline_delegates_to_router(self) -> None:
        with mock.patch("mcp_pipeline_router.classify_pipeline_with_edge_llm", return_value={}):
            pipeline, meta = mdr.resolve_mcp_chat_pipeline("What is the Splunk version?", "assisted")
        self.assertEqual(pipeline, "deterministic")
        self.assertTrue(meta["auto_routed"])

    def test_compare_routing_methods_shape(self) -> None:
        with mock.patch("mcp_pipeline_router.classify_pipeline_with_edge_llm", return_value={}):
            row = mpr.compare_routing_methods("What indexes do I have access to?")
        self.assertIn("keyword", row)
        self.assertIn("edge_resolved", row)
        self.assertEqual(row["keyword"]["pipeline"], "deterministic")


    def test_edge_vetoed_falls_back_to_keyword_when_safe(self) -> None:
        edge = {
            "route": "deterministic_mcp",
            "mcp_tool": "splunk_get_indexes",
            "needs_event_search": False,
            "needs_time_window": True,
            "confidence": 0.85,
            "reason": "host_list",
            "source": "edge_llm",
            "vetoed": True,
            "veto_reasons": ["needs_time_window"],
        }
        with mock.patch("mcp_pipeline_router.classify_pipeline_with_edge_llm", return_value=edge):
            with mock.patch(
                "mcp_pipeline_router.apply_pipeline_hard_vetoes",
                return_value=edge,
            ):
                pipeline, meta = mpr.resolve_pipeline_route("List hosts in my environment", "assisted", use_edge_llm=True)
        self.assertEqual(pipeline, "deterministic")
        self.assertEqual(meta["router_method"], "edge_llm_safe_keyword_fallback")

    def test_edge_contradiction_falls_back_to_keyword(self) -> None:
        edge = {
            "route": "llm_assisted",
            "mcp_tool": "none",
            "needs_event_search": False,
            "needs_time_window": False,
            "confidence": 0.99,
            "reason": "splunk_instance_info",
            "source": "edge_llm",
            "vetoed": False,
        }
        with mock.patch("mcp_pipeline_router.classify_pipeline_with_edge_llm", return_value=edge):
            with mock.patch(
                "mcp_pipeline_router.apply_pipeline_hard_vetoes",
                return_value=edge,
            ):
                pipeline, meta = mpr.resolve_pipeline_route("What is the Splunk version?", "assisted", use_edge_llm=True)
        self.assertEqual(pipeline, "deterministic")
        self.assertEqual(meta["router_method"], "edge_llm_safe_keyword_fallback")


if __name__ == "__main__":
    raise SystemExit(unittest.main())
