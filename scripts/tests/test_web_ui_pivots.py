#!/usr/bin/env python3
"""Regression tests for structured investigation pivots."""

from __future__ import annotations

import sys
import types
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def _install_stub_modules() -> None:
    stubs: dict[str, types.ModuleType] = {}

    mod = types.ModuleType("langgraph_agentic_soc")
    mod.run_agentic_investigation = lambda *args, **kwargs: {}
    stubs["langgraph_agentic_soc"] = mod

    mod = types.ModuleType("langgraph_case_state")
    mod.bootstrap_graph_case_state = lambda *args, **kwargs: {}
    mod.snapshot_graph_case_state = lambda *args, **kwargs: {}
    stubs["langgraph_case_state"] = mod

    mod = types.ModuleType("langgraph_multi_model_soc")
    mod.describe_multi_model_graph = lambda *args, **kwargs: {}
    mod.run_multi_model_soc = lambda *args, **kwargs: {}
    stubs["langgraph_multi_model_soc"] = mod

    mod = types.ModuleType("local_learning")
    mod.ensure_learning_registry = lambda *args, **kwargs: None
    mod.generate_self_learn_candidates = lambda *args, **kwargs: {}
    mod.learning_registry_summary = lambda *args, **kwargs: {}
    mod.load_learning_progress = lambda *args, **kwargs: {}
    mod.set_learning_record_status = lambda *args, **kwargs: False
    stubs["local_learning"] = mod

    mod = types.ModuleType("minimal_question_to_answer")
    mod.map_question_to_template = lambda *args, **kwargs: types.SimpleNamespace(intent="failed_login_activity")
    mod.run_splunk_get_indexes = lambda *args, **kwargs: {}
    mod.run_splunk_get_info = lambda *args, **kwargs: {}
    mod.run_splunk_get_metadata = lambda *args, **kwargs: {}
    mod.run_splunk_query_args = lambda query_args, **kwargs: {
        "structured": {
            "results": [{"Computer": "Jupiter", "Image": "chrome.exe", "QueryName": "slackb.com"}],
            "total_rows": 1,
        }
    }
    mod.summarize_with_ollama_model = lambda *args, **kwargs: "summary"
    mod.template_to_query_args = lambda *args, **kwargs: {"query": "search index=test", "earliest_time": "-24h", "latest_time": "now"}
    stubs["minimal_question_to_answer"] = mod

    mod = types.ModuleType("ollama_log_stream")
    mod.RemoteLogSourceRegistry = type("RemoteLogSourceRegistry", (), {})
    mod.StreamParams = type("StreamParams", (), {})
    mod.format_sse = lambda *args, **kwargs: b""
    mod.get_remote_health_url = lambda *args, **kwargs: ""
    mod.redact_secrets = lambda value: value
    mod.role_allowed = lambda role: True
    stubs["ollama_log_stream"] = mod

    mod = types.ModuleType("environment_profile")
    mod.load_environment_profile = lambda *args, **kwargs: {}
    mod.suggest_domains_for_question = lambda *args, **kwargs: []
    stubs["environment_profile"] = mod

    mod = types.ModuleType("runtime_config")
    mod.DEFAULT_MODEL_AGENTIC_CONTINUATION_REVIEWER = "stub"
    mod.DEFAULT_MODEL_EVIDENCE_REVIEWER = "stub"
    mod.DEFAULT_MODEL_FINAL_SUMMARY = "stub"
    mod.DEFAULT_MODEL_PEER_REVIEWER = "stub"
    mod.DEFAULT_MODEL_PEER_REVIEWER_2 = "stub"
    mod.DEFAULT_MODEL_QUERY_PLANNER = "stub"
    mod.DEFAULT_MODEL_QUERY_REPAIR = "stub"
    mod.DEFAULT_MODEL_QUERY_WRITER = "stub"
    mod.DEFAULT_MODEL_SECURITY_REVIEWER = "stub"
    mod.UI_ENV_PATH = Path("/tmp/agtsmith-ui.env")
    mod.display_path = lambda path: str(path)
    mod.get_edge_llm_enabled = lambda: False
    mod.get_edge_llm_host = lambda: ""
    mod.get_edge_llm_model = lambda: ""
    mod.get_edge_llm_role = lambda: ""
    mod.get_edge_llm_timeout_sec = lambda: 30
    mod.get_ollama_host = lambda: ""
    mod.get_splunk_base_url = lambda: ""
    mod.get_splunk_mcp_url = lambda: ""
    mod.get_runtime_secret = lambda name, default="": default
    mod.parse_env_file = lambda path: ([], {})
    mod.write_env_file = lambda updates, path: None
    stubs["runtime_config"] = mod

    mod = types.ModuleType("case_store")
    mod.build_case_timeline = lambda *args, **kwargs: []
    mod.case_store_backend = lambda *args, **kwargs: "memory"
    mod.load_case = lambda *args, **kwargs: {}
    mod.load_case_node = lambda *args, **kwargs: {}
    mod.list_recent_cases = lambda *args, **kwargs: []
    mod.persist_case_result = lambda *args, **kwargs: {}
    stubs["case_store"] = mod

    for name, module in stubs.items():
        sys.modules[name] = module


_install_stub_modules()

import web_ui_server as wus


class WebUiPivotTests(unittest.TestCase):
    def test_dns_pivot_context_prefers_evidence_driven_candidates(self) -> None:
        result_body = {
            "intent": "windows_sysmon_dns_activity",
            "question": "Show Windows Sysmon DNS queries.",
            "query_args": {
                "query": "search index=botsv3 sourcetype=XmlWinEventLog Channel=\"Microsoft-Windows-Sysmon/Operational\" (EventID=22 OR QueryName=*) | table _time Computer Image QueryName QueryResults | head 20",
                "earliest_time": "0",
                "latest_time": "now",
            },
            "mitre_attack": {"next_pivots": ["Pivot to index inventory for broader visibility"]},
        }
        rows = [
            {"Computer": "Jupiter", "Image": "chrome.exe", "QueryName": "slackb.com", "QueryResults": "13.107.42.14"},
            {"Computer": "Jupiter", "Image": "chrome.exe", "QueryName": "slackb.com", "QueryResults": "13.107.42.14"},
            {"Computer": "Jupiter", "Image": "svchost.exe", "QueryName": "wpad", "QueryResults": "10.0.0.5"},
        ]
        context = wus._build_structured_pivot_context(result_body, rows)
        candidates = context["pivot_candidates"]
        self.assertGreaterEqual(len(candidates), 3)
        self.assertEqual(candidates[0]["target_type"], "dns_query")
        self.assertEqual(candidates[0]["execution_mode"], "deterministic_query")
        self.assertIn('QueryName="slackb.com"', candidates[0]["query_args"]["query"])
        self.assertEqual(candidates[1]["target_type"], "process_image")
        self.assertIn('match(_pivot_image, "(?i)(^|\\\\\\\\|/)(chrome\\.exe|svchost\\.exe)$")', candidates[1]["query_args"]["query"])

    def test_second_level_dns_pivot_can_build_from_first_pivot_query(self) -> None:
        base_query_args = {
            "query": "search index=botsv3 sourcetype=XmlWinEventLog Channel=\"Microsoft-Windows-Sysmon/Operational\" (EventID=22 OR QueryName=*) | table _time Computer Image QueryName QueryResults | search (QueryName=\"slackb.com\") | head 50",
            "earliest_time": "0",
            "latest_time": "now",
        }
        query_args = wus._build_deterministic_pivot_query_args(
            base_intent="windows_sysmon_dns_activity",
            pivot_kind="process_image_drilldown",
            target_type="process_image",
            target_values=["chrome.exe"],
            entities={"hosts": ["Jupiter"]},
            base_query_args=base_query_args,
        )
        self.assertIsNotNone(query_args)
        query = str(query_args["query"])
        self.assertIn('QueryName="slackb.com"', query)
        self.assertIn('match(_pivot_image, "(?i)(^|\\\\\\\\|/)(chrome\\.exe)$")', query)
        self.assertTrue(query.strip().endswith("| head 50"))

    def test_cloudtrail_pivot_context_prefers_principal_source_ip_and_service(self) -> None:
        result_body = {
            "intent": "aws_cloudtrail_activity",
            "question": "Show AWS CloudTrail API activity by source IP and principal.",
            "query_args": {
                "query": "search index=botsv3 sourcetype=aws:cloudtrail | stats count by eventSource eventName sourceIPAddress principal userAgent error_state | head 20",
                "earliest_time": "0",
                "latest_time": "now",
            },
        }
        rows = [
            {"eventSource": "iam.amazonaws.com", "eventName": "ConsoleLogin", "sourceIPAddress": "203.0.113.10", "principal": "arn:aws:iam::123456789012:user/demo-user", "userAgent": "signin.amazonaws.com", "error_state": "success"},
            {"eventSource": "iam.amazonaws.com", "eventName": "ConsoleLogin", "sourceIPAddress": "203.0.113.10", "principal": "arn:aws:iam::123456789012:user/demo-user", "userAgent": "signin.amazonaws.com", "error_state": "success"},
            {"eventSource": "s3.amazonaws.com", "eventName": "GetObject", "sourceIPAddress": "198.51.100.25", "principal": "arn:aws:iam::123456789012:role/demo-role", "userAgent": "aws-cli/2.0", "error_state": "AccessDenied"},
        ]
        context = wus._build_structured_pivot_context(result_body, rows)
        candidates = context["pivot_candidates"]
        self.assertEqual(candidates[0]["target_type"], "principal")
        self.assertIn('principal="arn:aws:iam::123456789012:user/demo-user"', candidates[0]["query_args"]["query"])
        self.assertEqual(candidates[1]["target_type"], "source_ip")
        self.assertIn('sourceIPAddress="203.0.113.10"', candidates[1]["query_args"]["query"])
        self.assertEqual(candidates[2]["target_type"], "service")
        self.assertIn('eventSource="iam.amazonaws.com"', candidates[2]["query_args"]["query"])

    def test_http_demo_pivot_context_prefers_site_source_ip_and_status(self) -> None:
        result_body = {
            "intent": "stream_http_activity",
            "question": "Show HTTP methods and sites.",
            "query_args": {
                "query": "search index=botsv3 sourcetype=stream:http | stats count by http_method status site src_ip | head 20",
                "earliest_time": "0",
                "latest_time": "now",
            },
        }
        rows = [
            {"http_method": "GET", "status": "200", "site": "cisco.com", "src_ip": "10.1.1.10"},
            {"http_method": "GET", "status": "200", "site": "cisco.com", "src_ip": "10.1.1.10"},
            {"http_method": "POST", "status": "404", "site": "slack.com", "src_ip": "10.1.1.20"},
            {"http_method": "GET", "status": "200", "site": "172.16.0.178", "src_ip": "10.1.1.30"},
        ]
        context = wus._build_structured_pivot_context(result_body, rows)
        candidates = context["pivot_candidates"]
        self.assertEqual(candidates[0]["target_type"], "site")
        self.assertIn('site="cisco.com"', candidates[0]["query_args"]["query"])
        self.assertNotIn("172.16.0.178", candidates[0]["target_values"])
        self.assertEqual(candidates[1]["target_type"], "source_ip")
        self.assertIn('src_ip="10.1.1.10"', candidates[1]["query_args"]["query"])
        self.assertEqual(candidates[2]["target_type"], "status")
        self.assertIn('status="200"', candidates[2]["query_args"]["query"])

    def test_second_level_context_avoids_repeating_parent_pivot_type(self) -> None:
        result_body = {
            "intent": "aws_cloudtrail_activity",
            "question": "Show AWS CloudTrail API activity by source IP and principal.",
            "query_args": {
                "query": "search index=botsv3 sourcetype=aws:cloudtrail | stats count by eventSource eventName sourceIPAddress principal userAgent error_state | head 20",
                "earliest_time": "0",
                "latest_time": "now",
            },
            "pivot_source": {
                "kind": "structured_pivot",
                "candidate": {
                    "target_type": "principal",
                    "target_label": "Principal",
                    "target_values": ["arn:aws:iam::123456789012:user/demo-user"],
                    "query_args": {
                        "query": "search index=botsv3 sourcetype=aws:cloudtrail | stats count by eventSource eventName sourceIPAddress principal userAgent error_state | search (principal=\"arn:aws:iam::123456789012:user/demo-user\") | head 50",
                        "earliest_time": "0",
                        "latest_time": "now",
                    },
                },
            },
        }
        rows = [
            {"eventSource": "iam.amazonaws.com", "eventName": "ConsoleLogin", "sourceIPAddress": "203.0.113.10", "principal": "arn:aws:iam::123456789012:user/demo-user", "userAgent": "signin.amazonaws.com", "error_state": "success"},
            {"eventSource": "s3.amazonaws.com", "eventName": "GetObject", "sourceIPAddress": "198.51.100.25", "principal": "arn:aws:iam::123456789012:user/demo-user", "userAgent": "aws-cli/2.0", "error_state": "AccessDenied"},
        ]
        context = wus._build_structured_pivot_context(result_body, rows)
        candidates = context["pivot_candidates"]
        self.assertGreaterEqual(len(candidates), 2)
        self.assertNotEqual(candidates[0]["target_type"], "principal")
        self.assertEqual(candidates[0]["target_type"], "source_ip")
        self.assertIn('sourceIPAddress="203.0.113.10"', candidates[0]["query_args"]["query"])
        self.assertNotIn("autoscaling.amazonaws.com", candidates[0]["target_values"])

    def test_http_playbook_prefers_new_dimension_after_two_levels(self) -> None:
        result_body = {
            "intent": "stream_http_activity",
            "question": "Pivot on the source IPs that generated this HTTP activity.",
            "query_args": {
                "query": "search index=botsv3 sourcetype=stream:http | stats count by http_method status site src_ip http_user_agent | search (site=\"cisco.com\") | search (src_ip=\"10.1.1.10\") | head 50",
                "earliest_time": "0",
                "latest_time": "now",
            },
            "pivot_source": {
                "kind": "structured_pivot",
                "candidate": {
                    "title": "Pivot on the source IPs that generated this HTTP activity.",
                    "target_type": "source_ip",
                    "target_label": "Source IP",
                    "target_values": ["10.1.1.10"],
                    "pivot_kind": "same_source_ip_followup",
                    "query_args": {
                        "query": "search index=botsv3 sourcetype=stream:http | stats count by http_method status site src_ip http_user_agent | search (site=\"cisco.com\") | search (src_ip=\"10.1.1.10\") | head 50",
                        "earliest_time": "0",
                        "latest_time": "now",
                    },
                },
            },
        }
        rows = [
            {"http_method": "GET", "status": "200", "site": "cisco.com", "src_ip": "10.1.1.10", "http_user_agent": "curl/8.0"},
            {"http_method": "GET", "status": "200", "site": "cisco.com", "src_ip": "10.1.1.10", "http_user_agent": "curl/8.0"},
            {"http_method": "POST", "status": "404", "site": "cisco.com", "src_ip": "10.1.1.10", "http_user_agent": "python-requests/2.31"},
        ]
        context = wus._build_structured_pivot_context(
            result_body,
            rows,
            prior_graph_state={
                "pivot_history": [
                    {
                        "title": "Pivot on the destination sites from this HTTP activity.",
                        "target_type": "site",
                        "target_label": "Site",
                        "target_values": ["cisco.com"],
                        "pivot_kind": "site_followup",
                        "signature": "site|site_followup|cisco.com",
                    }
                ]
            },
        )
        candidates = context["pivot_candidates"]
        self.assertGreaterEqual(len(candidates), 2)
        self.assertEqual(context["playbook"]["id"], "web_traffic_hunt")
        self.assertEqual(candidates[0]["target_type"], "user_agent")
        self.assertGreater(float(candidates[0]["score"]), float(candidates[1]["score"]))
        self.assertNotEqual(candidates[0]["target_type"], "site")
        self.assertNotEqual(candidates[0]["target_type"], "source_ip")

    def test_http_playbook_deduplicates_same_signature_candidates(self) -> None:
        result_body = {
            "intent": "stream_http_activity",
            "question": "Show HTTP methods and sites.",
            "query_args": {
                "query": "search index=botsv3 sourcetype=stream:http | stats count by http_method status site src_ip | head 20",
                "earliest_time": "0",
                "latest_time": "now",
            },
            "mitre_attack": {
                "next_pivots": [
                    "Pivot on the destination sites from this HTTP activity.",
                    "Pivot by destination site, user agent, and URI path to separate routine browsing from repeated suspicious HTTP behavior.",
                ]
            },
        }
        rows = [
            {"http_method": "GET", "status": "200", "site": "cisco.com", "src_ip": "10.1.1.10"},
            {"http_method": "GET", "status": "200", "site": "cisco.com", "src_ip": "10.1.1.10"},
        ]
        context = wus._build_structured_pivot_context(result_body, rows)
        site_candidates = [item for item in context["pivot_candidates"] if item["target_type"] == "site"]
        self.assertEqual(len(site_candidates), 1)


if __name__ == "__main__":
    unittest.main()
