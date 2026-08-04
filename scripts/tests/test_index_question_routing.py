#!/usr/bin/env python3
"""Unit tests for review_profile routing across question types."""

from __future__ import annotations

import importlib
import sys
from pathlib import Path
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

DEFAULT_INDEX_QUESTION = "Which indexes have data in the last hour?"
FAILED_LOGIN_QUESTION = "Show failed login activity in the last 24 hours"
OPERATIONAL_QUESTION = "Show top source IPs in apache access logs in the last 24 hours"
DEFAULT_MODEL_SECURITY = "hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q8_0-GGUF:latest"
DEFAULT_MODEL_ANALYST = "TechyShishy/ministral-3:3b-reasoning-2512-q4_K_M"


def _ensure_real_routing_modules() -> None:
    """Reload routing modules when earlier UI layout tests installed stubs."""
    for module_name in ("minimal_question_to_answer", "langgraph_minimal_flow"):
        module = sys.modules.get(module_name)
        if module is not None and not getattr(module, "__file__", None):
            del sys.modules[module_name]
    import langgraph_minimal_flow  # noqa: WPS433
    import minimal_question_to_answer  # noqa: WPS433

    importlib.reload(langgraph_minimal_flow)
    importlib.reload(minimal_question_to_answer)


class IndexQuestionRoutingTests(unittest.TestCase):
    def setUp(self) -> None:
        _ensure_real_routing_modules()
        from langgraph_minimal_flow import determine_splunk_tool
        from minimal_question_to_answer import map_question_to_template, template_to_query_args
        from question_intelligence import infer_time_window

        self.determine_splunk_tool = determine_splunk_tool
        self.map_question_to_template = map_question_to_template
        self.template_to_query_args = template_to_query_args
        self.infer_time_window = infer_time_window

    def test_default_index_question_maps_to_top_indexes_intent(self) -> None:
        template = self.map_question_to_template(DEFAULT_INDEX_QUESTION)
        self.assertEqual(template.intent, "top_indexes")

    def test_default_index_question_uses_run_query_not_get_indexes(self) -> None:
        template = self.map_question_to_template(DEFAULT_INDEX_QUESTION)
        tool, reason, _meta, _mode = self.determine_splunk_tool(DEFAULT_INDEX_QUESTION, template.intent)
        self.assertEqual(tool, "splunk_run_query")
        self.assertIn("time_bounded", reason)

    def test_default_index_question_builds_stats_spl_with_last_hour(self) -> None:
        template = self.map_question_to_template(DEFAULT_INDEX_QUESTION)
        args = self.template_to_query_args(template, DEFAULT_INDEX_QUESTION, apply_environment=False)
        query = str(args.get("query", ""))
        self.assertIn("stats", query.lower())
        self.assertIn("by index", query.lower())
        self.assertNotIn("tstats", query.lower())
        self.assertTrue(query.lower().startswith("search "))
        self.assertEqual(args.get("earliest_time"), "-1h")
        self.assertEqual(args.get("latest_time"), "now")
        self.assertEqual(self.infer_time_window(DEFAULT_INDEX_QUESTION), ("-1h", "now"))

    def test_how_many_indexes_uses_distinct_index_count_not_event_total(self) -> None:
        question = "how many indexes do I have in this splunk environment?"
        template = self.map_question_to_template(question)
        self.assertEqual(template.intent, "top_indexes")
        tool, reason, _, _ = self.determine_splunk_tool(question, template.intent)
        self.assertEqual(tool, "splunk_get_indexes")
        self.assertIn("index_inventory", reason)
        args = self.template_to_query_args(template, question, apply_environment=False)
        query = str(args.get("query", "")).lower()
        self.assertIn("dc(index)", query)
        self.assertNotRegex(query, r"\|\s*stats\s+count\s*$")


class ReviewProfileRoutingIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        _ensure_real_routing_modules()
        import langgraph_multi_model_soc as mm

        self.mm = mm

    def _run_with_fake_ollama(
        self,
        question: str,
        *,
        planner_intent: str | None = None,
        expect_security: bool = False,
        expect_analyst: bool = False,
    ) -> tuple[dict, list[str], list[dict]]:
        models_called: list[str] = []
        progress_events: list[dict] = []

        def fake_ollama(*, model: str, system_prompt: str, user_payload: dict) -> dict:
            models_called.append(model)
            prompt = system_prompt.lower()
            if "planning model" in prompt:
                from minimal_question_to_answer import map_question_to_template

                tpl = map_question_to_template(question)
                intent = planner_intent or tpl.intent
                return {
                    "intent": intent,
                    "intent_summary": intent,
                    "selected_tool": "splunk_run_query",
                    "search_strategy_summary": "test plan",
                    "likely_indexes": [],
                    "likely_sourcetypes": [],
                    "likely_fields": [],
                    "constraints": ["read_only_only"],
                    "tool_args": {"earliest_time": "-24h", "latest_time": "now", "row_limit": 50},
                    "confidence": 0.9,
                    "reason": "test",
                    "caveats": [],
                }
            if "writer" in prompt and "evidence" not in prompt and "validator" not in prompt and "reviewer / critic" not in prompt:
                from minimal_question_to_answer import map_question_to_template, template_to_query_args

                tpl = map_question_to_template(question)
                return {
                    "selected_tool": "splunk_run_query",
                    "tool_args": template_to_query_args(tpl, question),
                    "confidence": 0.9,
                    "reason": "test",
                    "caveats": [],
                }
            if "operational spl validator" in prompt:
                return {
                    "approved": True,
                    "confidence": 0.9,
                    "issues": [],
                    "revised_tool_args": user_payload.get("writer_output", {}).get("tool_args", {}),
                    "rationale": "spl ok",
                    "caveats": [],
                }
            if "reviewer / critic" in prompt or "security" in prompt:
                return {
                    "approved": True,
                    "confidence": 0.9,
                    "issues": [],
                    "improvements": [],
                    "revised_selected_tool": "splunk_run_query",
                    "revised_tool_args": user_payload.get("writer_output", {}).get("tool_args", {}),
                    "rationale": "security ok",
                    "caveats": [],
                }
            if "evidence reviewer" in prompt:
                return {
                    "confidence": 0.8,
                    "evidence_quality": "good",
                    "key_findings": ["rows_returned=1"],
                    "anomalies": [],
                    "gaps": [],
                    "recommendation": "continue",
                }
            if "soc analyst assistant" in prompt:
                return "- finding one\n- finding two\n- finding three\n- finding four"
            raise AssertionError(f"unexpected model invocation: {model} / {prompt[:80]}")

        def progress_cb(node: str, pct: int, label: str, title: str, skipped: bool = False) -> None:
            progress_events.append(
                {"node": node, "pct": pct, "label": label, "title": title, "skipped": skipped}
            )

        with patch.object(self.mm, "_call_ollama_json", side_effect=fake_ollama), patch.object(
            self.mm,
            "run_splunk_query_args",
            return_value={"structured": {"results": [{"index": "main", "count": 5}], "total_rows": 1}, "raw": ""},
        ), patch.object(
            self.mm,
            "_summarize_with_timeout",
            side_effect=AssertionError("summary model should not run"),
        ):
            app = self.mm.build_graph()
            result = self.mm._invoke_multi_model_graph(
                app,
                {"question": question},
                progress_cb=progress_cb,
            )

        if expect_security:
            self.assertTrue(
                any(DEFAULT_MODEL_SECURITY in model or "Foundation-Sec" in model for model in models_called),
                f"expected Foundation-Sec in call chain: {models_called}",
            )
        else:
            self.assertFalse(
                any(DEFAULT_MODEL_SECURITY in model or "Foundation-Sec" in model for model in models_called),
                f"Foundation-Sec should not run: {models_called}",
            )
        if expect_analyst:
            self.assertTrue(
                any(DEFAULT_MODEL_ANALYST in model or "ministral" in model.lower() for model in models_called),
                f"expected ministral analyst model: {models_called}",
            )
        return result, models_called, progress_events

    def test_index_question_metadata_profile_skips_security(self) -> None:
        result, _models, progress_events = self._run_with_fake_ollama(DEFAULT_INDEX_QUESTION)
        output = result.get("output", {}) if isinstance(result.get("output"), dict) else {}
        self.assertEqual(output.get("review_profile"), "metadata")
        self.assertIn("security_review", output.get("skipped_nodes") or result.get("skipped_nodes") or [])
        self.assertEqual(result.get("security_review_duration_ms", 0), 0)
        workflow_models = [
            str(entry.get("model", ""))
            for entry in (output.get("model_workflow") or [])
            if isinstance(entry, dict)
        ]
        self.assertFalse(any("Foundation-Sec" in model for model in workflow_models))
        skipped_security_events = [
            event for event in progress_events if event.get("node") == "security_review" and event.get("skipped")
        ]
        self.assertTrue(skipped_security_events)

    def test_failed_login_question_security_profile_runs_security_review(self) -> None:
        result, models_called, _events = self._run_with_fake_ollama(
            FAILED_LOGIN_QUESTION,
            expect_security=True,
        )
        output = result.get("output", {}) if isinstance(result.get("output"), dict) else {}
        self.assertEqual(output.get("review_profile"), "security")
        self.assertGreater(result.get("security_review_duration_ms", 0), 0)
        self.assertNotIn("security_review", output.get("skipped_nodes") or [])

    def test_operational_question_uses_analyst_evidence_review(self) -> None:
        result, models_called, _events = self._run_with_fake_ollama(
            OPERATIONAL_QUESTION,
            expect_analyst=True,
        )
        output = result.get("output", {}) if isinstance(result.get("output"), dict) else {}
        self.assertEqual(output.get("review_profile"), "operational")
        self.assertIn("security_review", output.get("skipped_nodes") or [])
        evidence_output = output.get("evidence_reviewer_output") or {}
        self.assertIn(
            evidence_output.get("source", ""),
            {"analyst_evidence_reviewer_model", "analyst_evidence_reviewer_model_fallback"},
        )


if __name__ == "__main__":
    unittest.main()
