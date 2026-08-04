#!/usr/bin/env python3
"""Shared SPL writer prompts with intent-matched few-shot gold examples.

Used by LangGraph writer/repair nodes and model-spl-eval so the small local
model learns structure from canonical templates instead of being bypassed.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from minimal_question_to_answer import map_question_to_template, template_to_query_args
from query_templates import TEMPLATES, QueryTemplate
from spl_query_schema import constrained_mode_enabled, constrained_writer_schema_hint

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SPL_CASES = PROJECT_ROOT / "benchmarks" / "spl_cases.json"

WRITER_COMPOSITION_RULES = (
    "SPL composition rules (mandatory):\n"
    "1. tool_args.query MUST start with 'search ' (never bare SPL).\n"
    "2. Put earliest_time and latest_time in tool_args — NOT inside query text.\n"
    "2a. Preserve an explicit question time range; when none is stated, use earliest_time=-7d and latest_time=now.\n"
    "3. Bind indexes and sourcetypes from canonical_template_query and resolved_domain_hints.\n"
    "4. Do not invent indexes, sourcetypes, or fields absent from hints/canonical.\n"
    "5. Prefer | stats, | timechart, or | table matching the canonical ending command.\n"
    "6. Read-only only: no delete, outputlookup, sendemail, collect, or map.\n"
    "7. row_limit must be 1–200.\n"
    "8. For cross-platform auth intents, preserve Linux and Windows branches with | append [ search ... ].\n"
    "9. Never mix Windows EventCode=4625 with Linux-only sourcetypes like linux_secure.\n"
    "10. Always quote sourcetypes: sourcetype=\"name\" — never bare sourcetype=name) inside OR groups.\n"
    "11. field_strategy is authoritative: use trusted native fields first, then trusted coalesce aliases, "
    "then spath for structured JSON, and rex only as the stated fallback.\n"
    "12. When field_strategy.forbid_unnecessary_extraction is true, do not rex fields listed as trusted native.\n"
    "13. For Apache questions, preserve every required_output_role from the question profile in the final stats/table "
    "and include an actual where/search predicate when suspicious criteria are required.\n"
    "14. Return strict JSON only — no markdown fences or prose."
)

WRITER_OUTPUT_SCHEMA = (
    "Return strict JSON with keys: selected_tool, tool_args, confidence, reason, caveats.\n"
    "When selected_tool is splunk_run_query, tool_args must include: "
    "query, earliest_time, latest_time, row_limit."
)

REPAIR_OUTPUT_SCHEMA = (
    "Return strict JSON with keys: query, earliest_time, latest_time, row_limit, repair_reason."
)

ANALYTICAL_PLAN_OUTPUT_SCHEMA = (
    "For splunk_run_query, analytical_plan is a mandatory top-level key and must use this exact shape: "
    '{"version":"1.0","datasets":[{"index":"name-or-*","sourcetype":"optional",'
    '"platform":"optional","filters":[{"field":"name","operator":"eq|neq|lt|lte|gt|gte|in|not_in|'
    'exists|not_exists|contains|prefix|suffix","value":"literal"}]}],'
    '"normalizations":[{"output":"canonical_field","kind":"native|coalesce|rex|spath",'
    '"fields":["trusted_field"],"source_field":"_raw","pattern":"","path":""}],'
    '"analysis":{"dimensions":[],"measures":[{"name":"events","function":"count|dc|sum|avg|min|max|'
    'values|list|earliest|latest|first|last","field":"required_except_count",'
    '"condition":{"field":"canonical_field","operator":"eq|neq|lt|lte|gt|gte|in|not_in|'
    'exists|not_exists|contains|prefix|suffix","value":"literal"}|null}],'
    '"post_aggregation_predicates":[],"time_bin":{"field":"_time","span":"5m","alias":"time_bucket"}|null,'
    '"ratios":[{"name":"error_pct","numerator":"error_events","denominator":"total_events",'
    '"scale":100,"zero_policy":"null|zero"}],'
    '"intersections":[{"name":"shared_values","fields":["left_values","right_values"]}],'
    '"ranking":[{"field":"events","direction":"asc|desc","limit":10}],'
    '"output_fields":[]},"execution":{"earliest":"-7d","latest":"now","row_limit":100,'
    '"materialization":"bounded"}}. '
    "Use only literals stated in the question or supplied context. Words naming output functions such as "
    "'counts' or 'values' are not filter literals. Explicit question index/sourcetype locks are immutable. "
    "Use function dc for cardinality/distinct/unique counts; never emit a function named cardinality. "
    "Dataset index and sourcetype are separate values, never an index/sourcetype combined string. "
    "Every ratio numerator and denominator must exactly name an earlier measure. Every ranking and output "
    "field must exactly name a dimension, measure, intersection, ratio, or time-bin alias declared in the plan. "
    "Ranking limits and execution row_limit must be integers from 1 through 200. "
    "Treat question_shape_hints as a preservation contract: carry forward every requested grouping dimension, "
    "conditional measure, collected values/list measure, intersection/overlap, ratio, time bin, ranking, "
    "threshold, and output field. Do not collapse a multi-operation request into a plain count or a single "
    "dimension. A phrase such as collect/retain observed values plus both/overlap requires values/list "
    "measures and an intersections entry; a percentage/share/rate requires a ratio over declared measures. "
    "A minimal valid analysis always has at least one measure or output field. Example: "
    '{"analytical_plan":{"version":"1.0","datasets":[{"index":"web","sourcetype":"access_combined",'
    '"platform":"web","filters":[]}],"normalizations":[{"output":"src_ip","kind":"native",'
    '"fields":["clientip"],"source_field":"_raw","pattern":"","path":""}],'
    '"analysis":{"dimensions":["src_ip"],"measures":[{"name":"events","function":"count",'
    '"field":"","condition":null}],"post_aggregation_predicates":[],"time_bin":null,"ratios":[],'
    '"intersections":[],"ranking":[{"field":"events","direction":"desc","limit":10}],'
    '"output_fields":["src_ip","events"]},"execution":{"earliest":"-7d","latest":"now",'
    '"row_limit":100,"materialization":"bounded"}}}.'
)


def build_analytical_planner_system_prompt(base_prompt: str) -> str:
    """Extend the legacy planner contract with optional typed analytical output."""
    return "\n\n".join(
        [
            base_prompt,
            "On the typed primary path, plan analytical operations; do not write free-form SPL. "
            "The analytical_plan key is required for every splunk_run_query response even if the legacy "
            "key list in the base contract omits it.",
            "question_shape_hints is deterministic structural guidance, not optional prose. Preserve its "
            "non-empty elements in analytical_plan before choosing fields or compiling SPL.",
            ANALYTICAL_PLAN_OUTPUT_SCHEMA,
        ]
    )


def build_analytical_plan_repair_system_prompt() -> str:
    """Prompt for the one allowed structured plan repair attempt."""
    return "\n\n".join(
        [
            "You repair a typed read-only Splunk AnalyticalPlan. Return strict JSON with the single key "
            "analytical_plan. Do not return SPL, prose, or a changed dataset lock. Correct only the supplied "
            "schema/contract errors and preserve requested analytical structure. Restore any missing "
            "conditional measures, value collections, intersections, ratios, time bins, comparisons, "
            "rankings, thresholds, and output fields indicated by question_shape_hints.",
            ANALYTICAL_PLAN_OUTPUT_SCHEMA,
        ]
    )


def _truncate_query(query: str, *, max_len: int = 520) -> str:
    text = " ".join(str(query or "").split())
    if len(text) <= max_len:
        return text
    stats_idx = text.lower().rfind("| stats ")
    timechart_idx = text.lower().rfind("| timechart ")
    table_idx = text.lower().rfind("| table ")
    tail_idx = max(stats_idx, timechart_idx, table_idx)
    if tail_idx > 80:
        head_budget = max(120, max_len - 80)
        return text[:head_budget].rstrip() + " ... " + text[tail_idx:].lstrip()
    return text[: max_len - 3].rstrip() + "..."


def _template_few_shot(template: QueryTemplate, question: str, *, max_query_len: int = 520) -> dict[str, Any]:
    args = template_to_query_args(template, question)
    return {
        "intent": template.intent,
        "question": question,
        "selected_tool": "splunk_run_query",
        "tool_args": {
            "query": _truncate_query(str(args.get("query", "")), max_len=max_query_len),
            "earliest_time": str(args.get("earliest_time", template.earliest_time)),
            "latest_time": str(args.get("latest_time", template.latest_time)),
            "row_limit": int(args.get("row_limit", template.row_limit)),
        },
    }


def _intent_templates(intent: str) -> list[QueryTemplate]:
    intent_l = str(intent or "").strip().lower()
    if not intent_l:
        return []
    exact = [t for t in TEMPLATES if t.intent == intent_l]
    if exact:
        return exact
    return [t for t in TEMPLATES if intent_l in t.intent or t.intent in intent_l]


@lru_cache(maxsize=1)
def _cases_by_intent() -> dict[str, str]:
    if not DEFAULT_SPL_CASES.exists():
        return {}
    try:
        rows = json.loads(DEFAULT_SPL_CASES.read_text(encoding="utf-8"))
    except Exception:
        return {}
    out: dict[str, str] = {}
    if not isinstance(rows, list):
        return out
    for row in rows:
        if not isinstance(row, dict):
            continue
        intent = str(row.get("expected_intent", "")).strip()
        question = str(row.get("question", "")).strip()
        if intent and question and intent not in out:
            out[intent] = question
    return out


def _example_question_for_template(template: QueryTemplate) -> str:
    from_cases = _cases_by_intent().get(template.intent, "").strip()
    if from_cases:
        return from_cases
    if template.keywords:
        kw = template.keywords[0].replace("_", " ")
        return f"Investigate {kw} in the last 24 hours."
    return f"Run a read-only {template.intent.replace('_', ' ')} search."


def few_shot_examples_for_intent(intent: str, *, max_examples: int = 2) -> list[dict[str, Any]]:
    """Return compact gold writer examples for the requested intent."""
    intent_l = str(intent or "").strip().lower()
    chosen: list[QueryTemplate] = []
    for template in _intent_templates(intent_l):
        if template not in chosen:
            chosen.append(template)
        if len(chosen) >= max_examples:
            break
    if not chosen and intent_l:
        mapped = map_question_to_template(_cases_by_intent().get(intent_l, intent_l.replace("_", " ")))
        if mapped.intent not in {t.intent for t in chosen}:
            chosen.append(mapped)
    if len(chosen) < max_examples:
        for template in TEMPLATES:
            if template in chosen:
                continue
            if intent_l and any(tag in intent_l for tag in template.tags):
                chosen.append(template)
            if len(chosen) >= max_examples:
                break
    examples: list[dict[str, Any]] = []
    for template in chosen[:max_examples]:
        examples.append(
            _template_few_shot(template, _example_question_for_template(template), max_query_len=320)
        )
    return examples


def format_few_shot_block(examples: list[dict[str, Any]]) -> str:
    if not examples:
        return ""
    lines = ["Few-shot gold examples (preserve structure; adapt filters only when the question requires it):"]
    for idx, example in enumerate(examples, start=1):
        lines.append(f"\nExample {idx} — intent={example.get('intent', '')}:")
        lines.append(f"Question: {example.get('question', '')}")
        lines.append("Output JSON:")
        lines.append(json.dumps(example, indent=2, ensure_ascii=False))
    return "\n".join(lines)


def build_writer_system_prompt(*, intent: str = "", max_few_shots: int = 2) -> str:
    examples = few_shot_examples_for_intent(intent, max_examples=max_few_shots)
    parts = [
        "You are the SPL writer in a guarded Splunk SOC workflow.",
        "Convert the structured search plan into executable read-only Splunk tool args.",
        "Optimize for syntactic correctness, command ordering, and field/index binding.",
        "When canonical_template_query is supplied, treat it as the anchor shape.",
        "When resolved_domain_hints are supplied, bind indexes and sourcetypes to those domains only.",
        "Do not widen scope beyond the canonical template unless the question explicitly requires it.",
        WRITER_COMPOSITION_RULES,
        WRITER_OUTPUT_SCHEMA,
    ]
    if constrained_mode_enabled():
        parts.append(constrained_writer_schema_hint())
    few_shot = format_few_shot_block(examples)
    if few_shot:
        parts.append(few_shot)
    return "\n\n".join(parts)


def build_writer_user_payload(
    *,
    question: str,
    planner_output: dict[str, Any],
    canonical_template_query: str = "",
    resolved_domain_hints: dict[str, Any] | list[Any] | str | None = None,
    rag_context: str = "",
    field_bind_output: dict[str, Any] | None = None,
    field_strategy_output: dict[str, Any] | None = None,
    domain_knowledge_output: dict[str, Any] | None = None,
) -> dict[str, Any]:
    from question_intelligence import infer_analytical_shape_hints

    intent = str(planner_output.get("intent", "")).strip()
    if not canonical_template_query:
        mapped = map_question_to_template(question)
        if mapped.intent == intent or not intent:
            canonical_template_query = str(template_to_query_args(mapped, question).get("query", ""))
    payload: dict[str, Any] = {
        "question": question,
        "planner_output": planner_output,
        "question_shape_hints": infer_analytical_shape_hints(question),
        "canonical_template_query": _truncate_query(canonical_template_query, max_len=900),
        "resolved_domain_hints": resolved_domain_hints or {},
    }
    from apache_intent import apache_intent_profile

    apache_profile = apache_intent_profile(question)
    if apache_profile.get("intent"):
        payload["apache_intent_contract"] = apache_profile
    if rag_context:
        payload["rag_context"] = rag_context
    if field_bind_output:
        payload["field_bind_output"] = field_bind_output
        if field_bind_output.get("index_expr"):
            payload["bound_index_expr"] = field_bind_output.get("index_expr")
        if field_bind_output.get("sourcetype"):
            payload["bound_sourcetype"] = field_bind_output.get("sourcetype")
        if field_bind_output.get("field_hints"):
            payload["bound_field_hints"] = field_bind_output.get("field_hints")
        if field_bind_output.get("coalesce_hints"):
            payload["coalesce_hints"] = field_bind_output.get("coalesce_hints")
        if field_bind_output.get("role_mappings"):
            payload["role_mappings"] = field_bind_output.get("role_mappings")
        if field_bind_output.get("raw_sample_snippet"):
            payload["raw_sample_snippet"] = str(field_bind_output.get("raw_sample_snippet", ""))[:400]
        if field_bind_output.get("interesting_field_examples"):
            payload["interesting_field_examples"] = field_bind_output.get("interesting_field_examples")
    if field_strategy_output:
        from spl_field_strategy import strategy_prompt_payload

        payload["field_strategy"] = strategy_prompt_payload(field_strategy_output)
    if domain_knowledge_output and domain_knowledge_output.get("matched"):
        payload["domain_knowledge"] = {
            "pattern_id": domain_knowledge_output.get("pattern_id"),
            "preferred_tool": domain_knowledge_output.get("preferred_tool"),
            "canonical_query": _truncate_query(str(domain_knowledge_output.get("query", "")), max_len=900),
            "guidance": domain_knowledge_output.get("explanation", ""),
            "anti_patterns": domain_knowledge_output.get("anti_patterns", [])[:4],
        }
        if str(domain_knowledge_output.get("context", "")).strip():
            payload["domain_oracle_context"] = str(domain_knowledge_output.get("context", ""))[:900]
    try:
        from sourcetype_cards import cards_for_question, format_cards_context

        cards_ctx = format_cards_context(cards_for_question(question, intent=intent, max_cards=2), max_chars=700)
        if cards_ctx:
            payload["sourcetype_cards"] = cards_ctx
    except Exception:
        pass
    checklist = []
    if intent:
        checklist.append(f"intent={intent}")
    if canonical_template_query:
        for token in re.findall(r"(index=\S+|sourcetype=\S+)", canonical_template_query, flags=re.IGNORECASE)[:6]:
            checklist.append(f"preserve:{token}")
    for role in apache_profile.get("roles", []):
        checklist.append(f"required_output_role={role}")
    if apache_profile.get("suspicious_required"):
        checklist.append("require_meaningful_suspicious_predicate=true")
    ending = ""
    lower = canonical_template_query.lower()
    for cmd in ("| stats ", "| timechart ", "| table "):
        if cmd in lower:
            ending = cmd.strip()
            break
    if ending:
        checklist.append(f"ending_command={ending}")
    if checklist:
        payload["writer_checklist"] = checklist
    return payload


def build_repair_system_prompt(*, intent: str = "") -> str:
    examples = few_shot_examples_for_intent(intent, max_examples=1)
    parts = [
        "You are a Splunk SPL repair assistant.",
        "Repair the query so it remains read-only and passes strict policy, environment, and intent coherence checks.",
        WRITER_COMPOSITION_RULES,
        REPAIR_OUTPUT_SCHEMA,
    ]
    few_shot = format_few_shot_block(examples)
    if few_shot:
        parts.append(few_shot)
    return "\n\n".join(parts)


def build_standalone_writer_system_prompt(*, intent: str = "", max_few_shots: int = 1) -> str:
    """Prompt for evaluate_spl_writer_models / RAG A/B (flat query JSON output)."""
    examples = few_shot_examples_for_intent(intent, max_examples=max_few_shots)
    flat_examples: list[dict[str, Any]] = []
    for row in examples:
        tool_args = row.get("tool_args", {}) if isinstance(row.get("tool_args"), dict) else {}
        flat_examples.append(
            {
                "query": tool_args.get("query", ""),
                "earliest_time": tool_args.get("earliest_time", "-7d"),
                "latest_time": tool_args.get("latest_time", "now"),
                "row_limit": tool_args.get("row_limit", 10),
            }
        )
    parts = [
        "You are a Splunk SPL writer for a read-only SOC lab.",
        WRITER_COMPOSITION_RULES,
        "Return strict JSON only with keys: query, earliest_time, latest_time, row_limit.",
        "Do NOT wrap the answer in intent/question fields. Output only the four keys above.",
    ]
    if constrained_mode_enabled():
        parts.append(constrained_writer_schema_hint())
        parts.append("When constrained, emit write_plan and the evaluator will materialize SPL.")
    if flat_examples:
        parts.append("Example output shape (adapt query to the TASK; do not copy verbatim unless it matches):")
        parts.append(json.dumps(flat_examples[0], indent=2, ensure_ascii=False))
    return "\n\n".join(parts)


def build_standalone_writer_user_payload(
    question: str,
    *,
    intent: str = "",
    rag_context: str = "",
) -> dict[str, Any]:
    mapped = map_question_to_template(question)
    resolved_intent = intent or mapped.intent
    payload: dict[str, Any] = {
        "task": question,
        "intent_hint": resolved_intent,
        "canonical_anchor_query": _truncate_query(
            str(template_to_query_args(mapped, question).get("query", "")),
            max_len=700,
        ),
    }
    if rag_context:
        payload["rag_context"] = rag_context
    return payload
