#!/usr/bin/env python3
"""One-pass SPL repair helper with RAG + environment-aware deterministic validation."""

from __future__ import annotations

import json
import re
from typing import Any

import httpx

from environment_profile import validate_query_against_environment
from intent_field_contracts import validate_platform_sourcetype_coherence, validate_intent_platform_scope, validate_query_for_intent
from minimal_question_to_answer import OLLAMA_HOST, map_question_to_template, template_to_query_args
from ollama_client import call_ollama_json
from query_policy import validate_query_args
from spl_rag_context import build_spl_rag_context
from spl_writer_prompt import build_repair_system_prompt


def _extract_json_object(text: str) -> dict[str, Any]:
    if not text:
        raise ValueError("empty_model_text")
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```[a-zA-Z]*\s*", "", cleaned)
        cleaned = re.sub(r"\s*```$", "", cleaned)
    try:
        obj = json.loads(cleaned)
        if isinstance(obj, dict):
            return obj
    except Exception:
        pass
    match = re.search(r"\{[\s\S]*\}", cleaned)
    if not match:
        raise ValueError("json_object_not_found")
    obj = json.loads(match.group(0))
    if not isinstance(obj, dict):
        raise ValueError("json_object_not_dict")
    return obj


def _normalize_query_args(args: dict[str, Any]) -> dict[str, Any]:
    src = dict(args if isinstance(args, dict) else {})
    out: dict[str, Any] = {}
    query = str(src.get("query", "")).strip()
    if not query and "search" in src:
        query = str(src.get("search", "")).strip()
    if query and not query.lower().startswith("search "):
        query = f"search {query}"
    out["query"] = query
    out["earliest_time"] = str(src.get("earliest_time", "")).strip() or "-7d"
    latest = str(src.get("latest_time", "")).strip() or "now"
    out["latest_time"] = "now" if latest.lower() == "now()" else latest
    try:
        rl = int(src.get("row_limit", 10))
    except Exception:
        rl = 10
    out["row_limit"] = max(1, min(200, rl))
    return out


def _validate_query(args: dict[str, Any], *, question: str, intent: str = "") -> tuple[bool, str]:
    ok, reason = validate_query_args(args, question=question)
    if not ok:
        return False, f"policy:{reason}"
    env_ok, env_reason = validate_query_against_environment(args)
    if not env_ok:
        return False, f"environment:{env_reason}"
    intent_name = (intent or "").strip()
    if not intent_name:
        template = map_question_to_template(question)
        intent_name = str(getattr(template, "intent", "") or "").strip()
    if intent_name:
        contract_ok, contract_reason = validate_query_for_intent(
            intent_name,
            args,
            question=question,
        )
        if not contract_ok:
            return False, f"intent:{contract_reason}"
        query_text = str(args.get("query", "")).strip()
        coherent, coherence_reason = validate_platform_sourcetype_coherence(query_text, intent_name)
        if not coherent:
            return False, f"coherence:{coherence_reason}"
        scope_ok, scope_reason = validate_intent_platform_scope(query_text, intent_name, question=question)
        if not scope_ok:
            return False, f"scope:{scope_reason}"
    return True, "query_valid"


def attempt_query_repair_once(
    *,
    question: str,
    failed_query_args: dict[str, Any],
    failure_reason: str,
    model: str,
    intent: str = "",
    rag_max_chars: int = 1600,
    timeout: float = 180.0,
) -> dict[str, Any]:
    """Try one model-assisted repair pass, then deterministic template fallback."""
    candidate = _normalize_query_args(failed_query_args if isinstance(failed_query_args, dict) else {})
    intent_name = (intent or "").strip()
    if not intent_name:
        intent_name = str(getattr(map_question_to_template(question), "intent", "") or "").strip()
    rag_context = build_spl_rag_context(question, intent=intent_name, max_chars=rag_max_chars)
    template_args = template_to_query_args(map_question_to_template(question), question)
    system = build_repair_system_prompt(intent=intent_name)
    payload = {
        "question": question,
        "intent": intent_name,
        "failure_reason": failure_reason,
        "failed_query_args": candidate,
        "canonical_template_query": str(template_args.get("query", "")).strip(),
        "constraints": {
            "query_must_start_with_search": True,
            "earliest_time_required": True,
            "latest_time_required": True,
            "row_limit_max": 200,
            "read_only_only": True,
            "environment_binding_required": True,
        },
        "rag_context": rag_context,
    }
    prompt = (
        f"{system}\n\n"
        "Return strict JSON only. No prose.\n\n"
        f"INPUT:\n{json.dumps(payload, indent=2)}"
    )
    model_error = ""
    coherence_failed = "coherence" in str(failure_reason).lower() or "platform_coherence" in str(failure_reason).lower()
    try:
        repaired = call_ollama_json(model=model, system_prompt=system, user_payload=payload, timeout=timeout)
        raw = str(repaired.get("_raw_text_preview", ""))
        repaired_args = _normalize_query_args(repaired)
        ok, reason = _validate_query(repaired_args, question=question, intent=intent_name)
        if ok:
            return {
                "ok": True,
                "args": repaired_args,
                "model": model,
                "repair_reason": str(repaired.get("repair_reason", "model_repair_pass")),
                "validation_reason": reason,
                "source": "model_repair",
                "raw_preview": raw[:600],
            }
        model_error = f"model_repair_invalid:{reason}"
        coherence_failed = reason.startswith("coherence:") or reason.startswith("intent:platform_coherence")
    except Exception as exc:
        model_error = f"model_repair_exception:{type(exc).__name__}:{exc}"
        coherence_failed = "coherence" in str(failure_reason).lower() or "platform_coherence" in str(failure_reason).lower()

    # Deterministic fallback if model repair fails or platform coherence is still broken.
    template_args = _normalize_query_args(template_to_query_args(map_question_to_template(question), question))
    ok, reason = _validate_query(template_args, question=question, intent=intent_name)
    if ok:
        return {
            "ok": True,
            "args": template_args,
            "model": "deterministic_template_fallback",
            "repair_reason": f"template_fallback_after_{model_error or 'model_repair_failure'}",
            "validation_reason": reason,
            "source": "template_fallback_repair",
            "raw_preview": "",
        }
    if coherence_failed or reason.startswith("coherence:") or reason.startswith("intent:platform_coherence"):
        return {
            "ok": False,
            "args": template_args,
            "model": model,
            "repair_reason": f"template_fallback_still_incoherent:{reason}",
            "validation_reason": reason,
            "source": "template_fallback_incoherent",
            "raw_preview": "",
        }
    return {
        "ok": False,
        "args": candidate,
        "model": model,
        "repair_reason": model_error or "repair_failed",
        "validation_reason": reason,
        "source": "repair_failed",
        "raw_preview": "",
    }
