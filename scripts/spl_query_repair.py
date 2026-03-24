#!/usr/bin/env python3
"""One-pass SPL repair helper with RAG + environment-aware deterministic validation."""

from __future__ import annotations

import json
import re
from typing import Any

import httpx

from environment_profile import validate_query_against_environment
from minimal_question_to_answer import OLLAMA_HOST, map_question_to_template, template_to_query_args
from query_policy import validate_query_args
from spl_rag_context import build_spl_rag_context


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
    out["earliest_time"] = str(src.get("earliest_time", "")).strip() or "-24h"
    latest = str(src.get("latest_time", "")).strip() or "now"
    out["latest_time"] = "now" if latest.lower() == "now()" else latest
    try:
        rl = int(src.get("row_limit", 10))
    except Exception:
        rl = 10
    out["row_limit"] = max(1, min(200, rl))
    return out


def _validate_query(args: dict[str, Any], *, question: str) -> tuple[bool, str]:
    ok, reason = validate_query_args(args, question=question)
    if not ok:
        return False, f"policy:{reason}"
    env_ok, env_reason = validate_query_against_environment(args)
    if not env_ok:
        return False, f"environment:{env_reason}"
    return True, "query_valid"


def attempt_query_repair_once(
    *,
    question: str,
    failed_query_args: dict[str, Any],
    failure_reason: str,
    model: str,
    rag_max_chars: int = 1600,
    timeout: float = 180.0,
) -> dict[str, Any]:
    """Try one model-assisted repair pass, then deterministic template fallback."""
    candidate = _normalize_query_args(failed_query_args if isinstance(failed_query_args, dict) else {})
    rag_context = build_spl_rag_context(question, max_chars=rag_max_chars)
    system = (
        "You are a Splunk SPL repair assistant. "
        "Repair the query so it remains read-only and passes strict policy+environment checks. "
        "Return strict JSON only with keys: query, earliest_time, latest_time, row_limit, repair_reason."
    )
    payload = {
        "question": question,
        "failure_reason": failure_reason,
        "failed_query_args": candidate,
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
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.post(
                f"{OLLAMA_HOST}/api/generate",
                json={"model": model, "prompt": prompt, "stream": False, "think": False},
            )
            resp.raise_for_status()
            body = resp.json()
        raw = str(body.get("response") or "").strip()
        repaired = _extract_json_object(raw)
        repaired_args = _normalize_query_args(repaired)
        ok, reason = _validate_query(repaired_args, question=question)
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
    except Exception as exc:
        model_error = f"model_repair_exception:{type(exc).__name__}:{exc}"

    # Deterministic fallback if model repair fails.
    template_args = _normalize_query_args(template_to_query_args(map_question_to_template(question), question))
    ok, reason = _validate_query(template_args, question=question)
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
    return {
        "ok": False,
        "args": candidate,
        "model": model,
        "repair_reason": model_error or "repair_failed",
        "validation_reason": reason,
        "source": "repair_failed",
        "raw_preview": "",
    }
