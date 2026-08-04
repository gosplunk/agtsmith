#!/usr/bin/env python3
"""Compare LLM-generated SPL against canonical (template/domain) reference SPL."""

from __future__ import annotations

import argparse
import json
import random
import re
from datetime import datetime, timezone
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any

from evaluate_spl_writer_models import (
    _normalize_writer_candidate,
    generate_candidate,
    load_benchmark_cases,
    score_candidate,
)
from langgraph_multi_model_soc import _display_spl_for_plan
from minimal_question_to_answer import map_question_to_template, template_to_query_args
from spl_domain_knowledge import resolve_domain_knowledge

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT = PROJECT_ROOT / "artifacts" / "benchmark" / "spl_llm_canonical_compare_latest.json"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_case_pool() -> list[dict[str, Any]]:
    pool: dict[str, dict[str, Any]] = {}

    def add(row: dict[str, Any], *, source: str) -> None:
        question = str(row.get("question", "")).strip()
        if not question:
            return
        key = question.lower()
        if key in pool:
            return
        case_id = str(row.get("id", "")).strip() or f"{source}_{len(pool)+1}"
        pool[key] = {
            "id": case_id,
            "question": question,
            "expected_intent": str(row.get("expected_intent", row.get("intent", ""))).strip(),
            "canonical_spl": str(row.get("canonical_spl", "")).strip(),
            "required_terms": list(row.get("required_query_terms", row.get("required_terms", []))),
            "forbidden_terms": list(row.get("forbidden_query_terms", row.get("forbidden_terms", []))),
            "preferred_indexes": list(row.get("preferred_indexes", [])),
            "preferred_sourcetypes": list(row.get("preferred_sourcetypes", [])),
            "expected_shape": str(row.get("expected_shape", "")).strip(),
            "expected_earliest_time": str(row.get("expected_earliest_time", "-24h")).strip(),
            "expected_latest_time": str(row.get("expected_latest_time", "now")).strip(),
            "source": source,
        }

    spl_cases = PROJECT_ROOT / "benchmarks" / "spl_cases.json"
    if spl_cases.is_file():
        for row in json.loads(spl_cases.read_text(encoding="utf-8")):
            if isinstance(row, dict):
                add(row, source="spl_cases")

    op_cases = PROJECT_ROOT / "benchmarks" / "operational_spl_accuracy.json"
    if op_cases.is_file():
        for row in json.loads(op_cases.read_text(encoding="utf-8")):
            if isinstance(row, dict):
                add(row, source="operational")

    gold_path = PROJECT_ROOT / "benchmarks" / "gold_spl_oracles.json"
    if gold_path.is_file():
        payload = json.loads(gold_path.read_text(encoding="utf-8"))
        for row in payload.get("oracles", []) if isinstance(payload, dict) else []:
            if isinstance(row, dict):
                add(row, source="gold_oracle")

    return list(pool.values())


def _normalize_spl(text: str) -> str:
    q = re.sub(r"\s+", " ", str(text or "").strip().lower())
    q = q.replace('"', "").replace("'", "")
    return q


def _token_set(text: str) -> set[str]:
    return {t for t in re.split(r"[\s|(),=]+", _normalize_spl(text)) if t}


def _jaccard(a: str, b: str) -> float:
    sa, sb = _token_set(a), _token_set(b)
    if not sa and not sb:
        return 1.0
    if not sa or not sb:
        return 0.0
    return len(sa & sb) / len(sa | sb)


def _sequence_ratio(a: str, b: str) -> float:
    na, nb = _normalize_spl(a), _normalize_spl(b)
    if not na and not nb:
        return 1.0
    if not na or not nb:
        return 0.0
    return SequenceMatcher(None, na, nb).ratio()


def canonical_reference(case: dict[str, Any]) -> dict[str, Any]:
    question = str(case["question"])
    intent = str(case.get("expected_intent", "")).strip()
    if not intent:
        intent = map_question_to_template(question).intent

    if case.get("canonical_spl"):
        query = str(case["canonical_spl"])
        tool = "splunk_run_query"
        source = "benchmark_canonical_spl"
    else:
        domain = resolve_domain_knowledge(question, intent=intent)
        if domain is not None and domain.preferred_tool == "splunk_get_indexes":
            tool = "splunk_get_indexes"
            query = _display_spl_for_plan({"selected_tool": tool, "tool_args": {}})
            source = f"domain_oracle:{domain.pattern_id}"
        elif domain is not None and domain.query and domain.preferred_tool == "splunk_run_query":
            tool = "splunk_run_query"
            query = domain.query
            source = f"domain_oracle:{domain.pattern_id}"
        else:
            template = map_question_to_template(question)
            args = template_to_query_args(template, question)
            tool = "splunk_run_query"
            query = str(args.get("query", "")).strip()
            source = f"template:{template.intent}"

    mapped = map_question_to_template(question)
    args = template_to_query_args(mapped, question)
    ref_candidate = _normalize_writer_candidate(
        {
            "query": query,
            "earliest_time": args.get("earliest_time", case.get("expected_earliest_time", "-24h")),
            "latest_time": args.get("latest_time", case.get("expected_latest_time", "now")),
            "row_limit": args.get("row_limit", 50),
        },
        question=question,
        case=case,
    )
    eval_case = {
        **case,
        "required_terms": case.get("required_terms") or [],
    }
    ref_score, ref_notes = score_candidate(ref_candidate, eval_case)
    return {
        "tool": tool,
        "query": query,
        "source": source,
        "candidate": ref_candidate,
        "score": ref_score,
        "notes": ref_notes,
    }


def classify_match(jaccard: float, ratio: float, llm_score: int, ref_score: int) -> str:
    if jaccard >= 0.92 or ratio >= 0.92:
        return "exact_or_near"
    if jaccard >= 0.65 or ratio >= 0.72:
        return "strong_overlap"
    if jaccard >= 0.35 or llm_score >= max(70, ref_score - 15):
        return "partial"
    return "miss"


def run_compare(
    *,
    model: str,
    count: int,
    seed: int,
    use_rag: bool,
    out_path: Path,
) -> dict[str, Any]:
    pool = _load_case_pool()
    if not pool:
        raise RuntimeError("no benchmark cases available")

    rng = random.Random(seed)
    sample = pool if count >= len(pool) else rng.sample(pool, count)

    rows: list[dict[str, Any]] = []
    for idx, case in enumerate(sample, start=1):
        print(f"[{idx}/{len(sample)}] {case['id']}", flush=True)
        ref = canonical_reference(case)
        rag_context = ""
        if use_rag:
            from spl_rag_context import build_spl_rag_context

            rag_context = build_spl_rag_context(
                case["question"],
                intent=str(case.get("expected_intent", "")).strip(),
            )
        try:
            llm_raw = generate_candidate(
                model,
                case["question"],
                rag_context=rag_context,
                intent=str(case.get("expected_intent", "")).strip(),
            )
            llm_score, llm_notes = score_candidate(llm_raw, case)
            llm_error = ""
        except Exception as exc:
            llm_raw = {"query": "", "earliest_time": "", "latest_time": "", "row_limit": ""}
            llm_score, llm_notes = 0, [f"model_error:{type(exc).__name__}"]
            llm_error = str(exc)

        llm_query = str(llm_raw.get("query", "")).strip()
        ref_query = str(ref.get("query", "")).strip()
        jac = round(_jaccard(llm_query, ref_query), 4)
        ratio = round(_sequence_ratio(llm_query, ref_query), 4)
        tier = classify_match(jac, ratio, llm_score, int(ref.get("score", 0)))

        rows.append(
            {
                "id": case["id"],
                "source": case.get("source", ""),
                "question": case["question"],
                "expected_intent": case.get("expected_intent", ""),
                "canonical_source": ref.get("source", ""),
                "canonical_tool": ref.get("tool", ""),
                "canonical_query": ref_query[:1200],
                "canonical_score": ref.get("score", 0),
                "llm_query": llm_query[:1200],
                "llm_score": llm_score,
                "llm_notes": llm_notes[:8],
                "llm_error": llm_error,
                "jaccard": jac,
                "sequence_ratio": ratio,
                "match_tier": tier,
                "score_delta": llm_score - int(ref.get("score", 0)),
            }
        )

    tiers = {t: sum(1 for r in rows if r["match_tier"] == t) for t in ("exact_or_near", "strong_overlap", "partial", "miss")}
    summary = {
        "timestamp_utc": _utc_now(),
        "model": model,
        "seed": seed,
        "case_count": len(rows),
        "use_rag": use_rag,
        "llm_avg_score": round(sum(r["llm_score"] for r in rows) / max(1, len(rows)), 2),
        "canonical_avg_score": round(sum(r["canonical_score"] for r in rows) / max(1, len(rows)), 2),
        "avg_jaccard": round(sum(r["jaccard"] for r in rows) / max(1, len(rows)), 4),
        "avg_sequence_ratio": round(sum(r["sequence_ratio"] for r in rows) / max(1, len(rows)), 4),
        "match_tiers": tiers,
        "match_tier_pct": {k: round(v / max(1, len(rows)) * 100, 1) for k, v in tiers.items()},
        "miss_case_ids": [r["id"] for r in rows if r["match_tier"] == "miss"],
        "partial_or_worse_ids": [r["id"] for r in rows if r["match_tier"] in {"miss", "partial"}],
    }
    payload = {"summary": summary, "results": rows}
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare LLM SPL vs canonical reference SPL")
    parser.add_argument("--model", default="granite4:3b")
    parser.add_argument("--count", type=int, default=42)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--rag", action="store_true")
    parser.add_argument("--out", default=str(DEFAULT_OUT))
    args = parser.parse_args()

    payload = run_compare(
        model=args.model,
        count=args.count,
        seed=args.seed,
        use_rag=args.rag,
        out_path=Path(args.out),
    )
    print(json.dumps(payload["summary"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
