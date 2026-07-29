#!/usr/bin/env python3
"""Deterministic SPL-writer model benchmark for lab selection.

Compares candidate models on fixed query-authoring tasks and rule-based scoring.
No human grading is used.
"""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from minimal_question_to_answer import OLLAMA_HOST

try:
    from spl_rag_context import build_spl_rag_context
except ImportError:
    build_spl_rag_context = None  # type: ignore[assignment,misc]


TEST_CASES: list[dict[str, Any]] = [
    {
        "id": "failed_login",
        "question": "Write a read-only Splunk SPL query for failed login activity in the last 24 hours.",
        "required_terms": ["failed", "stats", "user"],
    },
    {
        "id": "linux_auth",
        "question": "Write a read-only Splunk SPL query for Linux authentication failures in index=linux over last 24 hours.",
        "required_terms": ["index=linux", "auth.log", "failed", "stats"],
    },
    {
        "id": "linux_priv_esc",
        "question": "Write a read-only Splunk SPL query for failed sudo or su activity in Linux logs over last 24 hours.",
        "required_terms": ["index=linux", "sudo", "su", "stats"],
    },
    {
        "id": "apache_top_ips",
        "question": "Write a read-only Splunk SPL query for top client IPs in index=linux sourcetype=access_combined over last 24 hours.",
        "required_terms": ["index=linux", "access_combined", "clientip", "stats"],
    },
    {
        "id": "apache_404",
        "question": "Write a read-only Splunk SPL query for 404 spikes in index=linux sourcetype=access_combined over last 24 hours.",
        "required_terms": ["index=linux", "access_combined", "404", "timechart"],
    },
]

FORBIDDEN_TERMS = ("delete", "drop", "outputlookup", "| outputcsv", "| sendemail", "| map ", " collect ")

ORIGIN_BY_KEY: tuple[tuple[str, str], ...] = (
    ("deepseek", "CN / DeepSeek"),
    ("qwen", "CN / Alibaba"),
    ("codegemma", "US / Google"),
    ("gemma", "US / Google"),
    ("llama", "US / Meta"),
    ("mistral", "FR / Mistral AI"),
    ("devstral", "FR / Mistral AI"),
    ("mixtral", "FR / Mistral AI"),
    ("magistral", "FR / Mistral AI"),
    ("ministral", "FR / Mistral AI"),
    ("granite", "US / IBM"),
    ("phi", "US / Microsoft"),
    ("foundation-sec", "US / Foundation"),
    ("foundation", "US / Foundation"),
    ("nemotron", "US / NVIDIA"),
)


def model_origin(tag: str) -> str:
    lower = tag.lower()
    for key, origin in ORIGIN_BY_KEY:
        if key in lower:
            return origin
    return "unknown"


def list_models(timeout: float = 20.0) -> list[str]:
    with httpx.Client(timeout=timeout) as client:
        resp = client.get(f"{OLLAMA_HOST}/api/tags")
        resp.raise_for_status()
        data = resp.json()
    out: list[str] = []
    for m in data.get("models", []):
        name = str(m.get("name", "")).strip()
        if name:
            out.append(name)
    return out


def _extract_json(text: str) -> dict[str, Any]:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
    except Exception:
        pass
    m = re.search(r"\{[\s\S]*\}", text)
    if not m:
        return {}
    try:
        obj = json.loads(m.group(0))
        return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}


def generate_candidate(
    model: str,
    question: str,
    *,
    rag_context: str = "",
    timeout: float = 120.0,
) -> dict[str, Any]:
    system = (
        "You are a Splunk SPL writer for a read-only SOC lab. "
        "Return strict JSON only with keys: query, earliest_time, latest_time, row_limit. "
        "Rules: read-only, query starts with 'search ', use row_limit <= 200."
    )
    if rag_context:
        prompt = (
            f"{system}\n\n"
            "Use the retrieval context as guidance, but keep output minimal and policy-safe.\n\n"
            f"RETRIEVAL_CONTEXT:\n{rag_context}\n\n"
            f"TASK:\n{question}"
        )
    else:
        prompt = f"{system}\n\nTASK:\n{question}"
    payload = {"model": model, "prompt": prompt, "stream": False, "think": False}
    with httpx.Client(timeout=timeout) as client:
        resp = client.post(f"{OLLAMA_HOST}/api/generate", json=payload)
        resp.raise_for_status()
        body = resp.json()
    raw = str(body.get("response", "")).strip()
    parsed = _extract_json(raw)
    query = str(parsed.get("query", "")).strip()
    return {
        "query": query,
        "earliest_time": str(parsed.get("earliest_time", "")).strip(),
        "latest_time": str(parsed.get("latest_time", "")).strip(),
        "row_limit": parsed.get("row_limit", 10),
        "raw_preview": raw[:500],
    }


def score_candidate(candidate: dict[str, Any], required_terms: list[str]) -> tuple[int, list[str]]:
    score = 0
    notes: list[str] = []

    query = str(candidate.get("query", "")).strip()
    lower = query.lower()

    if query:
        score += 10
    else:
        notes.append("missing_query")

    if lower.startswith("search "):
        score += 20
    else:
        notes.append("query_not_search_prefix")

    hit_terms = sum(1 for t in required_terms if t.lower() in lower)
    term_score = int((hit_terms / max(1, len(required_terms))) * 30)
    score += term_score
    if hit_terms < len(required_terms):
        notes.append(f"required_term_hits:{hit_terms}/{len(required_terms)}")

    if all(ft not in lower for ft in FORBIDDEN_TERMS):
        score += 20
    else:
        notes.append("forbidden_term_present")

    earliest = str(candidate.get("earliest_time", "")).strip()
    latest = str(candidate.get("latest_time", "")).strip().lower()
    if earliest and latest in {"now", "now()"}:
        score += 10
    else:
        notes.append("missing_or_bad_time_bounds")

    try:
        rl = int(candidate.get("row_limit", 10))
        if 1 <= rl <= 200:
            score += 10
        else:
            notes.append("row_limit_out_of_bounds")
    except Exception:
        notes.append("row_limit_not_int")

    return max(0, min(100, score)), notes


def _evaluate_model_cases(
    model: str,
    *,
    use_rag: bool,
) -> tuple[list[dict[str, Any]], float]:
    case_rows: list[dict[str, Any]] = []
    total = 0
    for case in TEST_CASES:
        question = str(case["question"])
        rag_context = ""
        if use_rag:
            if build_spl_rag_context is None:
                raise RuntimeError("spl_rag_context_unavailable")
            rag_context = build_spl_rag_context(question)
        try:
            c = generate_candidate(model, question, rag_context=rag_context)
            sc, notes = score_candidate(c, list(case["required_terms"]))
        except Exception as exc:
            c = {"query": "", "earliest_time": "", "latest_time": "", "row_limit": "", "raw_preview": ""}
            sc = 0
            notes = [f"model_error:{type(exc).__name__}"]
        total += sc
        case_rows.append(
            {
                "case_id": case["id"],
                "score": sc,
                "notes": notes,
                "candidate": c,
                "rag_enabled": use_rag,
            }
        )
    avg = round(total / len(TEST_CASES), 2)
    return case_rows, avg


def _discover_candidates(explicit: list[str], top_k: int) -> list[str]:
    discovered = list_models()
    if explicit:
        return explicit
    preferred_keys = ("deepseek", "qwen", "gemma", "codegemma", "llama", "mistral", "granite", "phi", "foundation")
    preferred = [m for m in discovered if any(k in m.lower() for k in preferred_keys)]
    return preferred[:top_k] if preferred else discovered[:top_k]


def main() -> int:
    parser = argparse.ArgumentParser(description="Deterministic benchmark for SPL writer models")
    parser.add_argument("--models", nargs="*", default=[], help="Explicit model names to test")
    parser.add_argument("--top-k", type=int, default=4, help="When --models is empty, test up to top-k discovered candidates")
    parser.add_argument(
        "--rag-mode",
        choices=("off", "on", "both"),
        default="off",
        help="off=vanilla only, on=RAG-augmented (production parity), both=dual-track with lift",
    )
    parser.add_argument("--out-dir", default="artifacts/model_eval")
    args = parser.parse_args()

    if args.rag_mode in {"on", "both"} and build_spl_rag_context is None:
        raise RuntimeError("RAG mode requires spl_rag_context module")

    candidates = _discover_candidates(args.models, args.top_k)
    if not candidates:
        raise RuntimeError("no_models_found")

    results: list[dict[str, Any]] = []
    for model in candidates:
        origin = model_origin(model)
        row: dict[str, Any] = {"model": model, "origin": origin}
        if args.rag_mode == "off":
            cases, avg = _evaluate_model_cases(model, use_rag=False)
            row["avg_score"] = avg
            row["vanilla_avg_score"] = avg
            row["cases"] = cases
        elif args.rag_mode == "on":
            cases, avg = _evaluate_model_cases(model, use_rag=True)
            row["avg_score"] = avg
            row["rag_avg_score"] = avg
            row["cases"] = cases
        else:
            vanilla_cases, vanilla_avg = _evaluate_model_cases(model, use_rag=False)
            rag_cases, rag_avg = _evaluate_model_cases(model, use_rag=True)
            row["vanilla_avg_score"] = vanilla_avg
            row["rag_avg_score"] = rag_avg
            row["rag_lift"] = round(rag_avg - vanilla_avg, 2)
            row["avg_score"] = rag_avg
            row["cases"] = rag_cases
            row["vanilla_cases"] = vanilla_cases
        results.append(row)

    ranked = sorted(results, key=lambda r: r["avg_score"], reverse=True)
    best = ranked[0]

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_json = out_dir / f"spl_writer_eval_{stamp}.json"
    out_md = out_dir / f"spl_writer_eval_{stamp}.md"
    latest_json = out_dir / "spl_writer_eval_latest.json"
    latest_md = out_dir / "spl_writer_eval_latest.md"

    payload = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "ollama_host": OLLAMA_HOST,
        "rag_mode": args.rag_mode,
        "tested_models": candidates,
        "test_case_count": len(TEST_CASES),
        "ranked": ranked,
        "recommended_query_writer_model": best["model"],
        "recommended_score": best["avg_score"],
        "recommended_origin": best.get("origin", model_origin(best["model"])),
        "method": "deterministic_rule_scoring_v2_rag_mode",
    }
    out_json.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    latest_json.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    lines = [
        "# SPL Writer Model Evaluation (Deterministic)",
        "",
        f"- Timestamp (UTC): `{payload['timestamp_utc']}`",
        f"- Ollama host: `{OLLAMA_HOST}`",
        f"- RAG mode: `{args.rag_mode}`",
        f"- Cases: `{len(TEST_CASES)}`",
        f"- Recommended query-writer model: `{best['model']}`",
        f"- Recommended origin: `{payload['recommended_origin']}`",
        f"- Recommended avg score: `{best['avg_score']}`",
        "",
        "## Ranked Results",
    ]
    for row in ranked:
        if args.rag_mode == "both":
            lines.append(
                f"- model=`{row['model']}` origin=`{row.get('origin', 'unknown')}` "
                f"rag_avg=`{row.get('rag_avg_score')}` vanilla_avg=`{row.get('vanilla_avg_score')}` "
                f"lift=`{row.get('rag_lift')}`"
            )
        else:
            lines.append(
                f"- model=`{row['model']}` origin=`{row.get('origin', 'unknown')}` avg_score=`{row['avg_score']}`"
            )
    lines.append("")
    lines.append("## Scoring Method")
    lines.append("- Query presence: 10")
    lines.append("- `search` prefix: 20")
    lines.append("- Required-term coverage: 30")
    lines.append("- Forbidden-term absence: 20")
    lines.append("- Time bounds validity: 10")
    lines.append("- Row-limit validity: 10")
    lines.append("")
    lines.append("SOAR note: intentionally not part of this benchmark phase.")
    out_md.write_text("\n".join(lines) + "\n", encoding="utf-8")
    latest_md.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print("=== SPL Writer Model Evaluation ===")
    print(f"rag_mode={args.rag_mode}")
    print(f"tested_models={len(candidates)}")
    print(f"recommended_model={best['model']}")
    print(f"recommended_origin={payload['recommended_origin']}")
    print(f"recommended_score={best['avg_score']}")
    print(f"json={out_json}")
    print(f"md={out_md}")
    print(f"latest_json={latest_json}")
    print(f"latest_md={latest_md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
