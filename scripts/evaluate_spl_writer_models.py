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


def generate_candidate(model: str, question: str, timeout: float = 120.0) -> dict[str, Any]:
    system = (
        "You are a Splunk SPL writer. Return strict JSON only with keys: "
        "query, earliest_time, latest_time, row_limit. "
        "Rules: read-only, query starts with 'search ', use row_limit <= 200."
    )
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


def main() -> int:
    parser = argparse.ArgumentParser(description="Deterministic benchmark for SPL writer models")
    parser.add_argument("--models", nargs="*", default=[], help="Explicit model names to test")
    parser.add_argument("--top-k", type=int, default=4, help="When --models is empty, test up to top-k discovered candidates")
    parser.add_argument("--out-dir", default="artifacts/model_eval")
    args = parser.parse_args()

    discovered = list_models()
    candidates = args.models
    if not candidates:
        preferred = [m for m in discovered if any(k in m.lower() for k in ("qwen", "foundation-sec", "foundation", "nemotron"))]
        candidates = preferred[: args.top_k] if preferred else discovered[: args.top_k]

    if not candidates:
        raise RuntimeError("no_models_found")

    results: list[dict[str, Any]] = []
    for model in candidates:
        case_rows: list[dict[str, Any]] = []
        total = 0
        for case in TEST_CASES:
            try:
                c = generate_candidate(model, case["question"])
                sc, notes = score_candidate(c, case["required_terms"])
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
                }
            )
        avg = round(total / len(TEST_CASES), 2)
        results.append({"model": model, "avg_score": avg, "cases": case_rows})

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
        "tested_models": candidates,
        "test_case_count": len(TEST_CASES),
        "ranked": ranked,
        "recommended_query_writer_model": best["model"],
        "recommended_score": best["avg_score"],
        "method": "deterministic_rule_scoring_v1",
    }
    out_json.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    latest_json.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    lines = [
        "# SPL Writer Model Evaluation (Deterministic)",
        "",
        f"- Timestamp (UTC): `{payload['timestamp_utc']}`",
        f"- Ollama host: `{OLLAMA_HOST}`",
        f"- Cases: `{len(TEST_CASES)}`",
        f"- Recommended query-writer model: `{best['model']}`",
        f"- Recommended avg score: `{best['avg_score']}`",
        "",
        "## Ranked Results",
    ]
    for row in ranked:
        lines.append(f"- model=`{row['model']}` avg_score=`{row['avg_score']}`")
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
    print(f"tested_models={len(candidates)}")
    print(f"recommended_model={best['model']}")
    print(f"recommended_score={best['avg_score']}")
    print(f"json={out_json}")
    print(f"md={out_md}")
    print(f"latest_json={latest_json}")
    print(f"latest_md={latest_md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
