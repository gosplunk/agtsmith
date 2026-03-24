#!/usr/bin/env python3
"""Deep SPL quality pass for live lab data (Windows/Linux/Apache).

Compares:
1) SOC analyst baseline (gold query) SPL
2) Model-written SPL (vanilla + RAG)

Then executes both through Splunk MCP and scores drift/relevance deterministically.
"""

from __future__ import annotations

import argparse
import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from environment_profile import validate_query_against_environment
from minimal_question_to_answer import OLLAMA_HOST, OLLAMA_MODEL, run_splunk_query_args
from query_policy import validate_query_args
from spl_rag_context import build_spl_rag_context


CASES: list[dict[str, Any]] = [
    {
        "id": "windows_failed_login_24h",
        "question": "Show failed login activity in Windows logs in the last 24 hours.",
        "baseline_args": {
            "query": (
                "search index=windows sourcetype=XmlWinEventLog (EventCode=4625 OR \"An account failed to log on\") "
                "| eval src_ip=coalesce(Source_Network_Address,IpAddress,src,src_ip) "
                "| eval user_name=coalesce(TargetUserName,SubjectUserName,Account_Name,user) "
                "| stats count by host user_name src_ip | sort - count"
            ),
            "earliest_time": "-24h",
            "latest_time": "now",
            "row_limit": 50,
        },
        "required_terms": ["index=windows", "xmlwineventlog", "4625", "stats count"],
        "forbidden_terms": ["index=_audit", "index=_internal"],
    },
    {
        "id": "linux_failed_login_rpi5_24h",
        "question": "Show failed Linux login activity on host rpi5 in the last 24 hours.",
        "baseline_args": {
            "query": (
                "search index=linux host=\"rpi5\" (sourcetype=auth.log OR sourcetype=linux_secure OR sourcetype=auth-4) "
                "(failed password OR authentication failure OR invalid user) "
                "| eval src_ip=coalesce(rhost,src,src_ip,ip) "
                "| eval user_name=coalesce(user,account,uid) "
                "| stats count by host sourcetype user_name src_ip | sort - count"
            ),
            "earliest_time": "-24h",
            "latest_time": "now",
            "row_limit": 50,
        },
        "required_terms": ["index=linux", "rpi5", "failed", "stats count"],
        "forbidden_terms": ["index=_audit", "index=_internal"],
    },
    {
        "id": "linux_failed_sudo_rpi5_24h",
        "question": "Investigate failed sudo or su activity on host rpi5 over the last 24 hours.",
        "baseline_args": {
            "query": (
                "search index=linux host=\"rpi5\" (sourcetype=auth.log OR sourcetype=linux_secure OR sourcetype=auth-4) "
                "(sudo OR su) (failure OR failed OR incorrect password) "
                "| eval src_ip=coalesce(rhost,src,src_ip,ip) "
                "| eval user_name=coalesce(user,account,uid) "
                "| stats count by host user_name tty src_ip | sort - count"
            ),
            "earliest_time": "-24h",
            "latest_time": "now",
            "row_limit": 50,
        },
        "required_terms": ["index=linux", "sudo", "su", "stats count"],
        "forbidden_terms": ["index=_audit", "index=_internal"],
    },
    {
        "id": "apache_top_client_ips_24h",
        "question": "Show top client IPs in Apache access logs in the last 24 hours.",
        "baseline_args": {
            "query": (
                "search index=linux sourcetype=access_combined "
                "| eval src_ip=coalesce(clientip,src,src_ip,ip) "
                "| stats count by src_ip status method | sort - count"
            ),
            "earliest_time": "-24h",
            "latest_time": "now",
            "row_limit": 50,
        },
        "required_terms": ["index=linux", "access_combined", "clientip", "stats count"],
        "forbidden_terms": ["index=_audit", "index=_internal"],
    },
    {
        "id": "apache_404_spike_24h",
        "question": "Show 404 spike activity in Apache access logs in the last 24 hours.",
        "baseline_args": {
            "query": "search index=linux sourcetype=access_combined status=404 | timechart span=1h count by host limit=10",
            "earliest_time": "-24h",
            "latest_time": "now",
            "row_limit": 50,
        },
        "required_terms": ["index=linux", "access_combined", "404", "timechart"],
        "forbidden_terms": ["index=_audit", "index=_internal"],
    },
    {
        "id": "cross_domain_failed_login_24h",
        "question": "Show failed login activity in the last 24 hours across Linux and Windows, excluding Splunk internal indexes.",
        "baseline_args": {
            "query": (
                "search index=* NOT index=_* "
                "(eventtype=failed_login OR info=failed OR action=failure OR \"failed password\" OR \"authentication failure\") "
                "| eval src_ip=coalesce(src,src_ip,clientip,rhost,ip,Source_Network_Address,IpAddress) "
                "| eval user_name=coalesce(user,username,TargetUserName,SubjectUserName,Account_Name) "
                "| stats count by index host sourcetype user_name src_ip | sort - count"
            ),
            "earliest_time": "-24h",
            "latest_time": "now",
            "row_limit": 50,
        },
        "required_terms": ["index=*", "not index=_*", "failed", "stats count"],
        "forbidden_terms": [],
    },
]

MODEL_PROMPT_SYSTEM = (
    "You are a Splunk SPL author for SOC investigations. Return strict JSON only with keys: "
    "query, earliest_time, latest_time, row_limit, rationale. "
    "Hard rules: read-only SPL; query starts with 'search '; row_limit <= 200; "
    "unless explicitly requested, avoid internal Splunk indexes that start with '_' ; "
    "prefer environment-aware Windows/Linux/Apache fields."
)


def _extract_json(text: str) -> dict[str, Any]:
    cleaned = (text or "").strip()
    if not cleaned:
        return {}
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```[a-zA-Z]*\s*", "", cleaned)
        cleaned = re.sub(r"\s*```$", "", cleaned)
    try:
        obj = json.loads(cleaned)
        return obj if isinstance(obj, dict) else {}
    except Exception:
        pass
    m = re.search(r"\{[\s\S]*\}", cleaned)
    if not m:
        return {}
    try:
        obj = json.loads(m.group(0))
    except Exception:
        return {}
    return obj if isinstance(obj, dict) else {}


def _normalize_args(obj: dict[str, Any]) -> dict[str, Any]:
    args = dict(obj if isinstance(obj, dict) else {})
    query = str(args.get("query", "")).strip()
    if not query and "search" in args:
        query = str(args.get("search", "")).strip()
    if query and not query.lower().startswith("search "):
        query = f"search {query}"
    earliest = str(args.get("earliest_time", "")).strip() or "-24h"
    latest = str(args.get("latest_time", "")).strip() or "now"
    if latest.lower() == "now()":
        latest = "now"
    try:
        row_limit = int(args.get("row_limit", 50))
    except Exception:
        row_limit = 50
    row_limit = max(1, min(200, row_limit))
    return {
        "query": query,
        "earliest_time": earliest,
        "latest_time": latest,
        "row_limit": row_limit,
    }


def _score_query_text(query: str, required_terms: list[str], forbidden_terms: list[str]) -> dict[str, Any]:
    ql = (query or "").lower()
    required_hits = [t for t in required_terms if t.lower() in ql]
    forbidden_hits = [t for t in forbidden_terms if t.lower() in ql]
    score = 0
    score += 15 if ql.startswith("search ") else 0
    score += int((len(required_hits) / max(1, len(required_terms))) * 55)
    score += 30 if not forbidden_hits else -20
    return {
        "score_textual": max(0, min(100, score)),
        "required_hits": required_hits,
        "forbidden_hits": forbidden_hits,
    }


def _run_query(args: dict[str, Any]) -> dict[str, Any]:
    started = time.monotonic()
    data = run_splunk_query_args(args, intent="spl_quality_eval", summary_hint="quality pass")
    elapsed_ms = int((time.monotonic() - started) * 1000)
    structured = data.get("structured", {}) if isinstance(data, dict) else {}
    rows = structured.get("results", []) if isinstance(structured, dict) else []
    total_rows = structured.get("total_rows") if isinstance(structured, dict) else None
    sample = []
    if isinstance(rows, list):
        sample = [r for r in rows[:5] if isinstance(r, dict)]
    return {
        "execution_ms": elapsed_ms,
        "rows_returned": len(rows) if isinstance(rows, list) else 0,
        "total_rows": total_rows,
        "sample_rows": sample,
        "raw": data,
    }


def _generate_model_args(model: str, question: str, *, rag_context: str = "") -> dict[str, Any]:
    prompt = (
        f"{MODEL_PROMPT_SYSTEM}\n\n"
        "Return strict JSON only. No prose.\n\n"
        f"RAG_CONTEXT:\n{rag_context}\n\n"
        f"QUESTION:\n{question}"
    )
    payload = {"model": model, "prompt": prompt, "stream": False, "think": False}
    with httpx.Client(timeout=180.0) as client:
        resp = client.post(f"{OLLAMA_HOST}/api/generate", json=payload)
        resp.raise_for_status()
        body = resp.json()
    parsed = _extract_json(str(body.get("response", "")))
    return _normalize_args(parsed)


def _evaluate_candidate(case: dict[str, Any], candidate_args: dict[str, Any]) -> dict[str, Any]:
    policy_ok, policy_reason = validate_query_args(candidate_args, question=str(case["question"]))
    env_ok, env_reason = validate_query_against_environment(candidate_args)
    text_score = _score_query_text(
        str(candidate_args.get("query", "")),
        list(case.get("required_terms", [])),
        list(case.get("forbidden_terms", [])),
    )
    final_score = text_score["score_textual"]
    if policy_ok:
        final_score += 10
    else:
        final_score -= 25
    if env_ok:
        final_score += 10
    else:
        final_score -= 20
    return {
        "score": max(0, min(100, int(final_score))),
        "policy_ok": policy_ok,
        "policy_reason": policy_reason,
        "environment_ok": env_ok,
        "environment_reason": env_reason,
        **text_score,
    }


def _case_domain_assessment(row: dict[str, Any]) -> str:
    b = row["baseline_exec"]
    v = row["model_exec_vanilla"]
    r = row["model_exec_rag"]
    parts: list[str] = []
    parts.append(f"baseline_rows={b['rows_returned']}")
    parts.append(f"vanilla_rows={v['rows_returned']}")
    parts.append(f"rag_rows={r['rows_returned']}")
    if r["rows_returned"] > v["rows_returned"]:
        parts.append("rag_improves_retrieval")
    if r["rows_returned"] == 0 and b["rows_returned"] > 0:
        parts.append("rag_gap_vs_baseline")
    if v["rows_returned"] == 0 and b["rows_returned"] > 0:
        parts.append("vanilla_gap_vs_baseline")
    return ";".join(parts)


def main() -> int:
    parser = argparse.ArgumentParser(description="Deep SPL quality pass against live Splunk dataset")
    parser.add_argument(
        "--models",
        nargs="*",
        default=[
            "hf.co/MaziyarPanahi/Qwen3-30B-A3B-Instruct-2507-GGUF:Q4_K_M",
            "hf.co/dr-ry/Foundation-Sec-8B-Instruct-GGUF:Q4_K_M",
        ],
    )
    parser.add_argument("--out-dir", default="artifacts/model_eval")
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    all_results: list[dict[str, Any]] = []
    for model in args.models:
        model_rows: list[dict[str, Any]] = []
        for case in CASES:
            baseline_args = _normalize_args(case["baseline_args"])
            baseline_exec = _run_query(baseline_args)

            vanilla_args = _generate_model_args(model, str(case["question"]), rag_context="")
            rag_ctx = build_spl_rag_context(str(case["question"]), max_chars=1800)
            rag_args = _generate_model_args(model, str(case["question"]), rag_context=rag_ctx)

            vanilla_eval = _evaluate_candidate(case, vanilla_args)
            rag_eval = _evaluate_candidate(case, rag_args)

            model_exec_vanilla = _run_query(vanilla_args)
            model_exec_rag = _run_query(rag_args)

            model_rows.append(
                {
                    "case_id": case["id"],
                    "question": case["question"],
                    "baseline_args": baseline_args,
                    "baseline_exec": baseline_exec,
                    "vanilla_args": vanilla_args,
                    "vanilla_eval": vanilla_eval,
                    "model_exec_vanilla": model_exec_vanilla,
                    "rag_args": rag_args,
                    "rag_eval": rag_eval,
                    "model_exec_rag": model_exec_rag,
                }
            )

        avg_v = round(sum(int(r["vanilla_eval"]["score"]) for r in model_rows) / len(model_rows), 2)
        avg_r = round(sum(int(r["rag_eval"]["score"]) for r in model_rows) / len(model_rows), 2)
        rows_v = sum(int(r["model_exec_vanilla"]["rows_returned"]) for r in model_rows)
        rows_r = sum(int(r["model_exec_rag"]["rows_returned"]) for r in model_rows)
        rows_b = sum(int(r["baseline_exec"]["rows_returned"]) for r in model_rows)
        all_results.append(
            {
                "model": model,
                "avg_vanilla_score": avg_v,
                "avg_rag_score": avg_r,
                "total_rows_baseline": rows_b,
                "total_rows_vanilla": rows_v,
                "total_rows_rag": rows_r,
                "case_rows": model_rows,
            }
        )

    ranked = sorted(all_results, key=lambda x: (x["avg_rag_score"], x["avg_vanilla_score"]), reverse=True)
    best = ranked[0] if ranked else {}

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_json = out_dir / f"deep_spl_quality_pass_{stamp}.json"
    latest_json = out_dir / "deep_spl_quality_pass_latest.json"
    out_md = out_dir / f"deep_spl_quality_pass_{stamp}.md"
    latest_md = out_dir / "deep_spl_quality_pass_latest.md"

    payload = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "ollama_host": OLLAMA_HOST,
        "models_tested": list(args.models),
        "case_count": len(CASES),
        "ranked_results": ranked,
        "recommended_writer_model": best.get("model"),
        "method": "deterministic_text_policy_environment_live_exec_v1",
    }
    out_json.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    latest_json.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    md: list[str] = [
        "# Deep SPL Quality Pass (Live Dataset)",
        "",
        f"- Timestamp (UTC): `{payload['timestamp_utc']}`",
        f"- Case count: `{len(CASES)}`",
        f"- Recommended writer model: `{best.get('model', 'n/a')}`",
        "",
        "## Model Ranking",
    ]
    for row in ranked:
        md.append(
            f"- model=`{row['model']}` rag_avg=`{row['avg_rag_score']}` vanilla_avg=`{row['avg_vanilla_score']}` "
            f"rows(baseline/vanilla/rag)=`{row['total_rows_baseline']}/{row['total_rows_vanilla']}/{row['total_rows_rag']}`"
        )
    md.append("")
    md.append("## Case Notes")
    for row in ranked:
        md.append(f"### Model: `{row['model']}`")
        for c in row["case_rows"]:
            assessment = _case_domain_assessment(c)
            md.append(
                f"- case=`{c['case_id']}` "
                f"score(v/r)=`{c['vanilla_eval']['score']}/{c['rag_eval']['score']}` "
                f"policy(v/r)=`{c['vanilla_eval']['policy_ok']}/{c['rag_eval']['policy_ok']}` "
                f"env(v/r)=`{c['vanilla_eval']['environment_ok']}/{c['rag_eval']['environment_ok']}` "
                f"assessment=`{assessment}`"
            )
        md.append("")
    md.append("SOAR note: still out of scope in this phase.")
    out_md.write_text("\n".join(md) + "\n", encoding="utf-8")
    latest_md.write_text("\n".join(md) + "\n", encoding="utf-8")

    print("=== Deep SPL Quality Pass ===")
    print(f"models_tested={len(args.models)}")
    print(f"cases={len(CASES)}")
    print(f"recommended_writer_model={best.get('model', 'n/a')}")
    if ranked:
        top = ranked[0]
        print(f"top_rag_avg={top['avg_rag_score']} top_vanilla_avg={top['avg_vanilla_score']}")
    print(f"json={out_json}")
    print(f"md={out_md}")
    print(f"latest_json={latest_json}")
    print(f"latest_md={latest_md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
