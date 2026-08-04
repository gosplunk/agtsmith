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

from minimal_question_to_answer import OLLAMA_HOST, map_question_to_template

try:
    from ollama_client import call_ollama_json, extract_json_object
except ImportError:
    call_ollama_json = None  # type: ignore[assignment,misc]
    extract_json_object = None  # type: ignore[assignment,misc]

try:
    from intent_field_contracts import validate_query_for_intent
except ImportError:
    validate_query_for_intent = None  # type: ignore[assignment,misc]

try:
    from query_policy import validate_query_args
except ImportError:
    validate_query_args = None  # type: ignore[assignment,misc]

try:
    from spl_rag_context import build_spl_rag_context
except ImportError:
    build_spl_rag_context = None  # type: ignore[assignment,misc]

try:
    from spl_writer_prompt import build_standalone_writer_system_prompt, build_standalone_writer_user_payload
except ImportError:
    build_standalone_writer_system_prompt = None  # type: ignore[assignment,misc]
    build_standalone_writer_user_payload = None  # type: ignore[assignment,misc]

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CASES_PATH = PROJECT_ROOT / "benchmarks" / "spl_cases.json"


TEST_CASES: list[dict[str, Any]] = [
    {
        "id": "failed_login",
        "question": "Write a read-only Splunk SPL query for failed login activity in the last 24 hours.",
        "required_terms": ["failed", "stats", "user"],
        "expected_intent": "failed_login_activity",
    },
    {
        "id": "linux_auth",
        "question": "Write a read-only Splunk SPL query for Linux authentication failures in index=linux over last 24 hours.",
        "required_terms": ["index=linux", "auth.log", "failed", "stats"],
        "expected_intent": "linux_auth_failures",
    },
    {
        "id": "linux_priv_esc",
        "question": "Write a read-only Splunk SPL query for failed sudo or su activity in Linux logs over last 24 hours.",
        "required_terms": ["index=linux", "sudo", "su", "stats"],
        "expected_intent": "linux_privilege_escalation",
    },
    {
        "id": "apache_top_ips",
        "question": "Write a read-only Splunk SPL query for top client IPs in index=linux sourcetype=access_combined over last 24 hours.",
        "required_terms": ["index=linux", "access_combined", "clientip", "stats"],
        "expected_intent": "apache_access_top_ips",
    },
    {
        "id": "apache_404",
        "question": "Write a read-only Splunk SPL query for 404 spikes in index=linux sourcetype=access_combined over last 24 hours.",
        "required_terms": ["index=linux", "access_combined", "404", "timechart"],
        "expected_intent": "apache_404_spike",
    },
]

LEGACY_QUICK_CASES = TEST_CASES

FORBIDDEN_TERMS = ("delete", "drop", "outputlookup", "| outputcsv", "| sendemail", "| map ", " collect ")


def load_benchmark_cases(path: Path, *, max_cases: int = 0) -> list[dict[str, Any]]:
    """Load writer eval cases from spl_cases.json (or legacy inline TEST_CASES)."""
    if not path.exists():
        return list(LEGACY_QUICK_CASES)
    rows = json.loads(path.read_text(encoding="utf-8"))
    cases: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        question = str(row.get("question", "")).strip()
        if not question:
            continue
        cases.append(
            {
                "id": str(row.get("id", "")),
                "question": question,
                "expected_intent": str(row.get("expected_intent", "")).strip(),
                "required_terms": list(row.get("required_query_terms", [])),
                "forbidden_terms": list(row.get("forbidden_query_terms", [])),
                "preferred_indexes": list(row.get("preferred_indexes", [])),
                "preferred_sourcetypes": list(row.get("preferred_sourcetypes", [])),
                "expected_shape": str(row.get("expected_shape", "")).strip(),
                "expected_earliest_time": str(row.get("expected_earliest_time", "")).strip(),
                "expected_latest_time": str(row.get("expected_latest_time", "")).strip(),
            }
        )
    if max_cases > 0:
        cases = cases[:max_cases]
    return cases or list(LEGACY_QUICK_CASES)


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


def _extract_shape(query: str) -> str:
    lower = query.lower()
    if "| table " in lower:
        return "table"
    if "| timechart " in lower:
        return "timechart"
    if "| stats " in lower:
        return "stats"
    return "unknown"


def _normalize_writer_candidate(parsed: dict[str, Any], *, question: str = "", case: dict[str, Any] | None = None) -> dict[str, Any]:
    tool_args = parsed.get("tool_args", {}) if isinstance(parsed.get("tool_args"), dict) else {}
    query = str(parsed.get("query") or tool_args.get("query") or "").strip()
    if query:
        from spl_query_normalize import normalize_writer_query
        from environment_profile import load_environment_profile, normalize_query_index_aliases

        query = normalize_writer_query(query)
        query = normalize_query_index_aliases(query, load_environment_profile())
        try:
            from spl_domain_knowledge import apply_domain_postprocess

            query = apply_domain_postprocess(query, question=question)
        except Exception:
            pass
    earliest = str(parsed.get("earliest_time") or tool_args.get("earliest_time") or "").strip()
    latest = str(parsed.get("latest_time") or tool_args.get("latest_time") or "").strip()
    if case:
        if not earliest and case.get("expected_earliest_time"):
            earliest = str(case.get("expected_earliest_time"))
        if not latest and case.get("expected_latest_time"):
            latest = str(case.get("expected_latest_time"))
    if question and (not earliest or not latest):
        from minimal_question_to_answer import infer_time_window

        inferred_e, inferred_l = infer_time_window(question)
        if not earliest:
            earliest = inferred_e
        if not latest:
            latest = inferred_l
    row_limit = parsed.get("row_limit", tool_args.get("row_limit", 10))
    raw_preview = str(parsed.get("_raw_text_preview") or parsed.get("raw_preview") or "")[:500]
    return {
        "query": query,
        "earliest_time": earliest,
        "latest_time": latest,
        "row_limit": row_limit,
        "raw_preview": raw_preview,
    }


def generate_candidate(
    model: str,
    question: str,
    *,
    rag_context: str = "",
    intent: str = "",
    timeout: float = 120.0,
) -> dict[str, Any]:
    mapped_intent = intent or map_question_to_template(question).intent
    if build_standalone_writer_user_payload is not None and call_ollama_json is not None:
        system = build_standalone_writer_system_prompt(intent=mapped_intent)
        user_payload = build_standalone_writer_user_payload(question, intent=mapped_intent, rag_context=rag_context)
        parsed = call_ollama_json(model=model, system_prompt=system, user_payload=user_payload, timeout=timeout)
        from spl_query_schema import constrained_mode_enabled, parse_write_plan, validate_write_plan, write_plan_to_tool_args

        if constrained_mode_enabled():
            plan = parse_write_plan(parsed)
            if plan is not None:
                ok, _reason = validate_write_plan(plan)
                if ok:
                    tool_plan = write_plan_to_tool_args(plan, intent=mapped_intent)
                    parsed = {
                        "query": tool_plan.get("tool_args", {}).get("query", ""),
                        "earliest_time": tool_plan.get("tool_args", {}).get("earliest_time", "-7d"),
                        "latest_time": tool_plan.get("tool_args", {}).get("latest_time", "now"),
                        "row_limit": tool_plan.get("tool_args", {}).get("row_limit", 10),
                    }
        return _normalize_writer_candidate(parsed, question=question, case=None)

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
    payload = {"model": model, "prompt": prompt, "stream": False, "think": False, "format": "json"}
    with httpx.Client(timeout=timeout) as client:
        resp = client.post(f"{OLLAMA_HOST}/api/generate", json=payload)
        resp.raise_for_status()
        body = resp.json()
    raw = str(body.get("response", "")).strip()
    if extract_json_object is not None:
        parsed = extract_json_object(raw)
    else:
        parsed = _extract_json(raw)
    parsed["raw_preview"] = raw[:500]
    return _normalize_writer_candidate(parsed, question=question, case=None)


def score_candidate(candidate: dict[str, Any], case: dict[str, Any]) -> tuple[int, list[str]]:
    required_terms = list(case.get("required_terms", []))
    forbidden_terms = list(case.get("forbidden_terms", [])) or list(FORBIDDEN_TERMS)
    score = 0
    notes: list[str] = []

    query = str(candidate.get("query", "")).strip()
    lower = query.lower()

    if query:
        score += 10
    else:
        notes.append("missing_query")

    if lower.startswith("search "):
        score += 15
    else:
        notes.append("query_not_search_prefix")

    hit_terms = sum(1 for t in required_terms if t.lower() in lower)
    if required_terms:
        term_score = int((hit_terms / len(required_terms)) * 25)
        score += term_score
        if hit_terms < len(required_terms):
            notes.append(f"required_term_hits:{hit_terms}/{len(required_terms)}")
    else:
        score += 25

    forbidden_present = [term for term in forbidden_terms if term.lower() in lower]
    if forbidden_present:
        notes.append("forbidden_term_present:" + ",".join(forbidden_present[:3]))
    else:
        score += 15

    for pref_group, points in (
        (list(case.get("preferred_indexes", [])), 5),
        (list(case.get("preferred_sourcetypes", [])), 5),
    ):
        if not pref_group:
            score += points
            continue
        hits = sum(1 for term in pref_group if term.lower() in lower)
        score += int((hits / len(pref_group)) * points)
        if hits < len(pref_group):
            notes.append(f"preferred_miss:{hits}/{len(pref_group)}")

    expected_shape = str(case.get("expected_shape", "")).strip()
    if expected_shape:
        actual_shape = _extract_shape(query)
        if actual_shape == expected_shape:
            score += 5
        else:
            notes.append(f"shape_mismatch:{actual_shape}->{expected_shape}")
    else:
        score += 5

    earliest = str(candidate.get("earliest_time", "")).strip()
    latest = str(candidate.get("latest_time", "")).strip().lower()
    expected_earliest = str(case.get("expected_earliest_time", "")).strip()
    expected_latest = str(case.get("expected_latest_time", "")).strip().lower()
    if earliest and latest in {"now", "now()"}:
        score += 5
        if expected_earliest and earliest != expected_earliest:
            notes.append(f"earliest_mismatch:{earliest}->{expected_earliest}")
        if expected_latest and latest.replace("()", "") != expected_latest.replace("()", ""):
            notes.append(f"latest_mismatch:{latest}->{expected_latest}")
    else:
        notes.append("missing_or_bad_time_bounds")

    try:
        rl = int(candidate.get("row_limit", 10))
        if 1 <= rl <= 200:
            score += 5
        else:
            notes.append("row_limit_out_of_bounds")
    except Exception:
        notes.append("row_limit_not_int")

    query_args = {
        "query": query,
        "earliest_time": earliest or "-7d",
        "latest_time": "now" if latest in {"now", "now()"} else latest or "now",
        "row_limit": candidate.get("row_limit", 10),
    }
    if validate_query_args is not None:
        policy_ok, policy_reason = validate_query_args(query_args, question=str(case.get("question", "")))
        if policy_ok:
            score += 5
        else:
            notes.append(f"policy_fail:{policy_reason}")

    intent = str(case.get("expected_intent", "")).strip()
    if intent and validate_query_for_intent is not None:
        contract_ok, contract_reason = validate_query_for_intent(
            intent,
            query_args,
            question=str(case.get("question", "")),
        )
        if contract_ok:
            score += 5
        else:
            notes.append(f"intent_contract_fail:{contract_reason}")

    try:
        from spl_structure_validate import structure_score_penalty, validate_structure

        structure_ok, structure_reason = validate_structure(
            query,
            intent=intent,
            question=str(case.get("question", "")),
        )
        if structure_ok:
            score += 5
        else:
            penalty = int(structure_score_penalty(query, intent=intent, question=str(case.get("question", ""))))
            score = max(0, score - penalty)
            notes.append(f"structure_fail:{structure_reason}")
    except Exception:
        pass

    return max(0, min(100, score)), notes


def _evaluate_model_cases(
    model: str,
    cases: list[dict[str, Any]],
    *,
    use_rag: bool,
) -> tuple[list[dict[str, Any]], float]:
    case_rows: list[dict[str, Any]] = []
    total = 0
    for case in cases:
        question = str(case["question"])
        intent = str(case.get("expected_intent", "")).strip()
        rag_context = ""
        if use_rag:
            if build_spl_rag_context is None:
                raise RuntimeError("spl_rag_context_unavailable")
            rag_context = build_spl_rag_context(question, intent=intent)
        try:
            c = generate_candidate(model, question, rag_context=rag_context, intent=intent)
            c = _normalize_writer_candidate(
                {
                    "query": c.get("query", ""),
                    "earliest_time": c.get("earliest_time", ""),
                    "latest_time": c.get("latest_time", ""),
                    "row_limit": c.get("row_limit", 10),
                },
                question=question,
                case=case,
            )
            sc, notes = score_candidate(c, case)
        except Exception as exc:
            c = {"query": "", "earliest_time": "", "latest_time": "", "row_limit": "", "raw_preview": ""}
            sc = 0
            notes = [f"model_error:{type(exc).__name__}"]
        total += sc
        case_rows.append(
            {
                "case_id": case.get("id", ""),
                "score": sc,
                "notes": notes,
                "candidate": c,
                "rag_enabled": use_rag,
            }
        )
    avg = round(total / max(1, len(cases)), 2)
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
    parser.add_argument(
        "--cases",
        default=str(DEFAULT_CASES_PATH),
        help="Benchmark cases JSON (default: benchmarks/spl_cases.json). Use 'quick' for 5 legacy prompts.",
    )
    parser.add_argument("--max-cases", type=int, default=0, help="Limit case count (0 = all)")
    args = parser.parse_args()

    if args.cases.strip().lower() == "quick":
        cases_path = Path("/dev/null")
        benchmark_cases = list(LEGACY_QUICK_CASES)
    else:
        cases_path = Path(args.cases)
        benchmark_cases = load_benchmark_cases(cases_path, max_cases=args.max_cases)

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
            case_rows, avg = _evaluate_model_cases(model, benchmark_cases, use_rag=False)
            row["avg_score"] = avg
            row["vanilla_avg_score"] = avg
            row["cases"] = case_rows
        elif args.rag_mode == "on":
            case_rows, avg = _evaluate_model_cases(model, benchmark_cases, use_rag=True)
            row["avg_score"] = avg
            row["rag_avg_score"] = avg
            row["cases"] = case_rows
        else:
            vanilla_cases, vanilla_avg = _evaluate_model_cases(model, benchmark_cases, use_rag=False)
            rag_cases, rag_avg = _evaluate_model_cases(model, benchmark_cases, use_rag=True)
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
        "test_case_count": len(benchmark_cases),
        "cases_source": str(cases_path) if args.cases.strip().lower() != "quick" else "legacy_quick",
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
