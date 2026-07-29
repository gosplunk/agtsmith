#!/usr/bin/env python3
"""Evaluate planner models in isolation (planner_node only, no writer).

Scores structured plan quality against benchmarks/spl_cases.json expectations.
Use this to choose OLLAMA_MODEL_QUERY_PLANNER independently from the SPL writer.
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

from evaluate_spl_writer_models import ORIGIN_BY_KEY, list_models  # noqa: E402


def model_origin(tag: str) -> str:
    lower = tag.lower()
    for key, origin in ORIGIN_BY_KEY:
        if key in lower:
            return origin
    return "unknown"


def _load_cases(path: Path, *, limit: int = 0) -> list[dict[str, Any]]:
    rows = json.loads(path.read_text(encoding="utf-8"))
    if limit > 0:
        rows = rows[:limit]
    return rows


def _term_hits(values: list[str], haystack: str) -> tuple[int, int]:
    if not values:
        return 0, 0
    lower = haystack.lower()
    hits = sum(1 for value in values if str(value).lower() in lower)
    return hits, len(values)


def score_planner_output(case: dict[str, Any], plan: dict[str, Any]) -> tuple[int, list[str]]:
    score = 0
    notes: list[str] = []
    expected_intent = str(case.get("expected_intent", "")).strip()
    actual_intent = str(plan.get("intent", "")).strip()
    selected_tool = str(plan.get("selected_tool", "")).strip()

    if actual_intent == expected_intent:
        score += 35
    else:
        notes.append(f"intent_mismatch:{actual_intent}->{expected_intent}")

    if selected_tool == "splunk_run_query":
        score += 10
    elif selected_tool in {"splunk_get_indexes", "splunk_get_metadata", "splunk_get_info"}:
        if expected_intent in {"inventory", "internal_sourcetypes"}:
            score += 10
        else:
            notes.append(f"tool_mismatch:{selected_tool}")
    else:
        notes.append(f"tool_unknown:{selected_tool}")

    preferred_indexes = [str(x) for x in case.get("preferred_indexes", []) if str(x).strip()]
    preferred_sourcetypes = [str(x) for x in case.get("preferred_sourcetypes", []) if str(x).strip()]
    likely_indexes = plan.get("likely_indexes", [])
    likely_sourcetypes = plan.get("likely_sourcetypes", [])
    index_blob = " ".join(str(x) for x in likely_indexes if str(x).strip())
    sourcetype_blob = " ".join(str(x) for x in likely_sourcetypes if str(x).strip())

    idx_hits, idx_total = _term_hits(preferred_indexes, index_blob)
    if idx_total:
        score += int((idx_hits / idx_total) * 20)
        if idx_hits < idx_total:
            notes.append(f"preferred_indexes:{idx_hits}/{idx_total}")
    else:
        score += 20

    st_hits, st_total = _term_hits(preferred_sourcetypes, sourcetype_blob)
    if st_total:
        score += int((st_hits / st_total) * 20)
        if st_hits < st_total:
            notes.append(f"preferred_sourcetypes:{st_hits}/{st_total}")
    else:
        score += 20

    tool_args = plan.get("tool_args", {}) if isinstance(plan.get("tool_args"), dict) else {}
    earliest = str(tool_args.get("earliest_time", "")).strip()
    latest = str(tool_args.get("latest_time", "")).strip()
    expected_earliest = str(case.get("expected_earliest_time", "")).strip()
    expected_latest = str(case.get("expected_latest_time", "")).strip()
    if expected_earliest and earliest == expected_earliest:
        score += 8
    elif expected_earliest:
        notes.append(f"earliest_mismatch:{earliest}->{expected_earliest}")
    else:
        score += 8
    if expected_latest and latest == expected_latest:
        score += 7
    elif expected_latest:
        notes.append(f"latest_mismatch:{latest}->{expected_latest}")
    else:
        score += 7

    if str(plan.get("source", "")).strip() == "planner_fallback":
        notes.append("planner_fallback_used")
        score = min(score, 60)

    return max(0, min(100, score)), notes


def evaluate_model(model: str, cases: list[dict[str, Any]]) -> dict[str, Any]:
    os.environ["OLLAMA_MODEL_QUERY_PLANNER"] = model
    import importlib

    import langgraph_multi_model_soc as lg

    importlib.reload(lg)

    total_score = 0
    intent_hits = 0
    durations: list[int] = []
    case_rows: list[dict[str, Any]] = []

    for i, case in enumerate(cases):
        if i == 0 or (i + 1) % 10 == 0 or i + 1 == len(cases):
            print(f"[planner-eval] model={model} case {i + 1}/{len(cases)}", flush=True)
        t0 = time.perf_counter()
        try:
            state = lg.planner_node({"question": str(case["question"])})
            plan = state.get("planner_output", {}) if isinstance(state.get("planner_output"), dict) else {}
        except Exception as exc:
            plan = {"intent": "error", "source": "planner_exception", "reason": str(exc)}
        elapsed_ms = int((time.perf_counter() - t0) * 1000)
        durations.append(elapsed_ms)
        score, notes = score_planner_output(case, plan)
        total_score += score
        if str(plan.get("intent", "")).strip() == str(case.get("expected_intent", "")).strip():
            intent_hits += 1
        case_rows.append(
            {
                "case_id": case.get("id"),
                "family": case.get("family"),
                "score": score,
                "notes": notes,
                "actual_intent": plan.get("intent"),
                "expected_intent": case.get("expected_intent"),
                "selected_tool": plan.get("selected_tool"),
                "duration_ms": elapsed_ms,
                "planner_source": plan.get("source"),
            }
        )

    avg = round(total_score / max(1, len(cases)), 2)
    return {
        "model": model,
        "origin": model_origin(model),
        "avg_score": avg,
        "intent_match_rate_pct": round((intent_hits / max(1, len(cases))) * 100, 2),
        "median_duration_ms": int(statistics.median(durations)) if durations else 0,
        "p95_duration_ms": int(statistics.quantiles(durations, n=20)[18]) if len(durations) >= 20 else max(durations or [0]),
        "cases": case_rows,
    }


DEFAULT_PLANNER_MODELS = (
    "granite4:3b,gemma3:4b,mistral:7b,mistral-nemo:12b,granite3-moe:1b,granite3-moe:3b,"
    "qwen3:4b,qwen2.5:7b,llama3.2:3b,phi4-mini,qwen3:8b,devstral:24b,qwen3:30b-a3b"
)

# HF / Ollama tags not in the library-only bake-off (see hf_exhaustive_research.md).
DEFAULT_HF_PLANNER_MODELS = (
    "ibm/granite4.1:8b,phi4-mini-reasoning,ministral-3:3b,allenporter/xlam:1b,"
    "nemotron-mini:4b-instruct-q4_K_M,hf.co/bartowski/functionary-small-v3.2-GGUF:Q4_K_M,"
    "hf.co/bartowski/AgentFlow_agentflow-planner-7b-GGUF:Q4_K_M,"
    "hf.co/bartowski/granite-3.1-8b-instruct-GGUF:Q4_K_L,hermes3:3b,allenporter/xlam:7b,"
    "olmo2:7b-1124-instruct-q4_K_M,hf.co/bartowski/Qwen_Qwen3-4B-Instruct-2507-GGUF:Q4_K_L"
)

# Fast → slow for RTX 1000 Ada; avoids GPU contention from duplicate runs.
BAKEOFF_REMAINING_MODELS = (
    "allenporter/xlam:1b,ministral-3:3b,nemotron-mini:4b-instruct-q4_K_M,phi4-mini-reasoning,"
    "phi4-mini,llama3.2:3b,qwen2.5:7b,ibm/granite4.1:8b,"
    "hf.co/bartowski/functionary-small-v3.2-GGUF:Q4_K_M,qwen3:4b,qwen3:8b,devstral:24b,"
    "qwen3:30b-a3b"
)

BAKEOFF_SKIP_MODELS = "granite3-moe:3b,gemma3:4b,granite3-moe:1b,mistral-nemo:12b,mistral:7b"

# Round 2: user-requested small-model variants (Apr 2026 research batch).
BAKEOFF_ROUND2_MODELS = (
    "hf.co/EnlistedGhost/Ministral-3-3B-Reasoning-2512-GGUF:Q5_K_M,"
    "ibm/granite4.1:3b-q6_K,alibayram/smollm3,"  # Impulse2000/smollm3:3b-q5_k_m unavailable on registry
    "phi4-mini:3.8b-q4_K_M,gemma4:e2b-it-qat"
)


def _resolve_installed_tag(requested: str, installed: set[str]) -> str | None:
    if requested in installed:
        return requested
    latest = f"{requested}:latest"
    if latest in installed:
        return latest
    prefix = f"{requested}:"
    matches = [tag for tag in installed if tag.startswith(prefix)]
    if len(matches) == 1:
        return matches[0]
    return None


def _load_vram_smoke(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    try:
        rows = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    out: dict[str, str] = {}
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        model = str(row.get("model", "")).strip()
        if not model:
            continue
        if row.get("gpu_fit"):
            out[model] = str(row["gpu_fit"])
        elif row.get("status") == "not_installed":
            out[model] = "not_installed"
    return out


def _write_report(out_dir: Path, payload: dict[str, Any], *, vram_by_model: dict[str, str]) -> None:
    ranked = payload.get("ranked", [])
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    latest_json = out_dir / "planner_eval_latest.json"
    latest_json.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    (out_dir / f"planner_eval_{stamp}.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")

    md_lines = [
        "# Planner Model Evaluation (planner_node only)",
        "",
        f"- Timestamp (UTC): `{payload['timestamp_utc']}`",
        f"- Cases: `{payload['case_count']}`",
        f"- Recommended planner: `{payload.get('recommended_planner', '')}`",
        "",
        "| Rank | Model | Origin | Avg | Intent match | Median ms | GPU fit |",
        "|------|-------|--------|-----|--------------|-----------|---------|",
    ]
    for i, row in enumerate(ranked, 1):
        model = str(row.get("model", ""))
        md_lines.append(
            f"| {i} | `{model}` | {row.get('origin', '?')} | {row.get('avg_score', 0)} | "
            f"{row.get('intent_match_rate_pct', 0)}% | {row.get('median_duration_ms', 0)} | "
            f"{vram_by_model.get(model, row.get('gpu_fit', '—'))} |"
        )
    md = "\n".join(md_lines) + "\n"
    (out_dir / "planner_eval_latest.md").write_text(md, encoding="utf-8")
    (out_dir / f"planner_eval_{stamp}.md").write_text(md, encoding="utf-8")
    (out_dir / "planner_comparison.md").write_text(md, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate planner models in isolation")
    parser.add_argument("--cases", default="benchmarks/spl_cases.json")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--models", default=DEFAULT_PLANNER_MODELS, help="Comma-separated Ollama tags")
    parser.add_argument("--out-dir", default="artifacts/model_eval/planner_bakeoff")
    parser.add_argument("--skip-models", default="", help="Comma-separated tags to skip")
    args = parser.parse_args()

    cases = _load_cases(Path(args.cases), limit=args.limit)
    if not cases:
        raise SystemExit("no_cases_loaded")

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    vram_by_model = _load_vram_smoke(out_dir / "vram_smoke_planner_candidates.json")

    installed = set(list_models())
    skip = {m.strip() for m in args.skip_models.split(",") if m.strip()}
    requested = [m.strip() for m in args.models.split(",") if m.strip() and m.strip() not in skip]
    models: list[str] = []
    missing: list[str] = []
    for name in requested:
        resolved = _resolve_installed_tag(name, installed)
        if resolved:
            models.append(name)
        else:
            missing.append(name)
    if missing:
        print(f"warning: models not installed locally: {', '.join(missing)}", file=sys.stderr)
    if not models:
        raise SystemExit("no_installed_models_to_evaluate")

    ranked: list[dict[str, Any]] = []
    for model in models:
        resolved = _resolve_installed_tag(model, installed) or model
        print(f"[planner-eval] model={model} tag={resolved}", flush=True)
        row = evaluate_model(resolved, cases)
        row["model"] = model
        row["resolved_tag"] = resolved
        row["gpu_fit"] = vram_by_model.get(model, "unknown")
        ranked.append(row)
        ranked.sort(key=lambda r: (-r["avg_score"], r["median_duration_ms"]))
        payload = {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "cases_path": str(Path(args.cases)),
            "case_count": len(cases),
            "recommended_planner": ranked[0]["model"] if ranked else "",
            "ranked": ranked,
        }
        _write_report(out_dir, payload, vram_by_model=vram_by_model)

    print(
        json.dumps(
            {
                "recommended_planner": payload["recommended_planner"],
                "ranked": [
                    {
                        k: row[k]
                        for k in (
                            "model",
                            "origin",
                            "avg_score",
                            "intent_match_rate_pct",
                            "median_duration_ms",
                            "gpu_fit",
                        )
                    }
                    for row in ranked
                ],
            },
            indent=2,
        )
    )
    print(f"json={out_dir / 'planner_eval_latest.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
