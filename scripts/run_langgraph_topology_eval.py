#!/usr/bin/env python3
"""Run LangGraph topology experiments against a prompt eval set."""

from __future__ import annotations

import argparse
import json
import os
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean
from typing import Any

from langgraph_multi_model_soc import run_multi_model_soc


def _extract_shape(query: str) -> str:
    lower = str(query or "").lower()
    if "| table " in lower:
        return "table"
    if "| timechart " in lower:
        return "timechart"
    if "| stats " in lower:
        return "stats"
    if "earliest(_time)" in lower or "first_seen" in lower:
        return "first_seen"
    return "unknown"


@contextmanager
def _temporary_env(overrides: dict[str, str]):
    old = {}
    for key, value in overrides.items():
        old[key] = os.environ.get(key)
        os.environ[key] = str(value)
    try:
        yield
    finally:
        for key, value in old.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _score(reference: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    score = 0
    findings: list[str] = []

    supported = bool(result.get("supported", False))
    if supported:
        score += 20
    else:
        findings.append("unsupported")

    if str(result.get("intent", "")) == str(reference.get("intent", "")):
        score += 20
    else:
        findings.append(f"intent_mismatch:{result.get('intent','')}->{reference.get('intent','')}")

    if str(result.get("selected_tool", "")) == str(reference.get("selected_tool", "")):
        score += 10
    else:
        findings.append("selected_tool_mismatch")

    if _extract_shape(str(result.get("generated_spl", ""))) == str(reference.get("query_shape", "")):
        score += 10
    else:
        findings.append("query_shape_mismatch")

    reference_rows = int(reference.get("rows_returned", 0) or 0)
    actual_rows = int(result.get("rows_returned", 0) or 0)
    if reference_rows > 0 and actual_rows > 0:
        score += 15
    elif reference_rows == 0 and actual_rows == 0:
        score += 15
    else:
        findings.append(f"row_behavior_mismatch:{actual_rows}vs{reference_rows}")

    reference_fields = set(reference.get("result_fields", []) or [])
    preview = result.get("spl_results_preview", []) or []
    actual_fields = set(preview[0].keys()) if preview and isinstance(preview[0], dict) else set()
    if reference_fields:
        overlap = len(reference_fields & actual_fields) / max(1, len(reference_fields))
        score += int(overlap * 15)
        if overlap < 1.0:
            findings.append(f"field_overlap:{len(reference_fields & actual_fields)}/{len(reference_fields)}")
    else:
        score += 15

    total_ms = int(((result.get("stage_timings_ms", {}) or {}).get("total", 0)) or 0)
    latency_bonus = 10 if total_ms <= 45000 else 7 if total_ms <= 90000 else 4 if total_ms <= 140000 else 0
    score += latency_bonus
    if latency_bonus < 10:
        findings.append(f"latency_ms={total_ms}")

    return {
        "score": max(0, min(100, score)),
        "findings": findings,
        "rows_returned": actual_rows,
        "latency_ms": total_ms,
        "skip_peer_review": bool(result.get("skip_peer_review", False)),
    }


def _markdown_summary(payload: dict[str, Any]) -> str:
    lines = [
        "# LangGraph Topology Eval",
        "",
        f"- generated_at_utc: `{payload['generated_at_utc']}`",
        f"- experiments: `{len(payload['experiments'])}`",
        "",
        "## Ranking",
        "",
        "| Rank | Experiment | Avg Score | Support Rate | Intent Rate | Avg Latency ms | Skip Peer Rate |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for idx, experiment in enumerate(payload["experiments"], start=1):
        lines.append(
            f"| {idx} | `{experiment['id']}` | {experiment['avg_score']:.2f} | {experiment['support_rate_pct']:.1f}% | "
            f"{experiment['intent_match_rate_pct']:.1f}% | {experiment['avg_latency_ms']:.0f} | {experiment['skip_peer_rate_pct']:.1f}% |"
        )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Run LangGraph topology experiments")
    parser.add_argument("--gold", default="artifacts/evals/langgraph/gold_corpus_latest.json")
    parser.add_argument("--prompts", default="artifacts/evals/langgraph/eval_prompts_latest.json")
    parser.add_argument("--experiments", default="benchmarks/langgraph_topology_experiments.json")
    parser.add_argument("--experiment", default="")
    parser.add_argument("--output-dir", default="artifacts/evals/langgraph/topology")
    parser.add_argument("--limit", type=int, default=0)
    args = parser.parse_args()

    gold_payload = json.loads(Path(args.gold).read_text(encoding="utf-8"))
    prompt_payload = json.loads(Path(args.prompts).read_text(encoding="utf-8"))
    experiments = json.loads(Path(args.experiments).read_text(encoding="utf-8"))
    if args.experiment:
        experiments = [item for item in experiments if str(item.get("id", "")) == args.experiment]

    prompts = prompt_payload.get("prompts", [])
    if args.limit > 0:
        prompts = prompts[: args.limit]

    gold_by_id = {str(case["id"]): case for case in gold_payload.get("cases", [])}
    experiment_results: list[dict[str, Any]] = []

    for experiment in experiments:
        env = {str(k): str(v) for k, v in (experiment.get("env", {}) or {}).items()}
        cases: list[dict[str, Any]] = []
        with _temporary_env(env):
            for prompt in prompts:
                gold_case = gold_by_id[str(prompt["gold_case_id"])]
                result = run_multi_model_soc(str(prompt["prompt"])).get("result", {})
                scored = _score(gold_case.get("reference", {}), result)
                cases.append(
                    {
                        "prompt_id": str(prompt["id"]),
                        "gold_case_id": str(prompt["gold_case_id"]),
                        "variant": str(prompt["variant"]),
                        "prompt": str(prompt["prompt"]),
                        "reference_intent": str((gold_case.get("reference", {}) or {}).get("intent", "")),
                        "actual_intent": str(result.get("intent", "")),
                        "score": scored["score"],
                        "findings": scored["findings"],
                        "rows_returned": scored["rows_returned"],
                        "latency_ms": scored["latency_ms"],
                        "skip_peer_review": scored["skip_peer_review"],
                        "supported": bool(result.get("supported", False)),
                    }
                )

        avg_score = mean([item["score"] for item in cases]) if cases else 0.0
        support_rate = 100.0 * sum(1 for item in cases if item["supported"]) / max(1, len(cases))
        intent_rate = 100.0 * sum(1 for item in cases if item["actual_intent"] == item["reference_intent"]) / max(1, len(cases))
        avg_latency = mean([item["latency_ms"] for item in cases]) if cases else 0.0
        skip_peer_rate = 100.0 * sum(1 for item in cases if item["skip_peer_review"]) / max(1, len(cases))
        experiment_results.append(
            {
                "id": str(experiment["id"]),
                "description": str(experiment.get("description", "")),
                "env": env,
                "avg_score": avg_score,
                "support_rate_pct": support_rate,
                "intent_match_rate_pct": intent_rate,
                "avg_latency_ms": avg_latency,
                "skip_peer_rate_pct": skip_peer_rate,
                "cases": cases,
            }
        )

    experiment_results.sort(key=lambda item: (-item["avg_score"], -item["support_rate_pct"], item["avg_latency_ms"]))
    payload = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "gold_source": str(Path(args.gold)),
        "prompt_source": str(Path(args.prompts)),
        "experiment_source": str(Path(args.experiments)),
        "experiments": experiment_results,
    }

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "langgraph_topology_eval_latest.json"
    md_path = output_dir / "langgraph_topology_eval_latest.md"
    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    md_path.write_text(_markdown_summary(payload), encoding="utf-8")
    print(json_path)
    print(md_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
