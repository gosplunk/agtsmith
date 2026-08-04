#!/usr/bin/env python3
"""A/B benchmark: vanilla SPL writer vs RAG-augmented SPL writer.

Uses the same model and fixed SOC prompts, then scores outputs with deterministic
rules aligned to this lab's query policy and MCP constraints.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from evaluate_spl_writer_models import TEST_CASES, generate_candidate as shared_generate_candidate, score_candidate
from minimal_question_to_answer import OLLAMA_MODEL
from spl_rag_context import RAG_SOURCES, build_spl_rag_context


def generate_candidate(model: str, question: str, *, rag_context: str = "", timeout: float = 120.0) -> dict[str, Any]:
    return shared_generate_candidate(model, question, rag_context=rag_context, timeout=timeout)


def score_with_policy(candidate: dict[str, Any], case: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    base_score, base_notes = score_candidate(candidate, case)

    mcp_ok = True
    mcp_reason = "mcp_compatible"
    q = str(candidate.get("query", "")).lower()
    if "| tstats" in q and " by " in q:
        mcp_ok = False
        mcp_reason = "mcp_tstats_by_not_supported"

    final = base_score
    notes = list(base_notes)
    policy_ok = not any(str(n).startswith("policy_fail:") for n in notes)
    policy_reason = next((str(n).split(":", 1)[1] for n in notes if str(n).startswith("policy_fail:")), "policy_ok")

    if mcp_ok:
        final = min(100, final + 3)
    else:
        notes.append(mcp_reason)
        final = max(0, final - 10)

    return max(0, min(100, final)), {
        "base_score": base_score,
        "policy_ok": policy_ok,
        "policy_reason": policy_reason,
        "mcp_ok": mcp_ok,
        "mcp_reason": mcp_reason,
        "notes": notes,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="A/B test vanilla vs RAG SPL writing")
    parser.add_argument("--model", default=OLLAMA_MODEL)
    parser.add_argument("--runs", type=int, default=1)
    parser.add_argument("--out-dir", default="artifacts/model_eval")
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    rows: list[dict[str, Any]] = []
    for case in TEST_CASES:
        cid = str(case["id"])
        question = str(case["question"])
        terms = list(case["required_terms"])
        rag_ctx = build_spl_rag_context(question)
        for run_idx in range(1, max(1, args.runs) + 1):
            vanilla = generate_candidate(args.model, question, rag_context="")
            rag = generate_candidate(args.model, question, rag_context=rag_ctx)
            v_score, v_meta = score_with_policy(vanilla, case)
            r_score, r_meta = score_with_policy(rag, case)
            rows.append(
                {
                    "case_id": cid,
                    "question": question,
                    "run": run_idx,
                    "vanilla": {"score": v_score, "candidate": vanilla, "meta": v_meta},
                    "rag": {"score": r_score, "candidate": rag, "meta": r_meta},
                    "delta": r_score - v_score,
                }
            )

    vanilla_avg = round(sum(r["vanilla"]["score"] for r in rows) / len(rows), 2)
    rag_avg = round(sum(r["rag"]["score"] for r in rows) / len(rows), 2)
    delta_avg = round(rag_avg - vanilla_avg, 2)
    rag_wins = sum(1 for r in rows if r["delta"] > 0)
    ties = sum(1 for r in rows if r["delta"] == 0)
    vanilla_wins = sum(1 for r in rows if r["delta"] < 0)

    payload = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "model": args.model,
        "runs_per_case": args.runs,
        "cases": len(TEST_CASES),
        "comparisons": len(rows),
        "summary": {
            "vanilla_avg_score": vanilla_avg,
            "rag_avg_score": rag_avg,
            "avg_delta_rag_minus_vanilla": delta_avg,
            "rag_wins": rag_wins,
            "ties": ties,
            "vanilla_wins": vanilla_wins,
        },
        "rows": rows,
        "rag_docs": list(RAG_SOURCES),
        "method": "ab_vanilla_vs_rag_rule_policy_mcp_scoring_v1",
    }

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_json = out_dir / f"rag_vs_vanilla_spl_{stamp}.json"
    latest_json = out_dir / "rag_vs_vanilla_spl_latest.json"
    out_md = out_dir / f"rag_vs_vanilla_spl_{stamp}.md"
    latest_md = out_dir / "rag_vs_vanilla_spl_latest.md"
    out_json.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    latest_json.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    md = [
        "# RAG vs Vanilla SPL A/B Evaluation",
        "",
        f"- Timestamp (UTC): `{payload['timestamp_utc']}`",
        f"- Model: `{args.model}`",
        f"- Cases: `{len(TEST_CASES)}`",
        f"- Runs per case: `{args.runs}`",
        f"- Vanilla avg score: `{vanilla_avg}`",
        f"- RAG avg score: `{rag_avg}`",
        f"- Avg delta (RAG - vanilla): `{delta_avg}`",
        f"- Wins: `rag={rag_wins}` `ties={ties}` `vanilla={vanilla_wins}`",
        "",
        "## Case Deltas",
    ]
    for r in rows:
        md.append(
            f"- case=`{r['case_id']}` run=`{r['run']}` "
            f"vanilla=`{r['vanilla']['score']}` rag=`{r['rag']['score']}` delta=`{r['delta']}`"
        )
    md.append("")
    md.append("## RAG Sources")
    for p in RAG_SOURCES:
        md.append(f"- `{p}`")
    out_md.write_text("\n".join(md) + "\n", encoding="utf-8")
    latest_md.write_text("\n".join(md) + "\n", encoding="utf-8")

    print("=== RAG vs Vanilla SPL A/B ===")
    print(f"model={args.model}")
    print(f"cases={len(TEST_CASES)} runs_per_case={args.runs} comparisons={len(rows)}")
    print(f"vanilla_avg={vanilla_avg}")
    print(f"rag_avg={rag_avg}")
    print(f"avg_delta={delta_avg}")
    print(f"wins rag={rag_wins} ties={ties} vanilla={vanilla_wins}")
    print(f"json={out_json}")
    print(f"md={out_md}")
    print(f"latest_json={latest_json}")
    print(f"latest_md={latest_md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
