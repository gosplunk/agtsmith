#!/usr/bin/env python3
"""Build a reference gold corpus from the live LangGraph pipeline."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
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


def _load_seeds(path: Path) -> list[dict[str, Any]]:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description="Build LangGraph gold corpus from seed questions")
    parser.add_argument("--seeds", default="benchmarks/langgraph_gold_seed_questions.json")
    parser.add_argument("--output", default="artifacts/evals/langgraph/gold_corpus_latest.json")
    parser.add_argument("--limit", type=int, default=0)
    args = parser.parse_args()

    seeds = _load_seeds(Path(args.seeds))
    if args.limit > 0:
        seeds = seeds[: args.limit]

    out_cases: list[dict[str, Any]] = []
    for item in seeds:
        question = str(item["question"])
        result = run_multi_model_soc(question).get("result", {})
        preview = result.get("spl_results_preview", []) if isinstance(result, dict) else []
        result_fields = list(preview[0].keys()) if isinstance(preview, list) and preview and isinstance(preview[0], dict) else []
        out_cases.append(
            {
                "id": str(item["id"]),
                "family": str(item.get("family", "unknown")),
                "canonical_question": question,
                "reference_generated_at_utc": datetime.now(timezone.utc).isoformat(),
                "reference": {
                    "intent": str(result.get("intent", "")),
                    "selected_tool": str(result.get("selected_tool", "")),
                    "generated_spl": str(result.get("generated_spl", "")),
                    "query_shape": _extract_shape(str(result.get("generated_spl", ""))),
                    "rows_returned": int(result.get("rows_returned", 0) or 0),
                    "result_fields": result_fields,
                    "supported": bool(result.get("supported", False)),
                    "skip_peer_review": bool(result.get("skip_peer_review", False)),
                    "topology_settings": result.get("topology_settings", {}),
                },
                "validation_notes": {
                    "reviewer_notes": result.get("reviewer_notes", []),
                    "reviewer_caveats": result.get("reviewer_caveats", []),
                    "final_confidence": result.get("final_confidence", 0),
                },
            }
        )

    payload = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "seed_file": str(Path(args.seeds)),
        "cases": out_cases,
    }

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(output_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
