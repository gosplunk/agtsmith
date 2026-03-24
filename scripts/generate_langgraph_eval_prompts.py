#!/usr/bin/env python3
"""Generate prompt variants from a LangGraph gold corpus."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


def _variants(question: str) -> list[tuple[str, str]]:
    stem = question.strip().rstrip(".")
    return [
        ("exact", question.strip()),
        ("investigate", f"Investigate this and show me the evidence: {stem}."),
        ("terse", stem),
        ("analyst_style", stem.replace("Show ", "").replace("show ", "")),
        ("preserve_evidence", f"{stem}. Preserve the evidence rows and keep the query read-only."),
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate eval prompt variants from a gold corpus")
    parser.add_argument("--gold", default="artifacts/evals/langgraph/gold_corpus_latest.json")
    parser.add_argument("--output", default="artifacts/evals/langgraph/eval_prompts_latest.json")
    args = parser.parse_args()

    gold = json.loads(Path(args.gold).read_text(encoding="utf-8"))
    prompts: list[dict[str, str]] = []
    for case in gold.get("cases", []):
        gold_case_id = str(case["id"])
        question = str(case["canonical_question"])
        family = str(case.get("family", "unknown"))
        for variant_name, prompt in _variants(question):
            prompts.append(
                {
                    "id": f"{gold_case_id}__{variant_name}",
                    "gold_case_id": gold_case_id,
                    "family": family,
                    "variant": variant_name,
                    "prompt": prompt,
                }
            )

    payload = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "gold_source": str(Path(args.gold)),
        "prompts": prompts,
    }
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(output_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
