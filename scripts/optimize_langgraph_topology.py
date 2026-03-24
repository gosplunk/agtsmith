#!/usr/bin/env python3
"""Rank topology experiments and print the current best candidate."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Pick the current best LangGraph topology experiment")
    parser.add_argument("--results", default="artifacts/evals/langgraph/topology/langgraph_topology_eval_latest.json")
    args = parser.parse_args()

    payload = json.loads(Path(args.results).read_text(encoding="utf-8"))
    experiments = payload.get("experiments", [])
    if not experiments:
        print("no experiments found")
        return 1
    best = experiments[0]
    print(json.dumps(
        {
            "best_experiment": best.get("id"),
            "avg_score": best.get("avg_score"),
            "support_rate_pct": best.get("support_rate_pct"),
            "intent_match_rate_pct": best.get("intent_match_rate_pct"),
            "avg_latency_ms": best.get("avg_latency_ms"),
            "env": best.get("env", {}),
        },
        indent=2,
    ))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
