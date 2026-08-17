#!/usr/bin/env python3
"""Promote a passing multimodel case into domain pattern hints (dry-run by default)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REPORT = PROJECT_ROOT / "artifacts" / "spl_autonomy" / "internal_benchmark" / "latest.json"


def main() -> int:
    parser = argparse.ArgumentParser(description="Suggest promotion artifacts for a passing internal case")
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--report", default=str(DEFAULT_REPORT))
    parser.add_argument("--apply", action="store_true", help="Reserved for future auto-merge; currently dry-run only")
    args = parser.parse_args()

    rows = json.loads(Path(args.report).read_text(encoding="utf-8"))
    results = rows.get("results", []) if isinstance(rows, dict) else []
    match = next((r for r in results if isinstance(r, dict) and r.get("id") == args.case_id), None)
    if not match:
        print(json.dumps({"error": f"case_not_found:{args.case_id}"}, indent=2))
        return 1

    suggestion = {
        "case_id": args.case_id,
        "question": match.get("question"),
        "intent": match.get("expected_intent"),
        "promote_query": match.get("multi_model_query") or match.get("pipeline_query") or match.get("canonical_spl"),
        "next_steps": [
            "Add/confirm domain pattern in scripts/spl_domain_knowledge.py",
            "Add intent contract groups in scripts/intent_field_contracts.py if missing",
            "Refresh internal sourcetype card gold fragment via make internal-sourcetype-cards",
            "Add oracle row to benchmarks/internal_spl_oracles.json when human-validated",
        ],
        "apply": bool(args.apply),
    }
    print(json.dumps(suggestion, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
