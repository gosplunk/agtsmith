#!/usr/bin/env python3
"""Build SPL domain pattern oracle artifact from templates, benchmarks, and gold oracles."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from holdout_firewall import filter_holdout_records
from minimal_question_to_answer import map_question_to_template, template_to_query_args
from query_templates import TEMPLATES
from spl_domain_knowledge import BUILTIN_PATTERNS

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT = PROJECT_ROOT / "artifacts" / "knowledge" / "spl_domain_patterns.json"


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_") or "pattern"


def _patterns_from_templates() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for template in TEMPLATES:
        if template.intent in {"unknown", "custom_query"}:
            continue
        question = template.keywords[0] if template.keywords else template.intent.replace("_", " ")
        query = str(template_to_query_args(template, question).get("query", "")).strip()
        rows.append(
            {
                "id": f"template_{_slug(template.intent)}",
                "intent": template.intent,
                "triggers": [kw.lower() for kw in template.keywords[:6]],
                "preferred_tool": "splunk_run_query",
                "query_template": query or template.query,
                "anti_patterns": [r"\|\s*stats\s+count\s*$"] if " by " in (query or template.query).lower() else [],
                "explanation": template.summary_hint or f"Canonical template for intent={template.intent}.",
                "tags": list(template.tags),
                "priority": 55,
                "source": "query_templates",
            }
        )
    return rows


def _patterns_from_benchmark_cases(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    try:
        cases = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    if isinstance(cases, dict):
        cases = cases.get("cases", [])
    if not isinstance(cases, list):
        return []
    rows: list[dict[str, Any]] = []
    for case in cases:
        if not isinstance(case, dict):
            continue
        case_id = str(case.get("id", "")).strip()
        question = str(case.get("question", "")).strip()
        intent = str(case.get("expected_intent", "")).strip()
        if not case_id or not question:
            continue
        canonical = str(case.get("canonical_spl", "")).strip()
        if not canonical and intent:
            mapped = map_question_to_template(question)
            canonical = str(template_to_query_args(mapped, question).get("query", "")).strip()
        rows.append(
            {
                "id": f"benchmark_{_slug(case_id)}",
                "intent": intent,
                "triggers": [question.lower()],
                "preferred_tool": "splunk_run_query",
                "query_template": canonical,
                "anti_patterns": [],
                "explanation": f"Operational benchmark case {case_id}.",
                "tags": ["benchmark", str(case.get("category", "")).strip()],
                "priority": 65,
                "source": str(path.name),
            }
        )
    return rows


def _patterns_from_gold_oracles(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    oracle_rows = payload.get("oracles", []) if isinstance(payload, dict) else []
    if not isinstance(oracle_rows, list):
        return []
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for entry in oracle_rows:
        if not isinstance(entry, dict):
            continue
        intent = str(entry.get("intent", "")).strip()
        question = str(entry.get("question", "")).strip()
        oracle_id = str(entry.get("id", "")).strip()
        if not intent or not question or not oracle_id:
            continue
        dedupe = f"{intent}:{question.lower()}"
        if dedupe in seen:
            continue
        seen.add(dedupe)
        mapped = map_question_to_template(question)
        query = str(template_to_query_args(mapped, question).get("query", "")).strip()
        rows.append(
            {
                "id": f"gold_{_slug(oracle_id)}",
                "intent": intent,
                "triggers": [question.lower()],
                "preferred_tool": "splunk_run_query",
                "query_template": query,
                "anti_patterns": [str(x) for x in entry.get("forbidden_patterns", []) if str(x).strip()],
                "explanation": "Gold oracle constraints: "
                + ", ".join(str(x) for x in entry.get("required_substrings", [])[:4]),
                "tags": ["gold_oracle", str(entry.get("variant", "")).strip()],
                "priority": 72,
                "source": "gold_spl_oracles",
            }
        )
    return rows


def build_patterns(
    *,
    templates: bool = True,
    operational_cases: Path | None = None,
    gold_oracles: Path | None = None,
) -> dict[str, Any]:
    merged: dict[str, dict[str, Any]] = {}
    for row in BUILTIN_PATTERNS:
        merged[str(row["id"])] = dict(row)

    if templates:
        for row in _patterns_from_templates():
            merged.setdefault(row["id"], row)

    op_path = operational_cases or (PROJECT_ROOT / "benchmarks" / "operational_spl_accuracy.json")
    for row in _patterns_from_benchmark_cases(op_path):
        merged.setdefault(row["id"], row)

    gold_path = gold_oracles or (PROJECT_ROOT / "benchmarks" / "gold_spl_oracles.json")
    for row in _patterns_from_gold_oracles(gold_path):
        merged.setdefault(row["id"], row)

    allowed, rejected = filter_holdout_records(merged.values())
    patterns = sorted(allowed, key=lambda r: (-int(r.get("priority", 0)), str(r.get("id", ""))))
    return {
        "timestamp_utc": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
        "pattern_count": len(patterns),
        "holdout_rejected_count": len(rejected),
        "patterns": patterns,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Build SPL domain pattern oracle")
    parser.add_argument("--out", default=str(DEFAULT_OUT))
    parser.add_argument("--no-templates", action="store_true")
    args = parser.parse_args()
    payload = build_patterns(templates=not args.no_templates)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(json.dumps({"out": str(out), "pattern_count": payload["pattern_count"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
