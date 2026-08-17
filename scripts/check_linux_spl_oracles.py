#!/usr/bin/env python3
"""Offline validator for Linux SPL oracle corpus."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

from intent_field_contracts import validate_platform_sourcetype_coherence
from langgraph_minimal_flow import determine_splunk_tool
from minimal_question_to_answer import map_question_to_template, template_to_query_args
from query_policy import validate_query_args

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ORACLES_PATH = PROJECT_ROOT / "benchmarks" / "linux_spl_oracles.json"
REQUIRED_KEYS = (
    "id",
    "question",
    "expected_intent",
    "canonical_spl",
    "compare_fields",
)


def _load_cases(path: Path) -> list[dict[str, Any]]:
    rows = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(rows, list):
        raise ValueError("linux_oracles_must_be_array")
    return [row for row in rows if isinstance(row, dict)]


def _validate_case(row: dict[str, Any]) -> list[str]:
    findings: list[str] = []
    for key in REQUIRED_KEYS:
        if not str(row.get(key, "")).strip():
            findings.append(f"missing:{key}")

    question = str(row.get("question", "")).strip()
    intent = str(row.get("expected_intent", "")).strip()
    canonical = str(row.get("canonical_spl", "")).strip()
    index_scope = str(row.get("index_scope", "")).strip()

    if index_scope and index_scope not in canonical:
        findings.append(f"canonical_missing_index_scope:{index_scope}")

    for tag in row.get("sourcetype_tags", []) or []:
        tag_text = str(tag).strip()
        if tag_text and tag_text.lower() not in canonical.lower() and tag_text.lower() not in question.lower():
            findings.append(f"sourcetype_tag_not_reflected:{tag_text}")

    if canonical:
        ok, reason = validate_query_args(
            {
                "query": canonical,
                "earliest_time": str(row.get("earliest_time", "-24h")),
                "latest_time": str(row.get("latest_time", "now")),
                "row_limit": 20,
            },
            question=question,
        )
        if not ok:
            findings.append(f"policy:{reason}")
        coherent, coherence_reason = validate_platform_sourcetype_coherence(canonical, intent)
        if not coherent:
            findings.append(f"coherence:{coherence_reason}")

    template = map_question_to_template(question)
    if template.intent != intent:
        findings.append(f"routing_mismatch:{template.intent}->{intent}")

    tool, reason, _, _ = determine_splunk_tool(question, intent)
    if tool != "splunk_run_query" and any(
        term in question.lower()
        for term in ("last hour", "last 24", "last day", "have data", "events in", "activity")
    ):
        findings.append(f"tool_should_be_run_query:{tool}:{reason}")

    rendered = str(template_to_query_args(template, question, apply_environment=False).get("query", "")).strip()
    if index_scope and f"index={index_scope}" not in rendered.lower() and index_scope in {"linux"}:
        if index_scope not in rendered:
            findings.append(f"template_missing_index_scope:{index_scope}")

    if re.search(r"stats\s+count\s+by\s+index\b", rendered, flags=re.IGNORECASE) and "sourcetype" in question.lower():
        findings.append("template_stats_by_index_for_sourcetype_question")

    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate Linux SPL oracle corpus offline")
    parser.add_argument("--cases", default=str(DEFAULT_ORACLES_PATH))
    args = parser.parse_args()

    cases = _load_cases(Path(args.cases))
    if not cases:
        print("no internal oracle cases configured", file=sys.stderr)
        return 1

    failed = 0
    for row in cases:
        findings = _validate_case(row)
        case_id = str(row.get("id", "unknown"))
        if findings:
            failed += 1
            print(f"FAIL {case_id}: {', '.join(findings)}")
        else:
            print(f"OK   {case_id}")

    print(json.dumps({"total": len(cases), "failed": failed}, indent=2))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
