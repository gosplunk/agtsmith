#!/usr/bin/env python3
"""Seed internal SPL oracle cases from catalog + sourcetype briefs (offline batch)."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

import yaml

from minimal_question_to_answer import run_splunk_query_args
from query_policy import validate_query_args

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CATALOG = PROJECT_ROOT / "artifacts" / "environment" / "internal_index_catalog.json"
DEFAULT_BRIEFS = PROJECT_ROOT / "benchmarks" / "internal_sourcetype_briefs.yaml"
DEFAULT_OUT = PROJECT_ROOT / "benchmarks" / "internal_spl_oracles.json"


def _rows(data: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not isinstance(data, dict):
        return []
    structured = data.get("structured", data)
    if not isinstance(structured, dict):
        return []
    results = structured.get("results", [])
    if not isinstance(results, list):
        return []
    return [row for row in results if isinstance(row, dict)]


def _slug(text: str) -> str:
    cleaned = re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")
    return cleaned[:64] or "case"


def _catalog_has_data(catalog: dict[str, Any], index: str, sourcetype: str | None) -> bool:
    indexes = catalog.get("indexes", {})
    if not isinstance(indexes, dict):
        return True
    index_row = indexes.get(index, {})
    if not isinstance(index_row, dict):
        return True
    active = index_row.get("active_sourcetypes_24h", [])
    if not isinstance(active, list):
        return True
    if not sourcetype:
        return bool(active)
    return sourcetype in active


def _validate_canonical(
    *,
    question: str,
    canonical_spl: str,
    earliest: str,
    offline: bool,
    row_limit: int,
) -> tuple[bool, list[str], list[str]]:
    findings: list[str] = []
    ok, reason = validate_query_args(
        {
            "query": canonical_spl,
            "earliest_time": earliest,
            "latest_time": "now",
            "row_limit": row_limit,
        },
        question=question,
    )
    if not ok:
        findings.append(f"policy:{reason}")
        return False, findings, []

    if offline:
        return True, findings, []

    try:
        data = run_splunk_query_args(
            {
                "query": canonical_spl,
                "earliest_time": earliest,
                "latest_time": "now",
                "row_limit": row_limit,
            },
            intent="internal_oracle_seed",
            summary_hint="validate internal oracle canonical SPL",
        )
    except Exception as exc:
        findings.append(f"mcp:{type(exc).__name__}:{exc}")
        return False, findings, []

    result_rows = _rows(data)
    if not result_rows:
        findings.append("zero_rows")
        return False, findings, []
    headers = sorted({key for row in result_rows for key in row.keys() if key != "count"})
    return True, findings, headers


def _case_from_brief(
    brief_id: str,
    brief: dict[str, Any],
    *,
    catalog: dict[str, Any],
    offline: bool,
    row_limit: int,
) -> list[dict[str, Any]]:
    index = str(brief.get("index", "_internal")).strip()
    sourcetype = str(brief.get("sourcetype", "")).strip() or None
    sourcetypes = brief.get("sourcetypes", [])
    sourcetype_tags = [str(x) for x in sourcetypes if str(x).strip()]
    if sourcetype:
        sourcetype_tags = [sourcetype] + sourcetype_tags
    sourcetype_tags = sorted(set(sourcetype_tags))

    if not _catalog_has_data(catalog, index, sourcetype):
        return []

    questions = brief.get("example_questions", [])
    if not isinstance(questions, list) or not questions:
        return []
    canonical = str(brief.get("canonical_shape", "")).strip()
    if not canonical:
        return []

    compare_fields = [str(x) for x in brief.get("compare_fields", []) if str(x).strip()]
    entity_fields = [field for field in compare_fields if field != "count"]
    cases: list[dict[str, Any]] = []
    for question in questions[:3]:
        q = str(question).strip()
        if not q:
            continue
        ok, findings, headers = _validate_canonical(
            question=q,
            canonical_spl=canonical,
            earliest="-24h",
            offline=offline,
            row_limit=row_limit,
        )
        if not ok:
            continue
        resolved_compare = compare_fields or headers
        cases.append(
            {
                "id": f"{brief_id}_{_slug(q)}",
                "category": "platform_ops",
                "index_scope": index,
                "sourcetype_tags": sourcetype_tags,
                "question": q,
                "expected_intent": _intent_for_brief(brief_id, q),
                "canonical_spl": canonical,
                "earliest_time": "-24h" if "24" in q.lower() else "-1h",
                "latest_time": "now",
                "compare_fields": resolved_compare,
                "entity_fields": entity_fields or [field for field in resolved_compare if field != "count"],
                "min_jaccard": 0.7,
                "min_entity_recall": 0.75,
                "min_equivalence_score": 0.7,
                "data_present_required": bool(brief.get("data_present_required", True)),
                "seed_findings": findings,
            }
        )
    return cases


def _intent_for_brief(brief_id: str, question: str) -> str:
    q = question.lower()
    mapping = {
        "scheduler": "splunk_internal_health",
        "splunkd": "internal_splunkd_health",
        "deploymentclient": "forwarder_connectivity",
        "license_usage": "splunk_license_usage",
        "audittrail": "internal_auth_failures",
        "internal_inventory": "internal_sourcetypes",
    }
    if brief_id in mapping:
        return mapping[brief_id]
    if "splunkd" in q:
        return "internal_splunkd_health"
    if "auth" in q:
        return "internal_auth_failures"
    if "forwarder" in q:
        return "forwarder_connectivity"
    if "license" in q:
        return "splunk_license_usage"
    if "sourcetype" in q:
        return "internal_sourcetypes"
    return "splunk_internal_health"


def build_oracles(
    *,
    catalog_path: Path,
    briefs_path: Path,
    offline: bool,
    row_limit: int,
) -> list[dict[str, Any]]:
    catalog: dict[str, Any] = {}
    if catalog_path.is_file():
        catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    briefs = yaml.safe_load(briefs_path.read_text(encoding="utf-8"))
    if not isinstance(briefs, dict):
        raise ValueError("briefs_must_be_mapping")

    cases: list[dict[str, Any]] = []
    for brief_id, brief in briefs.items():
        if not isinstance(brief, dict):
            continue
        cases.extend(
            _case_from_brief(
                str(brief_id),
                brief,
                catalog=catalog,
                offline=offline,
                row_limit=row_limit,
            )
        )
    deduped: dict[str, dict[str, Any]] = {}
    for case in cases:
        deduped[str(case["id"])] = case
    return [deduped[key] for key in sorted(deduped.keys())]


def main() -> int:
    parser = argparse.ArgumentParser(description="Build internal SPL oracle cases from catalog + briefs")
    parser.add_argument("--catalog", default=str(DEFAULT_CATALOG))
    parser.add_argument("--briefs", default=str(DEFAULT_BRIEFS))
    parser.add_argument("--out", default=str(DEFAULT_OUT))
    parser.add_argument("--row-limit", type=int, default=20)
    parser.add_argument("--offline", action="store_true", help="Skip MCP row validation")
    parser.add_argument("--merge-existing", action="store_true", help="Keep hand-authored cases not in seed output")
    args = parser.parse_args()

    seeded = build_oracles(
        catalog_path=Path(args.catalog),
        briefs_path=Path(args.briefs),
        offline=bool(args.offline),
        row_limit=max(1, args.row_limit),
    )
    out_path = Path(args.out)
    merged: dict[str, dict[str, Any]] = {str(row["id"]): row for row in seeded}
    if args.merge_existing and out_path.is_file():
        existing = json.loads(out_path.read_text(encoding="utf-8"))
        if isinstance(existing, list):
            for row in existing:
                if isinstance(row, dict) and str(row.get("id", "")).strip():
                    merged.setdefault(str(row["id"]), row)
    payload = [merged[key] for key in sorted(merged.keys())]
    out_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"out": str(out_path), "case_count": len(payload)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
