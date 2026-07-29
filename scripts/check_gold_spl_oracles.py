#!/usr/bin/env python3
"""Offline validator for gold SPL oracles (no MCP)."""

from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

from environment_profile import apply_environment_query_constraints
from intent_field_contracts import validate_platform_sourcetype_coherence, validate_intent_platform_scope
from minimal_question_to_answer import map_question_to_template, template_to_query_args
from query_templates import TEMPLATES

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ORACLES_PATH = PROJECT_ROOT / "benchmarks" / "gold_spl_oracles.json"


def _load_payload(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("oracle_payload_must_be_object")
    return payload


def _template_for_intent(intent: str):
    for template in TEMPLATES:
        if template.intent == intent:
            return template
    raise KeyError(f"unknown_intent:{intent}")


def _count_branches(query: str) -> int:
    append_count = len(re.findall(r"\|\s*append\s*\[", query, flags=re.IGNORECASE))
    return 1 + append_count


def _subsearch_segments(query: str) -> list[str]:
    parts = re.split(r"\|\s*append\s*\[\s*search\s+", query, flags=re.IGNORECASE)
    segments = [parts[0].strip()]
    for part in parts[1:]:
        branch = part.rsplit("]", 1)[0] if "]" in part else part
        segments.append(f"search {branch}".strip())
    return [segment for segment in segments if segment]


def _render_query(intent: str, question: str, profile_path: Path) -> str:
    mapped = map_question_to_template(question, profile_path=profile_path)
    if mapped.intent != intent:
        raise ValueError(f"question_maps_to:{mapped.intent}:expected:{intent}")
    args = template_to_query_args(template=mapped, question=question, apply_environment=True, profile_path=profile_path)
    return str(args.get("query", "")).strip()


def _validate_oracle(query: str, oracle: dict[str, Any], *, profile_path: Path | None = None) -> tuple[bool, list[str]]:
    findings: list[str] = []
    lower = query.lower()
    segments = _subsearch_segments(query)

    for substring in oracle.get("required_substrings", []):
        term = str(substring)
        if term.lower() not in lower:
            findings.append(f"missing_substring:{term}")

    for pattern in oracle.get("forbidden_patterns", []):
        compiled = re.compile(str(pattern), flags=re.IGNORECASE)
        if any(compiled.search(segment) for segment in segments):
            findings.append(f"forbidden_pattern:{pattern}")

    intent = str(oracle.get("intent", "")).strip()
    question = str(oracle.get("question", "")).strip()
    if intent:
        coherent, coherence_reason = validate_platform_sourcetype_coherence(query, intent)
        if not coherent:
            findings.append(f"coherence:{coherence_reason}")
        scope_ok, scope_reason = validate_intent_platform_scope(
            query,
            intent,
            question=question,
            profile_path=profile_path,
        )
        if not scope_ok:
            findings.append(f"scope:{scope_reason}")

    min_branches = int(oracle.get("min_branches", 1))
    branch_count = _count_branches(query)
    if branch_count < min_branches:
        findings.append(f"branch_count:{branch_count}<{min_branches}")

    if not query.strip():
        findings.append("empty_query")

    return not findings, findings


def _write_profile_fixtures(payload: dict[str, Any], root: Path) -> dict[str, Path]:
    fixtures = payload.get("profile_fixtures", {})
    if not isinstance(fixtures, dict):
        raise ValueError("profile_fixtures_missing")
    paths: dict[str, Path] = {}
    for variant, profile in fixtures.items():
        if not isinstance(profile, dict):
            raise ValueError(f"invalid_profile_fixture:{variant}")
        path = root / f"{variant}.json"
        path.write_text(json.dumps(profile, indent=2), encoding="utf-8")
        paths[str(variant)] = path
    return paths


def run_check(oracles_path: Path, *, live_profile_path: Path | None = None) -> tuple[int, dict[str, Any]]:
    payload = _load_payload(oracles_path)
    oracles = payload.get("oracles", [])
    if not isinstance(oracles, list) or not oracles:
        raise SystemExit("no_oracles_configured")

    report_rows: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="gold_spl_oracles_") as tmp:
        profile_paths = _write_profile_fixtures(payload, Path(tmp))
        if live_profile_path is not None and live_profile_path.exists():
            profile_paths["live_profile"] = live_profile_path
        for oracle in oracles:
            if not isinstance(oracle, dict):
                continue
            oracle_id = str(oracle.get("id", "")).strip()
            intent = str(oracle.get("intent", "")).strip()
            variant = str(oracle.get("variant", "")).strip()
            question = str(oracle.get("question", "")).strip()
            profile_path = profile_paths.get(variant)
            if live_profile_path is not None and live_profile_path.exists() and variant in {"live_lab_real_profile", "existing_lab"}:
                profile_path = live_profile_path
            if not oracle_id or not intent or not variant or not question or profile_path is None:
                report_rows.append(
                    {
                        "id": oracle_id or "unknown",
                        "ok": False,
                        "findings": ["invalid_oracle_entry"],
                    }
                )
                continue
            try:
                query = _render_query(intent, question, profile_path)
                ok, findings = _validate_oracle(query, oracle, profile_path=profile_path)
            except Exception as exc:
                query = ""
                ok = False
                findings = [f"render_error:{type(exc).__name__}:{exc}"]
            report_rows.append(
                {
                    "id": oracle_id,
                    "intent": intent,
                    "variant": variant,
                    "question": question,
                    "ok": ok,
                    "findings": findings,
                    "branch_count": _count_branches(query) if query else 0,
                    "query_preview": query[:500],
                }
            )

    passed = sum(1 for row in report_rows if row.get("ok"))
    report = {
        "oracle_count": len(report_rows),
        "passed": passed,
        "failed": len(report_rows) - passed,
        "results": report_rows,
    }
    return (0 if passed == len(report_rows) else 1), report


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate gold SPL oracles offline")
    parser.add_argument("--oracles", default=str(DEFAULT_ORACLES_PATH))
    parser.add_argument("--profile", default="", help="Optional live environment profile path")
    parser.add_argument("--json-out", default="")
    args = parser.parse_args()

    live_profile = Path(args.profile).expanduser() if args.profile else None
    exit_code, report = run_check(Path(args.oracles), live_profile_path=live_profile)
    print("=== Gold SPL Oracles ===")
    print(f"oracle_count={report['oracle_count']}")
    print(f"passed={report['passed']}")
    print(f"failed={report['failed']}")
    for row in report["results"]:
        status = "PASS" if row.get("ok") else "FAIL"
        print(f"{status} {row.get('id')}")
        if not row.get("ok"):
            for finding in row.get("findings", []):
                print(f"  - {finding}")
    if args.json_out:
        out_path = Path(args.json_out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"json_out={out_path}")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
