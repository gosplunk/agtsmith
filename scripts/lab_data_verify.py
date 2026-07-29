#!/usr/bin/env python3
"""Verify lab-generated events via Splunk MCP search."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from lab_data.config import (  # noqa: E402
    format_verify_query,
    load_event_catalog,
    load_ui_env,
    resolve_domain_target,
    resolve_layout_name,
    write_verify_manifest,
)
from minimal_question_to_answer import run_splunk_query_args  # noqa: E402

from environment_profile import PROFILE_PATH_DEFAULT  # noqa: E402


def _row_count(structured: dict[str, Any]) -> int:
    if not isinstance(structured, dict):
        return 0
    for key in ("rows_returned", "row_count", "result_count"):
        if key in structured:
            try:
                return int(structured[key])
            except (TypeError, ValueError):
                pass
    results = structured.get("results")
    if isinstance(results, list):
        return len(results)
    return 0


def verify(*, layout: str, skip_mcp: bool) -> dict[str, Any]:
    ui_env = load_ui_env()
    layout_name = resolve_layout_name(layout, profile_path=PROFILE_PATH_DEFAULT, ui_env=ui_env)
    catalog = load_event_catalog()
    sets_raw = catalog.get("event_sets", {})
    if not isinstance(sets_raw, dict):
        raise ValueError("event_sets_missing")

    rows: list[dict[str, Any]] = []
    all_ok = True

    for name, event_set in sets_raw.items():
        if not isinstance(event_set, dict):
            continue
        domain = str(event_set.get("domain", "")).strip()
        try:
            target = resolve_domain_target(layout_name, domain)
        except Exception as exc:
            rows.append({"event_set": name, "ok": False, "error": str(exc)})
            all_ok = False
            continue

        verify_template = str(event_set.get("verify_query", "")).strip()
        min_expected = int(event_set.get("min_expected_rows", 1))
        if not verify_template:
            rows.append({"event_set": name, "ok": True, "skipped": True, "reason": "no_verify_query"})
            continue

        query = format_verify_query(
            verify_template,
            index=target["index"],
            sourcetype=target["sourcetype"],
        )
        if not query.lower().startswith("search "):
            query = f"search {query}"

        entry: dict[str, Any] = {
            "event_set": name,
            "benchmark_case": event_set.get("benchmark_case"),
            "domain": domain,
            "index": target["index"],
            "sourcetype": target["sourcetype"],
            "verify_query": query,
            "min_expected_rows": min_expected,
        }

        if skip_mcp:
            entry["ok"] = True
            entry["skipped_mcp"] = True
            entry["row_count"] = None
            rows.append(entry)
            continue

        try:
            result = run_splunk_query_args(
                {"query": query, "earliest_time": "-24h", "latest_time": "now", "row_limit": 10},
                intent="lab_data_verify",
            )
            structured = result.get("structured", {}) if isinstance(result, dict) else {}
            count = _row_count(structured if isinstance(structured, dict) else {})
            entry["row_count"] = count
            entry["ok"] = count >= min_expected
            if not entry["ok"]:
                all_ok = False
                entry["error"] = f"row_count_low:{count}<{min_expected}"
        except Exception as exc:
            entry["ok"] = False
            entry["error"] = str(exc)
            all_ok = False

        rows.append(entry)

    manifest = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "layout": layout_name,
        "all_ok": all_ok,
        "skip_mcp": skip_mcp,
        "domains": rows,
        "benchmark_case_expectations": {
            str(row.get("benchmark_case")): {
                "min_rows": row.get("min_expected_rows", 0),
                "actual_rows": row.get("row_count"),
                "ok": row.get("ok"),
            }
            for row in rows
            if row.get("benchmark_case")
        },
    }
    path = write_verify_manifest(manifest)
    manifest["manifest_path"] = str(path)
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify lab data via Splunk MCP")
    parser.add_argument("--layout", default="")
    parser.add_argument("--skip-mcp", action="store_true")
    parser.add_argument("--json-out", default="")
    args = parser.parse_args()

    try:
        manifest = verify(layout=args.layout, skip_mcp=args.skip_mcp)
    except Exception as exc:
        print(f"ERROR lab_data_verify: {exc}", file=sys.stderr)
        return 1

    if args.json_out:
        Path(args.json_out).write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    print(f"layout={manifest.get('layout')}")
    print(f"all_ok={manifest.get('all_ok')}")
    for row in manifest.get("domains", []):
        status = "PASS" if row.get("ok") else "FAIL"
        print(f"{status} {row.get('event_set')} rows={row.get('row_count')}")
    return 0 if manifest.get("all_ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
