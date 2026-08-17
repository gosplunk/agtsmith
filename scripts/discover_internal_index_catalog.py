#!/usr/bin/env python3
"""Discover sourcetypes, counts, and field samples in Splunk internal indexes."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from build_environment_profile import _extract_field_inventory, _field_summary_query
from minimal_question_to_answer import run_splunk_query_args

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT = PROJECT_ROOT / "artifacts" / "environment" / "internal_index_catalog.json"
INTERNAL_INDEXES = ("_internal", "_audit", "_introspection")
WINDOWS = ("-1h", "-24h", "-7d")


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


def _discover_sourcetypes(index: str, *, earliest: str, latest: str, row_limit: int) -> list[dict[str, Any]]:
    args = {
        "query": f"search index={index} | stats count by sourcetype | sort - count",
        "earliest_time": earliest,
        "latest_time": latest,
        "row_limit": row_limit,
    }
    try:
        data = run_splunk_query_args(args, intent="internal_catalog", summary_hint="internal sourcetype inventory")
    except Exception as exc:
        return [{"error": f"{type(exc).__name__}: {exc}"}]
    return _rows(data)


def _discover_hosts(index: str, *, earliest: str, latest: str, row_limit: int) -> list[dict[str, Any]]:
    args = {
        "query": f"search index={index} | stats count by host | sort - count",
        "earliest_time": earliest,
        "latest_time": latest,
        "row_limit": min(row_limit, 20),
    }
    try:
        data = run_splunk_query_args(args, intent="internal_catalog", summary_hint="internal host inventory")
    except Exception as exc:
        return [{"error": f"{type(exc).__name__}: {exc}"}]
    return _rows(data)


def _discover_fields(index: str, sourcetype: str, *, earliest: str, latest: str, sample_size: int) -> dict[str, Any]:
    query_args = {
        "query": _field_summary_query([index], sourcetype, sample_size),
        "earliest_time": earliest,
        "latest_time": latest,
        "row_limit": 40,
    }
    try:
        data = run_splunk_query_args(query_args, intent="internal_catalog", summary_hint="internal field inventory")
        fields = _extract_field_inventory(data)
    except Exception as exc:
        return {"query_error": f"{type(exc).__name__}: {exc}", "fields": []}
    return {
        "sampled_query": query_args["query"],
        "field_count": len(fields),
        "fields": fields[:20],
    }


def build_catalog(*, row_limit: int = 50, field_sample_size: int = 500, offline: bool = False) -> dict[str, Any]:
    if offline:
        return {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "offline": True,
            "indexes": {},
        }

    indexes: dict[str, Any] = {}
    for index_name in INTERNAL_INDEXES:
        sourcetypes_by_window: dict[str, list[dict[str, Any]]] = {}
        for window in WINDOWS:
            sourcetypes_by_window[window] = _discover_sourcetypes(
                index_name,
                earliest=window,
                latest="now",
                row_limit=row_limit,
            )
        active_24h = [
            str(row.get("sourcetype", "")).strip()
            for row in sourcetypes_by_window.get("-24h", [])
            if str(row.get("sourcetype", "")).strip() and int(row.get("count", 0) or 0) > 0
        ]
        field_inventory: dict[str, Any] = {}
        for sourcetype in active_24h[:12]:
            field_inventory[sourcetype] = _discover_fields(
                index_name,
                sourcetype,
                earliest="-24h",
                latest="now",
                sample_size=field_sample_size,
            )
        indexes[index_name] = {
            "sourcetypes_by_window": sourcetypes_by_window,
            "active_sourcetypes_24h": active_24h,
            "top_hosts_24h": _discover_hosts(index_name, earliest="-24h", latest="now", row_limit=row_limit),
            "field_inventory_24h": field_inventory,
        }
    return {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "offline": False,
        "indexes": indexes,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Discover Splunk internal index catalog via MCP")
    parser.add_argument("--out", default=str(DEFAULT_OUT))
    parser.add_argument("--row-limit", type=int, default=50)
    parser.add_argument("--field-sample-size", type=int, default=500)
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()

    catalog = build_catalog(
        row_limit=max(1, args.row_limit),
        field_sample_size=max(50, args.field_sample_size),
        offline=bool(args.offline),
    )
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(catalog, indent=2), encoding="utf-8")
    index_count = len(catalog.get("indexes", {}))
    active_total = sum(
        len((catalog.get("indexes", {}).get(name, {}) or {}).get("active_sourcetypes_24h", []))
        for name in INTERNAL_INDEXES
    )
    print(
        json.dumps(
            {
                "out": str(out_path),
                "indexes": index_count,
                "active_sourcetypes_24h": active_total,
                "offline": catalog.get("offline", False),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
