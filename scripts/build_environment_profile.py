#!/usr/bin/env python3
"""Build and persist index/sourcetype environment profile from Splunk MCP."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from environment_profile import PROFILE_PATH_DEFAULT, attach_semantics
from minimal_question_to_answer import run_splunk_get_indexes, run_splunk_get_metadata, run_splunk_query_args


def _safe_text(v: Any) -> str:
    return str(v or "").strip()


def _escape_spl_literal(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


LOW_SIGNAL_FIELDS = {
    "_raw",
    "_time",
    "date_hour",
    "date_mday",
    "date_minute",
    "date_month",
    "date_second",
    "date_wday",
    "date_year",
    "date_zone",
    "index",
    "linecount",
    "punct",
    "source",
    "source_host",
    "sourcetype",
    "splunk_server",
    "splunk_server_group",
    "sourcetype",
    "tag",
    "tag::eventtype",
    "timestamp",
    "timeendpos",
    "timestartpos",
    "eventtype",
}

HIGH_SIGNAL_FIELDS = {
    "account",
    "app",
    "clientip",
    "command",
    "dest",
    "dest_ip",
    "dvc",
    "eventcode",
    "eventid",
    "exe",
    "file",
    "host",
    "http_method",
    "http_user_agent",
    "ip",
    "message",
    "method",
    "parent_process",
    "path",
    "pid",
    "port",
    "process",
    "process_name",
    "query",
    "request",
    "response_code",
    "rhost",
    "src",
    "src_ip",
    "status",
    "status_code",
    "targetusername",
    "tty",
    "uid",
    "uri",
    "uri_path",
    "url",
    "user",
    "user_name",
    "username",
    "useragent",
}

LOW_SIGNAL_PREFIXES = (
    "date_",
    "info_",
    "linebreaker",
    "meta::",
    "punct_",
    "splunk_",
)

LOW_SIGNAL_SUFFIXES = (
    "_pos",
    "_time",
    "::mv",
)


def _field_priority(field_name: str) -> tuple[int, str]:
    name = _safe_text(field_name).lower()
    if not name:
        return (3, "")
    if name in HIGH_SIGNAL_FIELDS:
        return (0, name)
    if (
        name in LOW_SIGNAL_FIELDS
        or name.startswith(LOW_SIGNAL_PREFIXES)
        or name.endswith(LOW_SIGNAL_SUFFIXES)
    ):
        return (2, name)
    return (1, name)


def _clean_sample_value(value: Any) -> str:
    text = _safe_text(value)
    if not text:
        return ""
    if len(text) > 48:
        text = text[:45] + "..."
    return text


def _sample_value_is_useful(field_name: str, value: str) -> bool:
    name = _safe_text(field_name).lower()
    text = _safe_text(value)
    if not text:
        return False
    if name in LOW_SIGNAL_FIELDS or name.startswith("date_"):
        return False
    lowered = text.lower()
    if lowered in {"null", "none", "n/a", "-", "unknown"}:
        return False
    if lowered.startswith("[{") or lowered.startswith("{"):
        return False
    if len(text) > 48:
        return False
    return True


def _field_is_display_worthy(field_name: str, item: dict[str, Any]) -> bool:
    name = _safe_text(field_name).lower()
    priority, _ = _field_priority(name)
    if priority >= 2:
        return False
    try:
        count = int(item.get("count", 0) or 0)
    except Exception:
        count = 0
    if count <= 0:
        return False
    if priority == 0:
        return True
    try:
        distinct_count = int(item.get("distinct_count", 0) or 0)
    except Exception:
        distinct_count = 0
    if distinct_count <= 1 and count < 5:
        return False
    if name.isdigit():
        return False
    return True


def _interesting_field_examples(fields: list[dict[str, Any]], *, limit: int = 8) -> list[dict[str, Any]]:
    examples: list[dict[str, Any]] = []
    for item in fields:
        if not isinstance(item, dict):
            continue
        field_name = _safe_text(item.get("field"))
        if not field_name:
            continue
        if not _field_is_display_worthy(field_name, item):
            continue
        sample_values = item.get("sample_values", [])
        if not isinstance(sample_values, list):
            sample_values = []
        cleaned_values: list[str] = []
        for raw in sample_values:
            cleaned = _clean_sample_value(raw)
            if _sample_value_is_useful(field_name, cleaned) and cleaned not in cleaned_values:
                cleaned_values.append(cleaned)
        examples.append(
            {
                "field": field_name,
                "sample_values": cleaned_values[:3],
                "count": int(item.get("count", 0) or 0),
            }
        )
    examples.sort(key=lambda x: (_field_priority(str(x.get("field", ""))), -int(x.get("count", 0))))
    return examples[:limit]


def _display_fields(fields: list[dict[str, Any]], *, limit: int = 20) -> list[dict[str, Any]]:
    chosen: list[dict[str, Any]] = []
    for item in fields:
        if not isinstance(item, dict):
            continue
        field_name = _safe_text(item.get("field"))
        if not field_name or not _field_is_display_worthy(field_name, item):
            continue
        chosen.append(item)
    chosen.sort(key=lambda x: (_field_priority(str(x.get("field", ""))), -int(x.get("count", 0))))
    return chosen[:limit]


def _extract_indexes(index_data: dict[str, Any]) -> list[str]:
    rows = index_data.get("structured", {}).get("results", []) if isinstance(index_data, dict) else []
    out: list[str] = []
    if isinstance(rows, list):
        for row in rows:
            if not isinstance(row, dict):
                continue
            title = _safe_text(row.get("title"))
            if title and title not in out:
                out.append(title)
    return out


def _extract_sourcetypes(metadata_data: dict[str, Any]) -> tuple[list[str], dict[str, int]]:
    rows = metadata_data.get("structured", {}).get("results", []) if isinstance(metadata_data, dict) else []
    sourcetypes: list[str] = []
    counts: dict[str, int] = {}
    if isinstance(rows, list):
        for row in rows:
            if not isinstance(row, dict):
                continue
            st = _safe_text(row.get("sourcetype"))
            if not st:
                continue
            if st not in sourcetypes:
                sourcetypes.append(st)
            total = row.get("totalCount")
            try:
                counts[st] = int(total) if total is not None else 0
            except Exception:
                counts[st] = 0
    return sorted(sourcetypes), counts


def _load_index_sourcetypes(
    *,
    index_name: str,
    earliest_time: str,
    latest_time: str,
    metadata_row_limit: int,
) -> tuple[list[str], dict[str, int], str]:
    md_args = {
        "type": "sourcetypes",
        "index": index_name,
        "earliest_time": earliest_time,
        "latest_time": latest_time,
        "row_limit": metadata_row_limit,
    }
    md_data = run_splunk_get_metadata(md_args)
    st_list, st_counts = _extract_sourcetypes(md_data)
    if index_name.strip().lower() == "botsv3" and not st_list and earliest_time != "0":
        md_args["earliest_time"] = "0"
        md_args["latest_time"] = "now"
        md_data = run_splunk_get_metadata(md_args)
        st_list, st_counts = _extract_sourcetypes(md_data)
        return st_list, st_counts, "0"
    return st_list, st_counts, earliest_time


def _extract_host_query_sourcetypes(query_data: dict[str, Any]) -> tuple[list[str], dict[str, int]]:
    rows = query_data.get("structured", {}).get("results", []) if isinstance(query_data, dict) else []
    sourcetypes: list[str] = []
    counts: dict[str, int] = {}
    if isinstance(rows, list):
        for row in rows:
            if not isinstance(row, dict):
                continue
            st = _safe_text(row.get("sourcetype"))
            if not st:
                continue
            if st not in sourcetypes:
                sourcetypes.append(st)
            try:
                counts[st] = int(row.get("count", 0))
            except Exception:
                counts[st] = 0
    return sorted(sourcetypes), counts


def _parse_tags_field(value: Any) -> list[str]:
    if isinstance(value, list):
        vals = [str(x).strip() for x in value if str(x).strip()]
    else:
        raw = str(value or "").strip()
        if not raw:
            vals = []
        else:
            # Splunk may return list-like strings, comma/space delimited strings, or single tags.
            raw = raw.strip("[]")
            parts = [p.strip(" '\"") for p in raw.replace(",", " ").split()]
            vals = [p for p in parts if p]
    out: list[str] = []
    for t in vals:
        if t not in out:
            out.append(t)
    return sorted(out)


def _extract_tag_inventory(query_data: dict[str, Any]) -> list[dict[str, Any]]:
    rows = query_data.get("structured", {}).get("results", []) if isinstance(query_data, dict) else []
    out: list[dict[str, Any]] = []
    if not isinstance(rows, list):
        return out
    for row in rows:
        if not isinstance(row, dict):
            continue
        idx = _safe_text(row.get("index"))
        st = _safe_text(row.get("sourcetype"))
        tags = _parse_tags_field(row.get("tags", row.get("tag", "")))
        try:
            count = int(row.get("count", 0))
        except Exception:
            count = 0
        if not idx or not st or not tags:
            continue
        out.append({"index": idx, "sourcetype": st, "tags": tags, "count": count})
    return out


def _merge_tag_inventory(existing_rows: list[dict[str, Any]], fresh_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    def _key(row: dict[str, Any]) -> tuple[str, str]:
        return (_safe_text(row.get("index")), _safe_text(row.get("sourcetype")))

    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for src_rows in (existing_rows, fresh_rows):
        if not isinstance(src_rows, list):
            continue
        for row in src_rows:
            if not isinstance(row, dict):
                continue
            idx, st = _key(row)
            if not idx or not st:
                continue
            tags = _parse_tags_field(row.get("tags", []))
            try:
                count = int(row.get("count", 0))
            except Exception:
                count = 0
            key = (idx, st)
            if key not in merged:
                merged[key] = {"index": idx, "sourcetype": st, "tags": tags, "count": count}
            else:
                prior = merged[key]
                tag_union = sorted(set(_parse_tags_field(prior.get("tags", []))) | set(tags))
                prior["tags"] = tag_union
                if count > int(prior.get("count", 0) or 0):
                    prior["count"] = count
    return sorted(merged.values(), key=lambda x: (str(x.get("index", "")), str(x.get("sourcetype", ""))))


def _build_tag_to_index_sourcetype(tag_rows: list[dict[str, Any]]) -> dict[str, list[dict[str, str]]]:
    out: dict[str, list[dict[str, str]]] = {}
    if not isinstance(tag_rows, list):
        return out
    for row in tag_rows:
        if not isinstance(row, dict):
            continue
        idx = _safe_text(row.get("index"))
        st = _safe_text(row.get("sourcetype"))
        tags = _parse_tags_field(row.get("tags", []))
        if not idx or not st:
            continue
        for tag in tags:
            out.setdefault(tag, []).append({"index": idx, "sourcetype": st})
    for tag in list(out.keys()):
        dedup: list[dict[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for pair in out[tag]:
            key = (_safe_text(pair.get("index")), _safe_text(pair.get("sourcetype")))
            if key in seen:
                continue
            seen.add(key)
            dedup.append({"index": key[0], "sourcetype": key[1]})
        out[tag] = sorted(dedup, key=lambda x: (x["index"], x["sourcetype"]))
    return dict(sorted(out.items(), key=lambda x: x[0]))


def _infer_tags_for_sourcetype(st: str) -> list[str]:
    s = _safe_text(st).lower()
    tags: list[str] = []
    if any(t in s for t in ("auth", "audit", "security", "failed_login", "linux_secure")):
        tags.extend(["authentication", "security"])
    if any(t in s for t in ("access_combined", "apache", "nginx", "http")):
        tags.extend(["web", "network"])
    if any(t in s for t in ("xmlwineventlog", "wineventlog", "win", "sysmon")):
        tags.extend(["windows", "endpoint"])
    if any(t in s for t in ("syslog", "dmesg", "linux", "secure", "ufw", "fail2ban")):
        tags.extend(["linux", "endpoint"])
    if any(t in s for t in ("splunkd", "scheduler", "search_telemetry", "_audit", "_internal")):
        tags.extend(["splunk", "internal"])
    out: list[str] = []
    for t in tags:
        if t not in out:
            out.append(t)
    return out


def _infer_tag_inventory_from_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if not isinstance(rows, list):
        return out
    for row in rows:
        if not isinstance(row, dict):
            continue
        idx = _safe_text(row.get("index"))
        if not idx:
            continue
        st_counts = row.get("sourcetype_event_counts", {})
        if not isinstance(st_counts, dict):
            st_counts = {}
        sts = row.get("sourcetypes", [])
        if not isinstance(sts, list):
            sts = []
        for st in sts:
            st_name = _safe_text(st)
            if not st_name:
                continue
            tags = _infer_tags_for_sourcetype(st_name)
            if not tags:
                continue
            try:
                count = int(st_counts.get(st_name, 0))
            except Exception:
                count = 0
            out.append({"index": idx, "sourcetype": st_name, "tags": tags, "count": count})
    return out


def _rows_to_map(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        idx = _safe_text(row.get("index"))
        if not idx:
            continue
        sts = {str(x).strip() for x in row.get("sourcetypes", []) if str(x).strip()}
        st_counts = row.get("sourcetype_event_counts", {})
        if not isinstance(st_counts, dict):
            st_counts = {}
        counts: dict[str, int] = {}
        for k, v in st_counts.items():
            try:
                counts[str(k)] = int(v)
            except Exception:
                counts[str(k)] = 0
        out[idx] = {
            "index": idx,
            "sourcetypes": sts,
            "sourcetype_event_counts": counts,
            "error": _safe_text(row.get("error")),
        }
    return out


def _merge_rows(existing_rows: list[dict[str, Any]], fresh_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    e_map = _rows_to_map(existing_rows)
    f_map = _rows_to_map(fresh_rows)
    merged_keys = sorted(set(e_map.keys()) | set(f_map.keys()))
    out: list[dict[str, Any]] = []
    for idx in merged_keys:
        e = e_map.get(idx, {"index": idx, "sourcetypes": set(), "sourcetype_event_counts": {}, "error": ""})
        f = f_map.get(idx, {"index": idx, "sourcetypes": set(), "sourcetype_event_counts": {}, "error": ""})
        sts = sorted(set(e.get("sourcetypes", set())) | set(f.get("sourcetypes", set())))
        counts = dict(e.get("sourcetype_event_counts", {}))
        for st, c in f.get("sourcetype_event_counts", {}).items():
            counts[st] = c
        out.append(
            {
                "index": idx,
                "sourcetypes": sts,
                "sourcetype_event_counts": counts,
                "error": _safe_text(f.get("error")) or _safe_text(e.get("error")),
            }
        )
    return out


def _build_sourcetype_to_indexes(rows: list[dict[str, Any]]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        idx = _safe_text(row.get("index"))
        sts = row.get("sourcetypes", [])
        if not idx or not isinstance(sts, list):
            continue
        for st in sts:
            s = _safe_text(st)
            if not s:
                continue
            out.setdefault(s, []).append(idx)
    for st in list(out.keys()):
        out[st] = sorted(set(out[st]))
    return dict(sorted(out.items(), key=lambda x: x[0]))


def _field_summary_query(indexes: list[str], sourcetype: str, sample_size: int) -> str:
    idx_terms = [f'index="{_escape_spl_literal(idx)}"' for idx in indexes if _safe_text(idx)]
    idx_expr = " OR ".join(idx_terms) if idx_terms else "index=*"
    st_esc = _escape_spl_literal(sourcetype)
    return (
        f"search ({idx_expr}) sourcetype=\"{st_esc}\" "
        f"| head {max(1, sample_size)} "
        "| fields * "
        "| fieldsummary maxvals=5"
    )


def _extract_field_inventory(query_data: dict[str, Any]) -> list[dict[str, Any]]:
    rows = query_data.get("structured", {}).get("results", []) if isinstance(query_data, dict) else []
    out: list[dict[str, Any]] = []
    if not isinstance(rows, list):
        return out
    for row in rows:
        if not isinstance(row, dict):
            continue
        field_name = _safe_text(row.get("field"))
        if not field_name:
            continue
        sample_values_raw = row.get("values", row.get("sampleValues", []))
        if isinstance(sample_values_raw, list):
            sample_values = [_safe_text(v) for v in sample_values_raw if _safe_text(v)]
        else:
            raw_text = str(sample_values_raw or "").strip()
            parsed_values: list[str] = []
            if raw_text.startswith("[") and raw_text.endswith("]"):
                try:
                    decoded = json.loads(raw_text)
                    if isinstance(decoded, list):
                        for item in decoded:
                            if isinstance(item, dict):
                                value_text = _safe_text(item.get("value"))
                                if value_text:
                                    parsed_values.append(value_text)
                            else:
                                value_text = _safe_text(item)
                                if value_text:
                                    parsed_values.append(value_text)
                except Exception:
                    parsed_values = []
            sample_values = parsed_values or [v.strip() for v in raw_text.split(",") if v.strip()]
        try:
            count = int(row.get("count", 0))
        except Exception:
            count = 0
        try:
            distinct_count = int(row.get("distinct_count", row.get("distinctCount", 0)))
        except Exception:
            distinct_count = 0
        out.append(
            {
                "field": field_name,
                "count": count,
                "distinct_count": distinct_count,
                "sample_values": sample_values[:5],
            }
        )
    out.sort(key=lambda x: (_field_priority(str(x.get("field", ""))), -int(x.get("count", 0))))
    return out


def _ordered_sourcetypes(rows: list[dict[str, Any]]) -> list[str]:
    names: list[str] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        for st in row.get("sourcetypes", []):
            st_name = _safe_text(st)
            if st_name and st_name not in names:
                names.append(st_name)
    return sorted(names)


def _pick_next_sourcetype(
    *,
    rows: list[dict[str, Any]],
    existing_profile: dict[str, Any] | None,
    requested_sourcetype: str,
) -> str:
    if requested_sourcetype:
        return requested_sourcetype
    ordered = _ordered_sourcetypes(rows)
    if not ordered:
        return ""
    meta = (existing_profile or {}).get("field_inventory_meta", {})
    if not isinstance(meta, dict):
        meta = {}
    last = _safe_text(meta.get("last_refreshed_sourcetype"))
    if not last or last not in ordered:
        return ordered[0]
    idx = ordered.index(last)
    return ordered[(idx + 1) % len(ordered)]


def _build_sourcetype_field_inventory(
    *,
    rows: list[dict[str, Any]],
    earliest_time: str,
    latest_time: str,
    existing_profile: dict[str, Any] | None,
    refresh_mode: str,
    requested_sourcetype: str,
    sample_size: int,
    field_row_limit: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    existing_inventory = {}
    if isinstance(existing_profile, dict):
        prior = existing_profile.get("sourcetype_field_inventory", {})
        if isinstance(prior, dict):
            existing_inventory = dict(prior)

    ordered = _ordered_sourcetypes(rows)
    meta: dict[str, Any] = {
        "ordered_sourcetypes": ordered,
        "refresh_mode": refresh_mode,
        "sample_size": sample_size,
        "field_row_limit": field_row_limit,
        "query_shape": 'search (index=...) sourcetype="..." | head N | fields * | fieldsummary maxvals=5',
    }
    if refresh_mode == "none" or not ordered:
        meta["next_sourcetype"] = ordered[0] if ordered else ""
        return existing_inventory, meta

    requested_sourcetype = _safe_text(requested_sourcetype)
    effective_mode = refresh_mode
    if refresh_mode == "auto":
        if requested_sourcetype:
            effective_mode = "one"
        else:
            missing = [st for st in ordered if st not in existing_inventory]
            effective_mode = "all" if missing else "one"
    meta["effective_refresh_mode"] = effective_mode

    targets = ordered if effective_mode == "all" else []
    if effective_mode == "all":
        missing = [st for st in ordered if st not in existing_inventory]
        if missing:
            targets = missing
    if effective_mode == "one":
        next_st = _pick_next_sourcetype(
            rows=rows,
            existing_profile=existing_profile,
            requested_sourcetype=requested_sourcetype,
        )
        if next_st:
            targets = [next_st]
    meta["target_count"] = len(targets)
    for idx, sourcetype in enumerate(targets, start=1):
        print(f"[field-inventory] {idx}/{len(targets)} sourcetype={sourcetype}")
        indexes = sorted(
            {
                _safe_text(row.get("index"))
                for row in rows
                if isinstance(row, dict)
                and sourcetype in [str(x).strip() for x in row.get("sourcetypes", []) if str(x).strip()]
                and _safe_text(row.get("index"))
            }
        )
        if not indexes:
            continue
        query_args = {
            "query": _field_summary_query(indexes, sourcetype, sample_size),
            "earliest_time": earliest_time,
            "latest_time": latest_time,
            "row_limit": field_row_limit,
        }
        query_error = ""
        fields: list[dict[str, Any]] = []
        try:
            data = run_splunk_query_args(query_args, intent="sourcetype_field_inventory", summary_hint="field inventory")
            fields = _extract_field_inventory(data)
        except Exception as exc:
            query_error = f"{type(exc).__name__}: {exc}"
        existing_inventory[sourcetype] = {
            "sourcetype": sourcetype,
            "indexes": indexes,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "sampled_query": query_args["query"],
            "sample_size": sample_size,
            "field_count": len(fields),
            "fields": fields[: min(len(fields), field_row_limit)],
            "display_fields": _display_fields(fields, limit=min(20, field_row_limit)),
            "interesting_field_examples": _interesting_field_examples(fields),
            "interesting_fields": (
                [
                    str(item.get("field", "")).strip()
                    for item in _interesting_field_examples(fields, limit=12)
                    if isinstance(item, dict) and str(item.get("field", "")).strip()
                ]
                or [
                    str(item.get("field", "")).strip()
                    for item in fields[:8]
                    if isinstance(item, dict) and str(item.get("field", "")).strip()
                ]
            ),
            "query_error": query_error,
        }
        meta["last_refreshed_sourcetype"] = sourcetype

    if ordered:
        last = _safe_text(meta.get("last_refreshed_sourcetype"))
        if last in ordered:
            meta["next_sourcetype"] = ordered[(ordered.index(last) + 1) % len(ordered)]
        else:
            meta["next_sourcetype"] = ordered[0]
    else:
        meta["next_sourcetype"] = ""
    return dict(sorted(existing_inventory.items(), key=lambda x: x[0])), meta


def _build_index_sourcetype_field_inventory(
    *,
    rows: list[dict[str, Any]],
    earliest_time: str,
    latest_time: str,
    sample_size: int,
    field_row_limit: int,
) -> dict[str, dict[str, Any]]:
    inventory: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        index_name = _safe_text(row.get("index"))
        sourcetypes = [str(st).strip() for st in row.get("sourcetypes", []) if str(st).strip()]
        if not index_name or not sourcetypes:
            continue
        bucket = inventory.setdefault(index_name, {})
        for sourcetype in sourcetypes:
            query_args = {
                "query": _field_summary_query([index_name], sourcetype, sample_size),
                "earliest_time": earliest_time,
                "latest_time": latest_time,
                "row_limit": field_row_limit,
            }
            query_error = ""
            fields: list[dict[str, Any]] = []
            try:
                data = run_splunk_query_args(query_args, intent="index_sourcetype_field_inventory", summary_hint="domain field inventory")
                fields = _extract_field_inventory(data)
            except Exception as exc:
                query_error = f"{type(exc).__name__}: {exc}"
            bucket[sourcetype] = {
                "index": index_name,
                "sourcetype": sourcetype,
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                "sampled_query": query_args["query"],
                "sample_size": sample_size,
                "field_count": len(fields),
                "fields": fields[: min(len(fields), field_row_limit)],
                "display_fields": _display_fields(fields, limit=min(20, field_row_limit)),
                "interesting_field_examples": _interesting_field_examples(fields),
                "interesting_fields": (
                    [
                        str(item.get("field", "")).strip()
                        for item in _interesting_field_examples(fields, limit=12)
                        if isinstance(item, dict) and str(item.get("field", "")).strip()
                    ]
                    or [
                        str(item.get("field", "")).strip()
                        for item in fields[:8]
                        if isinstance(item, dict) and str(item.get("field", "")).strip()
                    ]
                ),
                "query_error": query_error,
            }
    return inventory


def _build_host_focus(
    *,
    indexes: list[str],
    focus_host: str,
    row_limit: int,
    earliest_time: str,
    latest_time: str,
) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for index_name in indexes:
        args = {
            "query": f'search index={index_name} host="{focus_host}" | stats count by sourcetype | sort - count',
            "earliest_time": earliest_time,
            "latest_time": latest_time,
            "row_limit": row_limit,
        }
        try:
            q_data = run_splunk_query_args(args, intent="host_focus_profile", summary_hint="host focus inventory")
            st_list, st_counts = _extract_host_query_sourcetypes(q_data)
            rows.append(
                {
                    "index": index_name,
                    "sourcetypes": st_list,
                    "sourcetype_event_counts": st_counts,
                    "error": "",
                }
            )
        except Exception as exc:
            rows.append(
                {
                    "index": index_name,
                    "sourcetypes": [],
                    "sourcetype_event_counts": {},
                    "error": f"{type(exc).__name__}: {exc}",
                }
            )
    st_to_idx = _build_sourcetype_to_indexes(rows)
    return {
        "host": focus_host,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "time_window": {"earliest_time": earliest_time, "latest_time": latest_time},
        "indexes": sorted(rows, key=lambda x: x.get("index", "")),
        "sourcetype_to_indexes": st_to_idx,
        "counts": {
            "index_count": len(rows),
            "sourcetype_count": len(st_to_idx),
        },
    }


def build_profile(
    *,
    metadata_row_limit: int = 200,
    earliest_time: str = "-7d",
    latest_time: str = "now",
    existing_profile: dict[str, Any] | None = None,
    preserve_existing: bool = True,
    focus_host: str = "",
    field_refresh_mode: str = "one",
    field_sourcetype: str = "",
    field_sample_size: int = 200,
    field_row_limit: int = 120,
) -> dict[str, Any]:
    idx_data = run_splunk_get_indexes()
    indexes = _extract_indexes(idx_data)

    fresh_rows: list[dict[str, Any]] = []

    for index_name in indexes:
        try:
            st_list, st_counts, metadata_earliest = _load_index_sourcetypes(
                index_name=index_name,
                earliest_time=earliest_time,
                latest_time=latest_time,
                metadata_row_limit=metadata_row_limit,
            )
        except Exception as exc:
            fresh_rows.append(
                {
                    "index": index_name,
                    "sourcetypes": [],
                    "sourcetype_event_counts": {},
                    "error": f"{type(exc).__name__}: {exc}",
                }
            )
            continue

        fresh_rows.append(
            {
                "index": index_name,
                "sourcetypes": st_list,
                "sourcetype_event_counts": st_counts,
                "error": "",
                "metadata_earliest_time": metadata_earliest,
            }
        )
    rows = sorted(fresh_rows, key=lambda x: x.get("index", ""))

    if preserve_existing and isinstance(existing_profile, dict):
        existing_rows = existing_profile.get("indexes", [])
        if isinstance(existing_rows, list):
            rows = _merge_rows(existing_rows, rows)

    sourcetype_to_indexes = _build_sourcetype_to_indexes(rows)

    profile = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "source": "splunk_mcp",
        "time_window": {
            "earliest_time": earliest_time,
            "latest_time": latest_time,
        },
        "indexes": sorted(rows, key=lambda x: x.get("index", "")),
        "sourcetype_to_indexes": dict(sorted(sourcetype_to_indexes.items(), key=lambda x: x[0])),
        "counts": {
            "index_count": len(rows),
            "sourcetype_count": len(sourcetype_to_indexes),
        },
    }

    field_inventory, field_meta = _build_sourcetype_field_inventory(
        rows=rows,
        earliest_time=earliest_time,
        latest_time=latest_time,
        existing_profile=existing_profile,
        refresh_mode=field_refresh_mode,
        requested_sourcetype=_safe_text(field_sourcetype),
        sample_size=field_sample_size,
        field_row_limit=field_row_limit,
    )
    profile["sourcetype_field_inventory"] = field_inventory
    profile["field_inventory_meta"] = field_meta
    profile["counts"]["field_inventory_sourcetypes"] = len(field_inventory)
    index_sourcetype_inventory = _build_index_sourcetype_field_inventory(
        rows=rows,
        earliest_time=earliest_time,
        latest_time=latest_time,
        sample_size=field_sample_size,
        field_row_limit=field_row_limit,
    )
    profile["index_sourcetype_field_inventory"] = index_sourcetype_inventory
    profile["counts"]["index_sourcetype_inventory_indexes"] = len(index_sourcetype_inventory)

    # Build CIM/tag inventory (bounded) so models can leverage tag-to-domain mappings.
    tag_rows: list[dict[str, Any]] = []
    tag_query_error = ""
    try:
        tag_query_args = {
            "query": "search index=* tag=* | stats values(tag) as tags count by index sourcetype | sort - count",
            "earliest_time": earliest_time,
            "latest_time": latest_time,
            "row_limit": max(200, min(5000, metadata_row_limit * 10)),
        }
        tag_data = run_splunk_query_args(tag_query_args, intent="cim_tag_inventory", summary_hint="cim tag inventory")
        tag_rows = _extract_tag_inventory(tag_data)
    except Exception as exc:
        tag_rows = []
        tag_query_error = f"{type(exc).__name__}: {exc}"
    inferred_tag_rows = _infer_tag_inventory_from_rows(rows)
    tag_rows = _merge_tag_inventory(tag_rows, inferred_tag_rows)
    if preserve_existing and isinstance(existing_profile, dict):
        existing_tag_rows = existing_profile.get("tag_inventory", [])
        if isinstance(existing_tag_rows, list):
            tag_rows = _merge_tag_inventory(existing_tag_rows, tag_rows)
    profile["tag_inventory"] = tag_rows
    profile["tag_to_index_sourcetype"] = _build_tag_to_index_sourcetype(tag_rows)
    profile["counts"]["tag_inventory_rows"] = len(tag_rows)
    profile["counts"]["tag_count"] = len(profile.get("tag_to_index_sourcetype", {}))
    profile["tag_inventory_meta"] = {
        "source_query": "search index=* tag=* | stats values(tag) as tags count by index sourcetype | sort - count",
        "query_error": tag_query_error,
        "inference_enabled": True,
    }
    # Optional host-focused enrichment: merge host-specific discovered sourcetypes
    # into the global index inventory (append-only behavior).
    if focus_host:
        fresh_focus = _build_host_focus(
            indexes=indexes,
            focus_host=focus_host,
            row_limit=metadata_row_limit,
            earliest_time=earliest_time,
            latest_time=latest_time,
        )
        focus_rows = fresh_focus.get("indexes", []) if isinstance(fresh_focus, dict) else []
        if isinstance(focus_rows, list):
            merged_rows = _merge_rows(profile.get("indexes", []), focus_rows)
            profile["indexes"] = merged_rows
            merged_st_to_idx = _build_sourcetype_to_indexes(merged_rows)
            profile["sourcetype_to_indexes"] = merged_st_to_idx
            counts = profile.get("counts", {})
            if not isinstance(counts, dict):
                counts = {}
            counts["index_count"] = len(merged_rows)
            counts["sourcetype_count"] = len(merged_st_to_idx)
            profile["counts"] = counts
            profile["host_enrichment"] = {
                "focus_host": focus_host,
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                "note": "host-specific sourcetypes merged into global index inventory (append-only).",
            }
    return attach_semantics(profile)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build environment index/sourcetype profile")
    parser.add_argument("--out", default=str(PROFILE_PATH_DEFAULT), help="Output JSON path")
    parser.add_argument("--snapshot-dir", default="artifacts/environment/history")
    parser.add_argument("--snapshot", action="store_true", help="Write timestamped snapshot")
    parser.add_argument("--metadata-row-limit", type=int, default=200)
    parser.add_argument("--earliest-time", default="-7d")
    parser.add_argument("--latest-time", default="now")
    parser.add_argument("--focus-host", default="", help="Optional host name for host-focused Data Domains inventory")
    parser.add_argument("--replace", action="store_true", help="Replace profile instead of merge-preserving old entries")
    parser.add_argument("--field-refresh-mode", choices=("none", "one", "all", "auto"), default="auto")
    parser.add_argument("--field-sourcetype", default="", help="Refresh field inventory for this sourcetype explicitly")
    parser.add_argument("--field-sample-size", type=int, default=200)
    parser.add_argument("--field-row-limit", type=int, default=120)
    args = parser.parse_args()

    out_path = Path(args.out)
    existing_profile: dict[str, Any] = {}
    if out_path.exists():
        try:
            payload = json.loads(out_path.read_text(encoding="utf-8"))
            if isinstance(payload, dict):
                existing_profile = payload
        except Exception:
            existing_profile = {}

    profile = build_profile(
        metadata_row_limit=args.metadata_row_limit,
        earliest_time=args.earliest_time,
        latest_time=args.latest_time,
        existing_profile=existing_profile,
        preserve_existing=not args.replace,
        focus_host=_safe_text(args.focus_host),
        field_refresh_mode=_safe_text(args.field_refresh_mode) or "one",
        field_sourcetype=_safe_text(args.field_sourcetype),
        field_sample_size=max(25, int(args.field_sample_size)),
        field_row_limit=max(20, int(args.field_row_limit)),
    )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(profile, indent=2), encoding="utf-8")

    print("=== Environment Profile ===")
    print(f"out={out_path}")
    print(f"index_count={profile.get('counts', {}).get('index_count')}")
    print(f"sourcetype_count={profile.get('counts', {}).get('sourcetype_count')}")
    print(f"field_inventory_sourcetypes={profile.get('counts', {}).get('field_inventory_sourcetypes')}")
    fi_meta = profile.get("field_inventory_meta", {})
    if isinstance(fi_meta, dict):
        print(f"field_inventory_last={_safe_text(fi_meta.get('last_refreshed_sourcetype'))}")
        print(f"field_inventory_next={_safe_text(fi_meta.get('next_sourcetype'))}")
        print(f"field_inventory_mode={_safe_text(fi_meta.get('effective_refresh_mode', fi_meta.get('refresh_mode')))}")
        print(f"field_inventory_target_count={_safe_text(fi_meta.get('target_count'))}")
    if _safe_text(args.focus_host):
        print(f"focus_host={_safe_text(args.focus_host)}")
        he = profile.get("host_enrichment", {})
        if isinstance(he, dict):
            print(f"focus_host_enrichment={_safe_text(he.get('note'))}")

    if args.snapshot:
        snap_dir = Path(args.snapshot_dir)
        snap_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        snap_path = snap_dir / f"environment_profile_{stamp}.json"
        snap_path.write_text(json.dumps(profile, indent=2), encoding="utf-8")
        print(f"snapshot={snap_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
