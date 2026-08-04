#!/usr/bin/env python3
"""Inject time-fresh synthetic lab events via Splunk HEC."""

from __future__ import annotations

import argparse
import copy
import math
import random
import re
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape, quoteattr

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from lab_data.config import (  # noqa: E402
    load_event_catalog,
    load_ui_env,
    resolve_domain_target,
    resolve_layout_name,
)
from lab_data.hec_client import HecClient  # noqa: E402
from lab_data.receivers_client import ReceiversClient  # noqa: E402

from environment_profile import PROFILE_PATH_DEFAULT  # noqa: E402


_PLACEHOLDER_PATTERN = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")


def _sample_field_values(field_map: dict[str, list[Any]], rng: random.Random) -> dict[str, str]:
    return {
        key: str(rng.choice(values))
        for key, values in field_map.items()
        if values
    }


def _random_uuid(rng: random.Random) -> str:
    return str(uuid.UUID(int=rng.getrandbits(128), version=4))


def _runtime_field_values(event_time: float, rng: random.Random) -> dict[str, str]:
    timestamp = datetime.fromtimestamp(event_time, timezone.utc)
    iso_time = timestamp.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    sysmon_time = timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    process_id = rng.randint(800, 8192)
    parent_process_id = rng.randint(400, 799)
    return {
        "time": timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000"),
        "apache_time": timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000"),
        "apache_error_time": timestamp.strftime("%a %b %d %H:%M:%S.%f %Y"),
        "rfc3164_time": timestamp.strftime("%b %e %H:%M:%S"),
        "rfc3339_time": iso_time,
        "iso_time": iso_time,
        "sysmon_time": sysmon_time,
        "event_record_id": str(rng.randint(100_000, 9_999_999)),
        "activity_id": "{" + _random_uuid(rng).upper() + "}",
        "event_id": _random_uuid(rng),
        "request_id": _random_uuid(rng),
        "correlation_id": _random_uuid(rng),
        "process_guid": "{" + _random_uuid(rng).upper() + "}",
        "parent_process_guid": "{" + _random_uuid(rng).upper() + "}",
        "logon_guid": "{" + _random_uuid(rng).upper() + "}",
        "process_id": str(process_id),
        "parent_process_id": str(parent_process_id),
        "client_process_id": str(rng.randint(1000, 9999)),
        "process_id_hex": f"0x{process_id:x}",
        "parent_process_id_hex": f"0x{parent_process_id:x}",
        "subject_logon_id": f"0x{rng.randint(0x10000, 0xFFFFF):x}",
        "target_logon_id": f"0x{rng.randint(0x10000, 0xFFFFF):x}",
        "transaction_id": str(rng.randint(1, 65_535)),
    }


def _substitute_value(value: Any, sampled_fields: dict[str, str]) -> Any:
    if isinstance(value, str):
        rendered = value
        for key, replacement in sampled_fields.items():
            rendered = rendered.replace("{" + key + "}", replacement)
        return rendered
    if isinstance(value, dict):
        return {key: _substitute_value(item, sampled_fields) for key, item in value.items()}
    if isinstance(value, list):
        return [_substitute_value(item, sampled_fields) for item in value]
    return value


def _assert_fully_rendered(value: Any, *, benchmark_case: str) -> None:
    if isinstance(value, str):
        unresolved = sorted(set(_PLACEHOLDER_PATTERN.findall(value)))
    elif isinstance(value, dict):
        unresolved = sorted(
            {
                placeholder
                for item in value.values()
                for placeholder in _find_unresolved_placeholders(item)
            }
        )
    elif isinstance(value, list):
        unresolved = sorted(
            {
                placeholder
                for item in value
                for placeholder in _find_unresolved_placeholders(item)
            }
        )
    else:
        unresolved = []
    if unresolved:
        raise ValueError(
            f"event_set_unresolved_placeholders:{benchmark_case}:{','.join(unresolved)}"
        )


def _find_unresolved_placeholders(value: Any) -> list[str]:
    if isinstance(value, str):
        return _PLACEHOLDER_PATTERN.findall(value)
    if isinstance(value, dict):
        return [
            placeholder
            for item in value.values()
            for placeholder in _find_unresolved_placeholders(item)
        ]
    if isinstance(value, list):
        return [
            placeholder
            for item in value
            for placeholder in _find_unresolved_placeholders(item)
        ]
    return []


def _windows_event_xml(payload: dict[str, Any], *, event_time: float) -> str:
    system = payload.get("system", {})
    event_data = payload.get("event_data", {})
    rendering = payload.get("rendering", {})
    if not isinstance(system, dict) or not isinstance(event_data, dict):
        raise ValueError("windows_event_requires_system_and_event_data")
    if not isinstance(rendering, dict):
        rendering = {}

    event_id = str(system.get("event_id", "0"))
    channel = str(system.get("channel", "Security"))
    computer = str(system.get("computer", "agtsmith-win-lab.contoso.local"))
    provider = str(
        system.get(
            "provider_name",
            "Microsoft-Windows-Sysmon"
            if "Sysmon" in channel
            else "Microsoft-Windows-Security-Auditing",
        )
    )
    provider_guid = str(system.get("provider_guid", "")).strip()
    system_time = (
        datetime.fromtimestamp(event_time, timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )
    provider_attrs = f" Name={quoteattr(provider)}"
    if provider_guid:
        provider_attrs += f" Guid={quoteattr(provider_guid)}"
    qualifiers = str(system.get("qualifiers", "")).strip()
    event_id_attrs = f" Qualifiers={quoteattr(qualifiers)}" if qualifiers else ""
    activity_id = str(system.get("activity_id", "")).strip()
    correlation = (
        f"<Correlation ActivityID={quoteattr(activity_id)}/>"
        if activity_id
        else "<Correlation/>"
    )
    data_xml = "".join(
        f"<Data Name={quoteattr(str(key))}>{escape(str(value))}</Data>"
        for key, value in event_data.items()
        if value is not None
    )
    message = str(rendering.get("message", "")).strip()
    rendering_info = (
        (
            "<RenderingInfo Culture=\"en-US\">"
            f"<Message>{escape(message)}</Message>"
            f"<Level>{escape(str(rendering.get('level', 'Information')))}</Level>"
            f"<Task>{escape(str(rendering.get('task', '')))}</Task>"
            f"<Opcode>{escape(str(rendering.get('opcode', 'Info')))}</Opcode>"
            f"<Channel>{escape(str(rendering.get('channel', channel)))}</Channel>"
            f"<Provider>{escape(str(rendering.get('provider', provider)))}</Provider>"
            "</RenderingInfo>"
        )
        if message
        else ""
    )
    execution = (
        f"<Execution ProcessID={quoteattr(str(system.get('process_id', '4')))} "
        f"ThreadID={quoteattr(str(system.get('thread_id', '8')))}/>"
    )
    return (
        "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">"
        "<System>"
        f"<Provider{provider_attrs}/>"
        f"<EventID{event_id_attrs}>{escape(event_id)}</EventID>"
        f"<Version>{escape(str(system.get('version', 0)))}</Version>"
        f"<Level>{escape(str(system.get('level', 0)))}</Level>"
        f"<Task>{escape(str(system.get('task', 0)))}</Task>"
        f"<Opcode>{escape(str(system.get('opcode', 0)))}</Opcode>"
        f"<Keywords>{escape(str(system.get('keywords', '0x8020000000000000')))}</Keywords>"
        f"<TimeCreated SystemTime={quoteattr(system_time)}/>"
        f"<EventRecordID>{escape(str(system.get('event_record_id', '0')))}</EventRecordID>"
        f"{correlation}"
        f"{execution}"
        f"<Channel>{escape(channel)}</Channel>"
        f"<Computer>{escape(computer)}</Computer>"
        f"<Security UserID={quoteattr(str(system.get('security_user_id', 'S-1-5-18')))}/>"
        "</System>"
        f"<EventData>{data_xml}</EventData>"
        f"{rendering_info}"
        "</Event>"
    )


def _deep_merge(base: dict[str, Any], overrides: dict[str, Any]) -> dict[str, Any]:
    merged = copy.deepcopy(base)
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged


def _payload_template(event_set: dict[str, Any], rng: random.Random) -> dict[str, Any]:
    scenarios = event_set.get("scenarios")
    if isinstance(scenarios, list) and scenarios:
        selected = rng.choice(scenarios)
        if not isinstance(selected, dict):
            raise ValueError("event_set_scenario_must_be_mapping")
        return copy.deepcopy(selected)
    payload = event_set.get("payload", {})
    if not isinstance(payload, dict):
        raise ValueError("event_set_payload_must_be_mapping")
    overrides = event_set.get("scenario_overrides")
    if isinstance(overrides, list) and overrides:
        selected = rng.choice(overrides)
        if not isinstance(selected, dict):
            raise ValueError("event_set_scenario_override_must_be_mapping")
        return _deep_merge(payload, selected)
    return copy.deepcopy(payload)


def _pick_transport(ui_env: dict[str, str], transport: str) -> str:
    mode = (transport or "auto").strip().lower()
    hec_ready = bool(str(ui_env.get("SPLUNK_HEC_URL", "")).strip() and str(ui_env.get("SPLUNK_HEC_TOKEN", "")).strip())
    recv_ready = bool(str(ui_env.get("SPLUNK_USER", "")).strip() and str(ui_env.get("SPLUNK_PASS", ui_env.get("SPLUNK_PASSWORD", ""))).strip())
    if mode == "auto":
        if hec_ready:
            return "hec"
        if recv_ready:
            return "receivers"
        raise RuntimeError("lab_data_transport_missing: set SPLUNK_HEC_* or SPLUNK_USER/SPLUNK_PASS in config/ui.env")
    if mode == "hec" and not hec_ready:
        raise RuntimeError("hec_config_missing")
    if mode == "receivers" and not recv_ready:
        raise RuntimeError("receivers_auth_missing")
    return mode


def _send_event(client: Any, item: dict[str, Any]) -> None:
    client.send_event(
        index=item["index"],
        sourcetype=item["sourcetype"],
        host=item["host"],
        source=item["source"],
        time_epoch=float(item["time_epoch"]),
        event=item["event"],
        fields=item.get("fields"),
    )


def _resolve_time_bounds(
    *,
    hours: float,
    start_time: float | None,
    end_time: float | None,
) -> tuple[float, float, str]:
    explicit = start_time is not None or end_time is not None
    if explicit:
        if start_time is None or end_time is None:
            raise ValueError("explicit_time_range_requires_start_and_end")
        try:
            range_start = float(start_time)
            range_end = float(end_time)
        except (TypeError, ValueError) as exc:
            raise ValueError("invalid_explicit_time_range") from exc
        if not math.isfinite(range_start) or not math.isfinite(range_end):
            raise ValueError("invalid_explicit_time_range")
        if range_start >= range_end:
            raise ValueError("time_range_start_must_precede_end")
        return range_start, range_end, "explicit"

    range_hours = max(float(hours), 0.1)
    if not math.isfinite(range_hours):
        raise ValueError("invalid_hours")
    range_end = datetime.now(timezone.utc).timestamp()
    return range_end - (range_hours * 3600.0), range_end, "relative"


def _time_range_details(
    start_time: float,
    end_time: float,
    *,
    mode: str,
) -> dict[str, Any]:
    return {
        "mode": mode,
        "start_epoch": start_time,
        "end_epoch": end_time,
        "start_utc": datetime.fromtimestamp(start_time, timezone.utc).isoformat(),
        "end_utc": datetime.fromtimestamp(end_time, timezone.utc).isoformat(),
        "span_hours": (end_time - start_time) / 3600.0,
    }


def _build_events_for_set(
    event_set: dict[str, Any],
    *,
    layout_name: str,
    count: int,
    hours: float,
    defaults: dict[str, Any],
    rng: random.Random,
    start_time: float | None = None,
    end_time: float | None = None,
) -> list[dict[str, Any]]:
    domain = str(event_set.get("domain", "")).strip()
    target = resolve_domain_target(layout_name, domain)
    host = str(defaults.get("host", "agtsmith-lab-gen"))
    lab_tag = str(defaults.get("lab_data_source", "agtsmith_generator"))
    lab_version = str(defaults.get("lab_data_version", "fidelity_v2"))
    source = str(event_set.get("source", host))
    fmt = str(event_set.get("format", "raw")).strip().lower()
    fields = event_set.get("fields", {})
    field_map = {str(k): list(v) for k, v in fields.items()} if isinstance(fields, dict) else {}
    templates = event_set.get("templates", [])

    out: list[dict[str, Any]] = []
    range_start, range_end, _ = _resolve_time_bounds(
        hours=hours,
        start_time=start_time,
        end_time=end_time,
    )

    for _ in range(count):
        event_time = range_end - rng.uniform(0, range_end - range_start)
        hec_fields = {
            "lab_data_source": lab_tag,
            "lab_data_version": lab_version,
        }
        sampled_fields = _sample_field_values(field_map, rng)
        substitutions = {
            **_runtime_field_values(event_time, rng),
            **sampled_fields,
        }
        item_host = substitutions.get("event_host", host)
        if fmt in {"json", "xml"}:
            payload = _substitute_value(_payload_template(event_set, rng), substitutions)
            if fmt == "json":
                payload.setdefault("lab_data_source", lab_tag)
                payload.setdefault("lab_data_version", lab_version)
            _assert_fully_rendered(
                payload,
                benchmark_case=str(event_set.get("benchmark_case", "")),
            )
            if fmt == "xml":
                event_body: str | dict[str, Any] = _windows_event_xml(
                    payload,
                    event_time=event_time,
                )
            else:
                event_body = payload
        else:
            if not isinstance(templates, list) or not templates:
                raise ValueError(f"event_set_missing_templates:{event_set.get('benchmark_case')}")
            template = str(rng.choice(templates))
            raw = _substitute_value(template, substitutions)
            _assert_fully_rendered(
                raw,
                benchmark_case=str(event_set.get("benchmark_case", "")),
            )
            event_body = raw

        out.append(
            {
                "index": target["index"],
                "sourcetype": target["sourcetype"],
                "host": item_host,
                "source": source,
                "time_epoch": event_time,
                "event": event_body,
                "fields": hec_fields,
                "event_set": str(event_set.get("benchmark_case", "")),
            },
        )
    return out


def generate(
    *,
    layout: str,
    count: int,
    hours: float,
    event_sets: list[str] | None,
    dry_run: bool,
    transport: str = "auto",
    start_time: float | None = None,
    end_time: float | None = None,
) -> dict[str, Any]:
    ui_env = load_ui_env()
    layout_name = resolve_layout_name(layout, profile_path=PROFILE_PATH_DEFAULT, ui_env=ui_env)
    catalog = load_event_catalog()
    defaults = catalog.get("defaults", {}) if isinstance(catalog.get("defaults"), dict) else {}
    per_run = int(defaults.get("count_per_run", count))
    event_count = count if count > 0 else per_run
    jitter_hours = float(hours if hours > 0 else defaults.get("time_jitter_hours", 6))
    range_start, range_end, range_mode = _resolve_time_bounds(
        hours=jitter_hours,
        start_time=start_time,
        end_time=end_time,
    )
    range_details = _time_range_details(range_start, range_end, mode=range_mode)

    sets_raw = catalog.get("event_sets", {})
    if not isinstance(sets_raw, dict):
        raise ValueError("event_sets_missing")

    selected_names = event_sets or list(sets_raw.keys())
    if event_sets:
        unknown = [name for name in selected_names if name not in sets_raw]
        if unknown:
            raise ValueError(f"unknown_event_sets:{','.join(unknown)}")
    rng = random.Random(42)
    planned: list[dict[str, Any]] = []
    for name in selected_names:
        event_set = sets_raw.get(name)
        if not isinstance(event_set, dict):
            continue
        domain = str(event_set.get("domain", "")).strip()
        try:
            resolve_domain_target(layout_name, domain)
        except KeyError as exc:
            if event_sets:
                raise ValueError(
                    f"event_set_domain_not_in_layout:{name}:{domain}:{layout_name}"
                ) from exc
            continue
        except Exception:
            if event_sets:
                raise
            continue
        planned.extend(
            _build_events_for_set(
                event_set,
                layout_name=layout_name,
                count=event_count,
                hours=jitter_hours,
                defaults=defaults,
                rng=rng,
                start_time=range_start,
                end_time=range_end,
            )
        )

    report: dict[str, Any] = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "layout": layout_name,
        "event_count": len(planned),
        "hours": range_details["span_hours"],
        "time_range": range_details,
        "dry_run": dry_run,
        "sent": 0,
        "errors": [],
    }

    if dry_run:
        report["sample_events"] = planned[:3]
        report["transport"] = _pick_transport(ui_env, transport)
        return report

    mode = _pick_transport(ui_env, transport)
    report["transport"] = mode
    client: HecClient | ReceiversClient
    if mode == "hec":
        client = HecClient.from_env(ui_env)
    else:
        client = ReceiversClient.from_env(ui_env)

    for item in planned:
        try:
            _send_event(client, item)
            report["sent"] += 1
        except Exception as exc:
            report["errors"].append(str(exc))
        time.sleep(0.01)

    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Inject synthetic lab events via Splunk HEC")
    parser.add_argument("--layout", default="", help="existing_lab|multi_index_ideal|minimal_ci")
    parser.add_argument("--count", type=int, default=0, help="events per event set (default from YAML)")
    parser.add_argument("--hours", type=float, default=0, help="time jitter window in hours")
    parser.add_argument("--event-set", action="append", dest="event_sets", default=[], help="limit to event set id")
    parser.add_argument("--transport", default="auto", choices=("auto", "hec", "receivers"))
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    try:
        report = generate(
            layout=args.layout,
            count=args.count,
            hours=args.hours,
            event_sets=args.event_sets or None,
            dry_run=args.dry_run,
            transport=args.transport,
        )
    except Exception as exc:
        print(f"ERROR lab_data_generate: {exc}", file=sys.stderr)
        return 1

    print(f"layout={report.get('layout')}")
    print(f"transport={report.get('transport', 'dry-run')}")
    print(f"event_count={report.get('event_count')}")
    print(f"sent={report.get('sent')}")
    if report.get("errors"):
        for err in report["errors"][:5]:
            print(f"error={err}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
