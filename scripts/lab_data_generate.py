#!/usr/bin/env python3
"""Inject time-fresh synthetic lab events via Splunk HEC."""

from __future__ import annotations

import argparse
import random
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from lab_data.config import (  # noqa: E402
    load_event_catalog,
    load_ui_env,
    resolve_domain_target,
    resolve_layout_name,
    substitute_fields,
)
from lab_data.hec_client import HecClient  # noqa: E402
from lab_data.receivers_client import ReceiversClient  # noqa: E402

from environment_profile import PROFILE_PATH_DEFAULT  # noqa: E402


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


def _build_events_for_set(
    event_set: dict[str, Any],
    *,
    layout_name: str,
    count: int,
    hours: float,
    defaults: dict[str, Any],
    rng: random.Random,
) -> list[dict[str, Any]]:
    domain = str(event_set.get("domain", "")).strip()
    target = resolve_domain_target(layout_name, domain)
    host = str(defaults.get("host", "agtsmith-lab-gen"))
    lab_tag = str(defaults.get("lab_data_source", "agtsmith_generator"))
    source = str(event_set.get("source", host))
    fmt = str(event_set.get("format", "raw")).strip().lower()
    fields = event_set.get("fields", {})
    field_map = {str(k): list(v) for k, v in fields.items()} if isinstance(fields, dict) else {}
    templates = event_set.get("templates", [])
    payload_template = event_set.get("payload", {})

    out: list[dict[str, Any]] = []
    now = datetime.now(timezone.utc).timestamp()
    jitter_sec = max(hours, 0.1) * 3600.0

    for _ in range(count):
        offset = rng.uniform(0, jitter_sec)
        event_time = now - offset
        if fmt == "json" and isinstance(payload_template, dict):
            payload = json_copy(payload_template)
            for key, values in field_map.items():
                if key in payload and isinstance(payload[key], str):
                    payload[key] = substitute_fields(str(payload[key]), field_map, rng)
                elif values:
                    payload[key] = rng.choice(values)
            payload["lab_data_source"] = lab_tag
            event_body: str | dict[str, Any] = payload
        else:
            if not isinstance(templates, list) or not templates:
                raise ValueError(f"event_set_missing_templates:{event_set.get('benchmark_case')}")
            template = str(rng.choice(templates))
            raw = substitute_fields(template, field_map, rng)
            event_body = raw

        out.append(
            {
                "index": target["index"],
                "sourcetype": target["sourcetype"],
                "host": host,
                "source": source,
                "time_epoch": event_time,
                "event": event_body,
                "fields": {"lab_data_source": lab_tag},
                "event_set": str(event_set.get("benchmark_case", "")),
            }
        )
    return out


def json_copy(value: dict[str, Any]) -> dict[str, Any]:
    import json

    return json.loads(json.dumps(value))


def generate(
    *,
    layout: str,
    count: int,
    hours: float,
    event_sets: list[str] | None,
    dry_run: bool,
    transport: str = "auto",
) -> dict[str, Any]:
    ui_env = load_ui_env()
    layout_name = resolve_layout_name(layout, profile_path=PROFILE_PATH_DEFAULT, ui_env=ui_env)
    catalog = load_event_catalog()
    defaults = catalog.get("defaults", {}) if isinstance(catalog.get("defaults"), dict) else {}
    per_run = int(defaults.get("count_per_run", count))
    event_count = count if count > 0 else per_run
    jitter_hours = float(hours if hours > 0 else defaults.get("time_jitter_hours", 6))

    sets_raw = catalog.get("event_sets", {})
    if not isinstance(sets_raw, dict):
        raise ValueError("event_sets_missing")

    selected_names = event_sets or list(sets_raw.keys())
    rng = random.Random(42)
    planned: list[dict[str, Any]] = []
    for name in selected_names:
        event_set = sets_raw.get(name)
        if not isinstance(event_set, dict):
            continue
        domain = str(event_set.get("domain", "")).strip()
        try:
            resolve_domain_target(layout_name, domain)
        except KeyError:
            continue
        except Exception:
            continue
        planned.extend(
            _build_events_for_set(
                event_set,
                layout_name=layout_name,
                count=event_count,
                hours=jitter_hours,
                defaults=defaults,
                rng=rng,
            )
        )

    report: dict[str, Any] = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "layout": layout_name,
        "event_count": len(planned),
        "hours": jitter_hours,
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
