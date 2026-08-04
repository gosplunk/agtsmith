#!/usr/bin/env python3
"""Remove lab-generated events tagged with lab_data_source=agtsmith_generator."""

from __future__ import annotations

import argparse
import base64
import json
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from lab_data.config import layout_index_names, load_ui_env, resolve_layout_name  # noqa: E402

from environment_profile import PROFILE_PATH_DEFAULT  # noqa: E402


def _splunk_rest_delete_search(query: str, ui_env: dict[str, str]) -> dict[str, Any]:
    base = str(ui_env.get("SPLUNK_BASE_URL", "https://127.0.0.1:8089")).rstrip("/")
    user = str(ui_env.get("SPLUNK_USER", ui_env.get("SOC_UI_AUTH_USERNAME", ""))).strip()
    password = str(ui_env.get("SPLUNK_PASS", ui_env.get("SOC_UI_AUTH_PASSWORD", ""))).strip()
    token = str(ui_env.get("SPLUNK_LAB_BEARER_TOKEN", "")).strip()

    url = f"{base}/services/search/jobs/export?output_mode=json"
    data = urllib.parse.urlencode({"search": query, "exec_mode": "oneshot"}).encode("utf-8")

    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if user and password:
        cred = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
        headers["Authorization"] = f"Basic {cred}"
    elif token:
        headers["Authorization"] = f"Bearer {token}"
    else:
        raise RuntimeError("cleanup_auth_missing: set SPLUNK_USER/SPLUNK_PASS or SPLUNK_LAB_BEARER_TOKEN")

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(url, data=data, method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=120, context=ctx) as resp:
            body = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:500]
        raise RuntimeError(f"cleanup_search_failed:{exc.code}:{detail}") from exc

    lines = [line for line in body.splitlines() if line.strip()]
    return {"preview_lines": len(lines), "query": query}


def cleanup(*, layout: str, hours: int, dry_run: bool) -> dict[str, Any]:
    ui_env = load_ui_env()
    layout_name = resolve_layout_name(layout, profile_path=PROFILE_PATH_DEFAULT, ui_env=ui_env)
    indexes = sorted(layout_index_names(layout_name))
    if not indexes:
        raise ValueError("no_indexes_for_layout")

    index_clause = " OR ".join(f'index="{idx}"' for idx in indexes)
    generator_clause = '(lab_data_source=agtsmith_generator OR "agtsmith_generator")'
    # delete command requires admin; preview with search first when dry_run
    delete_query = (
        f"search ({index_clause}) {generator_clause} earliest=-{hours}h | delete"
    )
    preview_query = (
        f"search ({index_clause}) {generator_clause} earliest=-{hours}h | stats count"
    )

    report: dict[str, Any] = {
        "layout": layout_name,
        "indexes": indexes,
        "hours": hours,
        "dry_run": dry_run,
    }

    if dry_run:
        report["preview"] = _splunk_rest_delete_search(preview_query, ui_env)
        report["would_run"] = delete_query
        return report

    report["result"] = _splunk_rest_delete_search(delete_query, ui_env)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Cleanup lab-generated Splunk events")
    parser.add_argument("--layout", default="")
    parser.add_argument("--hours", type=int, default=168)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    try:
        report = cleanup(layout=args.layout, hours=args.hours, dry_run=args.dry_run)
    except Exception as exc:
        print(f"ERROR lab_data_cleanup: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
