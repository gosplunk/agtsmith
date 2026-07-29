#!/usr/bin/env python3
"""Provision Splunk indexes from lab_data_layout.yaml via REST API."""

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

from lab_data.config import get_layout, load_layout_config, load_ui_env, resolve_layout_name  # noqa: E402

from environment_profile import PROFILE_PATH_DEFAULT  # noqa: E402


def _auth_headers(ui_env: dict[str, str]) -> dict[str, str]:
    user = str(ui_env.get("SPLUNK_USER", ui_env.get("SOC_UI_AUTH_USERNAME", ""))).strip()
    password = str(ui_env.get("SPLUNK_PASS", ui_env.get("SOC_UI_AUTH_PASSWORD", ui_env.get("SPLUNK_PASSWORD", "")))).strip()
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if user and password:
        cred = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
        headers["Authorization"] = f"Basic {cred}"
        return headers
    token = str(ui_env.get("SPLUNK_LAB_BEARER_TOKEN", "")).strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
        return headers
    raise RuntimeError("provision_auth_missing")


def _ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _index_exists(base: str, name: str, headers: dict[str, str]) -> bool:
    url = f"{base}/services/data/indexes/{urllib.parse.quote(name)}?output_mode=json"
    req = urllib.request.Request(url, method="GET", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30, context=_ssl_context()) as resp:
            return resp.status < 300
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return False
        raise


def _create_index(base: str, name: str, headers: dict[str, str]) -> None:
    url = f"{base}/services/data/indexes?output_mode=json"
    data = urllib.parse.urlencode({"name": name}).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST", headers=headers)
    with urllib.request.urlopen(req, timeout=30, context=_ssl_context()) as resp:
        if resp.status >= 300:
            raise RuntimeError(f"create_index_failed:{name}:{resp.status}")


def provision(*, layout: str, dry_run: bool) -> dict[str, Any]:
    ui_env = load_ui_env()
    layout_name = resolve_layout_name(layout, profile_path=PROFILE_PATH_DEFAULT, ui_env=ui_env)
    cfg = load_layout_config()
    layout_obj = get_layout(layout_name, cfg)
    provision_list = layout_obj.get("provision_indexes", [])
    if not isinstance(provision_list, list) or not provision_list:
        return {
            "layout": layout_name,
            "created": [],
            "existing": [],
            "skipped": True,
            "reason": "no_provision_indexes_for_layout",
        }

    base = str(ui_env.get("SPLUNK_BASE_URL", "https://127.0.0.1:8089")).rstrip("/")
    headers = _auth_headers(ui_env)
    created: list[str] = []
    existing: list[str] = []

    for raw in provision_list:
        name = str(raw).strip()
        if not name:
            continue
        if _index_exists(base, name, headers):
            existing.append(name)
            continue
        if dry_run:
            created.append(name)
            continue
        _create_index(base, name, headers)
        created.append(name)

    return {
        "layout": layout_name,
        "created": created,
        "existing": existing,
        "dry_run": dry_run,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Provision Splunk indexes for lab layout")
    parser.add_argument("--layout", default="")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    try:
        report = provision(layout=args.layout, dry_run=args.dry_run)
    except Exception as exc:
        print(f"ERROR lab_data_provision: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
