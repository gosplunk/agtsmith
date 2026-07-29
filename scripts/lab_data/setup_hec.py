#!/usr/bin/env python3
"""Enable Splunk HEC and mint agtsmith lab token via REST; update config/ui.env."""

from __future__ import annotations

import argparse
import base64
import json
import re
import secrets
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from lab_data.config import DEFAULT_UI_ENV, layout_index_names, load_ui_env, resolve_layout_name  # noqa: E402

from environment_profile import PROFILE_PATH_DEFAULT  # noqa: E402

HEC_NAME = "agtsmith-lab-generator"


def _ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _auth_header(ui_env: dict[str, str]) -> dict[str, str]:
    user = str(ui_env.get("SPLUNK_USER", "")).strip()
    password = str(ui_env.get("SPLUNK_PASS", ui_env.get("SPLUNK_PASSWORD", ""))).strip()
    if not user or not password:
        raise RuntimeError("setup_hec_auth_missing:SPLUNK_USER and SPLUNK_PASS required in config/ui.env")
    cred = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
    return {"Authorization": f"Basic {cred}", "Content-Type": "application/x-www-form-urlencoded"}


def _request(
    method: str,
    url: str,
    headers: dict[str, str],
    data: bytes | None = None,
) -> dict[str, Any]:
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=60, context=_ssl_context()) as resp:
            body = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:800]
        raise RuntimeError(f"rest_error:{exc.code}:{detail}") from exc
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        payload = {"raw": body}
    return payload if isinstance(payload, dict) else {"raw": body}


def _enable_hec(base: str, headers: dict[str, str]) -> None:
    url = f"{base}/services/data/inputs/http/http?output_mode=json"
    data = _encode_form([("disabled", "0"), ("enableSSL", "1"), ("port", "8088")])
    _request("POST", url, headers, data)


def _hec_exists(base: str, headers: dict[str, str], name: str) -> bool:
    url = f"{base}/services/data/inputs/http/{urllib.parse.quote(name)}?output_mode=json"
    try:
        _request("GET", url, headers)
        return True
    except RuntimeError as exc:
        if "404" in str(exc):
            return False
        raise


def _encode_form(fields: list[tuple[str, str]]) -> bytes:
    return urllib.parse.urlencode(fields).encode("utf-8")


def _create_hec_token(base: str, headers: dict[str, str], *, name: str, indexes: list[str]) -> str:
    if not indexes:
        raise ValueError("hec_indexes_missing")
    token = secrets.token_hex(16)
    # Splunk expects a single default index in `index`; allowed list in `indexes`.
    fields: list[tuple[str, str]] = [
        ("name", name),
        ("index", indexes[0]),
        ("indexes", ",".join(indexes)),
        ("source", name),
        ("sourcetype", "_json"),
        ("disabled", "0"),
        ("token", token),
    ]
    url = f"{base}/services/data/inputs/http?output_mode=json"
    _request("POST", url, headers, _encode_form(fields))
    return token


def _update_hec_token_indexes(base: str, headers: dict[str, str], *, name: str, indexes: list[str]) -> None:
    if not indexes:
        raise ValueError("hec_indexes_missing")
    fields: list[tuple[str, str]] = [
        ("index", indexes[0]),
        ("indexes", ",".join(indexes)),
    ]
    url = f"{base}/services/data/inputs/http/{urllib.parse.quote(name)}?output_mode=json"
    _request("POST", url, headers, _encode_form(fields))


def _update_ui_env(path: Path, updates: dict[str, str]) -> None:
    text = path.read_text(encoding="utf-8") if path.is_file() else ""
    for key, value in updates.items():
        pattern = rf"^{re.escape(key)}=.*$"
        line = f"{key}={value}"
        if re.search(pattern, text, flags=re.M):
            text = re.sub(pattern, line, text, count=1, flags=re.M)
        else:
            text = text.rstrip() + "\n" + line + "\n"
    path.write_text(text, encoding="utf-8")


def setup(*, layout: str, ui_env_path: Path, dry_run: bool) -> dict[str, Any]:
    ui_env = load_ui_env(ui_env_path)
    layout_name = resolve_layout_name(layout, profile_path=PROFILE_PATH_DEFAULT, ui_env=ui_env)
    indexes = sorted(layout_index_names(layout_name))
    if not indexes:
        raise ValueError("no_indexes_for_layout")

    base = str(ui_env.get("SPLUNK_BASE_URL", "https://127.0.0.1:8089")).rstrip("/")
    headers = _auth_header(ui_env)

    report: dict[str, Any] = {
        "layout": layout_name,
        "indexes": indexes,
        "hec_name": HEC_NAME,
        "dry_run": dry_run,
    }

    if dry_run:
        report["would_enable_hec"] = True
        report["would_create_token"] = True
        return report

    _enable_hec(base, headers)
    if _hec_exists(base, headers, HEC_NAME):
        _update_hec_token_indexes(base, headers, name=HEC_NAME, indexes=indexes)
        token = str(ui_env.get("SPLUNK_HEC_TOKEN", "")).strip()
        if not token:
            raise RuntimeError(
                f"hec_input_exists:{HEC_NAME}: set SPLUNK_HEC_TOKEN in config/ui.env or delete the HEC input in Splunk Web"
            )
    else:
        token = _create_hec_token(base, headers, name=HEC_NAME, indexes=indexes)

    hec_url = str(ui_env.get("SPLUNK_HEC_URL", "https://127.0.0.1:8088/services/collector/event")).strip()
    updates = {
        "SPLUNK_HEC_URL": hec_url,
        "SPLUNK_HEC_TOKEN": token,
        "SPLUNK_HEC_INSECURE": "1",
        "LAB_DATA_LAYOUT": layout_name,
        "LAB_DATA_ENABLED": "1",
    }
    _update_ui_env(ui_env_path, updates)
    report["hec_url"] = hec_url
    report["ui_env_updated"] = str(ui_env_path)
    report["token_created"] = bool(token)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Enable HEC and write token to config/ui.env")
    parser.add_argument("--layout", default="")
    parser.add_argument("--ui-env", default=str(DEFAULT_UI_ENV))
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    try:
        report = setup(layout=args.layout, ui_env_path=Path(args.ui_env), dry_run=args.dry_run)
    except Exception as exc:
        print(f"ERROR setup_hec: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
