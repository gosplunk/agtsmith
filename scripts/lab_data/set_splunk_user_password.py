#!/usr/bin/env python3
"""Set Splunk user password via REST (avoids splunk CLI permission issues)."""

from __future__ import annotations

import argparse
import base64
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from lab_data.config import DEFAULT_UI_ENV, load_ui_env  # noqa: E402


def _ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _basic_auth(user: str, password: str) -> str:
    cred = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
    return f"Basic {cred}"


def _verify_login(base: str, user: str, password: str) -> bool:
    url = f"{base}/services/server/info?output_mode=json"
    req = urllib.request.Request(url, method="GET", headers={"Authorization": _basic_auth(user, password)})
    try:
        with urllib.request.urlopen(req, timeout=15, context=_ssl_context()) as resp:
            return resp.status < 300
    except Exception:
        return False


def set_password(
    *,
    target_user: str,
    new_password: str,
    admin_user: str,
    admin_password: str,
    base_url: str,
) -> None:
    base = base_url.rstrip("/")
    if not _verify_login(base, admin_user, admin_password):
        raise RuntimeError("admin_auth_failed: check SPLUNK_ADMIN_USER/SPLUNK_ADMIN_PASS")

    url = f"{base}/services/admin/users/{urllib.parse.quote(target_user)}"
    data = urllib.parse.urlencode({"password": new_password}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={
            "Authorization": _basic_auth(admin_user, admin_password),
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30, context=_ssl_context()) as resp:
            if resp.status >= 300:
                raise RuntimeError(f"set_password_http:{resp.status}")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:500]
        raise RuntimeError(f"set_password_error:{exc.code}:{detail}") from exc

    if not _verify_login(base, target_user, new_password):
        raise RuntimeError(f"verify_failed:user={target_user}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Set Splunk user password via REST")
    parser.add_argument("--user", default="dev")
    parser.add_argument("--password", required=True, help="New password for target user")
    parser.add_argument("--admin-user", default="")
    parser.add_argument("--admin-password", default="")
    args = parser.parse_args()

    ui_env = load_ui_env()
    admin_user = args.admin_user or str(ui_env.get("SPLUNK_ADMIN_USER", "admin")).strip()
    admin_password = args.admin_password or str(ui_env.get("SPLUNK_ADMIN_PASS", "")).strip()
    base = str(ui_env.get("SPLUNK_BASE_URL", "https://127.0.0.1:8089")).strip()
    if not admin_password:
        print("ERROR: set SPLUNK_ADMIN_PASS in config/ui.env or pass --admin-password", file=sys.stderr)
        return 1

    try:
        set_password(
            target_user=args.user,
            new_password=args.password,
            admin_user=admin_user,
            admin_password=admin_password,
            base_url=base,
        )
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print(f"OK password updated for user={args.user}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
