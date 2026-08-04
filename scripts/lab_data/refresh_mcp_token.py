#!/usr/bin/env python3
"""Ensure Splunk MCP bearer token in config/ui.env — reuse when valid, rotate only when needed."""

from __future__ import annotations

import argparse
import base64
import json
import re
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

MCP_TOKEN_USER_DEFAULT = "mcp"
MCP_TOKEN_PATH = "/servicesNS/nobody/Splunk_MCP_Server/mcp_token?output_mode=json"
MIN_TOKEN_LEN = 100


def _ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _splunk_basic_auth(ui_env: dict[str, str]) -> str:
    user = str(ui_env.get("SPLUNK_USER", "")).strip()
    password = str(ui_env.get("SPLUNK_PASS", ui_env.get("SPLUNK_PASSWORD", ""))).strip()
    if not user or not password:
        raise RuntimeError("mcp_refresh_auth_missing:SPLUNK_USER and SPLUNK_PASS required in config/ui.env")
    cred = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
    return f"Basic {cred}"


def fetch_mcp_token(*, ui_env: dict[str, str], token_user: str) -> str:
    """Read the current encrypted MCP token from Splunk without rotating it."""
    base = str(ui_env.get("SPLUNK_BASE_URL", "https://127.0.0.1:8089")).rstrip("/")
    auth = _splunk_basic_auth(ui_env)
    fetch_url = f"{base}{MCP_TOKEN_PATH}&username={urllib.parse.quote(token_user)}"
    fetch_req = urllib.request.Request(fetch_url, method="GET", headers={"Authorization": auth})
    try:
        with urllib.request.urlopen(fetch_req, timeout=30, context=_ssl_context()) as resp:
            body = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:500]
        raise RuntimeError(f"mcp_fetch_error:{exc.code}:{detail}") from exc

    payload = json.loads(body)
    token = str(payload.get("token", "")).strip()
    if len(token) < MIN_TOKEN_LEN:
        raise RuntimeError("mcp_token_missing_or_truncated")
    return token


def rotate_mcp_token(*, ui_env: dict[str, str], token_user: str) -> str:
    """Rotate Splunk MCP token (invalidates the previous token) and return the new value."""
    base = str(ui_env.get("SPLUNK_BASE_URL", "https://127.0.0.1:8089")).rstrip("/")
    auth = _splunk_basic_auth(ui_env)
    rotate_url = f"{base}{MCP_TOKEN_PATH}"
    rotate_body = urllib.parse.urlencode({"username": token_user, "action": "rotate"}).encode("utf-8")
    rotate_req = urllib.request.Request(
        rotate_url,
        data=rotate_body,
        method="POST",
        headers={"Authorization": auth, "Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(rotate_req, timeout=30, context=_ssl_context()) as resp:
            if resp.status >= 300:
                raise RuntimeError(f"mcp_rotate_status:{resp.status}")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:500]
        raise RuntimeError(f"mcp_rotate_error:{exc.code}:{detail}") from exc

    return fetch_mcp_token(ui_env=ui_env, token_user=token_user)


# Backward-compatible alias used by older call sites/tests.
mint_mcp_token = rotate_mcp_token


def verify_mcp_token(token: str, *, ui_env: dict[str, str]) -> None:
    base = str(ui_env.get("SPLUNK_MCP_URL", "https://127.0.0.1:8089/services/mcp")).rstrip("/")
    init_payload = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "agtsmith-lab-data", "version": "1.0"},
            },
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        base,
        data=init_payload,
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30, context=_ssl_context()) as resp:
            body = json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:500]
        raise RuntimeError(f"mcp_verify_error:{exc.code}:{detail}") from exc
    if "error" in body:
        raise RuntimeError(f"mcp_verify_rpc_error:{body['error']}")


def upsert_ui_env(path: Path, key: str, value: str) -> None:
    text = path.read_text(encoding="utf-8") if path.is_file() else ""
    pattern = rf"^{re.escape(key)}=.*$"
    line = f"{key}={value}"
    if re.search(pattern, text, flags=re.M):
        text = re.sub(pattern, line, text, count=1, flags=re.M)
    else:
        text = text.rstrip() + "\n" + line + "\n"
    path.write_text(text, encoding="utf-8")


def ensure_mcp_token(
    *,
    ui_env_path: Path,
    token_user: str,
    verify: bool = True,
    force_rotate: bool = False,
) -> tuple[str, str]:
    """Return (token, action) where action is reused|rotated|fetched."""
    ui_env = load_ui_env(ui_env_path)
    existing = str(ui_env.get("SPLUNK_LAB_BEARER_TOKEN", "")).strip()

    if not force_rotate and len(existing) >= MIN_TOKEN_LEN:
        try:
            if verify:
                verify_mcp_token(existing, ui_env=ui_env)
            return existing, "reused"
        except Exception:
            pass

    if not force_rotate:
        try:
            fetched = fetch_mcp_token(ui_env=ui_env, token_user=token_user)
            if verify:
                verify_mcp_token(fetched, ui_env=ui_env)
            if fetched != existing:
                upsert_ui_env(ui_env_path, "SPLUNK_LAB_BEARER_TOKEN", fetched)
            return fetched, "fetched"
        except Exception:
            pass

    token = rotate_mcp_token(ui_env=ui_env, token_user=token_user)
    if verify:
        verify_mcp_token(token, ui_env=ui_env)
    upsert_ui_env(ui_env_path, "SPLUNK_LAB_BEARER_TOKEN", token)
    return token, "rotated"


def refresh(*, ui_env_path: Path, token_user: str, verify: bool = True, force_rotate: bool = False) -> str:
    token, _action = ensure_mcp_token(
        ui_env_path=ui_env_path,
        token_user=token_user,
        verify=verify,
        force_rotate=force_rotate,
    )
    return token


def main() -> int:
    parser = argparse.ArgumentParser(description="Ensure Splunk MCP token in config/ui.env (reuse when valid)")
    parser.add_argument("--ui-env", default=str(DEFAULT_UI_ENV))
    parser.add_argument("--token-user", default=MCP_TOKEN_USER_DEFAULT)
    parser.add_argument("--no-verify", action="store_true")
    parser.add_argument("--force-rotate", action="store_true", help="Always rotate (invalidates the previous token)")
    parser.add_argument("--print-token", action="store_true", help="Print token to stdout (avoid in CI logs)")
    args = parser.parse_args()

    try:
        token, action = ensure_mcp_token(
            ui_env_path=Path(args.ui_env),
            token_user=args.token_user,
            verify=not args.no_verify,
            force_rotate=bool(args.force_rotate),
        )
    except Exception as exc:
        print(f"ERROR refresh_mcp_token: {exc}", file=sys.stderr)
        return 1

    print(f"OK mcp_token_user={args.token_user} action={action} token_len={len(token)}")
    if args.print_token:
        print(token)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
