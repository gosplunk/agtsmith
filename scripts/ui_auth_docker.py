#!/usr/bin/env python3
"""Shared Docker-deploy UI auth helpers for explicit bootstrap and E2E setup."""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DOCKER_UI_CONTAINER = "agtsmith-ui-deploy"
DEFAULT_DEV_USER = "admin"
DEFAULT_E2E_USER = "e2e_admin"


def dev_seed_auth_enabled() -> bool:
    return str(os.getenv("AGTSMITH_DEV_SEED_AUTH", "")).strip().lower() in {"1", "true", "yes", "on"}


def generated_test_password() -> str:
    """Return a non-reusable password for this test process."""
    return secrets.token_urlsafe(24)


def seed_dev_auth(*, path: Path | None = None) -> dict[str, str]:
    """Write explicitly supplied developer credentials to ui.env."""
    import sys

    sys.path[:0] = [str(PROJECT_ROOT), str(PROJECT_ROOT / "scripts")]
    from runtime_config import write_env_file
    from web_ui_server import _auth_users_env_value, _hash_password

    user = os.getenv("AGTSMITH_DEV_SEED_USER", DEFAULT_DEV_USER).strip()
    password = os.getenv("AGTSMITH_DEV_SEED_PASSWORD", "").strip()
    if not user or not password:
        raise RuntimeError(
            "AGTSMITH_DEV_SEED_AUTH requires AGTSMITH_DEV_SEED_PASSWORD "
            "(and optionally AGTSMITH_DEV_SEED_USER)"
        )
    hashed = _hash_password(password)
    users = {user: {"password": hashed, "role": "admin"}}
    updates = {
        "SOC_UI_AUTH_ENABLED": "1",
        "SOC_UI_AUTH_USERNAME": user,
        "SOC_UI_AUTH_PASSWORD": hashed,
        "SOC_UI_AUTH_ROLE": "admin",
        "SOC_UI_AUTH_USERS_JSON": _auth_users_env_value(users),
        "SOC_UI_AUTH_INITIALIZED": "1",
    }
    write_env_file(updates, path)
    for key, value in updates.items():
        os.environ[key] = value
    return updates


def merge_auth_user(user: str, password: str, *, role: str = "admin", path: Path | None = None) -> dict[str, str]:
    """Add or update one auth user without removing existing accounts."""
    import sys

    sys.path[:0] = [str(PROJECT_ROOT), str(PROJECT_ROOT / "scripts")]
    from runtime_config import write_env_file
    from web_ui_server import _auth_users_env_value, _hash_password, _load_auth_users

    users = _load_auth_users()
    users[user] = {"password": _hash_password(password), "role": role}
    primary = DEFAULT_DEV_USER if DEFAULT_DEV_USER in users else user
    updates = {
        "SOC_UI_AUTH_ENABLED": "1",
        "SOC_UI_AUTH_USERNAME": primary,
        "SOC_UI_AUTH_PASSWORD": users[primary]["password"],
        "SOC_UI_AUTH_ROLE": users[primary].get("role", "admin"),
        "SOC_UI_AUTH_USERS_JSON": _auth_users_env_value(users),
        "SOC_UI_AUTH_INITIALIZED": "1",
    }
    write_env_file(updates, path)
    for key, value in updates.items():
        os.environ[key] = value
    return updates


def replace_auth_user(user: str, password: str, *, role: str = "admin", path: Path | None = None) -> dict[str, str]:
    """Replace the local auth store with one explicitly supplied user."""
    import sys

    sys.path[:0] = [str(PROJECT_ROOT), str(PROJECT_ROOT / "scripts")]
    from runtime_config import write_env_file
    from web_ui_server import _auth_users_env_value, _hash_password

    hashed = _hash_password(password)
    users = {user: {"password": hashed, "role": role}}
    updates = {
        "SOC_UI_AUTH_ENABLED": "1",
        "SOC_UI_AUTH_USERNAME": user,
        "SOC_UI_AUTH_PASSWORD": hashed,
        "SOC_UI_AUTH_ROLE": role,
        "SOC_UI_AUTH_USERS_JSON": _auth_users_env_value(users),
        "SOC_UI_AUTH_INITIALIZED": "1",
    }
    write_env_file(updates, path)
    for key, value in updates.items():
        os.environ[key] = value
    return updates


def docker_ui_running() -> bool:
    try:
        proc = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", DOCKER_UI_CONTAINER],
            capture_output=True,
            text=True,
            check=False,
        )
        return proc.returncode == 0 and proc.stdout.strip() == "true"
    except (OSError, subprocess.SubprocessError):
        return False


def try_urllib_login(base_url: str, user: str, password: str) -> bool:
    jar = CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    data = urllib.parse.urlencode({"username": user, "password": password}).encode()
    req = urllib.request.Request(f"{base_url.rstrip('/')}/login", data=data, method="POST")
    try:
        with opener.open(req, timeout=10) as resp:
            if resp.status >= 400 or "/login" in resp.geturl():
                return False
    except urllib.error.HTTPError as exc:
        if exc.code != 401:
            raise
        return False
    except (urllib.error.URLError, TimeoutError, OSError):
        return False
    try:
        probe = urllib.request.Request(f"{base_url.rstrip('/')}/investigation", method="GET")
        with opener.open(probe, timeout=10) as resp:
            final_url = resp.geturl()
            return resp.status < 400 and "/login" not in final_url and "/setup/first-run" not in final_url
    except urllib.error.HTTPError as exc:
        return exc.code not in {401, 403}


def lab_up(base_url: str) -> bool:
    try:
        with urllib.request.urlopen(f"{base_url.rstrip('/')}/login", timeout=3) as resp:
            return resp.status < 500
    except (urllib.error.URLError, TimeoutError, OSError):
        return False


def _docker_exec_python(python_source: str) -> None:
    proc = subprocess.run(
        ["docker", "exec", DOCKER_UI_CONTAINER, "python", "-c", python_source],
        capture_output=True,
        text=True,
        check=False,
        cwd=PROJECT_ROOT,
    )
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout or "docker exec failed").strip())


def bootstrap_docker_ui_auth(user: str, password: str, *, merge: bool = True) -> None:
    """Configure auth inside agtsmith-ui-deploy; merge=True keeps existing users."""
    if merge:
        bootstrap_py = f"""
import sys
sys.path[:0] = [".", "scripts"]
from ui_auth_docker import merge_auth_user
merge_auth_user({user!r}, {password!r})
print("bootstrap_ok")
"""
    else:
        bootstrap_py = f"""
import sys
sys.path[:0] = [".", "scripts"]
from ui_auth_docker import replace_auth_user
replace_auth_user({user!r}, {password!r})
print("bootstrap_ok")
"""
    _docker_exec_python(bootstrap_py)
    subprocess.run(["docker", "restart", DOCKER_UI_CONTAINER], check=True)
    deadline = time.time() + 60
    while time.time() < deadline:
        if lab_up("http://127.0.0.1:8787") and try_urllib_login("http://127.0.0.1:8787", user, password):
            time.sleep(1)
            return
        time.sleep(1)
    raise RuntimeError("UI not reachable after auth bootstrap")
