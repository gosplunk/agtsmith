#!/usr/bin/env python3
"""Capture UI screenshots from manifest.yaml for docs and releases."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import yaml

SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_DIR = SCRIPT_DIR.parent
REPO_ROOT = SKILL_DIR.parents[2]


class AuthenticationError(RuntimeError):
    """Raised when an authenticated screenshot target remains unauthenticated."""


def load_manifest(path: Path) -> dict:
    with path.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def splunk_login(page, base_url: str) -> None:
    user = os.environ.get("SPLUNK_USER", "")
    password = os.environ.get("SPLUNK_PASS", "")
    if not user or not password:
        raise RuntimeError("SPLUNK_USER and SPLUNK_PASS required for splunk auth targets")
    page.goto(base_url, wait_until="domcontentloaded")
    if page.locator('input[name="username"]').count():
        page.fill('input[name="username"]', user)
        page.fill('input[name="password"]', password)
        page.click('input[type="submit"], button[type="submit"]')
        page.wait_for_load_state("networkidle")


def agtsmith_login(page, base_url: str) -> None:
    user = os.environ.get("AGTSMITH_UI_USER", "")
    password = os.environ.get("AGTSMITH_UI_PASS", "")
    if not user or not password:
        raise RuntimeError("AGTSMITH_UI_USER and AGTSMITH_UI_PASS required for agtsmith auth targets")
    page.goto(base_url, wait_until="domcontentloaded")
    user_input = page.locator('input[name="username"], input[name="user"], #username, #login-username')
    pass_input = page.locator('input[name="password"], #password, #login-password')
    if not user_input.count() and not pass_input.count() and "/login" not in page.url:
        return
    if not user_input.count() or not pass_input.count():
        raise AuthenticationError("agtsmith login form was not found")
    user_input.first.fill(user)
    pass_input.first.fill(password)
    submit = page.locator('button[type="submit"], input[type="submit"]')
    if submit.count():
        submit.first.click()
    else:
        page.keyboard.press("Enter")
    page.wait_for_load_state("networkidle")
    if "/login" in page.url or page.locator('input[name="password"], #password, #login-password').count():
        raise AuthenticationError("agtsmith login failed")


def assert_authenticated(page) -> None:
    if "/login" in page.url or page.locator('input[name="password"], #password, #login-password').count():
        raise AuthenticationError("authenticated screenshot target redirected to login")


def _target_tags(target: dict, configure_ui_tag: str) -> list[str]:
    tags = list(target.get("tags") or [])
    if configure_ui_tag and configure_ui_tag not in tags:
        tags.append(configure_ui_tag)
    return tags


def _ui_base_url() -> str:
    return os.environ.get("AGTSMITH_UI_URL", "http://127.0.0.1:8787").rstrip("/")


def _rewrite_ui_url(url: str) -> str:
    base = _ui_base_url()
    for prefix in ("http://127.0.0.1:8787", "http://localhost:8787"):
        if url.startswith(prefix):
            return base + url[len(prefix) :]
    return url


def capture_target(page, target: dict, out_dir: Path, version: str, configure_ui_tag: str = "") -> bool:
    url = _rewrite_ui_url(target["url"])
    tid = target["id"]
    wait_ms = int(target.get("wait_ms", 1500))
    out_path = out_dir / f"agtsmith-{version}-{tid}.png"

    try:
        auth = target.get("auth")
        if auth == "splunk":
            splunk_login(page, "http://127.0.0.1:8000/en-US/account/login")
        elif auth == "agtsmith":
            agtsmith_login(page, f"{_ui_base_url()}/login")
        page.goto(url, wait_until="domcontentloaded", timeout=30000)
        page.wait_for_timeout(wait_ms)
        if auth:
            assert_authenticated(page)
        page.screenshot(path=str(out_path), full_page=True)
        meta_path = out_path.with_suffix(".png.meta.json")
        meta_path.write_text(
            json.dumps(
                {
                    "target_id": tid,
                    "version": version,
                    "configure_ui_tag": configure_ui_tag,
                    "tags": _target_tags(target, configure_ui_tag),
                    "url": url,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        print(f"OK  {out_path}")
        return True
    except AuthenticationError:
        raise
    except Exception as exc:  # noqa: BLE001
        if target.get("skip_if_unreachable"):
            print(f"SKIP {tid}: {exc}")
            return False
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, default=SKILL_DIR / "manifest.yaml")
    parser.add_argument("--version", default=os.environ.get("SCREENSHOT_VERSION", "0.2.0-splunk"))
    parser.add_argument("--configure-ui-tag", default=os.environ.get("CONFIGURE_UI_TAG", ""))
    parser.add_argument("--target-id", action="append", default=[], help="Capture only these manifest target ids")
    args = parser.parse_args()

    manifest = load_manifest(args.manifest)
    out_dir = REPO_ROOT / manifest["output_dir_template"].format(version=args.version)
    out_dir.mkdir(parents=True, exist_ok=True)

    viewport = manifest.get("viewport", {"width": 1920, "height": 1080})

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("Install: pip install -r .cursor/skills/agtsmith-screenshots/scripts/requirements.txt", file=sys.stderr)
        print("Then: playwright install chromium", file=sys.stderr)
        return 1

    ok = 0
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            viewport={"width": int(viewport["width"]), "height": int(viewport["height"])},
            ignore_https_errors=True,
        )
        page = context.new_page()
        for target in manifest.get("targets", []):
            if args.target_id and target.get("id") not in args.target_id:
                continue
            if capture_target(page, target, out_dir, args.version, args.configure_ui_tag):
                ok += 1
        browser.close()

    print(f"Captured {ok} screenshot(s) in {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
