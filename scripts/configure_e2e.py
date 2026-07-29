#!/usr/bin/env python3
"""Playwright E2E flow for Configuration Setup Lanes."""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS_ROOT = PROJECT_ROOT / "artifacts" / "configure_ui"


def _lab_up(base_url: str) -> bool:
    try:
        with urllib.request.urlopen(f"{base_url.rstrip('/')}/login", timeout=3) as resp:
            return resp.status < 500
    except (urllib.error.URLError, TimeoutError, OSError):
        return False


def _login(page, base_url: str, user: str, password: str) -> None:
    page.goto(f"{base_url.rstrip('/')}/login", wait_until="domcontentloaded")
    user_input = page.locator('input[name="username"], input[name="user"], #username')
    pass_input = page.locator('input[name="password"], #password')
    user_input.first.fill(user)
    pass_input.first.fill(password)
    submit = page.locator('button[type="submit"], input[type="submit"]')
    if submit.count():
        submit.first.click()
    else:
        page.keyboard.press("Enter")
    page.wait_for_load_state("networkidle")


def main() -> int:
    base_url = os.environ.get("AGTSMITH_UI_URL", "http://127.0.0.1:8787")
    user = os.environ.get("AGTSMITH_UI_USER", "")
    password = os.environ.get("AGTSMITH_UI_PASS", "")
    expected_tag = os.environ.get("CONFIGURE_UI_TAG", "configure-ui-p3")

    if not _lab_up(base_url):
        print(f"SKIP configure-e2e: sidecar unreachable at {base_url}")
        return 0

    if not user or not password:
        print("SKIP configure-e2e: AGTSMITH_UI_USER and AGTSMITH_UI_PASS required")
        return 0

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("Install playwright: pip install -r .cursor/skills/agtsmith-screenshots/scripts/requirements.txt", file=sys.stderr)
        return 1

    report: dict[str, object] = {"configure_ui_tag": expected_tag, "steps": []}

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1920, "height": 1080})
        _login(page, base_url, user, password)

        page.goto(f"{base_url.rstrip('/')}/configure#connect", wait_until="domcontentloaded")
        page.wait_for_timeout(1200)
        report["steps"].append({"lane": "connect", "url": page.url})

        tag_text = page.locator("#cfg-ui-tag").inner_text(timeout=5000)
        if expected_tag not in tag_text:
            raise AssertionError(f"Expected tag {expected_tag!r} in badge text {tag_text!r}")

        page.locator("#cfg-sticky-footer").wait_for(timeout=5000)
        report["steps"].append({"sticky_footer": True})

        page.goto(f"{base_url.rstrip('/')}/configure#models", wait_until="domcontentloaded")
        page.wait_for_timeout(800)
        page.locator("#cfg-family-grid").wait_for(timeout=5000)
        report["steps"].append({"lane": "models", "family_tiles": page.locator(".cfg-family-tile").count()})

        page.goto(f"{base_url.rstrip('/')}/configure#validate", wait_until="domcontentloaded")
        page.wait_for_timeout(800)
        page.locator("#cfg-validate").click()
        page.wait_for_timeout(2500)
        report["steps"].append({"lane": "validate", "validated": True})

        page.goto(f"{base_url.rstrip('/')}/configure#ground", wait_until="domcontentloaded")
        page.wait_for_timeout(800)
        report["steps"].append({"lane": "ground", "refresh_button": page.locator("#cfg-env-refresh").count() > 0})

        browser.close()

    out_dir = ARTIFACTS_ROOT / expected_tag
    out_dir.mkdir(parents=True, exist_ok=True)
    report_path = out_dir / "e2e-report.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"OK  configure-e2e report -> {report_path.relative_to(PROJECT_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
