#!/usr/bin/env python3
"""Capture UI screenshots from manifest.yaml for docs and releases."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import yaml

SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_DIR = SCRIPT_DIR.parent
REPO_ROOT = SKILL_DIR.parents[2]


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


def capture_target(page, target: dict, out_dir: Path, version: str) -> bool:
    url = target["url"]
    tid = target["id"]
    wait_ms = int(target.get("wait_ms", 1500))
    out_path = out_dir / f"agtsmith-{version}-{tid}.png"

    try:
        if target.get("auth") == "splunk":
            splunk_login(page, "http://127.0.0.1:8000/en-US/account/login")
        page.goto(url, wait_until="domcontentloaded", timeout=30000)
        page.wait_for_timeout(wait_ms)
        page.screenshot(path=str(out_path), full_page=True)
        print(f"OK  {out_path}")
        return True
    except Exception as exc:  # noqa: BLE001
        if target.get("skip_if_unreachable"):
            print(f"SKIP {tid}: {exc}")
            return False
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, default=SKILL_DIR / "manifest.yaml")
    parser.add_argument("--version", default=os.environ.get("SCREENSHOT_VERSION", "0.2.0-splunk"))
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
            if capture_target(page, target, out_dir, args.version):
                ok += 1
        browser.close()

    print(f"Captured {ok} screenshot(s) in {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
