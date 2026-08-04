#!/usr/bin/env python3
"""Capture LangGraph playbook overlay layout variant PNGs for comparison."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from capture_playbook_overlay import (  # noqa: E402
    PlaybookOverlayVerificationError,
    _ensure_auth,
    _login,
    verify_playbook_overlay,
)
from investigation_progress import list_playbook_layout_presets  # noqa: E402

VARIANT_OUTPUTS: dict[str, Path] = {
    "variant-a": PROJECT_ROOT / "assets" / "playbook-render-variant-a.png",
    "variant-b": PROJECT_ROOT / "assets" / "playbook-render-variant-b.png",
    "variant-c": PROJECT_ROOT / "assets" / "playbook-render-variant-c.png",
}


def capture_layout_variant(
    base_url: str,
    preset: str,
    out_path: Path,
    user: str,
    password: str,
    *,
    verify: bool = True,
) -> list[str]:
    from playwright.sync_api import sync_playwright

    if preset not in VARIANT_OUTPUTS and preset not in list_playbook_layout_presets():
        raise ValueError(f"Unknown playbook layout preset: {preset!r}")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    passed: list[str] = []
    page_url = f"{base_url.rstrip('/')}/?playbook_preset={preset}"
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 1920, "height": 1080}, ignore_https_errors=True)
        page = context.new_page()
        _login(page, base_url, user, password)
        page.goto(page_url, wait_until="domcontentloaded")
        page.wait_for_timeout(1200)
        rail = page.locator("#runtime-rail")
        if rail.count():
            expanded = rail.get_attribute("data-expanded")
            if expanded != "true":
                toggle = page.locator("#runtime-rail-toggle")
                if toggle.count():
                    toggle.click()
                    page.wait_for_timeout(400)
        expand_btn = page.locator("#runtime-journey-expand")
        expand_btn.wait_for(state="visible", timeout=10000)
        expand_btn.click()
        overlay = page.locator("#runtime-journey-overlay")
        overlay.wait_for(state="visible", timeout=10000)
        page.wait_for_selector("#playbook-flowchart-svg .playbook-flow-node", timeout=10000)
        page.wait_for_timeout(600)
        if verify:
            passed = verify_playbook_overlay(page)
            print(f"[{preset}] Playwright verification passed:", ", ".join(passed))
        overlay.screenshot(path=str(out_path))
        browser.close()
    print(f"[{preset}] Saved {out_path}")
    return passed


def capture_all_variants(
    base_url: str,
    user: str,
    password: str,
    *,
    verify: bool = True,
) -> int:
    failures = 0
    for preset, out_path in VARIANT_OUTPUTS.items():
        try:
            capture_layout_variant(base_url, preset, out_path, user, password, verify=verify)
        except PlaybookOverlayVerificationError as exc:
            print(f"[{preset}] Playwright verification FAILED: {exc}", file=sys.stderr)
            failures += 1
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description="Capture playbook overlay layout variant PNGs")
    parser.add_argument("--url", default=os.environ.get("AGTSMITH_UI_URL", "http://127.0.0.1:8787"))
    parser.add_argument(
        "--preset",
        choices=sorted(VARIANT_OUTPUTS.keys()),
        help="Capture a single preset (default: all three variants)",
    )
    parser.add_argument(
        "--out",
        type=Path,
        help="Output path when using --preset (defaults to assets/playbook-render-<preset>.png)",
    )
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="Skip pre-screenshot overlay verification checks",
    )
    args = parser.parse_args()
    user, password = _ensure_auth(args.url.rstrip("/"))
    verify = not args.no_verify
    if args.preset:
        out_path = args.out or VARIANT_OUTPUTS[args.preset]
        try:
            capture_layout_variant(
                args.url.rstrip("/"),
                args.preset,
                out_path,
                user,
                password,
                verify=verify,
            )
        except PlaybookOverlayVerificationError as exc:
            print(f"Playwright verification FAILED: {exc}", file=sys.stderr)
            return 1
        return 0
    return capture_all_variants(args.url.rstrip("/"), user, password, verify=verify)


if __name__ == "__main__":
    sys.exit(main())
