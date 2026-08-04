#!/usr/bin/env python3
"""Capture LangGraph playbook overlay for layout iteration."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from investigation_progress import PLAYBOOK_FLOW_NODES  # noqa: E402
from ui_auth_docker import (  # noqa: E402
    DEFAULT_E2E_USER,
    bootstrap_docker_ui_auth,
    docker_ui_running,
    generated_test_password,
    try_urllib_login,
)

EXPECTED_NODE_COUNT = len(PLAYBOOK_FLOW_NODES)
MIN_VIEWBOX_WIDTH = 800
MIN_VIEWBOX_HEIGHT = 500


def _ensure_auth(base_url: str) -> tuple[str, str]:
    env_user = os.environ.get("AGTSMITH_UI_USER") or os.environ.get("AGTSMITH_E2E_USER")
    env_pass = os.environ.get("AGTSMITH_UI_PASS") or os.environ.get("AGTSMITH_E2E_PASS")
    candidates: list[tuple[str, str]] = [
        (env_user or DEFAULT_E2E_USER, env_pass or generated_test_password())
    ]
    for user, password in candidates:
        if try_urllib_login(base_url, user, password):
            return user, password
    if docker_ui_running():
        for user, password in candidates:
            bootstrap_docker_ui_auth(user, password, merge=True)
            if try_urllib_login(base_url, user, password):
                return user, password
    raise RuntimeError("Unable to authenticate for playbook overlay capture")


def _login(page, base_url: str, user: str, password: str) -> None:
    page.goto(f"{base_url.rstrip('/')}/login", wait_until="domcontentloaded")
    if "/setup/first-run" in page.url:
        page.locator('input[name="username"]').fill(user)
        page.locator('select[name="role"]').select_option("admin")
        page.locator('input[name="password"]').first.fill(password)
        page.locator('input[name="confirm_password"]').fill(password)
        page.locator('button.setup-btn, button[type="submit"]').first.click()
        page.wait_for_url(lambda url: "/setup/first-run" not in url, timeout=15000)
        page.wait_for_load_state("networkidle")
        return
    page.locator('input[name="username"], input[name="user"], #username').first.fill(user)
    page.locator('input[name="password"], #password').first.fill(password)
    submit = page.locator('button[type="submit"], input[type="submit"]')
    if submit.count():
        submit.first.click()
    else:
        page.keyboard.press("Enter")
    page.wait_for_load_state("networkidle")


class PlaybookOverlayVerificationError(RuntimeError):
    """Raised when pre-screenshot overlay checks fail."""


def verify_playbook_overlay(page) -> list[str]:
    """Assert overlay layout is healthy before capture. Returns list of passed check names."""
    checks: list[str] = []
    overlay = page.locator("#runtime-journey-overlay")
    if not overlay.count():
        raise PlaybookOverlayVerificationError("Overlay #runtime-journey-overlay not found")
    if not overlay.is_visible():
        raise PlaybookOverlayVerificationError("Overlay #runtime-journey-overlay is not visible")
    checks.append("overlay_visible")

    pill = page.locator("#runtime-journey-overlay-profile")
    if not pill.count() or not pill.is_visible():
        raise PlaybookOverlayVerificationError("Profile pill #runtime-journey-overlay-profile not visible")
    pill_text = (pill.inner_text() or "").strip().upper()
    if pill_text != "ALL PATHS":
        raise PlaybookOverlayVerificationError(
            f"Expected ALL PATHS pill in doc mode (no active run), got {pill_text!r}"
        )
    checks.append("all_paths_pill")

    svg = page.locator("#playbook-flowchart-svg")
    if not svg.count():
        raise PlaybookOverlayVerificationError("SVG #playbook-flowchart-svg not found")
    viewbox = svg.get_attribute("viewBox") or ""
    parts = [p for p in viewbox.split() if p]
    if len(parts) != 4:
        raise PlaybookOverlayVerificationError(f"SVG viewBox missing or malformed: {viewbox!r}")
    vb_w, vb_h = float(parts[2]), float(parts[3])
    if vb_w < MIN_VIEWBOX_WIDTH or vb_h < MIN_VIEWBOX_HEIGHT:
        raise PlaybookOverlayVerificationError(
            f"SVG viewBox too small ({vb_w}×{vb_h}); expected ≥{MIN_VIEWBOX_WIDTH}×{MIN_VIEWBOX_HEIGHT}"
        )
    checks.append("svg_viewbox")

    nodes = page.locator("#playbook-flowchart-svg .playbook-flow-node")
    node_count = nodes.count()
    if node_count < EXPECTED_NODE_COUNT:
        raise PlaybookOverlayVerificationError(
            f"Expected ≥{EXPECTED_NODE_COUNT} playbook nodes, found {node_count}"
        )
    checks.append(f"node_count_{node_count}")

    labels_layer = page.locator("#playbook-flowchart-svg .playbook-flow-edge-labels")
    if not labels_layer.count():
        raise PlaybookOverlayVerificationError("Edge labels layer .playbook-flow-edge-labels missing")
    checks.append("edge_labels_layer")

    legend = page.locator("#playbook-flowchart-svg .playbook-flow-legend")
    if not legend.count():
        raise PlaybookOverlayVerificationError("Legend .playbook-flow-legend missing")
    checks.append("legend_present")

    scroll_metrics = overlay.evaluate(
        """el => ({
            scrollWidth: el.scrollWidth,
            clientWidth: el.clientWidth,
            scrollHeight: el.scrollHeight,
            clientHeight: el.clientHeight,
        })"""
    )
    if scroll_metrics["scrollWidth"] > scroll_metrics["clientWidth"] + 1:
        raise PlaybookOverlayVerificationError(
            "Overlay has horizontal scroll: "
            f"scrollWidth={scroll_metrics['scrollWidth']} > clientWidth={scroll_metrics['clientWidth']}"
        )
    checks.append("no_horizontal_scroll")

    return checks


def capture_playbook_overlay(
    base_url: str,
    out_path: Path,
    user: str,
    password: str,
    *,
    verify: bool = True,
) -> list[str]:
    from playwright.sync_api import sync_playwright

    out_path.parent.mkdir(parents=True, exist_ok=True)
    passed: list[str] = []
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 1920, "height": 1080}, ignore_https_errors=True)
        page = context.new_page()
        _login(page, base_url, user, password)
        page.goto(f"{base_url.rstrip('/')}/", wait_until="domcontentloaded")
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
            print("Playwright verification passed:", ", ".join(passed))
        overlay.screenshot(path=str(out_path))
        browser.close()
    print(f"Saved {out_path}")
    return passed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default=os.environ.get("AGTSMITH_UI_URL", "http://127.0.0.1:8787"))
    parser.add_argument(
        "--out",
        type=Path,
        default=PROJECT_ROOT / "assets" / "playbook-render-iteration-1.png",
    )
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="Skip pre-screenshot overlay verification checks",
    )
    args = parser.parse_args()
    user, password = _ensure_auth(args.url.rstrip("/"))
    try:
        capture_playbook_overlay(
            args.url.rstrip("/"),
            args.out,
            user,
            password,
            verify=not args.no_verify,
        )
    except PlaybookOverlayVerificationError as exc:
        print(f"Playwright verification FAILED: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
