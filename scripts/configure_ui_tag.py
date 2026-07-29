#!/usr/bin/env python3
"""Record and inspect Configure UI version tags for screenshot/test gates."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
VERSION_PATH = PROJECT_ROOT / "VERSION"
ARTIFACTS_ROOT = PROJECT_ROOT / "artifacts" / "configure_ui"
SCREENSHOT_ROOT = PROJECT_ROOT / "docs" / "images" / "screenshots"

TAG_PATTERN = re.compile(r"^configure-ui(?:-[a-z0-9]+)?$")


def _git_sha() -> str:
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=PROJECT_ROOT,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        return out.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return ""


def _app_version() -> str:
    if VERSION_PATH.is_file():
        return VERSION_PATH.read_text(encoding="utf-8").strip()
    return ""


def _phase_from_tag(tag: str) -> int | None:
    match = re.search(r"-p(\d+)$", tag)
    if match:
        return int(match.group(1))
    return None


def _validate_tag(tag: str) -> None:
    if not TAG_PATTERN.match(tag):
        raise ValueError(f"Invalid configure UI tag: {tag!r}")


def _manifest_path(tag: str) -> Path:
    _validate_tag(tag)
    return ARTIFACTS_ROOT / tag / "manifest.json"


def _collect_screenshots(screenshot_version: str) -> list[str]:
    out_dir = SCREENSHOT_ROOT / screenshot_version
    if not out_dir.is_dir():
        return []
    paths = sorted(out_dir.glob("agtsmith-*-configure-*.png"))
    return [str(path.relative_to(PROJECT_ROOT)) for path in paths]


def cmd_show(args: argparse.Namespace) -> int:
    tag = args.tag or os.environ.get("CONFIGURE_UI_TAG", "configure-ui-dev")
    manifest = _manifest_path(tag) if TAG_PATTERN.match(tag) and _manifest_path(tag).is_file() else None
    print(f"configure_ui_tag={tag}")
    print(f"app_version={_app_version()}")
    print(f"git_sha={_git_sha()}")
    if manifest:
        print(f"manifest={manifest.relative_to(PROJECT_ROOT)}")
    else:
        print("manifest=(none)")
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    path = Path(args.path)
    payload = json.loads(path.read_text(encoding="utf-8"))
    required = {"configure_ui_tag", "app_version", "phase", "captured_at"}
    missing = required - set(payload)
    if missing:
        raise SystemExit(f"manifest missing keys: {sorted(missing)}")
    _validate_tag(str(payload["configure_ui_tag"]))
    print(f"OK  {path}")
    return 0


def cmd_record(args: argparse.Namespace) -> int:
    tag = args.tag or os.environ.get("CONFIGURE_UI_TAG", "")
    if not tag:
        raise SystemExit("CONFIGURE_UI_TAG or --tag required")
    _validate_tag(tag)

    screenshot_version = args.screenshot_version or os.environ.get("SCREENSHOT_VERSION", "")
    tests = [part.strip() for part in (args.tests or os.environ.get("CONFIGURE_UI_TESTS", "")).split(",") if part.strip()]

    payload = {
        "configure_ui_tag": tag,
        "app_version": _app_version(),
        "git_sha": _git_sha(),
        "phase": _phase_from_tag(tag),
        "screenshot_version": screenshot_version,
        "screenshots": _collect_screenshots(screenshot_version) if screenshot_version else [],
        "tests_passed": tests,
        "captured_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "notes": args.notes or "",
    }

    out_path = _manifest_path(tag)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"Recorded {out_path.relative_to(PROJECT_ROOT)}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Configure UI version tag utilities")
    sub = parser.add_subparsers(dest="command", required=True)

    show = sub.add_parser("show", help="Print current tag metadata")
    show.add_argument("--tag", default="")
    show.set_defaults(func=cmd_show)

    record = sub.add_parser("record", help="Write artifact manifest for a gate tag")
    record.add_argument("--tag", default="")
    record.add_argument("--screenshot-version", default="")
    record.add_argument("--tests", default="", help="Comma-separated test target names")
    record.add_argument("--notes", default="")
    record.set_defaults(func=cmd_record)

    validate = sub.add_parser("validate", help="Validate manifest JSON schema")
    validate.add_argument("path", type=Path)
    validate.set_defaults(func=cmd_validate)

    args = parser.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
