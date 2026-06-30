#!/usr/bin/env python3
"""Compare screenshot directory against a baseline using pixel diff."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from PIL import Image, ImageChops

SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_DIR = SCRIPT_DIR.parent
REPO_ROOT = SKILL_DIR.parents[2]


def diff_images(a: Path, b: Path, out: Path, threshold: float = 0.01) -> bool:
    img_a = Image.open(a).convert("RGB")
    img_b = Image.open(b).convert("RGB")
    if img_a.size != img_b.size:
        img_b = img_b.resize(img_a.size)
    diff = ImageChops.difference(img_a, img_b)
    out.parent.mkdir(parents=True, exist_ok=True)
    diff.save(out)
    hist = diff.histogram()
    # approximate changed pixel ratio from sum of non-zero channel diffs
    total = img_a.size[0] * img_a.size[1] * 3
    changed = sum(hist[1:256]) + sum(hist[257:512]) + sum(hist[513:768])
    ratio = changed / max(total, 1)
    return ratio <= threshold


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--baseline", help="baseline version dir name, default previous minor")
    parser.add_argument("--threshold", type=float, default=0.02)
    args = parser.parse_args()

    current = REPO_ROOT / "docs/images/screenshots" / f"v{args.version}"
    if not current.is_dir():
        print(f"Missing {current}", file=sys.stderr)
        return 1

    baseline_name = args.baseline
    if not baseline_name:
        # default: try v1.4.1 upstream screenshots
        baseline_name = "v1.4.1"
    baseline = REPO_ROOT / "docs/images/screenshots" / baseline_name
    if not baseline.is_dir():
        print(f"No baseline at {baseline} — skipping diff", file=sys.stderr)
        return 0

    diff_dir = REPO_ROOT / "output/playwright/diff" / f"v{args.version}"
    failures = 0
    for png in sorted(current.glob("*.png")):
        ref = baseline / png.name
        if not ref.exists():
            print(f"NEW {png.name} (no baseline)")
            continue
        diff_path = diff_dir / png.name
        if diff_images(ref, png, diff_path, args.threshold):
            print(f"OK  {png.name}")
        else:
            print(f"DIFF {png.name} -> {diff_path}")
            failures += 1

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
