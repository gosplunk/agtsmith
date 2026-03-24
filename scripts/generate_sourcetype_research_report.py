#!/usr/bin/env python3
"""Generate sourcetype classification research report from environment profile."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any


def _safe(v: Any) -> str:
    return str(v or "").strip()


def _md_escape(text: str) -> str:
    return text.replace("|", "\\|")


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate sourcetype research markdown report")
    parser.add_argument("--profile", default="artifacts/environment/environment_profile_latest.json")
    parser.add_argument("--out", default="docs/reference/sourcetype_research.md")
    args = parser.parse_args()

    profile_path = Path(args.profile)
    out_path = Path(args.out)
    if not profile_path.exists():
        print(f"missing profile: {profile_path}")
        return 1

    payload = json.loads(profile_path.read_text(encoding="utf-8"))
    sem = payload.get("sourcetype_semantics", {})
    if not isinstance(sem, dict):
        sem = {}

    confidence_counts: Counter[str] = Counter()
    by_st = sorted(sem.items(), key=lambda kv: kv[0].lower())
    unknown = 0
    for _st, meta in by_st:
        if not isinstance(meta, dict):
            continue
        conf = _safe(meta.get("confidence")) or "unknown"
        confidence_counts[conf] += 1
        if "Unclassified sourcetype" in _safe(meta.get("description")):
            unknown += 1

    lines: list[str] = []
    lines.append("# Sourcetype Research and Classification")
    lines.append("")
    lines.append("This report is generated from `artifacts/environment/environment_profile_latest.json`.")
    lines.append("")
    lines.append("## Coverage Summary")
    lines.append(f"- Total sourcetypes: {len(by_st)}")
    lines.append(f"- Unclassified sourcetypes: {unknown}")
    lines.append(f"- High confidence mappings: {confidence_counts.get('high', 0)}")
    lines.append(f"- Medium confidence mappings: {confidence_counts.get('medium', 0)}")
    lines.append(f"- Low confidence mappings: {confidence_counts.get('low', 0)}")
    lines.append("")
    lines.append("## Authoritative Sources")
    lines.append("- Splunk pretrained sourcetypes list: https://docs.splunk.com/Documentation/Splunk/latest/Data/Listofpretrainedsourcetypes")
    lines.append("- Splunk Add-on sourcetype naming guidance: https://docs.splunk.com/Documentation/AddOns/released/Overview/Sourcetypes")
    lines.append("- Splunk Add-on for Microsoft Windows sourcetypes/CIM: https://docs.splunk.com/Documentation/WindowsAddOn/latest/User/SourcetypesandCIMdatamodelinfo")
    lines.append("- Splunk Add-on for Unix and Linux sourcetypes/CIM: https://docs.splunk.com/Documentation/UnixAddOn/latest/User/SourcetypesandCIMdatamodelinfo")
    lines.append("")
    lines.append("## Sourcetype Classification Table")
    lines.append("| Sourcetype | Description | Confidence | Primary Use Cases | Sources |")
    lines.append("|---|---|---|---|---|")
    for st, meta in by_st:
        if not isinstance(meta, dict):
            continue
        desc = _md_escape(_safe(meta.get("description")))
        conf = _md_escape(_safe(meta.get("confidence")) or "unknown")
        use_cases = meta.get("use_cases", [])
        if isinstance(use_cases, list):
            uc = _md_escape(", ".join(_safe(x) for x in use_cases if _safe(x)))
        else:
            uc = ""
        srcs = meta.get("sources", [])
        if isinstance(srcs, list):
            src = _md_escape(", ".join(_safe(x) for x in srcs if _safe(x)))
        else:
            src = ""
        lines.append(f"| `{_md_escape(st)}` | {desc} | {conf} | {uc} | {src} |")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"out={out_path}")
    print(f"sourcetypes={len(by_st)}")
    print(f"unclassified={unknown}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
