#!/usr/bin/env python3
"""Generate a consolidated markdown status report for docs/logs artifacts."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path('.')
OUT = ROOT / 'docs' / 'logs' / 'status_report.md'
OUT_JSON = ROOT / 'docs' / 'logs' / 'status_report.json'
LATEST_STATUS = ROOT / 'docs' / 'logs' / 'latest_status.json'
REGRESSION_LATEST = ROOT / 'docs' / 'logs' / 'template_regression_latest.json'
LANGGRAPH_DIR = ROOT / 'docs' / 'logs' / 'langgraph_runs'
SNAPSHOT_HISTORY = ROOT / 'docs' / 'logs' / 'operator_snapshot' / 'history'


def load_json(path: Path):
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding='utf-8'))


def latest_file(pattern_dir: Path, glob_pat: str):
    if not pattern_dir.exists():
        return None
    items = sorted(pattern_dir.glob(glob_pat))
    return items[-1] if items else None


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate consolidated docs/logs status report")
    parser.add_argument(
        "--out",
        default=str(OUT),
        help="Markdown output path",
    )
    parser.add_argument(
        "--json-out",
        default=None,
        help="Optional JSON output path (default: docs/logs/status_report.json)",
    )
    args = parser.parse_args()

    out_md = Path(args.out)
    out_json = Path(args.json_out) if args.json_out else OUT_JSON

    now = datetime.now(timezone.utc).isoformat()

    latest_status = load_json(LATEST_STATUS) or {}
    regression = load_json(REGRESSION_LATEST) or {}

    latest_langgraph = latest_file(LANGGRAPH_DIR, 'langgraph_run_*.json')
    langgraph_count = len(list(LANGGRAPH_DIR.glob('langgraph_run_*.json'))) if LANGGRAPH_DIR.exists() else 0

    latest_snapshot_dir = latest_file(SNAPSHOT_HISTORY, 'snapshot_*')
    snapshot_count = len(list(SNAPSHOT_HISTORY.glob('snapshot_*'))) if SNAPSHOT_HISTORY.exists() else 0

    lines: list[str] = []
    lines.append('# Lab Status Report')
    lines.append('')
    lines.append(f'- Generated (UTC): `{now}`')
    lines.append('')

    lines.append('## Core Status')
    lines.append(f"- Latest status overall: `{latest_status.get('overall', 'unknown')}`")
    lines.append(f"- Latest status timestamp: `{latest_status.get('latest_timestamp_utc', 'unknown')}`")
    lines.append(f"- Regression latest status: `{regression.get('status', 'unknown')}`")
    lines.append('')

    rows = latest_status.get('rows_by_intent', {}) if isinstance(latest_status, dict) else {}
    lines.append('## Rows By Intent')
    if isinstance(rows, dict) and rows:
        for intent in sorted(rows):
            lines.append(f"- `{intent}`: `{rows[intent]}`")
    else:
        lines.append('- No rows_by_intent data found')
    lines.append('')

    lines.append('## LangGraph Artifacts')
    lines.append(f'- Total run artifacts: `{langgraph_count}`')
    lines.append(f"- Latest run artifact: `{latest_langgraph}`")
    lines.append('')

    lines.append('## Snapshot Bundles')
    lines.append(f'- Total snapshot bundles: `{snapshot_count}`')
    lines.append(f"- Latest snapshot bundle: `{latest_snapshot_dir}`")
    lines.append('')

    lines.append('## Key Files')
    lines.append(f'- `{LATEST_STATUS}`')
    lines.append(f'- `{REGRESSION_LATEST}`')
    lines.append(f'- `{LANGGRAPH_DIR / "latest_index.csv"}`')
    lines.append('')

    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text('\n'.join(lines) + '\n', encoding='utf-8')

    payload = {
        "generated_utc": now,
        "core_status": {
            "overall": latest_status.get("overall", "unknown") if isinstance(latest_status, dict) else "unknown",
            "latest_status_timestamp_utc": latest_status.get("latest_timestamp_utc", "unknown")
            if isinstance(latest_status, dict)
            else "unknown",
            "regression_latest_status": regression.get("status", "unknown")
            if isinstance(regression, dict)
            else "unknown",
        },
        "rows_by_intent": rows if isinstance(rows, dict) else {},
        "langgraph": {
            "run_count": langgraph_count,
            "latest_run_artifact": str(latest_langgraph) if latest_langgraph else None,
        },
        "snapshots": {
            "bundle_count": snapshot_count,
            "latest_bundle": str(latest_snapshot_dir) if latest_snapshot_dir else None,
        },
        "key_files": [
            str(LATEST_STATUS),
            str(REGRESSION_LATEST),
            str(LANGGRAPH_DIR / "latest_index.csv"),
        ],
    }
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    print(f'report={out_md}')
    print(f'report_json={out_json}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
