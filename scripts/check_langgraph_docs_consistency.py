#!/usr/bin/env python3
"""Check LangGraph telemetry doc consistency between README and daily runbook."""

from __future__ import annotations

from pathlib import Path

README = Path("README.md")
DAILY = Path("docs/runbooks/daily_ops.md")

REQUIRED_MARKERS = [
    "make langgraph-policy-status",
    "make langgraph-policy-snapshot",
    "make langgraph-policy-trend",
    "make langgraph-policy-freshness",
    "make langgraph-policy-trend-freshness",
    "make langgraph-policy-trend-anomaly",
    "make langgraph-ops",
    "make langgraph-all-quick",
    "make langgraph-tool-routing-check",
    "make langgraph-session-check",
    "make langgraph-tool-demo",
    "make langgraph-metadata-demo",
    "make langgraph-chain-demo",
    "make langgraph-session-demo",
    "make langgraph-demo-ready",
    "make agentic-check",
    "make agentic-run",
    "make agentic-demo",
    "make agentic-session-demo",
    "make agentic-status",
    "make agentic-case-report",
    "make agentic-demo-ready",
    "make model-show",
    "make model-smoke",
    "make ui-dev",
    "POLICY_SUMMARY_MAX_AGE_MINUTES",
    "POLICY_TREND_MAX_AGE_MINUTES",
    "docs/logs/langgraph_runs/latest_policy_summary.json",
    "docs/logs/langgraph_policy_summary_history/latest_trend.csv",
    "If `make langgraph-policy-trend-anomaly` fails:",
]


def missing_markers(text: str) -> list[str]:
    return [m for m in REQUIRED_MARKERS if m not in text]


def main() -> int:
    if not README.exists():
        print(f"FAIL: missing file: {README}")
        return 1
    if not DAILY.exists():
        print(f"FAIL: missing file: {DAILY}")
        return 1

    readme_text = README.read_text(encoding="utf-8")
    daily_text = DAILY.read_text(encoding="utf-8")

    readme_missing = missing_markers(readme_text)
    daily_missing = missing_markers(daily_text)

    print("=== LangGraph Docs Consistency Check ===")
    print(f"readme={README}")
    print(f"daily={DAILY}")
    print(f"required_markers={len(REQUIRED_MARKERS)}")

    if readme_missing or daily_missing:
        print("status=FAIL")
        if readme_missing:
            print("README missing markers:")
            for i, marker in enumerate(readme_missing, start=1):
                print(f"  {i}. {marker}")
        if daily_missing:
            print("daily_ops missing markers:")
            for i, marker in enumerate(daily_missing, start=1):
                print(f"  {i}. {marker}")
        return 1

    print("status=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
