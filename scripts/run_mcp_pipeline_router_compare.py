#!/usr/bin/env python3
"""Compare keyword-only vs edge-LLM MCP pipeline routing (+ saved query shortcut)."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import local_learning as ll
import mcp_deterministic_routing as mdr
import mcp_pipeline_router as mpr
import saved_query_library as sql
from runtime_config import get_edge_llm_enabled, get_edge_llm_host, get_edge_llm_model, get_ollama_host

# Golden cases: expected effective pipeline when requested=assisted
GOLDEN_CASES: list[dict[str, str]] = [
    {
        "question": "What indexes do I have access to?",
        "expected": "deterministic",
        "note": "pure inventory (matches user's saved query question)",
    },
    {
        "question": "What indexes had data in the last 15 minutes?",
        "expected": "assisted",
        "note": "time-bound data question must not auto-route",
    },
    {
        "question": "Show failed login activity in the last 24 hours",
        "expected": "assisted",
        "note": "security investigation",
    },
    {
        "question": "What is the Splunk version?",
        "expected": "deterministic",
        "note": "splunk_get_info",
    },
    {
        "question": "List hosts in my environment",
        "expected": "deterministic",
        "note": "metadata inventory",
    },
    {
        "question": "Which indexes had the most events in 24h?",
        "expected": "assisted",
        "note": "ranking/volume",
    },
]

SAVED_QUERY_QUESTION = "Which indexes do I have access to?"
SAVED_QUERY_SPL = (
    "| rest splunk_server=local /services/data/indexes "
    "| table title disabled currentDBSizeMB totalEventCount splunk_server"
)


def _keyword_pipeline(question: str) -> str:
    elig = mdr.classify_mcp_deterministic_eligibility(question)
    return "deterministic" if elig.get("eligible") else "assisted"


def _edge_pipeline(question: str, *, live: bool) -> tuple[str, dict]:
    if live:
        pipeline, meta = mpr.resolve_pipeline_route(question, "assisted", use_edge_llm=True)
        return pipeline, meta
    with _mock_edge_for_question(question):
        pipeline, meta = mpr.resolve_pipeline_route(question, "assisted", use_edge_llm=True)
        return pipeline, meta


class _mock_edge_for_question:
    """Context manager that stubs edge LLM responses for offline comparison."""

    def __init__(self, question: str) -> None:
        self.question = question.strip().lower()
        self._patch = None

    def __enter__(self):
        def _fake_classify(q: str, **kwargs):
            q_lower = q.strip().lower()
            if "had data" in q_lower or "last 15" in q_lower or "most events" in q_lower:
                return {
                    "route": "llm_assisted",
                    "mcp_tool": "none",
                    "needs_event_search": True,
                    "needs_time_window": "last" in q_lower,
                    "confidence": 0.97,
                    "reason": "event_search_time_window",
                    "source": "edge_llm",
                }
            if "failed login" in q_lower:
                return {
                    "route": "llm_assisted",
                    "mcp_tool": "none",
                    "needs_event_search": True,
                    "needs_time_window": True,
                    "confidence": 0.99,
                    "reason": "security_investigation",
                    "source": "edge_llm",
                }
            if any(
                phrase in q_lower
                for phrase in (
                    "indexes do i have",
                    "indexes available",
                    "splunk version",
                    "list hosts",
                )
            ):
                tool = "splunk_get_indexes"
                if "splunk version" in q_lower:
                    tool = "splunk_get_info"
                elif "list hosts" in q_lower:
                    tool = "splunk_get_metadata"
                return {
                    "route": "deterministic_mcp",
                    "mcp_tool": tool,
                    "needs_event_search": False,
                    "needs_time_window": False,
                    "confidence": 0.96,
                    "reason": "pure_inventory",
                    "source": "edge_llm",
                }
            return {
                "route": "llm_assisted",
                "mcp_tool": "none",
                "needs_event_search": True,
                "needs_time_window": False,
                "confidence": 0.6,
                "reason": "uncertain",
                "source": "edge_llm",
            }

        self._patch = mock.patch("mcp_pipeline_router.classify_pipeline_with_edge_llm", side_effect=_fake_classify)
        return self._patch.__enter__()

    def __exit__(self, *args):
        if self._patch:
            return self._patch.__exit__(*args)
        return False


def _saved_query_shortcut(question: str) -> dict | None:
    tmp = tempfile.TemporaryDirectory()
    try:
        tmp_root = Path(tmp.name)
        ll.LEARNING_ROOT = tmp_root / "learning"
        ll.REGISTRY_PATH = ll.LEARNING_ROOT / "local_learning_registry.json"
        ll.SPL_OPTIMIZATION_REPOSITORY_PATH = ll.LEARNING_ROOT / "spl_optimization_repository.json"
        ll.ensure_learning_registry()
        sql.save_analyst_query(
            question=SAVED_QUERY_QUESTION,
            query=SAVED_QUERY_SPL,
            intent="inventory_indexes",
        )
        with mock.patch("saved_query_library.saved_query_shortcut_enabled", return_value=True):
            return sql.retrieve_saved_query_shortcut(question, "inventory_indexes")
    finally:
        tmp.cleanup()


def _ollama_reachable() -> bool:
    import urllib.error
    import urllib.request

    base = (get_edge_llm_host() or get_ollama_host()).rstrip("/")
    if not base:
        return False
    try:
        with urllib.request.urlopen(f"{base}/api/tags", timeout=3) as resp:
            return resp.status == 200
    except (urllib.error.URLError, TimeoutError, OSError):
        return False


def run_compare(*, live_edge: bool) -> dict:
    rows: list[dict] = []
    keyword_pass = edge_pass = 0

    for case in GOLDEN_CASES:
        question = case["question"]
        expected = case["expected"]
        kw = _keyword_pipeline(question)
        t0 = time.perf_counter()
        edge, edge_meta = _edge_pipeline(question, live=live_edge)
        edge_ms = round((time.perf_counter() - t0) * 1000, 1)

        kw_ok = kw == expected
        edge_ok = edge == expected
        keyword_pass += int(kw_ok)
        edge_pass += int(edge_ok)

        rows.append(
            {
                "question": question,
                "expected": expected,
                "keyword": kw,
                "keyword_ok": kw_ok,
                "edge": edge,
                "edge_ok": edge_ok,
                "edge_ms": edge_ms,
                "edge_method": edge_meta.get("router_method", ""),
                "edge_reason": edge_meta.get("auto_route_reason", ""),
                "edge_router": edge_meta.get("router", {}),
                "note": case.get("note", ""),
            }
        )

    saved = _saved_query_shortcut(SAVED_QUERY_QUESTION)
    saved_row = {
        "question": SAVED_QUERY_QUESTION,
        "saved_query_hit": bool(saved),
        "saved_query_mode": (saved or {}).get("mode", ""),
        "saved_query_spl_prefix": str((saved or {}).get("query", ""))[:80],
    }

    return {
        "mode": "live_edge" if live_edge else "mock_edge",
        "edge_llm_enabled_config": get_edge_llm_enabled(),
        "edge_llm_model": get_edge_llm_model(),
        "ollama_reachable": _ollama_reachable(),
        "summary": {
            "cases": len(GOLDEN_CASES),
            "keyword_pass": keyword_pass,
            "edge_pass": edge_pass,
            "keyword_accuracy": round(keyword_pass / len(GOLDEN_CASES), 3),
            "edge_accuracy": round(edge_pass / len(GOLDEN_CASES), 3),
        },
        "rows": rows,
        "saved_query": saved_row,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true", help="Use live Ollama edge LLM (requires EDGE_LLM_ENABLED=1)")
    parser.add_argument("--json", action="store_true", help="Emit JSON only")
    args = parser.parse_args()

    live = bool(args.live)
    if live and not (get_edge_llm_enabled() and _ollama_reachable()):
        print("Live edge compare skipped: set EDGE_LLM_ENABLED=1 and ensure Ollama is reachable.", file=sys.stderr)
        live = False

    result = run_compare(live_edge=live)

    if args.json:
        print(json.dumps(result, indent=2))
        return 0

    print(f"MCP pipeline router comparison ({result['mode']})")
    print(f"Ollama reachable: {result['ollama_reachable']} | edge model: {result['edge_llm_model']}")
    print(
        f"Accuracy — keyword: {result['summary']['keyword_pass']}/{result['summary']['cases']} "
        f"({result['summary']['keyword_accuracy']:.0%}) | "
        f"edge: {result['summary']['edge_pass']}/{result['summary']['cases']} "
        f"({result['summary']['edge_accuracy']:.0%})"
    )
    print()
    print(f"{'Question':<55} {'Exp':<8} {'Keyword':<8} {'Edge':<8} {'ms':<6} OK")
    print("-" * 95)
    for row in result["rows"]:
        ok = "✓" if row["edge_ok"] and row["keyword_ok"] else ("~edge" if row["edge_ok"] else ("~kw" if row["keyword_ok"] else "✗"))
        q = row["question"][:52] + ("..." if len(row["question"]) > 55 else "")
        print(
            f"{q:<55} {row['expected']:<8} {row['keyword']:<8} {row['edge']:<8} {row['edge_ms']:<6} {ok}"
        )
    sq = result["saved_query"]
    print()
    print("Saved query shortcut (fixture matching user's one saved query):")
    print(f"  question: {sq['question']}")
    print(f"  hit: {sq['saved_query_hit']} mode={sq['saved_query_mode']}")
    if sq.get("saved_query_spl_prefix"):
        print(f"  spl: {sq['saved_query_spl_prefix']}...")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
