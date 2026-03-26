#!/usr/bin/env python3
"""Run a first safe bounded Splunk MCP query via tools/call.

Safety bounds for lab:
- Read-only search
- Time window constrained (-24h to now)
- row_limit constrained (<= 20)
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any

import httpx
from runtime_config import get_splunk_mcp_url

SPLUNK_MCP_URL = get_splunk_mcp_url()
LAB_BEARER_TOKEN_FALLBACK = "REPLACE_WITH_SPLUNK_MCP_BEARER_TOKEN"


def rpc(client: httpx.Client, headers: dict[str, str], payload: dict[str, Any]) -> tuple[int, Any]:
    r = client.post(SPLUNK_MCP_URL, headers=headers, json=payload)
    try:
        return r.status_code, r.json()
    except Exception:
        return r.status_code, (r.text or "").strip()


def main() -> int:
    token = os.getenv("SPLUNK_LAB_BEARER_TOKEN", LAB_BEARER_TOKEN_FALLBACK)
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json, text/plain, */*",
    }

    init_payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "agtsmith-lab", "version": "0.1.0"},
        },
    }

    query_payload = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "splunk_run_query",
            "arguments": {
                "query": "search index=* | stats count by index | sort - count",
                "earliest_time": "-24h",
                "latest_time": "now",
                "row_limit": 20,
            },
        },
    }

    with httpx.Client(timeout=90.0, verify=False, follow_redirects=True) as client:
        init_status, init_body = rpc(client, headers, init_payload)
        q_status, q_body = rpc(client, headers, query_payload)

    print("=== initialize ===")
    print(json.dumps({"status": init_status, "body": init_body}, indent=2))
    print("\n=== tools/call: splunk_run_query ===")
    print(json.dumps({"status": q_status, "body": q_body}, indent=2))

    if init_status != 200:
        print("\nFAIL: initialize did not return HTTP 200")
        return 1
    if q_status != 200:
        print("\nFAIL: query call did not return HTTP 200")
        return 1
    if not isinstance(q_body, dict):
        print("\nFAIL: query response not JSON object")
        return 1
    if "error" in q_body:
        print(f"\nFAIL: JSON-RPC error: {q_body['error']}")
        return 1

    result = q_body.get("result", {}) if isinstance(q_body, dict) else {}
    structured = result.get("structuredContent", {}) if isinstance(result, dict) else {}
    rows = structured.get("results", []) if isinstance(structured, dict) else []
    total_rows = structured.get("total_rows") if isinstance(structured, dict) else None

    print("\n=== Summary ===")
    print(f"rows_returned={len(rows) if isinstance(rows, list) else 'n/a'}")
    print(f"total_rows={total_rows}")
    print("PASS: Safe bounded query executed successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
