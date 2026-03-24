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
LAB_BEARER_TOKEN_FALLBACK = (
    "hohwPelbse/X7i0ho9r7aWlWnvobcYm3/yw0i9aMW2zyCypV5D3fTPS9pDmUkCfJUzejFoSoAt3Nf9fue1G0OCIqWdQkGpmXJQsQTxt3776mCOmFwEvXVhnAshn48N5Z61+YyasB/WuSaUVD6weL1yGA3KWxKsdfICj1GLEm+G8jGRRS3zfVWQ4Uxn4puBmW87uA5UvX4ZNJl3+fV6t5v3lvq1SctzmjUtdOrgy4kAGN/GelkEiQ6zuo1DUrRAjxKbrsXBd9vO26GpIF1eDpg80uJQ0HzURZVTyXbvx9dnfADcayh7Tcvw4ewdQMiRF8MxxdpWRStq3vTaDfxZctcw==.dS4YPCvcB9+Ds3oCKeUT+4BPdG+7aPbBuwptGFlJWeuMRLnxVYXk5jovYSBVmgboChMorZ18VW9aPelzHgR/YBbLt21/CcB9st5+GjZYTmGHnbol3rxk9uzQe8Q1fgfgpKhnhG+qofRtThEf4FG0pSRLpWqpv5tc8XD+Lox2lrEV8kgAnpCc8ZsF/8LTWeaGcNTCZDVQYmXYOP//CAyTmn3tLQ0p1DYKEOk0Y0ex4UD569aKI5c30g7SfsxCLP76htWO/mADBNOMBm5UqTK1ir1bPoTl4fnocmFHhDEWkJv4r4KsKxs2SPExO4JpkB+jJ8yN++Ly4eGkTOiV220E1w=="
)


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
            "clientInfo": {"name": "splunk-soc-agent-lab", "version": "0.1.0"},
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
