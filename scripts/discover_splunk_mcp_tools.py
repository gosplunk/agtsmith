#!/usr/bin/env python3
"""Discover Splunk MCP tools via JSON-RPC initialize + tools/list.

Educational lab script:
- Sends valid MCP-style JSON-RPC requests over HTTP
- Uses bearer auth header for Splunk MCP endpoint
- Prints request/response diagnostics

LAB SAFETY:
- Token handling in this lab is temporary and not production-safe.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from typing import Any

import httpx
from runtime_config import get_splunk_mcp_url

SPLUNK_MCP_URL = get_splunk_mcp_url()

# LAB-ONLY / TEMPORARY / NOT PRODUCTION SAFE
LAB_BEARER_TOKEN_FALLBACK = (
    "hohwPelbse/X7i0ho9r7aWlWnvobcYm3/yw0i9aMW2zyCypV5D3fTPS9pDmUkCfJUzejFoSoAt3Nf9fue1G0OCIqWdQkGpmXJQsQTxt3776mCOmFwEvXVhnAshn48N5Z61+YyasB/WuSaUVD6weL1yGA3KWxKsdfICj1GLEm+G8jGRRS3zfVWQ4Uxn4puBmW87uA5UvX4ZNJl3+fV6t5v3lvq1SctzmjUtdOrgy4kAGN/GelkEiQ6zuo1DUrRAjxKbrsXBd9vO26GpIF1eDpg80uJQ0HzURZVTyXbvx9dnfADcayh7Tcvw4ewdQMiRF8MxxdpWRStq3vTaDfxZctcw==.dS4YPCvcB9+Ds3oCKeUT+4BPdG+7aPbBuwptGFlJWeuMRLnxVYXk5jovYSBVmgboChMorZ18VW9aPelzHgR/YBbLt21/CcB9st5+GjZYTmGHnbol3rxk9uzQe8Q1fgfgpKhnhG+qofRtThEf4FG0pSRLpWqpv5tc8XD+Lox2lrEV8kgAnpCc8ZsF/8LTWeaGcNTCZDVQYmXYOP//CAyTmn3tLQ0p1DYKEOk0Y0ex4UD569aKI5c30g7SfsxCLP76htWO/mADBNOMBm5UqTK1ir1bPoTl4fnocmFHhDEWkJv4r4KsKxs2SPExO4JpkB+jJ8yN++Ly4eGkTOiV220E1w=="
)


@dataclass
class RpcResponse:
    status_code: int
    body: dict[str, Any] | list[Any] | str


def post_rpc(client: httpx.Client, headers: dict[str, str], payload: dict[str, Any]) -> RpcResponse:
    resp = client.post(SPLUNK_MCP_URL, headers=headers, json=payload)
    text = (resp.text or "").strip()
    try:
        body: dict[str, Any] | list[Any] | str = resp.json()
    except Exception:
        body = text
    return RpcResponse(status_code=resp.status_code, body=body)


def main() -> int:
    token = os.getenv("SPLUNK_LAB_BEARER_TOKEN", LAB_BEARER_TOKEN_FALLBACK)
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json, text/plain, */*",
    }

    initialize_payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "agtsmith-lab",
                "version": "0.1.0",
            },
        },
    }

    tools_list_payload = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {},
    }

    with httpx.Client(timeout=45.0, verify=False, follow_redirects=True) as client:
        init_resp = post_rpc(client, headers, initialize_payload)
        tools_resp = post_rpc(client, headers, tools_list_payload)

    print("=== MCP initialize response ===")
    print(json.dumps({"status": init_resp.status_code, "body": init_resp.body}, indent=2))

    print("\n=== MCP tools/list response ===")
    print(json.dumps({"status": tools_resp.status_code, "body": tools_resp.body}, indent=2))

    if init_resp.status_code != 200:
        print("\nFAIL: initialize did not return HTTP 200.")
        return 1

    if tools_resp.status_code != 200:
        print("\nFAIL: tools/list did not return HTTP 200.")
        return 1

    body = tools_resp.body
    if not isinstance(body, dict) or "result" not in body:
        print("\nFAIL: tools/list response missing JSON-RPC result.")
        return 1

    tools = body.get("result", {}).get("tools", []) if isinstance(body.get("result"), dict) else []
    if not isinstance(tools, list) or len(tools) == 0:
        print("\nWARN: tools/list returned empty or unexpected tool list.")
        return 1

    names = [t.get("name", "") for t in tools if isinstance(t, dict)]
    print("\n=== Discovered Tool Names ===")
    for idx, name in enumerate(names, start=1):
        print(f"{idx}. {name}")

    print("\nPASS: initialize + tools/list discovery succeeded.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
