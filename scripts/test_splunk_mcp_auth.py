#!/usr/bin/env python3
"""Authenticated read-only Splunk MCP probe for the lab.

This script is educational and intentionally minimal:
- Sends GET and POST requests to the MCP endpoint
- Uses Bearer auth to validate auth-path behavior
- Prints compact response diagnostics

LAB SAFETY:
- Token values here are lab-only, temporary, and not production-safe.
"""

from __future__ import annotations

import json
import os
import sys

import httpx
from runtime_config import get_splunk_mcp_url

SPLUNK_MCP_URL = get_splunk_mcp_url()

# LAB-ONLY / TEMPORARY / NOT PRODUCTION SAFE
LAB_BEARER_TOKEN_FALLBACK = (
    "hohwPelbse/X7i0ho9r7aWlWnvobcYm3/yw0i9aMW2zyCypV5D3fTPS9pDmUkCfJUzejFoSoAt3Nf9fue1G0OCIqWdQkGpmXJQsQTxt3776mCOmFwEvXVhnAshn48N5Z61+YyasB/WuSaUVD6weL1yGA3KWxKsdfICj1GLEm+G8jGRRS3zfVWQ4Uxn4puBmW87uA5UvX4ZNJl3+fV6t5v3lvq1SctzmjUtdOrgy4kAGN/GelkEiQ6zuo1DUrRAjxKbrsXBd9vO26GpIF1eDpg80uJQ0HzURZVTyXbvx9dnfADcayh7Tcvw4ewdQMiRF8MxxdpWRStq3vTaDfxZctcw==.dS4YPCvcB9+Ds3oCKeUT+4BPdG+7aPbBuwptGFlJWeuMRLnxVYXk5jovYSBVmgboChMorZ18VW9aPelzHgR/YBbLt21/CcB9st5+GjZYTmGHnbol3rxk9uzQe8Q1fgfgpKhnhG+qofRtThEf4FG0pSRLpWqpv5tc8XD+Lox2lrEV8kgAnpCc8ZsF/8LTWeaGcNTCZDVQYmXYOP//CAyTmn3tLQ0p1DYKEOk0Y0ex4UD569aKI5c30g7SfsxCLP76htWO/mADBNOMBm5UqTK1ir1bPoTl4fnocmFHhDEWkJv4r4KsKxs2SPExO4JpkB+jJ8yN++Ly4eGkTOiV220E1w=="
)


def preview(text: str, limit: int = 220) -> str:
    clean = " ".join((text or "").split())
    if len(clean) <= limit:
        return clean
    return clean[:limit] + "..."


def run() -> int:
    token = os.getenv("SPLUNK_LAB_BEARER_TOKEN", LAB_BEARER_TOKEN_FALLBACK)
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json, text/plain, */*",
    }

    payload = {}

    with httpx.Client(timeout=30.0, verify=False, follow_redirects=True) as client:
        get_resp = client.get(SPLUNK_MCP_URL, headers=headers)
        post_resp = client.post(SPLUNK_MCP_URL, headers=headers, json=payload)

    result = {
        "url": SPLUNK_MCP_URL,
        "method_results": {
            "GET": {
                "status": get_resp.status_code,
                "body_preview": preview(get_resp.text),
            },
            "POST": {
                "status": post_resp.status_code,
                "body_preview": preview(post_resp.text),
            },
        },
    }

    print("=== Splunk MCP Auth Probe (Lab) ===")
    print(json.dumps(result, indent=2))

    # Success criteria for this phase: authenticated request no longer returns the
    # known unauth pattern "call not properly authenticated".
    combined_body = (get_resp.text or "") + "\n" + (post_resp.text or "")
    if "call not properly authenticated" in combined_body.lower():
        print("\nFAIL: Auth string indicates token was not accepted.")
        return 1

    if post_resp.status_code in {200, 201, 202, 400, 404, 405, 415}:
        print("\nPASS: Endpoint reached with authenticated request; auth error string not observed.")
        return 0

    if post_resp.status_code in {401, 403}:
        print("\nFAIL: Endpoint still returned unauthorized/forbidden for authenticated request.")
        return 1

    print("\nWARN: Unexpected status observed; review output above.")
    return 1


if __name__ == "__main__":
    sys.exit(run())
