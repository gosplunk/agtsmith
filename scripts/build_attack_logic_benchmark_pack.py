#!/usr/bin/env python3
"""Build a BOTSv3-heavy ATT&CK logic benchmark pack."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BOTSV3_CASES = ROOT / "benchmarks" / "spl_cases_botsv3.json"
BASE_CASES = ROOT / "benchmarks" / "spl_cases.json"
OUT_PATH = ROOT / "benchmarks" / "attack_logic_botsv3_pack.json"

MITRE_BY_FAMILY = {
    "apache_access_top_ips": (["T1595"], 2),
    "apache_suspicious_user_agents": (["T1595"], 2),
    "linux_privilege_escalation_activity": (["T1548"], 2),
    "linux_privilege_escalation": (["T1548"], 2),
    "linux_auth_failures": (["T1110"], 3),
    "windows_auth_failures": (["T1110"], 3),
    "cross_platform_auth_failures": (["T1110"], 3),
    "aws_cloudtrail_activity": (["T1526"], 2),
    "cisco_asa_network_flows": (["T1046"], 2),
    "stream_http_activity": (["T1071.001"], 2),
    "aad_signin_activity": (["T1078"], 2),
    "aws_vpc_flow_activity": (["T1046"], 2),
    "osquery_process_activity": (["T1059"], 2),
}


def _load(path: Path) -> list[dict]:
    return json.loads(path.read_text(encoding="utf-8"))


def _decorate(case: dict) -> dict:
    row = dict(case)
    techniques, pivots = MITRE_BY_FAMILY.get(str(row.get("family", "")).strip(), ([], 0))
    row["expected_mitre_techniques"] = techniques
    row["min_mitre_pivots"] = pivots
    return row


def build_pack() -> list[dict]:
    botsv3_cases = [_decorate(row) for row in _load(BOTSV3_CASES)]
    base_cases = [_decorate(row) for row in _load(BASE_CASES)]

    selected_live = [
        row
        for row in base_cases
        if str(row.get("family", "")).strip()
        in {"linux_auth_failures", "windows_auth_failures", "cross_platform_auth_failures", "apache_access_top_ips", "linux_privilege_escalation"}
    ][:8]

    pack = botsv3_cases + selected_live
    return pack


def main() -> int:
    pack = build_pack()
    OUT_PATH.write_text(json.dumps(pack, indent=2), encoding="utf-8")
    print(f"wrote {len(pack)} cases to {OUT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
