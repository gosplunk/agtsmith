#!/usr/bin/env python3
"""Build a 100-case pilot benchmark pack with an 80/20 BOTSv3 split."""

from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path

from botsv3_catalog import BOTSV3_SOURCETYPES


ROOT = Path(__file__).resolve().parents[1]
BASE_CASES = ROOT / "benchmarks" / "spl_cases.json"
BOTSV3_CASES = ROOT / "benchmarks" / "spl_cases_botsv3.json"
OUT_PATH = ROOT / "benchmarks" / "pilot_ready_100_cases.json"


def _load(path: Path) -> list[dict]:
    return json.loads(path.read_text(encoding="utf-8"))


def _slugify(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")


def _botsv3_inventory_case(sourcetype: str) -> dict:
    slug = _slugify(sourcetype)
    return {
        "id": f"pilot_botsv3_inventory_{slug}",
        "family": "botsv3_named_sourcetype_overview",
        "question": f"Across the full BOTSv3 dataset, show an overview of sourcetype {sourcetype} by host and source.",
        "expected_intent": "botsv3_named_sourcetype_overview",
        "expected_shape": "stats",
        "preferred_indexes": ["index=botsv3"],
        "preferred_sourcetypes": [f"sourcetype={sourcetype}"],
        "required_query_terms": ["index=botsv3", f"sourcetype={sourcetype}", "stats", "host", "source"],
        "forbidden_query_terms": [],
        "required_result_fields": ["host", "source", "sourcetype", "count"],
        "allow_zero_rows": False,
        "min_rows": 1,
        "expected_earliest_time": "0",
        "expected_latest_time": "now",
    }


def _pick_non_botsv3_cases(cases: list[dict], limit: int = 20) -> list[dict]:
    by_family: dict[str, list[dict]] = defaultdict(list)
    for row in cases:
        by_family[str(row["family"])].append(row)

    ordered_families = [
        "linux_auth_failures",
        "windows_auth_failures",
        "cross_platform_auth_failures",
        "apache_access_top_ips",
        "apache_suspicious_user_agents",
        "apache_404_spike",
        "linux_privilege_escalation",
        "linux_privilege_escalation_activity",
        "linux_privilege_escalation_first_seen",
        "windows_credential_access_activity",
        "windows_sysmon_network_activity",
        "windows_sysmon_dns_activity",
        "linux_session_activity",
        "inventory",
        "internal_auth_failures",
        "internal_sourcetypes",
    ]

    selected: list[dict] = []
    seen_ids: set[str] = set()

    # First pass: spread coverage across families.
    for family in ordered_families:
        for row in by_family.get(family, [])[:2]:
            case_id = str(row["id"])
            if case_id in seen_ids:
                continue
            selected.append(row)
            seen_ids.add(case_id)
            if len(selected) >= limit:
                return selected

    # Second pass: fill any remaining slots with unused cases in source order.
    for row in cases:
        case_id = str(row["id"])
        if case_id in seen_ids:
            continue
        selected.append(row)
        seen_ids.add(case_id)
        if len(selected) >= limit:
            return selected

    return selected


def build_pack() -> list[dict]:
    base_cases = _load(BASE_CASES)
    botsv3_cases = _load(BOTSV3_CASES)

    selected_non_botsv3 = _pick_non_botsv3_cases(base_cases, limit=20)

    selected_botsv3 = list(botsv3_cases)
    inventory_needed = 80 - len(selected_botsv3)
    inventory_cases = [_botsv3_inventory_case(sourcetype) for sourcetype in BOTSV3_SOURCETYPES[:inventory_needed]]
    selected_botsv3.extend(inventory_cases)

    pack = selected_botsv3[:80] + selected_non_botsv3[:20]
    return pack


def main() -> int:
    pack = build_pack()
    OUT_PATH.write_text(json.dumps(pack, indent=2), encoding="utf-8")
    print(f"wrote {len(pack)} cases to {OUT_PATH}")
    botsv3 = sum(1 for row in pack if "botsv3" in str(row["id"]).lower() or str(row["family"]).startswith("botsv3_"))
    print(f"botsv3_cases={botsv3}")
    print(f"non_botsv3_cases={len(pack) - botsv3}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
