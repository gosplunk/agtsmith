#!/usr/bin/env python3
"""Ten data-domain registry for long-horizon SPL learning loops."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

TARGET_PASS_RATE_PCT = 90.0


@dataclass(frozen=True)
class TenDomain:
    id: str
    title: str
    kind: str  # oracle | live_cluster
    make_template: str | None = None
    make_multimodel: str | None = None
    make_offline: str | None = None
    report_glob: str | None = None
    live_themes: tuple[str, ...] = ()
    lab_data_domains: tuple[str, ...] = ()


TEN_DOMAINS: tuple[TenDomain, ...] = (
    TenDomain(
        id="internal",
        title="Splunk Internal Indexes",
        kind="oracle",
        make_template="internal-spl-accuracy",
        make_multimodel="internal-spl-accuracy-multimodel",
        make_offline="internal-spl-accuracy-offline",
        report_glob="artifacts/spl_autonomy/internal_benchmark/latest.json",
    ),
    TenDomain(
        id="linux",
        title="Linux Data Domain",
        kind="oracle",
        make_template="linux-spl-accuracy",
        make_multimodel="linux-spl-accuracy-multimodel",
        make_offline="linux-spl-accuracy-offline",
        report_glob="artifacts/spl_autonomy/linux_benchmark/latest.json",
        lab_data_domains=("linux_auth", "linux_syslog"),
    ),
    TenDomain(
        id="operational",
        title="Operational SPL",
        kind="oracle",
        make_template="operational-spl-accuracy",
        make_multimodel="operational-spl-accuracy-multimodel",
        make_offline="operational-spl-accuracy-offline",
        report_glob="artifacts/benchmark/operational_spl_accuracy/latest.json",
    ),
    TenDomain(
        id="linux_auth",
        title="Linux Auth",
        kind="live_cluster",
        live_themes=("auth", "auth_cross", "linux_priv"),
        lab_data_domains=("linux_auth",),
    ),
    TenDomain(
        id="web_access",
        title="Web Access",
        kind="live_cluster",
        live_themes=("web", "web_404"),
        lab_data_domains=("web_access",),
    ),
    TenDomain(
        id="windows_auth",
        title="Windows Auth",
        kind="live_cluster",
        live_themes=("windows_auth",),
        lab_data_domains=("windows_auth",),
    ),
    TenDomain(
        id="windows_sysmon",
        title="Windows Sysmon",
        kind="live_cluster",
        live_themes=("windows_sysmon", "windows_process", "windows_credential", "windows_privilege"),
        lab_data_domains=("windows_sysmon", "windows_process"),
    ),
    TenDomain(
        id="stream_dns",
        title="Stream DNS",
        kind="live_cluster",
        live_themes=("dns",),
        lab_data_domains=("stream_dns",),
    ),
    TenDomain(
        id="aws_cloudtrail",
        title="AWS CloudTrail",
        kind="live_cluster",
        live_themes=("cloud_aws",),
        lab_data_domains=("aws_cloudtrail",),
    ),
    TenDomain(
        id="o365_management",
        title="O365 Management",
        kind="live_cluster",
        live_themes=("cloud_o365",),
        lab_data_domains=("o365_management",),
    ),
)


THEME_TO_DOMAIN: dict[str, str] = {}
for _domain in TEN_DOMAINS:
    for _theme in _domain.live_themes:
        THEME_TO_DOMAIN[_theme] = _domain.id


def domains_by_id() -> dict[str, TenDomain]:
    return {row.id: row for row in TEN_DOMAINS}


def oracle_domains() -> list[TenDomain]:
    return [row for row in TEN_DOMAINS if row.kind == "oracle"]


def live_cluster_domains() -> list[TenDomain]:
    return [row for row in TEN_DOMAINS if row.kind == "live_cluster"]


def lab_domains_for_ids(domain_ids: list[str]) -> list[str]:
    out: list[str] = []
    by_id = domains_by_id()
    for domain_id in domain_ids:
        row = by_id.get(domain_id)
        if not row:
            continue
        for lab_domain in row.lab_data_domains:
            if lab_domain not in out:
                out.append(lab_domain)
    return out


def score_snapshot_row(domain_id: str, *, pass_rate_pct: float | None, passed: int | None, total: int | None, path: str = "") -> dict[str, Any]:
    ok = pass_rate_pct is not None and pass_rate_pct >= TARGET_PASS_RATE_PCT
    return {
        "domain_id": domain_id,
        "pass_rate_pct": pass_rate_pct,
        "passed": passed,
        "total": total,
        "meets_target": ok,
        "report_path": path,
    }
