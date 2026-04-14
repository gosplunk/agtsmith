#!/usr/bin/env python3
"""Portable intent playbooks for deeper investigations."""

from __future__ import annotations

from typing import Any


def _normalize_intent(intent: str) -> str:
    return str(intent or "").strip().lower()


PLAYBOOK_LIBRARY: dict[str, dict[str, Any]] = {
    "credential_abuse_auth": {
        "name": "Credential Abuse",
        "description": "Move from broad authentication failures toward the source, account, host, and any success-after-failure evidence.",
        "targets": (
            {
                "target_type": "source_ip",
                "target_label": "Source IP",
                "pivot_kind": "same_source_ip_followup",
                "title": "Pivot on the source IPs responsible for these authentication failures.",
                "recommendation": "Pivot on the source IPs responsible for these authentication failures.",
            },
            {
                "target_type": "username",
                "target_label": "Username",
                "pivot_kind": "username_followup",
                "title": "Pivot on the usernames targeted by these authentication failures.",
                "recommendation": "Pivot on the usernames targeted by these authentication failures.",
            },
            {
                "target_type": "host",
                "target_label": "Host",
                "pivot_kind": "host_followup",
                "title": "Pivot on the hosts receiving these authentication failures.",
                "recommendation": "Pivot on the hosts receiving these authentication failures.",
            },
            {
                "target_type": "source_ip",
                "target_label": "Source IP",
                "pivot_kind": "success_after_failure",
                "title": "Check for successful logons from the same source IPs after the failures.",
                "recommendation": "Check for successful logons from the same source IPs after the failures.",
            },
        ),
    },
    "linux_privilege_escalation": {
        "name": "Linux Privilege Escalation",
        "description": "Follow sudo and su activity through actor, host, command, and prior auth context.",
        "targets": (
            {
                "target_type": "username",
                "target_label": "Username",
                "pivot_kind": "privilege_escalation_check",
                "title": "Pivot on the users associated with this privilege-escalation activity.",
                "recommendation": "Pivot on the users associated with this privilege-escalation activity.",
            },
            {
                "target_type": "host",
                "target_label": "Host",
                "pivot_kind": "host_followup",
                "title": "Pivot on the hosts where this privilege-escalation activity occurred.",
                "recommendation": "Pivot on the hosts where this privilege-escalation activity occurred.",
            },
            {
                "target_type": "command",
                "target_label": "Command",
                "pivot_kind": "command_followup",
                "title": "Pivot on the commands involved in this privilege-escalation activity.",
                "recommendation": "Pivot on the commands involved in this privilege-escalation activity.",
            },
            {
                "target_type": "source_ip",
                "target_label": "Source IP",
                "pivot_kind": "same_source_ip_followup",
                "title": "Pivot on the source IPs or rhost values tied to this privilege-escalation activity.",
                "recommendation": "Pivot on the source IPs or rhost values tied to this privilege-escalation activity.",
            },
        ),
    },
    "endpoint_dns_activity": {
        "name": "Endpoint DNS",
        "description": "Start with the query itself, then the process, host, and returned destination values.",
        "targets": (
            {
                "target_type": "dns_query",
                "target_label": "DNS Query",
                "pivot_kind": "dns_query_drilldown",
                "title": "Pivot on the top DNS query names from this evidence.",
                "recommendation": "Pivot on the top DNS query names from this evidence.",
            },
            {
                "target_type": "process_image",
                "target_label": "Process Image",
                "pivot_kind": "process_image_drilldown",
                "title": "Pivot on the process images that generated these DNS queries.",
                "recommendation": "Pivot on the process images that generated these DNS queries.",
            },
            {
                "target_type": "host",
                "target_label": "Host",
                "pivot_kind": "host_followup",
                "title": "Pivot on the hosts that generated these DNS queries.",
                "recommendation": "Pivot on the hosts that generated these DNS queries.",
            },
            {
                "target_type": "destination_ip",
                "target_label": "Resolved Value",
                "pivot_kind": "destination_ip_drilldown",
                "title": "Pivot on the resolved IPs or DNS answers returned with these queries.",
                "recommendation": "Pivot on the resolved IPs or DNS answers returned with these queries.",
            },
        ),
    },
    "endpoint_network_activity": {
        "name": "Endpoint Network",
        "description": "Trace network activity through destination, process, host, and transport details.",
        "targets": (
            {
                "target_type": "destination_ip",
                "target_label": "Destination IP",
                "pivot_kind": "destination_ip_drilldown",
                "title": "Pivot on the top destination IPs from this network evidence.",
                "recommendation": "Pivot on the top destination IPs from this network evidence.",
            },
            {
                "target_type": "process_image",
                "target_label": "Process Image",
                "pivot_kind": "process_image_drilldown",
                "title": "Pivot on the process images that opened these network connections.",
                "recommendation": "Pivot on the process images that opened these network connections.",
            },
            {
                "target_type": "host",
                "target_label": "Host",
                "pivot_kind": "host_followup",
                "title": "Pivot on the hosts that opened these network connections.",
                "recommendation": "Pivot on the hosts that opened these network connections.",
            },
            {
                "target_type": "transport",
                "target_label": "Transport",
                "pivot_kind": "transport_followup",
                "title": "Pivot on the transport and port combinations present in these connections.",
                "recommendation": "Pivot on the transport and port combinations present in these connections.",
            },
        ),
    },
    "web_traffic_hunt": {
        "name": "Web Traffic Hunt",
        "description": "Move from destination site to source, then user agent, status, and method or URI shape.",
        "targets": (
            {
                "target_type": "site",
                "target_label": "Site",
                "pivot_kind": "site_followup",
                "title": "Pivot on the destination sites from this HTTP activity.",
                "recommendation": "Pivot on the destination sites from this HTTP activity.",
            },
            {
                "target_type": "source_ip",
                "target_label": "Source IP",
                "pivot_kind": "same_source_ip_followup",
                "title": "Pivot on the source IPs that generated this HTTP activity.",
                "recommendation": "Pivot on the source IPs that generated this HTTP activity.",
            },
            {
                "target_type": "user_agent",
                "target_label": "User Agent",
                "pivot_kind": "user_agent_followup",
                "title": "Pivot on the user-agent values present in this HTTP activity.",
                "recommendation": "Pivot on the user-agent values present in this HTTP activity.",
            },
            {
                "target_type": "status",
                "target_label": "Status",
                "pivot_kind": "status_followup",
                "title": "Pivot on the HTTP status values observed in this activity.",
                "recommendation": "Pivot on the HTTP status values observed in this activity.",
            },
            {
                "target_type": "operation",
                "target_label": "HTTP Method",
                "pivot_kind": "operation_followup",
                "title": "Pivot on the HTTP methods observed in this activity.",
                "recommendation": "Pivot on the HTTP methods observed in this activity.",
            },
        ),
    },
    "web_recon_http": {
        "name": "Web Reconnaissance",
        "description": "Follow suspicious web traffic through client, site or path, user-agent, and response status.",
        "targets": (
            {
                "target_type": "source_ip",
                "target_label": "Client IP",
                "pivot_kind": "same_source_ip_followup",
                "title": "Pivot on the top client IPs from this HTTP evidence.",
                "recommendation": "Pivot on the top client IPs from this HTTP evidence.",
            },
            {
                "target_type": "site",
                "target_label": "Site or URI Path",
                "pivot_kind": "site_followup",
                "title": "Pivot on the destination sites or URI paths from this HTTP evidence.",
                "recommendation": "Pivot on the destination sites or URI paths from this HTTP evidence.",
            },
            {
                "target_type": "user_agent",
                "target_label": "User Agent",
                "pivot_kind": "user_agent_followup",
                "title": "Pivot on the user agents from this HTTP evidence.",
                "recommendation": "Pivot on the user agents from this HTTP evidence.",
            },
            {
                "target_type": "status",
                "target_label": "HTTP Status",
                "pivot_kind": "status_followup",
                "title": "Pivot on the HTTP status patterns associated with this HTTP evidence.",
                "recommendation": "Pivot on the HTTP status patterns associated with this HTTP evidence.",
            },
        ),
    },
    "cloud_api_identity": {
        "name": "Cloud API Identity",
        "description": "Pivot from cloud principals to source IP, targeted service, and operation.",
        "targets": (
            {
                "target_type": "principal",
                "target_label": "Principal",
                "pivot_kind": "principal_followup",
                "title": "Pivot on the principals responsible for these API events.",
                "recommendation": "Pivot on the principals responsible for these API events.",
            },
            {
                "target_type": "source_ip",
                "target_label": "Source IP",
                "pivot_kind": "same_source_ip_followup",
                "title": "Pivot on the source IPs responsible for these API events.",
                "recommendation": "Pivot on the source IPs responsible for these API events.",
            },
            {
                "target_type": "service",
                "target_label": "Service",
                "pivot_kind": "service_followup",
                "title": "Pivot on the AWS services targeted by these API events.",
                "recommendation": "Pivot on the AWS services targeted by these API events.",
            },
            {
                "target_type": "event_name",
                "target_label": "Operation",
                "pivot_kind": "event_name_followup",
                "title": "Pivot on the API operations observed in this activity.",
                "recommendation": "Pivot on the API operations observed in this activity.",
            },
        ),
    },
    "network_flow_hunt": {
        "name": "Network Flow Hunt",
        "description": "Pivot through source, destination, action, and transport in network flow evidence.",
        "targets": (
            {
                "target_type": "source_ip",
                "target_label": "Source IP",
                "pivot_kind": "same_source_ip_followup",
                "title": "Pivot on the top source IPs from these network flows.",
                "recommendation": "Pivot on the top source IPs from these network flows.",
            },
            {
                "target_type": "destination_ip",
                "target_label": "Destination IP",
                "pivot_kind": "destination_ip_drilldown",
                "title": "Pivot on the top destination IPs from these network flows.",
                "recommendation": "Pivot on the top destination IPs from these network flows.",
            },
            {
                "target_type": "action",
                "target_label": "Action",
                "pivot_kind": "action_followup",
                "title": "Pivot on the network actions observed in these flows.",
                "recommendation": "Pivot on the network actions observed in these flows.",
            },
            {
                "target_type": "transport",
                "target_label": "Transport",
                "pivot_kind": "transport_followup",
                "title": "Pivot on the transport or protocol values observed in these flows.",
                "recommendation": "Pivot on the transport or protocol values observed in these flows.",
            },
        ),
    },
    "cloud_identity_signin": {
        "name": "Cloud Identity Sign-In",
        "description": "Pivot through user, source IP, application, and sign-in result.",
        "targets": (
            {
                "target_type": "principal",
                "target_label": "Principal",
                "pivot_kind": "principal_followup",
                "title": "Pivot on the principals from these sign-ins.",
                "recommendation": "Pivot on the principals from these sign-ins.",
            },
            {
                "target_type": "source_ip",
                "target_label": "Source IP",
                "pivot_kind": "same_source_ip_followup",
                "title": "Pivot on the source IPs from these sign-ins.",
                "recommendation": "Pivot on the source IPs from these sign-ins.",
            },
            {
                "target_type": "application",
                "target_label": "Application",
                "pivot_kind": "application_followup",
                "title": "Pivot on the Azure AD applications targeted by these sign-ins.",
                "recommendation": "Pivot on the Azure AD applications targeted by these sign-ins.",
            },
            {
                "target_type": "status",
                "target_label": "Status",
                "pivot_kind": "status_followup",
                "title": "Pivot on the sign-in status values observed in this activity.",
                "recommendation": "Pivot on the sign-in status values observed in this activity.",
            },
        ),
    },
    "dns_stream_hunt": {
        "name": "Network DNS Hunt",
        "description": "Pivot through query name, source, reply code, and returned value.",
        "targets": (
            {
                "target_type": "dns_query",
                "target_label": "DNS Query",
                "pivot_kind": "dns_query_drilldown",
                "title": "Pivot on the DNS query names from this stream evidence.",
                "recommendation": "Pivot on the DNS query names from this stream evidence.",
            },
            {
                "target_type": "source_ip",
                "target_label": "Source IP",
                "pivot_kind": "same_source_ip_followup",
                "title": "Pivot on the source IPs that generated these DNS queries.",
                "recommendation": "Pivot on the source IPs that generated these DNS queries.",
            },
            {
                "target_type": "reply_code",
                "target_label": "Reply Code",
                "pivot_kind": "reply_code_followup",
                "title": "Pivot on the DNS reply codes observed in this evidence.",
                "recommendation": "Pivot on the DNS reply codes observed in this evidence.",
            },
            {
                "target_type": "destination_ip",
                "target_label": "Resolved Value",
                "pivot_kind": "destination_ip_drilldown",
                "title": "Pivot on the returned IPs or answers for these DNS lookups.",
                "recommendation": "Pivot on the returned IPs or answers for these DNS lookups.",
            },
        ),
    },
    "saas_management": {
        "name": "SaaS Management",
        "description": "Pivot across user, operation, workload, and source.",
        "targets": (
            {
                "target_type": "principal",
                "target_label": "User",
                "pivot_kind": "principal_followup",
                "title": "Pivot on the Office 365 users from this management activity.",
                "recommendation": "Pivot on the Office 365 users from this management activity.",
            },
            {
                "target_type": "operation",
                "target_label": "Operation",
                "pivot_kind": "operation_followup",
                "title": "Pivot on the Office 365 operations from this management activity.",
                "recommendation": "Pivot on the Office 365 operations from this management activity.",
            },
            {
                "target_type": "workload",
                "target_label": "Workload",
                "pivot_kind": "workload_followup",
                "title": "Pivot on the Office 365 workloads from this management activity.",
                "recommendation": "Pivot on the Office 365 workloads from this management activity.",
            },
            {
                "target_type": "source_ip",
                "target_label": "Source IP",
                "pivot_kind": "same_source_ip_followup",
                "title": "Pivot on the source IPs associated with this management activity.",
                "recommendation": "Pivot on the source IPs associated with this management activity.",
            },
        ),
    },
    "endpoint_process_execution": {
        "name": "Endpoint Process Execution",
        "description": "Pivot across executable path, host, command line, and action.",
        "targets": (
            {
                "target_type": "path",
                "target_label": "Executable Path",
                "pivot_kind": "path_followup",
                "title": "Pivot on the executable paths from this process activity.",
                "recommendation": "Pivot on the executable paths from this process activity.",
            },
            {
                "target_type": "host",
                "target_label": "Host",
                "pivot_kind": "host_followup",
                "title": "Pivot on the hosts from this process activity.",
                "recommendation": "Pivot on the hosts from this process activity.",
            },
            {
                "target_type": "command",
                "target_label": "Command Line",
                "pivot_kind": "command_followup",
                "title": "Pivot on the command-line values from this process activity.",
                "recommendation": "Pivot on the command-line values from this process activity.",
            },
            {
                "target_type": "action",
                "target_label": "Action",
                "pivot_kind": "action_followup",
                "title": "Pivot on the process actions from this activity.",
                "recommendation": "Pivot on the process actions from this activity.",
            },
        ),
    },
    "generic_hunt": {
        "name": "Generic Hunt",
        "description": "Use the strongest evidence dimensions first and keep widening or narrowing by entity.",
        "targets": (
            {
                "target_type": "host",
                "target_label": "Host",
                "pivot_kind": "host_followup",
                "title": "Pivot on the hosts present in the returned evidence.",
                "recommendation": "Pivot on the hosts present in the returned evidence.",
            },
            {
                "target_type": "source_ip",
                "target_label": "Source IP",
                "pivot_kind": "same_source_ip_followup",
                "title": "Pivot on the source IPs present in the returned evidence.",
                "recommendation": "Pivot on the source IPs present in the returned evidence.",
            },
            {
                "target_type": "username",
                "target_label": "User",
                "pivot_kind": "username_followup",
                "title": "Pivot on the users present in the returned evidence.",
                "recommendation": "Pivot on the users present in the returned evidence.",
            },
        ),
    },
}


INTENT_PLAYBOOKS: dict[str, str] = {
    "failed_login_activity": "credential_abuse_auth",
    "linux_auth_failures": "credential_abuse_auth",
    "windows_auth_failures": "credential_abuse_auth",
    "linux_privilege_escalation": "linux_privilege_escalation",
    "linux_privilege_escalation_first_seen": "linux_privilege_escalation",
    "windows_sysmon_dns_activity": "endpoint_dns_activity",
    "windows_sysmon_network_activity": "endpoint_network_activity",
    "apache_access_top_ips": "web_recon_http",
    "apache_404_spike": "web_recon_http",
    "apache_suspicious_user_agents": "web_recon_http",
    "stream_http_activity": "web_traffic_hunt",
    "aws_cloudtrail_activity": "cloud_api_identity",
    "cisco_asa_network_flows": "network_flow_hunt",
    "aws_vpc_flow_activity": "network_flow_hunt",
    "aad_signin_activity": "cloud_identity_signin",
    "stream_dns_activity": "dns_stream_hunt",
    "o365_management_activity": "saas_management",
    "osquery_process_activity": "endpoint_process_execution",
}


def playbook_for_intent(intent: str) -> dict[str, Any]:
    playbook_id = INTENT_PLAYBOOKS.get(_normalize_intent(intent), "generic_hunt")
    spec = PLAYBOOK_LIBRARY.get(playbook_id, PLAYBOOK_LIBRARY["generic_hunt"])
    return {
        "id": playbook_id,
        "name": str(spec.get("name") or playbook_id),
        "description": str(spec.get("description") or ""),
        "targets": tuple(dict(item) for item in spec.get("targets", ())),
    }


def playbook_targets_for_intent(intent: str) -> tuple[dict[str, str], ...]:
    playbook = playbook_for_intent(intent)
    return tuple(dict(item) for item in playbook.get("targets", ()))


def playbook_target_order(intent: str) -> tuple[str, ...]:
    return tuple(str(item.get("target_type") or "").strip() for item in playbook_targets_for_intent(intent) if str(item.get("target_type") or "").strip())


def playbook_recommended_pivots(intent: str, entities: dict[str, list[str]]) -> list[str]:
    recommendations: list[str] = []
    playbook = playbook_for_intent(intent)
    seen: set[str] = set()
    for item in playbook.get("targets", ()):
        recommendation = str(item.get("recommendation") or "").strip()
        if recommendation and recommendation not in seen:
            seen.add(recommendation)
            recommendations.append(recommendation)
        target_type = str(item.get("target_type") or "").strip()
        if target_type == "host" and entities.get("hosts"):
            recommendations.append(f"Priority host pivot: {entities['hosts'][0]}")
        elif target_type in {"username", "principal"} and entities.get("users"):
            recommendations.append(f"Priority user pivot: {entities['users'][0]}")
        elif target_type == "source_ip" and entities.get("source_ips"):
            recommendations.append(f"Priority source IP pivot: {entities['source_ips'][0]}")
        elif target_type == "destination_ip" and entities.get("destination_ips"):
            recommendations.append(f"Priority destination IP pivot: {entities['destination_ips'][0]}")
    if not recommendations:
        if entities.get("hosts"):
            recommendations.append(f"Priority host pivot: {entities['hosts'][0]}")
        if entities.get("users"):
            recommendations.append(f"Priority user pivot: {entities['users'][0]}")
        if entities.get("source_ips"):
            recommendations.append(f"Priority source IP pivot: {entities['source_ips'][0]}")
    ordered: list[str] = []
    seen_lower: set[str] = set()
    for item in recommendations:
        text = str(item or "").strip()
        if not text:
            continue
        lowered = text.lower()
        if lowered in seen_lower:
            continue
        seen_lower.add(lowered)
        ordered.append(text)
    return ordered[:6]
