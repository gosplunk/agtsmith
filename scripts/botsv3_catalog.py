#!/usr/bin/env python3
"""Static BOTSv3 sourcetype catalog used for benchmark-only routing.

This is intentionally separated from live environment grounding so BOTSv3 can
improve SPL authoring without becoming a production default.
"""

from __future__ import annotations

import re


BOTSV3_SOURCETYPES: tuple[str, ...] = (
    "access_combined",
    "alternatives",
    "amazon-ssm-agent",
    "amazon-ssm-agent-too_small",
    "apache_error",
    "aws:cloudtrail",
    "aws:cloudwatch",
    "aws:cloudwatch:guardduty",
    "aws:cloudwatchlogs",
    "aws:cloudwatchlogs:vpcflow",
    "aws:config:rule",
    "aws:description",
    "aws:elb:accesslogs",
    "aws:rds:audit",
    "aws:rds:error",
    "aws:s3:accesslogs",
    "bandwidth",
    "bash_history",
    "bootstrap",
    "cisco:asa",
    "cloud-init",
    "cloud-init-output",
    "code42:api",
    "code42:computer",
    "code42:org",
    "code42:security",
    "code42:user",
    "config_file",
    "cpu",
    "cron-too_small",
    "df",
    "dmesg",
    "dpkg",
    "error-too_small",
    "errors",
    "errors-too_small",
    "ess_content_importer",
    "hardware",
    "history-2",
    "interfaces",
    "iostat",
    "lastlog",
    "linux_audit",
    "linux_secure",
    "localhost-5",
    "lsof",
    "maillog-too_small",
    "ms:aad:audit",
    "ms:aad:signin",
    "ms:o365:management",
    "ms:o365:reporting:messagetrace",
    "netstat",
    "o365:management:activity",
    "openPorts",
    "osquery:info",
    "osquery:results",
    "osquery:warning",
    "out-3",
    "package",
    "PerfmonMk:Process",
    "protocol",
    "ps",
    "Script:GetEndpointInfo",
    "Script:InstalledApps",
    "Script:ListeningPorts",
    "stream:arp",
    "stream:dhcp",
    "stream:dns",
    "stream:http",
    "stream:icmp",
    "stream:igmp",
    "stream:ip",
    "stream:mysql",
    "stream:smb",
    "stream:smtp",
    "stream:tcp",
    "stream:udp",
    "symantec:ep:agent:file",
    "symantec:ep:agt_system:file",
    "symantec:ep:behavior:file",
    "symantec:ep:packet:file",
    "symantec:ep:risk:file",
    "symantec:ep:scm_system:file",
    "symantec:ep:security:file",
    "symantec:ep:traffic:file",
    "syslog",
    "time",
    "top",
    "Unix:ListeningPorts",
    "Unix:Service",
    "Unix:SSHDConfig",
    "Unix:Update",
    "Unix:Uptime",
    "Unix:UserAccounts",
    "Unix:Version",
    "usersWithLoginPrivs",
    "vmstat",
    "who",
    "WinEventLog",
    "WinHostMon",
    "xmlwineventlog",
)


def extract_explicit_botsv3_sourcetype(question: str) -> str:
    q = (question or "").strip().lower()
    if "botsv3" not in q:
        return ""
    for sourcetype in BOTSV3_SOURCETYPES:
        pattern = re.escape(sourcetype.lower())
        if re.search(rf"(?<![a-z0-9_:-]){pattern}(?![a-z0-9_:-])", q):
            return sourcetype
    return ""
