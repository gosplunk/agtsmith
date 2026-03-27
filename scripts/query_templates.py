#!/usr/bin/env python3
"""Query template definitions for the Splunk SOC lab pipeline.

This module keeps intent-routing metadata separate from pipeline execution code.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class QueryTemplate:
    intent: str
    keywords: tuple[str, ...]
    query: str
    tags: tuple[str, ...] = ()
    earliest_time: str = "-24h"
    latest_time: str = "now"
    row_limit: int = 10
    summary_hint: str = ""


TEMPLATES: tuple[QueryTemplate, ...] = (
    QueryTemplate(
        intent="failed_login_activity",
        keywords=("failed login", "failed authentication", "authentication failure"),
        query=(
            "search index=linux (source=\"/var/log/auth.log\" OR source=\"/var/log/secure\") "
            "(\"Failed password\" OR \"authentication failure\" OR \"Invalid user\" OR \"Connection closed by invalid user\" OR \"FAILED SU\") "
            "| eval platform=\"linux\" "
            "| rex field=_raw \"(?i)Failed password for (?:invalid user )?(?<failed_user>[^ ]+)\" "
            "| rex field=_raw \"(?i)user=(?<pam_user>[^\\s;]+)\" "
            "| rex field=_raw \"(?i)from (?<failed_src_ip>\\d{1,3}(?:\\.\\d{1,3}){3}) port (?<failed_port>\\d+)\" "
            "| rex field=_raw \"(?i)rhost=(?<failed_rhost>[^\\s;]+)\" "
            "| eval src_ip=coalesce(src_ip,failed_src_ip,failed_rhost,rhost,src,ip,\"local\") "
            "| eval user_name=coalesce(user,username,account,failed_user,pam_user) "
            "| eval auth_port=coalesce(port,lport) "
            "| append [ search (index=windows OR index=windows_sysmon) sourcetype=XmlWinEventLog "
            "(EventCode=4625 OR EventID=4625 OR \"An account failed to log on\") "
            "| eval platform=\"windows\" "
            "| eval src_ip=coalesce(Source_Network_Address,IpAddress,src,src_ip,clientip,ip) "
            "| eval user_name=coalesce(TargetUserName,SubjectUserName,Account_Name,Caller_User_Name,user,username,account) "
            "| eval auth_port=coalesce(DestinationPort,dest_port) ] "
            "| fillnull value=\"unknown\" src_ip user_name auth_port "
            "| stats count by platform index host user_name src_ip auth_port "
            "| sort - count"
        ),
        tags=("cross_domain", "auth_failure", "summary"),
        summary_hint="Focus on cross-platform failed login concentration by host, user, and source while preserving Linux and Windows evidence under a shared schema.",
    ),
    QueryTemplate(
        intent="linux_auth_failures",
        keywords=(
            "linux failed login",
            "linux auth failure",
            "linux ssh failure",
            "failed ssh login",
            "ssh brute force",
            "secure log",
        ),
        query=(
            "search index=linux (source=\"/var/log/auth.log\" OR source=\"/var/log/secure\") "
            "(\"Failed password\" OR \"authentication failure\" OR \"Invalid user\" OR \"Connection closed by invalid user\" OR \"FAILED SU\") "
            "| rex field=_raw \"(?i)Failed password for (?:invalid user )?(?<user>[^ ]+)\" "
            "| rex field=_raw \"(?i)user=(?<pam_user>[^\\s;]+)\" "
            "| rex field=_raw \"(?i)from (?<failed_src_ip>\\d{1,3}(?:\\.\\d{1,3}){3}) port (?<failed_port>\\d+)\" "
            "| rex field=_raw \"(?i)rhost=(?<rhost>[^\\s;]+)\" "
            "| eval user=coalesce(user,pam_user,username,account) "
            "| eval src_ip=coalesce(src_ip,failed_src_ip,rhost,src,ip,\"local\") "
            "| eval port=coalesce(port,failed_port,lport) "
            "| stats count by host user src_ip port | sort - count"
        ),
        tags=("linux", "auth_failure", "summary"),
        summary_hint="Focus on Linux authentication failures by host, user, source IP, and port.",
    ),
    QueryTemplate(
        intent="windows_auth_failures",
        keywords=(
            "windows failed login",
            "failed login windows",
            "windows auth failure",
            "windows authentication failure",
            "windows logon failure",
            "failed logon windows",
        ),
        query=(
            "search index=windows sourcetype=XmlWinEventLog "
            "(Channel=Security OR source=\"XmlWinEventLog:Security\") "
            "(EventCode=4625 OR EventID=4625 OR \"An account failed to log on\") "
            "| eval src_ip=coalesce(Source_Network_Address,IpAddress,src,src_ip,clientip,ip) "
            "| eval user_name=coalesce(TargetUserName,SubjectUserName,Account_Name,user,username,Caller_User_Name) "
            "| table _time index host Computer Channel EventCode EventID user_name src_ip LogonType FailureReason SubStatus "
            "TargetUserName SubjectUserName Account_Name Caller_User_Name Source_Network_Address IpAddress"
        ),
        tags=("windows", "auth_failure", "summary"),
        summary_hint="Focus on Windows failed logon evidence rows, preserving host, user, and source IP context even when some fields are sparse.",
    ),
    QueryTemplate(
        intent="windows_process_activity",
        keywords=(
            "windows process activity",
            "sysmon process creation",
            "process creation windows",
            "new processes on windows",
            "process monitoring windows",
        ),
        query=(
            "search (index=windows OR index=windows_sysmon) sourcetype=XmlWinEventLog \"<EventID>1</EventID>\" "
            "| rex field=_raw \"<Data Name='Image'>(?<Image>[^<]+)</Data>\" "
            "| rex field=_raw \"<Data Name='CommandLine'>(?<CommandLine>[^<]+)</Data>\" "
            "| rex field=_raw \"<Data Name='User'>(?<User>[^<]+)</Data>\" "
            "| rex field=_raw \"<Data Name='ParentImage'>(?<ParentImage>[^<]+)</Data>\" "
            "| rex field=_raw \"<Computer>(?<Computer>[^<]+)</Computer>\" "
            "| stats count by Computer Image CommandLine User ParentImage "
            "| sort - count | head 20"
        ),
        tags=("windows", "investigate", "summary"),
        summary_hint="Focus on Windows Sysmon process creation with image, command line, user, and parent image context.",
    ),
    QueryTemplate(
        intent="windows_sysmon_network_activity",
        keywords=(
            "sysmon network activity",
            "sysmon network connections",
            "windows network connections",
            "event id 3",
            "sysmon event 3",
        ),
        query=(
            "search index=windows_sysmon sourcetype=XmlWinEventLog "
            "Channel=\"Microsoft-Windows-Sysmon/Operational\" "
            "(EventID=3 OR EventCode=3 OR DestinationIp=*) "
            "| table _time Computer Image SourceIp DestinationIp DestinationPort Protocol "
            "| head 20"
        ),
        tags=("windows", "sysmon", "network", "investigate"),
        row_limit=20,
        summary_hint="Focus on Sysmon network connection evidence rows with source, destination, port, protocol, and process image.",
    ),
    QueryTemplate(
        intent="windows_sysmon_dns_activity",
        keywords=(
            "sysmon dns",
            "windows dns activity",
            "sysmon dns queries",
            "event id 22",
            "sysmon event 22",
            "dns queries windows",
        ),
        query=(
            "search index=windows_sysmon sourcetype=XmlWinEventLog "
            "Channel=\"Microsoft-Windows-Sysmon/Operational\" "
            "(EventID=22 OR EventCode=22 OR QueryName=*) "
            "| table _time Computer Image QueryName QueryResults "
            "| head 20"
        ),
        tags=("windows", "sysmon", "dns", "investigate"),
        row_limit=20,
        summary_hint="Focus on Sysmon DNS query evidence rows with process image, hostname queried, and returned answer context.",
    ),
    QueryTemplate(
        intent="windows_credential_access_activity",
        keywords=(
            "windows credential access",
            "credential manager reads",
            "event 5379",
            "stored credentials windows",
            "credential access windows",
        ),
        query=(
            "search index=windows sourcetype=XmlWinEventLog (EventID=5379 OR EventCode=5379 OR \"CountOfCredentialsReturned\") "
            "| rex field=_raw \"<Data Name='SubjectUserName'>(?<SubjectUserName>[^<]+)</Data>\" "
            "| rex field=_raw \"<Data Name='TargetName'>(?<TargetName>[^<]+)</Data>\" "
            "| rex field=_raw \"<Data Name='CountOfCredentialsReturned'>(?<CountOfCredentialsReturned>[^<]+)</Data>\" "
            "| rex field=_raw \"<Data Name='ClientProcessId'>(?<ClientProcessId>[^<]+)</Data>\" "
            "| rex field=_raw \"<Computer>(?<Computer>[^<]+)</Computer>\" "
            "| table _time Computer SubjectUserName TargetName CountOfCredentialsReturned ClientProcessId"
        ),
        tags=("windows", "investigate", "summary"),
        row_limit=50,
        summary_hint="Focus on Windows credential manager access events with user, target credential, and client process context.",
    ),
    QueryTemplate(
        intent="linux_privilege_escalation",
        keywords=(
            "linux sudo",
            "failed sudo",
            "sudo failure",
            "privilege escalation linux",
            "failed privilege escalation",
            "privilege escalation attempts",
            "su failed",
        ),
        query=(
            "search index=linux (source=\"/var/log/auth.log\" OR source=\"/var/log/secure\") "
            "((\"pam_unix(sudo:auth): authentication failure\" OR \"pam_unix(su:auth): authentication failure\" OR \"conversation failed\") "
            "OR ((\"sudo:\" OR \"su:\") (\"authentication failure\" OR \"incorrect password\" OR \"incorrect password attempts\" OR \"failed\"))) "
            "| rex field=_raw \"\\s(?<process_name>sudo|su)(?:\\[[^\\]]+\\])?:\" "
            "| rex field=_raw \"(?i)sudo:\\s+(?<sudo_actor>[A-Za-z0-9_.-]+)\\s+:\" "
            "| rex field=_raw \"(?i)logname=(?<logname_user>[^\\s;]+)\" "
            "| rex field=_raw \"(?i)ruser=(?<ruser>[^\\s;]+)\" "
            "| rex field=_raw \"(?i)\\buser=(?<auth_user>[^\\s;]+)\" "
            "| rex field=_raw \"(?i)tty=(?<tty_value>[^\\s;]+)\" "
            "| rex field=_raw \"(?i)rhost=(?<src_ip>[^\\s;]+)\" "
            "| eval actor=coalesce(sudo_actor,logname_user,ruser,auth_user,user,account,uid,user_name) "
            "| eval tty=coalesce(tty_value,tty) "
            "| eval src_ip=if(isnull(src_ip) OR len(trim(src_ip))=0, \"local\", src_ip) "
            "| stats count by host process_name actor tty src_ip sourcetype "
            "| sort - count"
        ),
        tags=("linux", "privilege_escalation", "summary"),
        summary_hint="Focus on failed sudo/su activity and potential Linux privilege escalation attempts.",
    ),
    QueryTemplate(
        intent="linux_privilege_escalation_activity",
        keywords=(
            "sudo behavior",
            "sudo activity",
            "su behavior",
            "su activity",
            "root session",
            "sudo sessions",
            "preserve context sudo",
            "not in sudoers",
            "sudoers file",
            "non-sudoer",
        ),
        query=(
            "search index=linux (source=\"/var/log/auth.log\" OR source=\"/var/log/secure\") "
            "(\"sudo:\" OR \"su:\" OR \"pam_unix(sudo:session)\" OR \"pam_unix(su:session)\" OR \"COMMAND=\" OR "
            "\"session opened for user root by\" OR \"incorrect password\" OR \"authentication failure\") "
            "| rex field=_raw \"\\s(?<process_name>sudo|su)(?:\\[[^\\]]+\\])?:\" "
            "| rex field=_raw \"(?i)sudo:\\s+(?<sudo_actor>[A-Za-z0-9_.-]+)\\s+:\" "
            "| rex field=_raw \"(?i)by\\s+(?<session_actor>[A-Za-z0-9_.-]+)\\(uid=\" "
            "| rex field=_raw \"(?i)\\(to\\s+(?<su_target>[A-Za-z0-9_.-]+)\\)\\s+(?<su_actor>[A-Za-z0-9_.-]+)\\s+on\\s+(?<su_tty>[^\\s;]+)\" "
            "| rex field=_raw \"(?i)for user\\s+(?<target_user>[A-Za-z0-9_.-]+)\" "
            "| rex field=_raw \"(?i)USER=(?<target_user_cmd>[A-Za-z0-9_.-]+)\" "
            "| rex field=_raw \"(?i)password changed for\\s+(?<passwd_target>[A-Za-z0-9_.-]+)\" "
            "| rex field=_raw \"(?i)new user:\\s+name=(?<new_user>[A-Za-z0-9_.-]+)\" "
            "| rex field=_raw \"(?i)delete user\\s+'(?<deleted_user>[A-Za-z0-9_.-]+)'\" "
            "| rex field=_raw \"(?i)COMMAND=(?<command>.+)$\" "
            "| eval target_user=coalesce(target_user,target_user_cmd,su_target,passwd_target,new_user,deleted_user) "
            "| eval outcome=case(match(_raw, \"(?i)incorrect password|failure|failed|not in sudoers|conversation failed|auth could not identify password\"), \"failure\", "
            "match(_raw, \"(?i)password changed for\"), \"password_changed\", "
            "match(_raw, \"(?i)new user:\"), \"user_created\", "
            "match(_raw, \"(?i)delete user\"), \"user_deleted\", "
            "match(_raw, \"(?i)session opened\"), \"session_opened\", "
            "match(_raw, \"(?i)session closed\"), \"session_closed\", "
            "match(_raw, \"(?i)COMMAND=\"), \"command\", true(), \"other\") "
            "| eval actor=coalesce(sudo_actor, su_actor, session_actor, user, account, uid, user_name) "
            "| eval src_ip=coalesce(rhost, src, src_ip, ip) "
            "| eval tty=coalesce(su_tty, tty) "
            "| table _time host sourcetype process_name outcome actor target_user command src_ip tty _raw"
        ),
        tags=("linux", "privilege_escalation", "investigate"),
        row_limit=50,
        summary_hint="Preserve both successful and unsuccessful sudo/su evidence rows, including process type, actor, target user, session activity, and command execution context.",
    ),
    QueryTemplate(
        intent="linux_session_activity",
        keywords=(
            "linux session activity",
            "session opened",
            "session closed",
            "cron session",
            "pam_unix session",
        ),
        query=(
            "search index=linux (source=\"/var/log/auth.log\" OR source=\"/var/log/secure\") "
            "(\"session opened for user\" OR \"session closed for user\" OR \"pam_unix(cron:session)\") "
            "| rex field=_raw \"(?i)session (?<session_state>opened|closed) for user (?<session_user>[A-Za-z0-9_.-]+)\" "
            "| rex field=_raw \"(?i)tty=(?<tty>[^\\s;]+)\" "
            "| rex field=_raw \"(?i)rhost=(?<src_ip>[^\\s;]+)\" "
            "| eval actor=session_user "
            "| eval src_ip=if(isnull(src_ip) OR len(trim(src_ip))=0, \"local\", src_ip) "
            "| table _time host sourcetype session_state actor tty src_ip _raw"
        ),
        tags=("linux", "investigate", "summary"),
        row_limit=20,
        summary_hint="Focus on Linux PAM and cron session activity by host, actor, tty, and source while preserving evidence rows.",
    ),
    QueryTemplate(
        intent="linux_audit_activity",
        keywords=(
            "linux audit activity",
            "auditd activity",
            "linux_audit",
            "audit operations linux",
        ),
        query=(
            "search index=linux sourcetype=linux_audit "
            "| rex field=_raw \"type=(?<audit_type>[^ ]+)\" "
            "| rex field=_raw \"\\bop=(?<audit_op>[^ ]+)\" "
            "| rex field=_raw \"\\bres=(?<audit_res>[^ ]+)\" "
            "| stats count by host audit_type audit_op audit_res "
            "| sort - count | head 20"
        ),
        tags=("linux", "investigate", "summary"),
        summary_hint="Focus on Linux auditd activity by audit type, operation, result, and host.",
    ),
    QueryTemplate(
        intent="linux_privilege_escalation_first_seen",
        keywords=(
            "first time privilege escalation",
            "first privilege escalation",
            "first seen privilege escalation",
            "first time sudo",
            "first seen sudo",
            "first time su",
        ),
        query=(
            "search index=linux (source=\"/var/log/auth.log\" OR source=\"/var/log/secure\") "
            "(\"session opened for user root by\" OR \"COMMAND=\" OR \"pam_unix(sudo:session)\" OR "
            "\"pam_unix(su:session)\" OR \"sudo:\" OR \"su:\") "
            "| eval user_name=coalesce(user, account, uid, user_name) "
            "| eval src_ip=coalesce(rhost, src, src_ip, ip) "
            "| stats earliest(_time) as first_seen latest(_time) as last_seen count "
            "by host user_name tty src_ip "
            "| convert ctime(first_seen) ctime(last_seen) "
            "| sort 0 first_seen"
        ),
        tags=("linux", "privilege_escalation", "first_seen", "investigate"),
        earliest_time="-7d",
        latest_time="now",
        row_limit=50,
        summary_hint=(
            "Focus on the earliest observed successful sudo/su activity by host, user, tty, and source "
            "to identify newly observed privilege-escalation patterns."
        ),
    ),
    QueryTemplate(
        intent="apache_access_top_ips",
        keywords=("apache access top ips", "top client ips", "top web client ips", "top source ips web", "web access logs"),
        query=(
            "search index=linux sourcetype=access_combined "
            "| stats count by clientip status method | sort - count"
        ),
        tags=("web", "web_access", "top_n", "summary"),
        summary_hint="Focus on top client IPs, status codes, and methods in Apache access logs.",
    ),
    QueryTemplate(
        intent="apache_404_spike",
        keywords=("apache 404", "404 spike", "not found web", "access_combined 404"),
        query=(
            "search index=linux sourcetype=access_combined status=404 "
            "| timechart span=1h count by host limit=10"
        ),
        tags=("web", "web_404", "time_series"),
        summary_hint="Focus on 404 error concentration and possible scanning activity by host.",
    ),
    QueryTemplate(
        intent="apache_suspicious_user_agents",
        keywords=(
            "suspicious user agents",
            "apache user agent",
            "access_combined user agents",
            "bot scanning",
            "suspicious bots",
            "apache bots",
            "web bots",
            "web crawlers",
            "suspicious web crawlers",
            "suspicious scanners",
            "web crawler evidence",
        ),
        query=(
            "search index=linux sourcetype=access_combined "
            "| stats count by useragent clientip | sort - count | head 20"
        ),
        tags=("web", "user_agent", "summary"),
        summary_hint="Focus on unusual user agents and correlated source IPs in web traffic.",
    ),
    QueryTemplate(
        intent="aws_cloudtrail_activity",
        keywords=("cloudtrail", "aws cloudtrail", "aws api activity", "cloudtrail events", "iam activity"),
        query=(
            "search index=main sourcetype=aws:cloudtrail "
            "| eval principal=coalesce('userIdentity.arn','userIdentity.principalId','userIdentity.type') "
            "| eval error_state=coalesce(errorCode,errorMessage,\"success\") "
            "| stats count by eventSource eventName sourceIPAddress principal userAgent error_state "
            "| sort - count | head 20"
        ),
        tags=("aws", "cloud_api", "summary"),
        summary_hint="Focus on the most frequent CloudTrail API actions, the service they hit, the calling source, the AWS principal, and whether the action succeeded or errored.",
    ),
    QueryTemplate(
        intent="cisco_asa_network_flows",
        keywords=("cisco asa", "asa firewall", "blocked flows", "firewall flows", "blocked traffic"),
        query=(
            "search index=main sourcetype=cisco:asa "
            "| stats count by action src_ip dest_ip dest_port transport "
            "| sort - count | head 20"
        ),
        tags=("network", "network_flow", "summary"),
        summary_hint="Focus on blocked versus allowed firewall flows, including source, destination, port, and transport.",
    ),
    QueryTemplate(
        intent="stream_http_activity",
        keywords=("stream:http", "stream http", "http methods", "http status codes", "destination sites", "http traffic"),
        query=(
            "search index=main sourcetype=stream:http "
            "| spath input=_raw path=http_method output=http_method "
            "| spath input=_raw path=status output=status "
            "| spath input=_raw path=site output=site "
            "| spath input=_raw path=src_ip output=src_ip "
            "| stats count by http_method status site src_ip "
            "| sort - count | head 20"
        ),
        tags=("web", "web_access", "summary"),
        summary_hint="Focus on HTTP methods, status codes, destination sites, and client IPs captured by stream:http.",
    ),
    QueryTemplate(
        intent="osquery_process_activity",
        keywords=("osquery process monitoring", "osquery results", "added processes", "process monitoring", "osquery process"),
        query=(
            "search index=main sourcetype=osquery:results "
            "| spath input=_raw path=name output=query_name "
            "| spath input=_raw path=action output=action "
            "| spath input=_raw path=hostIdentifier output=hostIdentifier "
            "| spath input=_raw path=columns.path output=path "
            "| spath input=_raw path=columns.cmdline output=cmdline "
            "| stats count by hostIdentifier action path cmdline "
            "| sort - count | head 20"
        ),
        tags=("cross_domain", "investigate", "summary"),
        summary_hint="Focus on osquery process-monitoring results with host, action, executable path, and command line.",
    ),
    QueryTemplate(
        intent="aws_vpc_flow_activity",
        keywords=("vpc flow", "vpc flows", "aws vpc flow", "accepted and rejected flows", "vpcflow"),
        query=(
            "search index=main sourcetype=aws:cloudwatchlogs:vpcflow "
            "| rex field=_raw \"^\\S+\\s+\\S+\\s+\\S+\\s+(?<src_ip>\\S+)\\s+(?<dest_ip>\\S+)\\s+\\S+\\s+(?<dest_port>\\S+)\\s+(?<protocol_num>\\S+)\\s+\\S+\\s+\\S+\\s+\\S+\\s+\\S+\\s+(?<action>\\S+)\\s+\\S+$\" "
            "| eval transport=case(protocol_num=\"6\",\"tcp\",protocol_num=\"17\",\"udp\",protocol_num=\"1\",\"icmp\",true(),protocol_num) "
            "| stats count by action src_ip dest_ip dest_port transport "
            "| sort - count | head 20"
        ),
        tags=("aws", "network_flow", "summary"),
        summary_hint="Focus on accepted and rejected AWS VPC flows by source, destination, port, and transport.",
    ),
    QueryTemplate(
        intent="aad_signin_activity",
        keywords=("azure ad sign-in", "azure ad signin", "aad sign-in", "aad signin", "login status"),
        query=(
            "search index=main sourcetype=ms:aad:signin "
            "| spath input=_raw path=userPrincipalName output=userPrincipalName "
            "| spath input=_raw path=ipAddress output=ipAddress "
            "| spath input=_raw path=appDisplayName output=appDisplayName "
            "| spath input=_raw path=loginStatus output=loginStatus "
            "| stats count by userPrincipalName ipAddress appDisplayName loginStatus "
            "| sort - count | head 20"
        ),
        tags=("cross_domain", "auth_failure", "summary"),
        summary_hint="Focus on Azure AD sign-ins by user, IP address, application, and login status.",
    ),
    QueryTemplate(
        intent="stream_dns_activity",
        keywords=("stream:dns", "stream dns", "dns activity", "reply code", "dns query"),
        query=(
            "search index=main sourcetype=stream:dns "
            "| spath input=_raw path=query{} output=query "
            "| spath input=_raw path=reply_code output=reply_code "
            "| spath input=_raw path=src_ip output=src_ip "
            "| spath input=_raw path=dest_ip output=dest_ip "
            "| mvexpand query "
            "| stats count by query reply_code src_ip dest_ip "
            "| sort - count | head 20"
        ),
        tags=("network", "summary"),
        summary_hint="Focus on DNS query names, reply codes, source IPs, and destination resolvers from stream:dns.",
    ),
    QueryTemplate(
        intent="o365_management_activity",
        keywords=("office 365 management", "o365 management", "ms:o365:management", "sharepoint activity", "onedrive activity"),
        query=(
            "search index=main sourcetype=ms:o365:management "
            "| spath input=_raw path=UserId output=UserId "
            "| spath input=_raw path=Operation output=Operation "
            "| spath input=_raw path=Workload output=Workload "
            "| spath input=_raw path=ClientIP output=ClientIP "
            "| stats count by UserId Operation Workload ClientIP "
            "| sort - count | head 20"
        ),
        tags=("cross_domain", "summary"),
        summary_hint="Focus on Office 365 management activity by user, operation, workload, and client IP.",
    ),
    QueryTemplate(
        intent="botsv3_named_sourcetype_overview",
        keywords=("botsv3 sourcetype overview", "show sourcetype", "overview of sourcetype"),
        query=(
            "search index=main sourcetype=PLACEHOLDER_SOURCETYPE "
            "| stats count by host source sourcetype "
            "| sort - count | head 20"
        ),
        tags=("cross_domain", "summary"),
        summary_hint="Focus on a named BOTSv3 sourcetype with a safe host/source overview.",
    ),
    QueryTemplate(
        intent="top_indexes",
        keywords=("index", "indexes"),
        query="search index=* NOT index=_* | stats count by index | sort - count",
        tags=("cross_domain", "inventory", "top_n"),
        summary_hint="Focus on which indexes dominate the event volume.",
    ),
    QueryTemplate(
        intent="internal_sourcetypes",
        keywords=("sourcetype", "internal"),
        query="search index=_internal | stats count by sourcetype | sort - count",
        tags=("splunk_internal", "metadata", "top_n"),
        summary_hint="Focus on top internal sourcetypes and operational significance.",
    ),
    QueryTemplate(
        intent="internal_auth_failures",
        keywords=(
            "splunk auth failures",
            "internal auth failures",
            "splunk internal auth",
            "internal splunk auth failures",
            "splunk internal auth failures",
            "failed splunk logins",
            "splunk logins",
            "internal auth failure sources",
            "top internal auth failure sources",
        ),
        query=(
            "search index=_audit sourcetype=audittrail info=failed "
            "| stats count by host user src | sort - count"
        ),
        tags=("splunk_internal", "auth_failure", "summary"),
        summary_hint="Focus on failed Splunk internal authentication in audittrail by host, user, and source.",
    ),
)


DEFAULT_TEMPLATE = TEMPLATES[-2]
