#!/usr/bin/env python3
"""Query template definitions for the Splunk SOC lab pipeline.

This module keeps intent-routing metadata separate from pipeline execution code.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from apache_intent import build_apache_query


@dataclass(frozen=True)
class QueryTemplate:
    intent: str
    keywords: tuple[str, ...]
    query: str
    tags: tuple[str, ...] = ()
    earliest_time: str = "-7d"
    latest_time: str = "now"
    row_limit: int = 10
    summary_hint: str = ""
    raw_parse_required: bool = False

    @property
    def native_query(self) -> str:
        """Return the template shape without optional extraction fallbacks."""
        if self.raw_parse_required:
            return self.query
        native, _fallbacks = split_field_extractions(self.query)
        return native

    @property
    def fallback_extractions(self) -> tuple[str, ...]:
        """Return ordered ``rex``/``spath`` stages available as fallbacks."""
        _native, fallbacks = split_field_extractions(self.query)
        return fallbacks


def _split_pipeline(query: str) -> list[str]:
    """Split top-level SPL pipes without splitting quoted expressions."""
    parts: list[str] = []
    current: list[str] = []
    quote = ""
    escaped = False
    bracket_depth = 0
    for char in str(query or ""):
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\":
            current.append(char)
            escaped = True
            continue
        if quote:
            current.append(char)
            if char == quote:
                quote = ""
            continue
        if char in {'"', "'"}:
            quote = char
            current.append(char)
            continue
        if char == "[":
            bracket_depth += 1
        elif char == "]" and bracket_depth:
            bracket_depth -= 1
        if char == "|" and bracket_depth == 0:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(char)
    parts.append("".join(current).strip())
    return [part for part in parts if part]


def split_field_extractions(query: str) -> tuple[str, tuple[str, ...]]:
    """Separate a template's native shape from optional extraction stages."""
    parts = _split_pipeline(query)
    if not parts:
        return "", ()
    fallbacks = tuple(
        part for part in parts[1:] if re.match(r"^(?:rex|spath)\b", part, flags=re.IGNORECASE)
    )
    native_parts = [
        parts[0],
        *(
            part
            for part in parts[1:]
            if not re.match(r"^(?:rex|spath)\b", part, flags=re.IGNORECASE)
        ),
    ]
    return " | ".join(native_parts), fallbacks


TEMPLATES: tuple[QueryTemplate, ...] = (
    QueryTemplate(
        intent="failed_login_activity",
        keywords=("failed login", "failed logon", "failed logons", "failed logins", "failed authentication", "authentication failure"),
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
            "| eval src_ip=coalesce(IpAddress,Source_Network_Address,src,src_ip,clientip,ip) "
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
        intent="successful_login_activity",
        keywords=("successful login", "successful logon", "successful authentication", "logon success"),
        query=(
            "search "
            "((index=linux (source=\"/var/log/auth.log\" OR source=\"/var/log/secure\") "
            "(\"Accepted password\" OR \"Accepted publickey\" OR \"Accepted keyboard-interactive/pam\" OR \"session opened for user\")) "
            "OR "
            "((index=windows OR index=windows_sysmon) sourcetype=XmlWinEventLog "
            "(EventCode=4624 OR EventID=4624 OR \"An account was successfully logged on\"))) "
            "| eval platform=case(match(index,\"(?i)linux\"),\"linux\", true(), \"windows\") "
            "| rex field=_raw \"(?i)Accepted (?:password|publickey|keyboard-interactive/pam) for (?<success_user>[^ ]+)\" "
            "| rex field=_raw \"(?i)from (?<success_src_ip>\\d{1,3}(?:\\.\\d{1,3}){3}) port (?<success_port>\\d+)\" "
            "| rex field=_raw \"(?i)session opened for user (?<session_user>[A-Za-z0-9_.-]+)\" "
            "| eval src_ip=coalesce(Source_Network_Address,IpAddress,src,src_ip,clientip,success_src_ip,ip,rhost,\"local\") "
            "| eval user_name=coalesce(TargetUserName,SubjectUserName,Account_Name,user,username,account,success_user,session_user) "
            "| eval auth_port=coalesce(DestinationPort,dest_port,port,success_port,lport) "
            "| fillnull value=\"unknown\" src_ip user_name auth_port "
            "| stats count by platform index host user_name src_ip auth_port "
            "| sort - count"
        ),
        tags=("cross_domain", "auth_success", "summary"),
        summary_hint="Focus on successful authentication activity across Linux and Windows by host, user, and source IP.",
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
        intent="linux_successful_logins",
        keywords=(
            "linux successful login",
            "linux successful logon",
            "successful ssh login",
            "accepted password",
            "accepted publickey",
            "linux login success",
        ),
        query=(
            "search index=linux (source=\"/var/log/auth.log\" OR source=\"/var/log/secure\") "
            "(\"Accepted password\" OR \"Accepted publickey\" OR \"Accepted keyboard-interactive/pam\" OR \"session opened for user\") "
            "| rex field=_raw \"(?i)Accepted (?:password|publickey|keyboard-interactive/pam) for (?<user>[^ ]+)\" "
            "| rex field=_raw \"(?i)from (?<success_src_ip>\\d{1,3}(?:\\.\\d{1,3}){3}) port (?<success_port>\\d+)\" "
            "| rex field=_raw \"(?i)session opened for user (?<session_user>[A-Za-z0-9_.-]+)\" "
            "| eval user=coalesce(user,session_user,username,account) "
            "| eval src_ip=coalesce(src_ip,success_src_ip,rhost,src,ip,\"local\") "
            "| eval port=coalesce(port,success_port,lport) "
            "| stats count by host user src_ip port | sort - count"
        ),
        tags=("linux", "auth_success", "summary"),
        summary_hint="Focus on successful Linux authentication activity by host, user, source IP, and port.",
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
            "search (index=windows OR index=windows_sysmon OR index=botsv3 OR index=soc_windows) "
            "(sourcetype=XmlWinEventLog OR sourcetype=xmlwineventlog OR sourcetype=WinEventLog) "
            "(EventCode=4625 OR EventID=4625 OR \"An account failed to log on\") "
            "| eval src_ip=coalesce(Source_Network_Address,IpAddress,src,src_ip,clientip,ip) "
            "| eval user_name=coalesce(TargetUserName,SubjectUserName,Account_Name,user,username,Caller_User_Name) "
            "| table _time index host Computer EventCode EventID user_name src_ip LogonType FailureReason SubStatus "
            "TargetUserName SubjectUserName Account_Name Caller_User_Name IpAddress IpPort"
        ),
        tags=("windows", "auth_failure", "summary"),
        summary_hint="Focus on Windows failed logon evidence rows, preserving host, user, and source IP context even when some fields are sparse.",
    ),
    QueryTemplate(
        intent="windows_successful_logons",
        keywords=(
            "windows successful login",
            "windows successful logon",
            "successful logon windows",
            "successful login windows",
            "4624",
        ),
        query=(
            "search index=windows sourcetype=XmlWinEventLog "
            "(EventCode=4624 OR EventID=4624 OR \"An account was successfully logged on\") "
            "| eval src_ip=coalesce(IpAddress,Source_Network_Address,src,src_ip,clientip,ip) "
            "| eval user_name=coalesce(TargetUserName,SubjectUserName,Account_Name,user,username,Caller_User_Name) "
            "| table _time index host Computer EventCode EventID user_name src_ip LogonType WorkstationName AuthenticationPackageName IpAddress IpPort"
        ),
        tags=("windows", "auth_success", "summary"),
        summary_hint="Focus on Windows successful logon evidence rows with host, user, source IP, and workstation context.",
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
            "search (index=windows OR index=windows_sysmon) sourcetype=XmlWinEventLog "
            "(\"Microsoft-Windows-Sysmon/Operational\" OR EventCode=1 OR EventID=1 OR \"<EventID>1</EventID>\") "
            "| spath input=_raw "
            "| search Channel=\"Microsoft-Windows-Sysmon/Operational\" (EventCode=1 OR EventID=1) "
            "| rex field=_raw \"<Data Name=[\\\"']Image[\\\"']>(?<Image_xml>[^<]+)</Data>\" "
            "| rex field=_raw \"<Data Name=[\\\"']CommandLine[\\\"']>(?<CommandLine_xml>[^<]+)</Data>\" "
            "| rex field=_raw \"<Data Name=[\\\"']User[\\\"']>(?<User_xml>[^<]+)</Data>\" "
            "| rex field=_raw \"<Data Name=[\\\"']ParentImage[\\\"']>(?<ParentImage_xml>[^<]+)</Data>\" "
            "| rex field=_raw \"<Computer>(?<Computer_xml>[^<]+)</Computer>\" "
            "| eval Image=coalesce(Image,Image_xml) "
            "| eval CommandLine=coalesce(CommandLine,CommandLine_xml) "
            "| eval User=coalesce(User,User_xml) "
            "| eval ParentImage=coalesce(ParentImage,ParentImage_xml) "
            "| eval Computer=coalesce(Computer,Computer_xml) "
            "| table _time Computer Image CommandLine User ParentImage "
            "| head 20"
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
            "search (index=windows_sysmon OR index=windows) sourcetype=XmlWinEventLog "
            "(\"Microsoft-Windows-Sysmon/Operational\" OR EventCode=3 OR EventID=3 OR DestinationIp=*) "
            "| spath input=_raw "
            "| rex field=_raw \"<EventID[^>]*>(?<EventID_xml>3)</EventID>\" "
            "| rex field=_raw \"<Channel>(?<Channel_xml>[^<]+)</Channel>\" "
            "| rex field=_raw \"<Computer>(?<Computer_xml>[^<]+)</Computer>\" "
            "| rex field=_raw \"<Data Name=[\\\"']Image[\\\"']>(?<Image_xml>[^<]+)</Data>\" "
            "| rex field=_raw \"<Data Name=[\\\"']SourceIp[\\\"']>(?<SourceIp_xml>[^<]+)</Data>\" "
            "| rex field=_raw \"<Data Name=[\\\"']DestinationIp[\\\"']>(?<DestinationIp_xml>[^<]+)</Data>\" "
            "| rex field=_raw \"<Data Name=[\\\"']DestinationPort[\\\"']>(?<DestinationPort_xml>[^<]+)</Data>\" "
            "| rex field=_raw \"<Data Name=[\\\"']Protocol[\\\"']>(?<Protocol_xml>[^<]+)</Data>\" "
            "| eval EventID=coalesce(EventID,EventID_xml), Channel=coalesce(Channel,Channel_xml), Computer=coalesce(Computer,Computer_xml) "
            "| eval Image=coalesce(Image,Image_xml), SourceIp=coalesce(SourceIp,SourceIp_xml), DestinationIp=coalesce(DestinationIp,DestinationIp_xml) "
            "| eval DestinationPort=coalesce(DestinationPort,DestinationPort_xml), Protocol=coalesce(Protocol,Protocol_xml) "
            "| search Channel=\"Microsoft-Windows-Sysmon/Operational\" EventID=3 "
            "| search Image=* SourceIp=* DestinationIp=* DestinationPort=* Protocol=* "
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
            "search (index=windows_sysmon OR index=windows) sourcetype=XmlWinEventLog "
            "(\"Microsoft-Windows-Sysmon/Operational\" OR EventCode=22 OR EventID=22 OR QueryName=*) "
            "| spath input=_raw "
            "| rex field=_raw \"<EventID[^>]*>(?<EventID_xml>22)</EventID>\" "
            "| rex field=_raw \"<Channel>(?<Channel_xml>[^<]+)</Channel>\" "
            "| rex field=_raw \"<Computer>(?<Computer_xml>[^<]+)</Computer>\" "
            "| rex field=_raw \"<Data Name=[\\\"']Image[\\\"']>(?<Image_xml>[^<]+)</Data>\" "
            "| rex field=_raw \"<Data Name=[\\\"']QueryName[\\\"']>(?<QueryName_xml>[^<]+)</Data>\" "
            "| rex field=_raw \"<Data Name=[\\\"']QueryStatus[\\\"']>(?<QueryStatus_xml>[^<]+)</Data>\" "
            "| rex field=_raw \"<Data Name=[\\\"']QueryResults[\\\"']>(?<QueryResults_xml>[^<]*)</Data>\" "
            "| eval EventID=coalesce(EventID,EventID_xml), Channel=coalesce(Channel,Channel_xml), Computer=coalesce(Computer,Computer_xml) "
            "| eval Image=coalesce(Image,Image_xml), QueryName=coalesce(QueryName,QueryName_xml), QueryStatus=coalesce(QueryStatus,QueryStatus_xml), QueryResults=coalesce(QueryResults,QueryResults_xml) "
            "| search Channel=\"Microsoft-Windows-Sysmon/Operational\" EventID=22 QueryName=* "
            "| table _time Computer Image QueryName QueryStatus QueryResults "
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
            "search index=windows sourcetype=XmlWinEventLog "
            "(EventID=5379 OR EventCode=5379 OR \"CountOfCredentialsReturned\") "
            "| spath input=_raw "
            "| search (EventID=5379 OR EventCode=5379 OR CountOfCredentialsReturned=*) "
            "| rex field=_raw \"<Data Name=[\\\"']SubjectUserName[\\\"']>(?<SubjectUserName_xml>[^<]+)</Data>\" "
            "| rex field=_raw \"<Data Name=[\\\"']TargetName[\\\"']>(?<TargetName_xml>[^<]+)</Data>\" "
            "| rex field=_raw \"<Data Name=[\\\"']CountOfCredentialsReturned[\\\"']>(?<CountOfCredentialsReturned_xml>[^<]+)</Data>\" "
            "| rex field=_raw \"<Data Name=[\\\"']ClientProcessId[\\\"']>(?<ClientProcessId_xml>[^<]+)</Data>\" "
            "| rex field=_raw \"<Computer>(?<Computer>[^<]+)</Computer>\" "
            "| eval SubjectUserName=coalesce(SubjectUserName,SubjectUserName_xml), TargetName=coalesce(TargetName,TargetName_xml) "
            "| eval CountOfCredentialsReturned=coalesce(CountOfCredentialsReturned,CountOfCredentialsReturned_xml), ClientProcessId=coalesce(ClientProcessId,ClientProcessId_xml) "
            "| table _time Computer SubjectUserName TargetName CountOfCredentialsReturned ClientProcessId"
        ),
        tags=("windows", "investigate", "summary"),
        row_limit=50,
        summary_hint="Focus on Windows credential manager access events with user, target credential, and client process context.",
    ),
    QueryTemplate(
        intent="windows_process_audit_activity",
        keywords=(
            "4688",
            "process creation audit",
            "new process has been created",
            "windows process audit",
            "security process creation",
        ),
        query=(
            "search (index=windows OR index=botsv3 OR index=soc_windows) sourcetype=XmlWinEventLog "
            "(EventCode=4688 OR EventID=4688 OR \"A new process has been created\") "
            "| rex field=_raw \"<Data Name=[\\\"']NewProcessName[\\\"']>(?<NewProcessName_xml>[^<]+)</Data>\" "
            "| rex field=_raw \"<Data Name=[\\\"']CommandLine[\\\"']>(?<CommandLine_xml>[^<]+)</Data>\" "
            "| rex field=_raw \"<Data Name=[\\\"']ParentProcessName[\\\"']>(?<ParentProcessName_xml>[^<]+)</Data>\" "
            "| eval process_name=coalesce(NewProcessName,NewProcessName_xml,New_Process_Name,Process_Name,Image) "
            "| eval command_line=coalesce(CommandLine,CommandLine_xml,Process_Command_Line) "
            "| eval parent_process_name=coalesce(ParentProcessName,ParentProcessName_xml,Creator_Process_Name) "
            "| eval user_name=coalesce(SubjectUserName,TargetUserName,user,username) "
            "| table _time Computer EventCode EventID user_name process_name command_line parent_process_name"
        ),
        tags=("windows", "process", "audit", "summary"),
        summary_hint="Focus on Security-audit process creation (4688) with executable path and command line.",
    ),
    QueryTemplate(
        intent="windows_privilege_assigned_activity",
        keywords=(
            "4672",
            "special privileges assigned",
            "privilege assignment",
            "admin privileges windows",
        ),
        query=(
            "search (index=windows OR index=botsv3 OR index=soc_windows) sourcetype=XmlWinEventLog "
            "(EventCode=4672 OR EventID=4672 OR \"Special privileges assigned to new logon\") "
            "| eval user_name=coalesce(SubjectUserName,TargetUserName,user,username) "
            "| table _time Computer user_name PrivilegeList EventCode EventID"
        ),
        tags=("windows", "privilege", "summary"),
        summary_hint="Focus on special privilege assignment at logon with user and privilege list context.",
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
            "| rex field=_raw \"(?i)pkexec\\[[^\\]]+\\]:\\s+(?<pkexec_actor>[A-Za-z0-9_.-]+):\" "
            "| eval target_user=coalesce(target_user,target_user_cmd,su_target,passwd_target,new_user,deleted_user) "
            "| eval outcome=case(match(_raw, \"(?i)incorrect password|failure|failed|not in sudoers|conversation failed|auth could not identify password\"), \"failure\", "
            "match(_raw, \"(?i)password changed for\"), \"password_changed\", "
            "match(_raw, \"(?i)new user:\"), \"user_created\", "
            "match(_raw, \"(?i)delete user\"), \"user_deleted\", "
            "match(_raw, \"(?i)session opened\"), \"session_opened\", "
            "match(_raw, \"(?i)session closed\"), \"session_closed\", "
            "match(_raw, \"(?i)COMMAND=\"), \"command\", true(), \"other\") "
            "| eval process_name=case(isnotnull(process_name),process_name,match(_raw,\"(?i)pkexec\"),\"pkexec\",true(),\"unknown\") "
            "| eval actor=coalesce(sudo_actor, su_actor, session_actor, pkexec_actor, user, account, uid, user_name) "
            "| eval actor=if(isnull(actor) AND match(_raw,\"(?i)by\\s+\\(uid=0\\)\"),\"root\",actor) "
            "| eval src_ip=coalesce(rhost, src, src_ip, ip) "
            "| eval tty=coalesce(su_tty, tty) "
            "| fillnull value=\"unknown\" actor target_user command src_ip tty "
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
        keywords=(
            "apache access top ips",
            "top client ips",
            "top web client ips",
            "top source ips web",
            "web access logs",
            "traffic summary",
        ),
        query=build_apache_query("apache_access_top_ips"),
        tags=("web", "web_access", "top_n", "summary"),
        summary_hint="Preserve every requested Apache dimension while summarizing client IP, response status, method, path, and user-agent traffic.",
    ),
    QueryTemplate(
        intent="apache_suspicious_activity",
        keywords=(
            "suspicious web activity",
            "suspicious activity",
            "malicious web access",
            "web attack activity",
            "web reconnaissance",
        ),
        query=build_apache_query("apache_suspicious_activity"),
        tags=("web", "web_access", "investigate", "suspicious"),
        row_limit=50,
        summary_hint=(
            "Focus on Apache requests that satisfy explicit suspicious criteria and preserve all analyst-requested "
            "dimensions plus the suspicious reason."
        ),
    ),
    QueryTemplate(
        intent="apache_404_spike",
        keywords=("apache 404", "404 spike", "not found web", "access_combined 404"),
        query=build_apache_query("apache_404_spike"),
        tags=("web", "web_404", "time_series"),
        summary_hint="Focus on 404 error concentration and possible scanning activity by host.",
    ),
    QueryTemplate(
        intent="apache_404_scanning",
        keywords=(
            "404 scanning",
            "404 scanner",
            "404 scanners",
            "404 probing",
            "not found scanning",
            "top 404 source ips",
        ),
        query=build_apache_query("apache_404_scanning"),
        tags=("web", "web_404", "investigate", "suspicious"),
        row_limit=50,
        summary_hint="Focus on clients generating repeated or diverse 404 paths, preserving methods, paths, and user agents.",
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
        query=build_apache_query("apache_suspicious_user_agents"),
        tags=("web", "user_agent", "summary", "suspicious"),
        summary_hint="Focus only on explicitly suspicious, automated, empty, or scanner-like user agents and correlated source IPs.",
    ),
    QueryTemplate(
        intent="apache_sensitive_path_probing",
        keywords=(
            "sensitive path probing",
            "sensitive paths",
            "admin path probing",
            ".env probing",
            ".git probing",
            "wp-admin probing",
            "configuration file probing",
        ),
        query=build_apache_query("apache_sensitive_path_probing"),
        tags=("web", "web_access", "investigate", "suspicious"),
        row_limit=50,
        summary_hint="Focus on requests for sensitive administrative, configuration, backup, and framework paths.",
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
        raw_parse_required=True,
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
            "| spath input=_raw path=query{} output=query_name "
            "| mvexpand query_name "
            "| stats count by query_name reply_code src_ip dest_ip "
            "| sort - count | head 20"
        ),
        tags=("network", "summary"),
        summary_hint="Focus on DNS query names, reply codes, source IPs, and destination resolvers from stream:dns.",
    ),
    QueryTemplate(
        intent="o365_management_activity",
        keywords=("office 365 management", "o365 management", "ms:o365:management", "sharepoint activity", "onedrive activity"),
        query=(
            "search index=main (sourcetype=o365:management:activity OR sourcetype=ms:o365:management) "
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
        intent="metadata_inventory",
        keywords=("metadata", "list hosts", "list sources", "list sourcetypes", "hosts in index", "sources in index"),
        query="search index=* | metadata type=hosts | sort + host",
        tags=("inventory", "metadata"),
        summary_hint="Focus on metadata inventory for hosts, sources, or sourcetypes in an index.",
    ),
    QueryTemplate(
        intent="index_sourcetype_volume",
        keywords=("sourcetype volume", "top sourcetypes", "sourcetypes by index", "sourcetype count"),
        query="search index=* NOT index=_* | stats count by index sourcetype | sort - count",
        tags=("inventory", "top_n"),
        summary_hint="Focus on sourcetype volume across indexes.",
    ),
    QueryTemplate(
        intent="host_activity_summary",
        keywords=("host activity", "active hosts", "hosts with events", "top hosts", "most activity", "busiest hosts"),
        query="search index=* NOT index=_* | stats count by index host | sort - count",
        tags=("inventory", "top_n"),
        summary_hint="Focus on hosts with the most events by index.",
    ),
    QueryTemplate(
        intent="index_staleness",
        keywords=("stale index", "no recent data", "indexes without data", "quiet indexes"),
        query="search index=* NOT index=_* | stats latest(_time) as last_seen by index | sort + last_seen",
        tags=("inventory", "staleness"),
        summary_hint="Focus on indexes with stale or missing recent event timestamps.",
    ),
    QueryTemplate(
        intent="splunk_internal_health",
        keywords=("splunk internal health", "scheduler activity", "search telemetry", "splunk platform health"),
        query="search index=_internal | stats count by sourcetype | sort - count",
        tags=("splunk_internal", "platform_ops", "top_n"),
        summary_hint="Focus on Splunk internal sourcetype volume for platform health.",
    ),
    QueryTemplate(
        intent="splunk_license_usage",
        keywords=("license usage", "license quota", "splunk license"),
        query="search index=_internal sourcetype=splunkd OR sourcetype=license_usage | stats count by sourcetype host | sort - count",
        tags=("splunk_internal", "platform_ops"),
        summary_hint="Focus on Splunk license and splunkd usage signals in internal indexes.",
    ),
    QueryTemplate(
        intent="forwarder_connectivity",
        keywords=("forwarder connectivity", "deployment client", "forwarder status", "uf status", "forwarder heartbeat", "heartbeat activity"),
        query="search index=_internal (sourcetype=splunkd OR sourcetype=deploymentclient) | stats count by host sourcetype | sort - count",
        tags=("splunk_internal", "platform_ops"),
        summary_hint="Focus on forwarder and deployment client connectivity signals.",
    ),
    QueryTemplate(
        intent="web_traffic_summary",
        keywords=("web traffic", "top uris", "http traffic summary", "web request volume"),
        query="search index=* NOT index=_* (sourcetype=access_combined OR sourcetype=apache:access OR sourcetype=nginx:access) | stats count by uri status clientip | sort - count",
        tags=("web", "operational", "top_n"),
        summary_hint="Focus on web traffic volume by URI, status, and client IP.",
    ),
    QueryTemplate(
        intent="network_flow_summary",
        keywords=("network flow", "top connections", "flow summary", "top src dest"),
        query="search index=* (sourcetype=stream:ip OR sourcetype=aws:cloudwatchlogs:vpcflow OR sourcetype=cisco:asa) | stats count by src dest dest_port action | sort - count",
        tags=("network", "operational", "top_n"),
        summary_hint="Focus on network flow volume by source, destination, and port.",
    ),
    QueryTemplate(
        intent="app_error_spike",
        keywords=("error spike", "application errors", "error log volume", "error count by host"),
        query="search index=* (error OR ERROR OR severity=error) | stats count by index sourcetype host | sort - count",
        tags=("operational", "top_n"),
        summary_hint="Focus on application error volume by index, sourcetype, and host.",
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


def question_requests_cardinality(question: str) -> bool:
    q = (question or "").strip().lower()
    return any(
        phrase in q
        for phrase in (
            "how many",
            "how much",
            "total number",
            "total count",
            "count of",
            "number of",
        )
    )


def apply_cardinality_transform(query: str, *, question: str = "") -> str:
    """Collapse breakdown queries to a scalar count of the requested entity."""
    rendered = str(query or "").strip()
    if not rendered:
        return rendered
    q = (question or "").strip().lower()

    entity_specs = (
        (r"\b(?:how many|number of|count of|total number of)\s+indexes?\b", "index", "index_count", "search index=* NOT index=_* | stats dc(index) as index_count"),
        (r"\b(?:how many|number of|count of|total number of)\s+sourcetypes?\b", "sourcetype", "sourcetype_count", "search index=* NOT index=_* | stats dc(sourcetype) as sourcetype_count"),
        (r"\b(?:how many|number of|count of|total number of)\s+hosts?\b", "host", "host_count", "search index=* NOT index=_* | stats dc(host) as host_count"),
    )
    for pattern, _field, _alias, replacement in entity_specs:
        if re.search(pattern, q):
            return replacement

    rendered = re.sub(r"\|\s*stats\s+count\s+by\s+[^|]+", "| stats count", rendered, flags=re.IGNORECASE)
    rendered = re.sub(r"\|\s*timechart\s+[^|]+", "| stats count", rendered, flags=re.IGNORECASE)
    rendered = re.sub(r"\|\s*table\s+[^|]+", "| stats count", rendered, flags=re.IGNORECASE)
    rendered = re.sub(r"\|\s*sort\s+-?\s*count(?:\s*\|\s*head\s+\d+)?", "", rendered, flags=re.IGNORECASE)
    rendered = re.sub(r"\|\s*head\s+\d+\s*$", "", rendered, flags=re.IGNORECASE)
    return re.sub(r"\s{2,}", " ", rendered).strip()
