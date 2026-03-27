# SPL Gold Standard Queries (Domain-Aware)

Lab-only query standards for this project. These are read-only investigation patterns intended to improve planner quality and reduce SPL drift.

## Core Rules
- Start with `search`.
- Use explicit time bounds via `earliest_time` and `latest_time`.
- Keep `row_limit <= 200`.
- Default to non-internal indexes unless the question explicitly asks for Splunk internal context.
- Use discovered Data Domains (index+sourcetype) and CIM/eventtype signals when available.

## Failed Login (Cross-Domain Default)
```spl
search index=* NOT index=_* (eventtype=failed_login OR info=failed OR action=failure OR "failed password" OR "authentication failure")
| eval src_ip=coalesce(src,src_ip,clientip,rhost,ip,Source_Network_Address,IpAddress)
| eval user_name=coalesce(user,username,TargetUserName,SubjectUserName,Account_Name)
| stats count by index host sourcetype user_name src_ip
| sort - count
```

## Linux Failed Login
Use the live auth log source first: `source="/var/log/auth.log"` or `source="/var/log/secure"`. Keep bounded `rex` fallbacks in the query so `auth-too_small`, `linux_secure`, or other parser variants still remain usable when field extraction is uneven.
```spl
search index=linux (source="/var/log/auth.log" OR source="/var/log/secure") ("Failed password" OR "authentication failure" OR "Invalid user" OR "Connection closed by invalid user" OR "FAILED SU")
| stats count by host user src_ip port
| sort - count
```

## Linux Failed Sudo / Privilege Escalation
```spl
search index=linux (source="/var/log/auth.log" OR source="/var/log/secure") ("pam_unix(sudo:auth): authentication failure" OR (("sudo:" OR "su:") ("authentication failure" OR "incorrect password" OR "failed")))
| rex field=_raw "(?i)logname=(?<logname_user>[^\s;]+)"
| rex field=_raw "(?i)ruser=(?<ruser>[^\s;]+)"
| rex field=_raw "(?i)\buser=(?<auth_user>[^\s;]+)"
| rex field=_raw "(?i)tty=(?<tty_value>[^\s;]+)"
| rex field=_raw "(?i)rhost=(?<src_ip>[^\s;]+)"
| eval actor=coalesce(logname_user,ruser,auth_user,user,account,uid,user_name)
| eval tty=coalesce(tty_value,tty)
| eval src_ip=if(isnull(src_ip) OR len(trim(src_ip))=0, "local", src_ip)
| stats count by host actor tty src_ip sourcetype
| sort - count
```

## Linux Sudo / Su Behavior Evidence
Use this when the analyst asks for sudo/su behavior or activity in general. This preserves both successful and unsuccessful evidence rows instead of forcing the question into a failures-only summary.
```spl
search index=linux (source="/var/log/auth.log" OR source="/var/log/secure") ("sudo:" OR "su:" OR "pam_unix(sudo:session)" OR "pam_unix(su:session)" OR "COMMAND=" OR "session opened for user root by" OR "incorrect password" OR "authentication failure")
| rex field=_raw "\s(?<process_name>sudo|su)(?:\[[^\]]+\])?:"
| rex field=_raw "(?i)sudo:\s+(?<sudo_actor>[A-Za-z0-9_.-]+)\s+:"
| rex field=_raw "(?i)by\s+(?<session_actor>[A-Za-z0-9_.-]+)\(uid="
| rex field=_raw "(?i)for user\s+(?<target_user>[A-Za-z0-9_.-]+)"
| rex field=_raw "(?i)USER=(?<target_user_cmd>[A-Za-z0-9_.-]+)"
| rex field=_raw "(?i)COMMAND=(?<command>.+)$"
| eval target_user=coalesce(target_user,target_user_cmd)
| eval outcome=case(match(_raw, "(?i)incorrect password|failure|failed"), "failure", match(_raw, "(?i)session opened"), "session_opened", match(_raw, "(?i)session closed"), "session_closed", match(_raw, "(?i)COMMAND="), "command", true(), "other")
| eval actor=coalesce(sudo_actor,session_actor,user,account,uid,user_name)
| eval src_ip=coalesce(rhost,src,src_ip,ip)
| table _time host sourcetype process_name outcome actor target_user command src_ip tty _raw
```

When the analyst explicitly names hosts, prepend a host scope such as:
```spl
search host IN (pidx1,pidx3) index=linux ...
```

## Linux First-Seen Privilege Escalation
Use this when the analyst is asking for newly observed or first-time sudo/su activity, not just failed escalation attempts.
```spl
search index=linux (source="/var/log/auth.log" OR source="/var/log/secure") ("session opened for user root by" OR "COMMAND=" OR "pam_unix(sudo:session)" OR "pam_unix(su:session)" OR "sudo:" OR "su:")
| eval user_name=coalesce(user,account,uid,user_name)
| eval src_ip=coalesce(rhost,src,src_ip,ip)
| stats earliest(_time) as first_seen latest(_time) as last_seen count by host user_name tty src_ip
| convert ctime(first_seen) ctime(last_seen)
| sort 0 first_seen
```

## Windows Authentication Failures
```spl
search index=windows sourcetype=XmlWinEventLog (EventCode=4625 OR "An account failed to log on")
| eval src_ip=coalesce(Source_Network_Address,IpAddress,src,src_ip)
| eval user_name=coalesce(TargetUserName,SubjectUserName,Account_Name,user)
| stats count by host sourcetype user_name src_ip
| sort - count
```

## Windows Process Activity
Use this when the analyst wants process creation evidence rather than a failed-auth summary. In BOTSv3 this maps cleanly to Sysmon-style EventID 1 in `xmlwineventlog`.
```spl
search (index=windows OR index=windows_sysmon) sourcetype=xmlwineventlog "<EventID>1</EventID>"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]+)</Data>"
| rex field=_raw "<Data Name='User'>(?<User>[^<]+)</Data>"
| rex field=_raw "<Data Name='ParentImage'>(?<ParentImage>[^<]+)</Data>"
| rex field=_raw "<Computer>(?<Computer>[^<]+)</Computer>"
| stats count by Computer Image CommandLine User ParentImage
| sort - count
| head 20
```

## Windows Sysmon Network Activity
Use this for Sysmon network connection evidence. In production, prefer `index=windows_sysmon` with Sysmon Operational events and keep the process image attached to the connection context.
```spl
search index=windows_sysmon sourcetype=XmlWinEventLog Channel="Microsoft-Windows-Sysmon/Operational" (EventID=3 OR EventCode=3 OR DestinationIp=*)
| table _time Computer Image SourceIp DestinationIp DestinationPort Protocol
| head 20
```

## Windows Sysmon DNS Activity
Use this for Sysmon DNS query evidence. Preserve the process image and the DNS query name instead of collapsing to host-only counts.
```spl
search index=windows_sysmon sourcetype=XmlWinEventLog Channel="Microsoft-Windows-Sysmon/Operational" (EventID=22 OR EventCode=22 OR QueryName=*)
| table _time Computer Image QueryName QueryResults
| head 20
```

## Windows Credential Access Activity
Use this when the analyst asks about stored-credential reads or Credential Manager access. Preserve the evidence rows instead of collapsing immediately to counts.
```spl
search index=windows sourcetype=XmlWinEventLog (EventID=5379 OR EventCode=5379 OR "CountOfCredentialsReturned")
| rex field=_raw "<Data Name='SubjectUserName'>(?<SubjectUserName>[^<]+)</Data>"
| rex field=_raw "<Data Name='TargetName'>(?<TargetName>[^<]+)</Data>"
| rex field=_raw "<Data Name='CountOfCredentialsReturned'>(?<CountOfCredentialsReturned>[^<]+)</Data>"
| rex field=_raw "<Data Name='ClientProcessId'>(?<ClientProcessId>[^<]+)</Data>"
| rex field=_raw "<Computer>(?<Computer>[^<]+)</Computer>"
| table _time Computer SubjectUserName TargetName CountOfCredentialsReturned ClientProcessId
```

## Linux Session Activity
Use this for PAM/cron session evidence when the analyst wants session-open/session-close behavior rather than failed SSH counts.
```spl
search index=linux (source="/var/log/auth.log" OR source="/var/log/secure") ("session opened for user" OR "session closed for user" OR "pam_unix(cron:session)")
| rex field=_raw "(?i)session (?<session_state>opened|closed) for user (?<session_user>[A-Za-z0-9_.-]+)"
| stats count by host sourcetype session_state session_user
| sort - count
| head 20
```

## Linux Audit Activity
Use this when the environment has auditd-style telemetry and the analyst wants an overview of audit types, operations, and results.
```spl
search index=<linux_audit_index> sourcetype=linux_audit
| rex field=_raw "type=(?<audit_type>[^ ]+)"
| rex field=_raw "\bop=(?<audit_op>[^ ]+)"
| rex field=_raw "\bres=(?<audit_res>[^ ]+)"
| stats count by host audit_type audit_op audit_res
| sort - count
| head 20
```

## Apache Access (Top Client IPs)
```spl
search index=linux sourcetype=access_combined
| eval src_ip=coalesce(clientip,src,src_ip,ip)
| stats count by src_ip status method
| sort - count
```

## Apache 404 Spike
```spl
search index=linux sourcetype=access_combined status=404
| timechart span=1h count by host limit=10
```

## Internal Splunk Auth (Explicit-Only)
Use only when question explicitly requests Splunk internal authentication context.
```spl
search index=_audit sourcetype=audittrail info=failed
| stats count by host user src
| sort - count
```

## AWS CloudTrail API Activity
Use this for CloudTrail service/action overviews. Keep the query generic in production. BOTSv3 all-time testing is valid only because that dataset is historical.
```spl
search index=<aws_index> sourcetype=aws:cloudtrail
| eval principal=coalesce('userIdentity.arn','userIdentity.principalId','userIdentity.type')
| eval error_state=coalesce(errorCode,errorMessage,"success")
| stats count by eventSource eventName sourceIPAddress principal userAgent error_state
| sort - count
| head 20
```

## Splunk Index Inventory (Non-Internal Default)
```spl
search index=* NOT index=_*
| stats count by index
| sort - count
```

## Query Authoring Notes
- Prefer `coalesce(...)` for source/user normalization across heterogeneous logs.
- For Linux SSH auth logs, prefer extracted `user`, `src_ip`, and `port` when the sourcetype already provides them.
- Do not use `match(...(?<capture>...))` as a pseudo-extraction strategy. `match()` does not create fields in Splunk.
- Prefer deterministic field references over speculative fields.
- Keep `earliest_time`, `latest_time`, and `row_limit` out of the SPL body. They belong in tool arguments, not in the query string.
- If no rows are returned, pivot by:
  - index
  - sourcetype
  - host
  - source IP / user
