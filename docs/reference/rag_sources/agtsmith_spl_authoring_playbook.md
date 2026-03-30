# A.G.E.N.T. Smith SPL Authoring Playbook

This playbook exists to help the query-writing model prefer simple, dataset-grounded SPL over speculative or over-engineered search logic.

## Global Rules
- Start with `search`.
- Keep `earliest_time`, `latest_time`, and `row_limit` out of the SPL body.
- Default to non-internal indexes unless the analyst explicitly asks for Splunk internal telemetry.
- Prefer the simplest field-native query that answers the question.
- Only parse `_raw` when the environment profile shows the needed field is not already extracted.
- Do not use `match(...(?<capture>...))` as field extraction. `match()` returns boolean, not extracted fields.
- Prefer `stats` for aggregation questions such as top, count, concentration, first seen, and summary by entity.
- Prefer `table` for evidence inspection questions when the analyst wants to inspect individual events.

## Linux Auth Failures
- Preferred index: `index=linux`
- Prefer the live Linux auth log source first: `source="/var/log/auth.log"` or `source="/var/log/secure"`. If extracted sourcetypes are present, auth-log variants such as `auth.log` and `linux_secure` are acceptable.
- Preferred fields: `host`, `user`, `src_ip`, `port`
- Default query shape:

```spl
search index=linux (source="/var/log/auth.log" OR source="/var/log/secure") ("Failed password" OR "authentication failure" OR "Invalid user" OR "FAILED SU")
| stats count by host user src_ip port
| sort - count
```

- Anti-patterns:
  - do not use wildcard indexes for Linux-specific questions
  - do not invent `eval case(match(_raw, ... (?<capture>...)))`
  - do not collapse the answer to `host` only when `user`, `src_ip`, and `port` exist

## Windows Authentication Failures
- Preferred indexes: `index=windows` or `index=windows_sysmon`
- Preferred sourcetype: `XmlWinEventLog`
- Preferred detection signals: `EventCode=4625`, `EventID=4625`, `"An account failed to log on"`
- Preferred normalized fields: `user_name`, `src_ip`
- Default query shape:

```spl
search (index=windows OR index=windows_sysmon) sourcetype=XmlWinEventLog (EventCode=4625 OR EventID=4625 OR "An account failed to log on")
| eval src_ip=coalesce(Source_Network_Address,IpAddress,src,src_ip,clientip,ip)
| eval user_name=coalesce(TargetUserName,SubjectUserName,Account_Name,user,username)
| stats count by index host user_name src_ip
| sort - count
```

- Anti-patterns:
  - do not drift to Linux or `_audit` for Windows auth questions
  - do not use `index=*` when the platform is explicitly Windows

## Windows Process Activity
- Preferred indexes: `index=windows`, `index=windows_sysmon`, or benchmark-only `index=botsv3`
- Preferred sourcetype: `xmlwineventlog`
- Preferred detection signal: Sysmon/EventID `1`
- Preferred fields: `Computer`, `Image`, `CommandLine`, `User`, `ParentImage`
- Default query shape:

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

- Anti-patterns:
  - do not answer process-creation questions with failed-logon events
  - do not drop `CommandLine` and `ParentImage` when the question is investigative

## Windows Sysmon Network Activity
- Preferred index: `index=windows_sysmon`
- Preferred sourcetype: `XmlWinEventLog`
- Preferred detection signals: `Channel="Microsoft-Windows-Sysmon/Operational"`, `EventID=3`, `DestinationIp`
- Preferred fields: `Computer`, `Image`, `SourceIp`, `DestinationIp`, `DestinationPort`, `Protocol`
- Default query shape:

```spl
search index=windows_sysmon sourcetype=XmlWinEventLog Channel="Microsoft-Windows-Sysmon/Operational" (EventID=3 OR EventCode=3 OR DestinationIp=*)
| table _time Computer Image SourceIp DestinationIp DestinationPort Protocol
| head 20
```

- Anti-patterns:
  - do not answer Sysmon network questions with generic firewall or VPC flow queries
  - do not drop `Image` or `DestinationIp` from the result shape

## Windows Sysmon DNS Activity
- Preferred index: `index=windows_sysmon`
- Preferred sourcetype: `XmlWinEventLog`
- Preferred detection signals: `Channel="Microsoft-Windows-Sysmon/Operational"`, `EventID=22`, `QueryName`
- Preferred fields: `Computer`, `Image`, `QueryName`, `QueryResults`
- Default query shape:

```spl
search index=windows_sysmon sourcetype=XmlWinEventLog Channel="Microsoft-Windows-Sysmon/Operational" (EventID=22 OR EventCode=22 OR QueryName=*)
| table _time Computer Image QueryName QueryResults
| head 20
```

- Anti-patterns:
  - do not answer Sysmon DNS questions with Windows authentication or generic DNS-only telemetry
  - do not remove `QueryName` and `Image` from the result shape

## Windows Credential Access Activity
- Preferred index: `index=windows`
- Preferred sourcetype: `XmlWinEventLog`
- Preferred detection signals: `EventID=5379`, `EventCode=5379`, `CountOfCredentialsReturned`
- Preferred fields: `Computer`, `SubjectUserName`, `TargetName`, `CountOfCredentialsReturned`, `ClientProcessId`
- Default query shape:

```spl
search index=windows sourcetype=XmlWinEventLog (EventID=5379 OR EventCode=5379 OR "CountOfCredentialsReturned")
| rex field=_raw "<Data Name='SubjectUserName'>(?<SubjectUserName>[^<]+)</Data>"
| rex field=_raw "<Data Name='TargetName'>(?<TargetName>[^<]+)</Data>"
| rex field=_raw "<Data Name='CountOfCredentialsReturned'>(?<CountOfCredentialsReturned>[^<]+)</Data>"
| rex field=_raw "<Data Name='ClientProcessId'>(?<ClientProcessId>[^<]+)</Data>"
| rex field=_raw "<Computer>(?<Computer>[^<]+)</Computer>"
| table _time Computer SubjectUserName TargetName CountOfCredentialsReturned ClientProcessId
```

- Anti-patterns:
  - do not collapse evidence-row questions into `stats count by ...`
  - do not drift from EventID 5379 into generic authentication failures

## Linux Session Activity
- Preferred index: `index=linux`
- Prefer the live Linux auth log source first: `source="/var/log/auth.log"` or `source="/var/log/secure"`. If extracted sourcetypes are present, auth-log variants such as `auth.log` and `linux_secure` are acceptable.
- Preferred signals: `session opened for user`, `session closed for user`, `pam_unix(cron:session)`
- Preferred fields: `host`, `session_state`, `session_user`
- Default query shape:

```spl
search index=linux (source="/var/log/auth.log" OR source="/var/log/secure") ("session opened for user" OR "session closed for user" OR "pam_unix(cron:session)")
| rex field=_raw "(?i)session (?<session_state>opened|closed) for user (?<session_user>[A-Za-z0-9_.-]+)"
| stats count by host sourcetype session_state session_user
| sort - count
| head 20
```

- Anti-patterns:
  - do not answer session-activity questions with failed SSH counts
  - do not drop `session_state` or `session_user`

## Linux Audit Activity
- Preferred index: environment-specific; `index=botsv3` is benchmark-only and `index=main` may be valid in some local labs
- Preferred sourcetype: `linux_audit`
- Preferred fields: `audit_type`, `audit_op`, `audit_res`, `host`
- Default query shape:

```spl
search index=<linux_audit_index> sourcetype=linux_audit
| rex field=_raw "type=(?<audit_type>[^ ]+)"
| rex field=_raw "\bop=(?<audit_op>[^ ]+)"
| rex field=_raw "\bres=(?<audit_res>[^ ]+)"
| stats count by host audit_type audit_op audit_res
| sort - count
| head 20
```

- Anti-patterns:
  - do not hard-code `index=botsv3` into reusable production guidance
  - do not summarize Linux audit activity without preserving `audit_type`, `audit_op`, and `audit_res`

## Linux Privilege Escalation First Seen
- Preferred index: `index=linux`
- Prefer the live Linux auth log source first: `source="/var/log/auth.log"` or `source="/var/log/secure"`. If extracted sourcetypes are present, auth-log variants such as `auth.log` and `linux_secure` are acceptable.
- Preferred signals: `"session opened for user root by"`, `"COMMAND="`, `"pam_unix(sudo:session)"`, `"pam_unix(su:session)"`, `"sudo:"`, `"su:"`
- Required shape: `earliest(_time) as first_seen`
- Default query shape:

```spl
search index=linux (source="/var/log/auth.log" OR source="/var/log/secure") ("session opened for user root by" OR "COMMAND=" OR "pam_unix(sudo:session)" OR "pam_unix(su:session)" OR "sudo:" OR "su:")
| eval user_name=coalesce(user,account,uid,user_name)
| eval src_ip=coalesce(rhost,src,src_ip,ip)
| stats earliest(_time) as first_seen latest(_time) as last_seen count by host user_name tty src_ip
| convert ctime(first_seen) ctime(last_seen)
| sort 0 first_seen
```

- Anti-patterns:
  - do not answer first-seen questions with plain `stats count by ...`
  - do not use failure-only strings for successful privilege-escalation questions

## Apache Access Investigation
- Preferred index: `index=linux`
- Preferred sourcetype: `access_combined`
- Preferred fields: `clientip`, `status`, `method`, `uri`, `uri_path`, `useragent`
- Top IP query shape:

```spl
search index=linux sourcetype=access_combined
| stats count by clientip status method
| sort - count
```

- Anti-patterns:
  - do not invent Apache-specific indexes when the domain is `access_combined`
  - do not group by low-signal fields first

## Query Repair Priorities
- First repair the index and sourcetype.
- Then repair the field list using the environment profile.
- Then simplify the query shape.
- Only add parsing logic if a required field truly does not exist in the sourcetype field inventory.

## CloudTrail Authoring Pattern
When the analyst is asking for AWS API activity, CloudTrail service/action breakdowns, or suspicious CloudTrail sources, prefer a query shape like:

```spl
search index=<aws_index> sourcetype=aws:cloudtrail
| eval principal=coalesce('userIdentity.arn','userIdentity.principalId','userIdentity.type')
| eval error_state=coalesce(errorCode,errorMessage,"success")
| stats count by eventSource eventName sourceIPAddress principal userAgent error_state
| sort - count
| head 20
```

Use this pattern because it preserves:
- service (`eventSource`)
- action (`eventName`)
- source (`sourceIPAddress`)
- caller identity (`principal`)
- success versus error outcome (`error_state`)

Do not hard-code `index=botsv3` or `earliest=0` in the reusable guidance. Those are benchmark-only BOTSv3 accommodations, not production defaults.
