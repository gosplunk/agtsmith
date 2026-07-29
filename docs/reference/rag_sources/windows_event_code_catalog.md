# Windows Security and Sysmon Event Code Catalog (Tier 1)

**Document Type**: Detection Reference for SPL authoring and SOC review  
**Audience**: SPL writer, planner, Foundation-Sec evidence/security reviewers  
**Keywords**: EventCode, EventID, XmlWinEventLog, Sysmon, 4625, 4624, 4688, 5379, failed logon, process creation

Use this catalog to pick the **correct Windows event code**, required fields, and SPL filters. Do not answer process-creation questions with 4625, and do not answer failed-logon questions with Sysmon EventID 1.

---

## 4625 — Failed Logon (Security)

- **Intent**: `windows_auth_failures`
- **Channel**: Security
- **MITRE**: T1110
- **Key fields**: TargetUserName, IpAddress, Source_Network_Address, LogonType, FailureReason
- **SPL filter**:

```spl
search (index=windows OR index=windows_sysmon OR index=botsv3 OR index=soc_windows) (sourcetype=XmlWinEventLog OR sourcetype=xmlwineventlog OR sourcetype=WinEventLog) (EventCode=4625 OR EventID=4625 OR "An account failed to log on")
| eval src_ip=coalesce(Source_Network_Address,IpAddress,src,src_ip,clientip,ip)
| eval user_name=coalesce(TargetUserName,SubjectUserName,Account_Name,user,username)
| table _time index host user_name src_ip EventCode EventID
```

- **Anti-patterns**: never apply 4625 to `linux_secure`; do not require `Channel=Security` if it zeroes rows on XmlWinEventLog indexes

---

## 4624 — Successful Logon (Security)

- **Intent**: `windows_successful_logons`
- **Channel**: Security
- **MITRE**: T1078
- **Key fields**: TargetUserName, IpAddress, LogonType, WorkstationName

```spl
search (index=windows OR index=botsv3 OR index=soc_windows) sourcetype=XmlWinEventLog (EventCode=4624 OR EventID=4624 OR "An account was successfully logged on")
| eval src_ip=coalesce(Source_Network_Address,IpAddress,src,src_ip,clientip,ip)
| eval user_name=coalesce(TargetUserName,SubjectUserName,Account_Name,user,username)
| table _time index host user_name src_ip EventCode EventID LogonType
```

---

## 4672 — Special Privileges Assigned (Security)

- **Intent**: `windows_privilege_assigned_activity`
- **Channel**: Security
- **MITRE**: T1078, T1548

```spl
search (index=windows OR index=botsv3 OR index=soc_windows) sourcetype=XmlWinEventLog (EventCode=4672 OR EventID=4672 OR "Special privileges assigned to new logon")
| eval user_name=coalesce(SubjectUserName,TargetUserName,user,username)
| table _time Computer user_name PrivilegeList EventCode EventID
```

---

## 4688 — Process Creation Audit (Security)

- **Intent**: `windows_process_audit_activity`
- **Channel**: Security
- **MITRE**: T1059, T1204
- **Key fields**: New_Process_Name, Process_Command_Line, SubjectUserName, Creator_Process_Name

```spl
search (index=windows OR index=botsv3 OR index=soc_windows) sourcetype=XmlWinEventLog (EventCode=4688 OR EventID=4688 OR "A new process has been created")
| eval process_name=coalesce(New_Process_Name,Process_Name,Image)
| eval command_line=coalesce(Process_Command_Line,CommandLine)
| eval user_name=coalesce(SubjectUserName,TargetUserName,user,username)
| table _time Computer user_name process_name command_line Creator_Process_Name
```

---

## Sysmon 1 — Process Create

- **Intent**: `windows_process_activity`
- **Channel**: Microsoft-Windows-Sysmon/Operational
- **MITRE**: T1059, T1204

```spl
search (index=windows_sysmon OR index=botsv3 OR index=soc_windows) sourcetype=XmlWinEventLog Channel="Microsoft-Windows-Sysmon/Operational" ("<EventID>1</EventID>" OR EventID=1 OR EventCode=1)
| table _time Computer Image CommandLine User ParentImage
```

---

## Sysmon 3 — Network Connection

- **Intent**: `windows_sysmon_network_activity`
- **Channel**: Microsoft-Windows-Sysmon/Operational
- **MITRE**: T1071, T1021

```spl
search (index=windows_sysmon OR index=botsv3 OR index=soc_windows) sourcetype=XmlWinEventLog Channel="Microsoft-Windows-Sysmon/Operational" (EventID=3 OR EventCode=3 OR DestinationIp=*)
| table _time Computer Image SourceIp DestinationIp DestinationPort Protocol
```

---

## Sysmon 22 — DNS Query

- **Intent**: `windows_sysmon_dns_activity`
- **Channel**: Microsoft-Windows-Sysmon/Operational
- **MITRE**: T1071, T1568

```spl
search (index=windows_sysmon OR index=botsv3 OR index=soc_windows) sourcetype=XmlWinEventLog Channel="Microsoft-Windows-Sysmon/Operational" (EventID=22 OR EventCode=22 OR QueryName=*)
| table _time Computer Image QueryName QueryResults
```

---

## 5379 — Credential Manager Access

- **Intent**: `windows_credential_access_activity`
- **Channel**: Security
- **MITRE**: T1555, T1003

```spl
search (index=windows OR index=botsv3 OR index=soc_windows) sourcetype=XmlWinEventLog (EventID=5379 OR EventCode=5379 OR "CountOfCredentialsReturned")
| table _time Computer SubjectUserName TargetName CountOfCredentialsReturned ClientProcessId
```

---

## Reviewer checklist (Foundation-Sec)

When reviewing Windows query results:

1. Confirm the SPL event code matches the user question (4625 vs 1 vs 4688 vs 5379).
2. Confirm result rows include the catalog key fields when populated in the environment.
3. Flag cross-platform contamination (4625 in linux branch, Sysmon fields in auth-only questions).
4. Prefer table/head shapes for investigative row review; stats for summary counts.
