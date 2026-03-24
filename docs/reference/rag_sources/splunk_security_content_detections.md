# Splunk Security Content Detections - Comprehensive Reference

## Overview

This document provides a comprehensive reference for Splunk Security Content detections from the official [security_content GitHub repository](https://github.com/splunk/security_content). It includes SPL searches, MITRE ATT&CK mappings, data source requirements, and implementation guidance for security analysts and engineers.

**Source Repository:** https://github.com/splunk/security_content  
**Detection Categories:** Endpoint, Cloud, Network, Web, Application

---

## Table of Contents

1. [Detection Categories Overview](#detection-categories-overview)
2. [Endpoint Detections](#endpoint-detections)
   - Windows Process Execution
   - Credential Access
   - Defense Evasion
   - Persistence
   - Ransomware
3. [Cloud Detections](#cloud-detections)
   - AWS Security
   - Azure Active Directory
   - Microsoft 365
   - Kubernetes
4. [Network Detections](#network-detections)
   - DNS Analysis
   - Command and Control
   - Data Exfiltration
5. [Web Detections](#web-detections)
   - CVE Exploits
   - Web Shells
   - SQL Injection
6. [Application Detections](#application-detections)
   - Okta Security
7. [MITRE ATT&CK Reference](#mitre-attck-reference)
8. [Data Source Requirements](#data-source-requirements)
9. [Implementation Guide](#implementation-guide)

---

## Detection Categories Overview

| Category | Description | Typical Detection Count |
|----------|-------------|------------------------|
| **Endpoint** | Windows, Linux, Mac endpoint detections (process, filesystem, registry) | 500+ |
| **Cloud** | AWS, Azure, GCP, O365, Kubernetes, GitHub, Okta | 150+ |
| **Network** | DNS, SMB, TOR traffic, network anomalies | 50+ |
| **Web** | Web attacks, CVE exploits, web shells | 70+ |
| **Application** | Okta, Duo, ESXi, Ollama, email | 60+ |

---

## Endpoint Detections

### Windows Process Injection Remote Thread

**Detection ID:** `8a618ade-ca8f-4d04-b972-2d526ba59924`  
**Type:** TTP  
**MITRE ATT&CK:** T1055.002 (Process Injection: Portable Executable Injection)  
**Data Sources:** Sysmon EventID 8  
**Analytic Stories:** Qakbot, Graceful Wipe Out Attack, Warzone RAT, Earth Alux, Water Gamayun

**Description:**
Detects suspicious remote thread execution in processes such as Taskmgr.exe, calc.exe, and notepad.exe, which may indicate process injection by malware like Qakbot. This detection leverages Sysmon EventCode 8 to identify remote thread creation in specific target processes.

**SPL Search:**
```spl
`sysmon` EventCode=8 TargetImage IN ("*\\Taskmgr.exe", "*\\calc.exe", "*\\notepad.exe",
  "*\\rdpclip.exe", "*\\explorer.exe", "*\\wermgr.exe", "*\\ping.exe", "*\\OneDriveSetup.exe",
  "*\\dxdiag.exe", "*\\mobsync.exe", "*\\msra.exe", "*\\xwizard.exe","*\\cmd.exe",
  "*\\powershell.exe") 
| stats count min(_time) as firstTime max(_time) as lastTime
  by EventID Guid NewThreadId ProcessID SecurityID SourceImage SourceProcessGuid SourceProcessId
  StartAddress StartFunction StartModule TargetImage TargetProcessGuid TargetProcessId
  UserID dest parent_process_exec parent_process_guid parent_process_id parent_process_name
  parent_process_path process_exec process_guid process_id process_name process_path
  signature signature_id user_id vendor_product 
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` 
| `windows_process_injection_remote_thread_filter`
```

**Implementation Requirements:**
- Sysmon version 6.0.4 or higher with EventCode 8 enabled
- Sysmon TA for Splunk

---

### Windows Credential Dumping LSASS Memory Createdump

**Detection ID:** `b3b7ce35-fce5-4c73-85f4-700aeada81a9`  
**Type:** TTP  
**MITRE ATT&CK:** T1003.001 (OS Credential Dumping: LSASS Memory)  
**Data Sources:** Sysmon EventID 1, Windows Event Log Security 4688, CrowdStrike ProcessRollup2  
**Analytic Stories:** Compromised Windows Host, Credential Dumping, Scattered Lapsus$ Hunters

**Description:**
Detects the use of CreateDump.exe to perform a process dump, which is not native to Windows and is often introduced by third-party applications including PowerShell 7. This may indicate an attempt to dump LSASS memory for credential extraction.

**SPL Search:**
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime 
  from datamodel=Endpoint.Processes 
  where Processes.process_name=createdump.exe
  OR Processes.original_file_name="FX_VER_INTERNALNAME_STR" 
  Processes.process="*-u *" AND Processes.process="*-f *" 
  by Processes.action Processes.dest Processes.original_file_name
  Processes.parent_process Processes.parent_process_exec Processes.parent_process_guid
  Processes.parent_process_id Processes.parent_process_name Processes.parent_process_path
  Processes.process Processes.process_exec Processes.process_guid Processes.process_hash
  Processes.process_id Processes.process_integrity_level Processes.process_name
  Processes.process_path Processes.user Processes.user_id Processes.vendor_product 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` 
| `windows_credential_dumping_lsass_memory_createdump_filter`
```

**Implementation Requirements:**
- EDR agent data ingestion with process command-line logging
- Endpoint data model mapping using CIM

---

### Windows Defender Exclusion Registry Entry

**Detection ID:** `13395a44-4dd9-11ec-9df7-acde48001122`  
**Type:** TTP  
**MITRE ATT&CK:** T1562.001 (Impair Defenses: Disable or Modify Tools)  
**Data Sources:** Sysmon EventID 13  
**Analytic Stories:** Qakbot, Remcos, ValleyRAT, XWorm, Azorult, Warzone RAT, Windows Defense Evasion Tactics

**Description:**
Detects modifications to Windows Defender exclusion registry entries. Adversaries often modify these entries to bypass Windows Defender, allowing malicious code to execute without detection.

**SPL Search:**
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime 
  FROM datamodel=Endpoint.Registry 
  WHERE (Registry.registry_path = "*\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Exclusions\\*") 
  by Registry.action Registry.dest Registry.process_guid Registry.process_id 
  Registry.registry_hive Registry.registry_path Registry.registry_key_name
  Registry.registry_value_data Registry.registry_value_name Registry.registry_value_type
  Registry.status Registry.user Registry.vendor_product 
| `drop_dm_object_name(Registry)` 
| where isnotnull(registry_value_data) 
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` 
| `windows_defender_exclusion_registry_entry_filter`
```

**Implementation Requirements:**
- Sysmon 2.0+ with registry monitoring enabled
- Registry value data capture configured

---

### Detect Exchange Web Shell

**Detection ID:** `8c14eeee-2af1-4a4b-bda8-228da0f4862a`  
**Type:** TTP  
**MITRE ATT&CK:** T1133 (External Remote Services), T1190 (Exploit Public-Facing Application), T1505.003 (Web Shell)  
**Data Sources:** Sysmon EventID 11  
**Analytic Stories:** ProxyNotShell, CISA AA22-257A, HAFNIUM Group, ProxyShell, BlackByte Ransomware

**Description:**
Detects web shell files (aspx, ashx) being written to Exchange Server directories commonly targeted by attackers including HttpProxy, inetpub/aspnet_client, and OAB paths.

**SPL Search:**
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime 
  FROM datamodel=Endpoint.Filesystem 
  where Filesystem.file_path IN ("*\\HttpProxy\\owa\\auth\\*",
  "*\\inetpub\\wwwroot\\aspnet_client\\*", "*\\HttpProxy\\OAB\\*")
  Filesystem.file_name IN ("*.aspx", "*.ashx") 
  by Filesystem.action Filesystem.dest Filesystem.file_access_time Filesystem.file_create_time 
  Filesystem.file_hash Filesystem.file_modify_time Filesystem.file_name Filesystem.file_path 
  Filesystem.file_acl Filesystem.file_size Filesystem.process_guid Filesystem.process_id 
  Filesystem.user Filesystem.vendor_product 
| `drop_dm_object_name(Filesystem)` 
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` 
| `detect_exchange_web_shell_filter`
```

---

### Detect RTLO In Process (Right-to-Left Override)

**Detection ID:** `22ac27b4-7189-4a4f-9375-b9017c9620d7`  
**Type:** TTP  
**MITRE ATT&CK:** T1036.002 (Masquerading: Right-to-Left Override)  
**Data Sources:** Sysmon EventID 1, Windows Event Log Security 4688, CrowdStrike ProcessRollup2  
**Analytic Stories:** Spearphishing Attachments

**Description:**
Detects the use of Right-to-Left Override (RTLO) Unicode character in process command lines, which attackers use to disguise malicious file extensions.

**SPL Search:**
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime 
  from datamodel=Endpoint.Processes 
  where Processes.process!=unknown AND Processes.action=allowed 
  by Processes.action Processes.dest Processes.original_file_name Processes.parent_process 
  Processes.parent_process_exec Processes.parent_process_guid Processes.parent_process_id 
  Processes.parent_process_name Processes.parent_process_path Processes.process 
  Processes.process_exec Processes.process_guid Processes.process_hash Processes.process_id 
  Processes.process_integrity_level Processes.process_name Processes.process_path 
  Processes.user Processes.user_id Processes.vendor_product 
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` 
| `drop_dm_object_name(Processes)` 
| regex process="\\x{202E}"
| rex field=process "(?<RTLO_command_1>.+)(?<RTLO_exist_process>\\x{202E})(?<RTLO_command_2>.+)"
| eval process_with_RTLO=process 
| eval process=RTLO_command_1.RTLO_command_2 
| fields - RTLO* 
| `detect_rtlo_in_process_filter`
```

---

### Ryuk Ransomware Test Files Detected

**Detection ID:** `57d44d70-28d9-4ed1-acf5-1c80ae2bbce3`  
**Type:** TTP  
**MITRE ATT&CK:** T1486 (Data Encrypted for Impact)  
**Data Sources:** Sysmon EventID 11  
**Analytic Stories:** Ryuk Ransomware

**Description:**
Detects file activity related to Ryuk ransomware test files created in the C:\ drive, indicating potential ransomware deployment.

**SPL Search:**
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime 
  FROM datamodel=Endpoint.Filesystem 
  WHERE "Filesystem.file_path"=C:\\*Ryuk*
  by Filesystem.action Filesystem.dest Filesystem.file_access_time Filesystem.file_create_time
  Filesystem.file_hash Filesystem.file_modify_time Filesystem.file_name Filesystem.file_path
  Filesystem.file_acl Filesystem.file_size Filesystem.process_guid Filesystem.process_id
  Filesystem.user Filesystem.vendor_product 
| `drop_dm_object_name(Filesystem)` 
| `security_content_ctime(lastTime)` | `security_content_ctime(firstTime)` 
| `ryuk_test_files_detected_filter`
```

---

### Linux Auditd Possible Access To Credential Files

**Detection ID:** `0419cb7a-57ea-467b-974f-77c303dfe2a3`  
**Type:** Anomaly  
**MITRE ATT&CK:** T1003.008 (/etc/passwd and /etc/shadow)  
**Data Sources:** Linux Auditd Proctitle  
**Analytic Stories:** Linux Persistence Techniques, Compromised Linux Host, Linux Privilege Escalation

**Description:**
Detects attempts to read credential files (/etc/shadow, /etc/passwd) using common text viewing tools, which may indicate credential harvesting on Linux systems.

**SPL Search:**
```spl
`linux_auditd` proctitle IN ("*shadow*", "*passwd*") AND proctitle IN ("*cat *", "*nano *", "*vim *", "*vi *") 
| rename host as dest 
| stats count min(_time) as firstTime max(_time) as lastTime by proctitle dest 
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` 
| `linux_auditd_possible_access_to_credential_files_filter`
```

---

## Cloud Detections

### AWS IAM Delete Policy

**Detection ID:** `ec3a9362-92fe-11eb-99d0-acde48001122`  
**Type:** Hunting  
**MITRE ATT&CK:** T1098 (Account Manipulation)  
**Data Sources:** AWS CloudTrail DeletePolicy  
**Analytic Stories:** AWS IAM Privilege Escalation

**Description:**
Detects AWS IAM policy deletion events, which could indicate an attacker attempting to remove security controls or cover tracks.

**SPL Search:**
```spl
`cloudtrail` eventName=DeletePolicy (userAgent!=*.amazonaws.com) 
| rename user_name as user
| stats count min(_time) as firstTime max(_time) as lastTime 
  by signature dest user user_agent src vendor_account vendor_region vendor_product
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` 
| `aws_iam_delete_policy_filter`
```

---

### AWS IAM Assume Role Policy Brute Force (Amazon Security Lake)

**Detection ID:** `726959fe-316d-445c-a584-fa187d64e295`  
**Type:** TTP  
**MITRE ATT&CK:** T1580 (Cloud Infrastructure Discovery), T1110 (Brute Force)  
**Data Sources:** ASL AWS CloudTrail  
**Analytic Stories:** AWS IAM Privilege Escalation, Scattered Lapsus$ Hunters

**Description:**
Detects multiple failed AssumeRole attempts which may indicate brute force attempts to discover valid role names or privilege escalation attempts.

**SPL Search:**
```spl
`amazon_security_lake` api.operation="AssumeRole" "api.response.error"=AccessDenied 
| bucket _time span=1h 
| stats count as failures min(_time) as firstTime max(_time) as lastTime 
  values(api.operation) as api.operation values(api.service.name) as api.service.name
  values(http_request.user_agent) as http_request.user_agent values(src_endpoint.ip) as src_ip
  values(actor.user.account.uid) as actor.user.account.uid values(cloud.provider) as cloud.provider 
  values(cloud.region) as cloud.region by _time actor.user.uid 
| where failures >= 3 
| rename actor.user.uid as user api.operation as action api.service.name as dest 
  http_request.user_agent as user_agent src_endpoint.ip as src actor.user.account.uid as vendor_account 
  cloud.provider as vendor_product cloud.region as vendor_region 
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` 
| `asl_aws_iam_assume_role_policy_brute_force_filter`
```

---

### Azure AD PIM Role Assigned

**Detection ID:** `fcd6dfeb-191c-46a0-a29c-c306382145ab`  
**Type:** TTP  
**MITRE ATT&CK:** T1098.003 (Additional Cloud Roles)  
**Data Sources:** Azure Active Directory  
**Analytic Stories:** Azure Active Directory Privilege Escalation, Azure Active Directory Persistence, Scattered Lapsus$ Hunters

**Description:**
Detects when privileged roles are assigned through Azure AD Privileged Identity Management (PIM), which could indicate unauthorized privilege escalation.

**SPL Search:**
```spl
`azure_monitor_aad` operationName="Add eligible member to role in PIM completed*" 
| rename properties.* as * 
| fillnull 
| stats count min(_time) as firstTime max(_time) as lastTime 
  by dest user src vendor_account vendor_product signature
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` 
| `azure_ad_pim_role_assigned_filter`
```

---

### O365 SharePoint Malware Detection

**Detection ID:** `583c5de3-7709-44cb-abfc-0e828d301b59`  
**Type:** TTP  
**MITRE ATT&CK:** T1204.002 (User Execution: Malicious File)  
**Data Sources:** Office 365 Universal Audit Log  
**Analytic Stories:** Azure Active Directory Persistence, Office 365 Account Takeover, Ransomware Cloud

**Description:**
Detects when Microsoft Defender for Office 365 identifies malware in SharePoint, OneDrive, or Teams files.

**SPL Search:**
```spl
`o365_management_activity` Operation=FileMalwareDetected 
| rename UserId as user, Id as signature_id 
| stats values(Workload) as category, values(SourceFileName) as file_name 
  values(ObjectId) as file_path, values(VirusInfo) as signature, count,
  min(_time) as firstTime, max(_time) as lastTime 
  by signature_id, user, dest, src, vendor_account, vendor_product 
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
| `o365_sharepoint_malware_detection_filter`
```

---

### Kubernetes Falco Shell Spawned

**Detection ID:** `d2feef92-d54a-4a19-8306-b47c6ceba5b2`  
**Type:** Anomaly  
**MITRE ATT&CK:** T1204 (User Execution)  
**Data Sources:** Kubernetes Falco  
**Analytic Stories:** Kubernetes Security

**Description:**
Detects when a shell is spawned inside a Kubernetes container, which may indicate container escape attempts or unauthorized access.

**SPL Search:**
```spl
`kube_container_falco` "A shell was spawned in a container" 
| fillnull
| stats count by container_image container_image_tag container_name parent proc_exepath process user 
| `kubernetes_falco_shell_spawned_filter`
```

---

## Network Detections

### TOR Traffic

**Detection ID:** `ea688274-9c06-4473-b951-e4cb7a5d7a45`  
**Type:** TTP  
**MITRE ATT&CK:** T1090.003 (Proxy: Multi-hop Proxy)  
**Data Sources:** Palo Alto Network Traffic, Cisco Secure Firewall Threat Defense  
**Analytic Stories:** Prohibited Traffic Allowed, Ransomware, NOBELIUM Group, Command And Control

**Description:**
Detects allowed TOR network traffic, which may indicate unauthorized anonymization attempts or command and control communication.

**SPL Search:**
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime 
  from datamodel=Network_Traffic 
  where All_Traffic.app=tor AND All_Traffic.action IN ("allowed", "allow") 
  by All_Traffic.action All_Traffic.app All_Traffic.bytes All_Traffic.bytes_in All_Traffic.bytes_out 
  All_Traffic.dest All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.dvc All_Traffic.protocol
  All_Traffic.protocol_version All_Traffic.src All_Traffic.src_ip All_Traffic.src_port 
  All_Traffic.transport All_Traffic.user All_Traffic.vendor_product All_Traffic.rule 
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` 
| `drop_dm_object_name("All_Traffic")` 
| `tor_traffic_filter`
```

---

### Detect Outbound SMB Traffic

**Detection ID:** `1bed7774-304a-4e8f-9d72-d80e45ff492b`  
**Type:** TTP  
**MITRE ATT&CK:** T1071.002 (Application Layer Protocol: File Transfer Protocols)  
**Data Sources:** Cisco Secure Firewall Threat Defense  
**Analytic Stories:** Hidden Cobra Malware, DHS Report TA18-074A, NOBELIUM Group

**Description:**
Detects outbound SMB traffic (ports 139, 445) from internal networks to external destinations, which may indicate data exfiltration or lateral movement attempts.

**SPL Search:**
```spl
| tstats `security_content_summariesonly` 
  earliest(_time) as start_time latest(_time) as end_time 
  values(All_Traffic.action) as action values(All_Traffic.app) as app
  values(sourcetype) as sourcetype count 
  from datamodel=Network_Traffic 
  where
    All_Traffic.action IN ("allowed", "allow") AND
    (All_Traffic.dest_port=139 OR All_Traffic.dest_port=445 OR All_Traffic.app="smb")
  AND All_Traffic.src_ip IN ("10.0.0.0/8","172.16.0.0/12","192.168.0.0/16") 
  AND NOT All_Traffic.dest_ip IN ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", 
    "127.0.0.0/8", "169.254.0.0/16", "192.0.0.0/24", "224.0.0.0/4")
  by All_Traffic.action All_Traffic.app All_Traffic.bytes All_Traffic.bytes_in All_Traffic.bytes_out
  All_Traffic.dest All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.dvc All_Traffic.protocol
  All_Traffic.protocol_version All_Traffic.src All_Traffic.src_ip All_Traffic.src_port
  All_Traffic.transport All_Traffic.user All_Traffic.vendor_product All_Traffic.rule 
| `drop_dm_object_name("All_Traffic")` 
| `security_content_ctime(start_time)` | `security_content_ctime(end_time)` 
| iplocation dest_ip 
| `detect_outbound_smb_traffic_filter`
```

---

### DNS Query Length With High Standard Deviation

**Detection ID:** `1a67f15a-f4ff-4170-84e9-08cf6f75d6f5`  
**Type:** Anomaly  
**MITRE ATT&CK:** T1048.003 (Exfiltration Over Alternative Protocol: DNS)  
**Data Sources:** Sysmon EventID 22  
**Analytic Stories:** Hidden Cobra Malware, Suspicious DNS Traffic, Command And Control

**Description:**
Detects DNS queries with unusually long query lengths based on statistical deviation, which may indicate DNS tunneling or data exfiltration.

**SPL Search:**
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime 
  from datamodel=Network_Resolution
  where NOT DNS.record_type IN ("Pointer","PTR","SOA", "SRV") DNS.query != *. 
  by DNS.answer DNS.answer_count DNS.query DNS.query_count DNS.reply_code_id 
  DNS.src DNS.vendor_product DNS.dest DNS.record_type 
| `drop_dm_object_name("DNS")` 
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` 
| eval tlds=split(query,".") 
| eval tld=mvindex(tlds,-1) 
| eval tld_len=len(tld) 
| search tld_len<=20
| eval query_length = len(query) 
| table firstTime lastTime src dest query query_length record_type count record_type 
| eventstats stdev(query_length) AS stdev avg(query_length) AS avg p50(query_length) AS p50 
| where query_length>(avg+stdev*2) 
| eval z_score=(query_length-avg)/stdev 
| stats count values(query) as query values(dest) as dest avg(query_length) as avg_query_length 
  values(record_type) as record_type min(firstTime) as firstTime latest(lastTime) as lastTime by src
| `dns_query_length_with_high_standard_deviation_filter`
```

---

## Web Detections

### Spring4Shell Payload URL Request (CVE-2022-22965)

**Detection ID:** `9d44d649-7d67-4559-95c1-8022ff49420b`  
**Type:** TTP  
**CVE:** CVE-2022-22965  
**MITRE ATT&CK:** T1133 (External Remote Services), T1190 (Exploit Public-Facing Application), T1505.003 (Web Shell)  
**Data Sources:** Nginx Access  
**Analytic Stories:** Spring4Shell CVE-2022-22965

**Description:**
Detects HTTP requests attempting to access common Spring4Shell web shell payloads (tomcatwar.jsp, poc.jsp, shell.jsp).

**SPL Search:**
```spl
| tstats count from datamodel=Web 
  where Web.http_method IN ("GET") 
  Web.url IN ("*tomcatwar.jsp*","*poc.jsp*","*shell.jsp*") 
  by Web.http_user_agent Web.http_method, Web.url, Web.url_length Web.src, Web.dest sourcetype 
| `drop_dm_object_name("Web")`
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` 
| `spring4shell_payload_url_request_filter`
```

---

### Log4Shell JNDI Payload Injection Attempt (CVE-2021-44228)

**Detection ID:** `c184f12e-5c90-11ec-bf1f-497c9a704a72`  
**Type:** Anomaly  
**CVE:** CVE-2021-44228  
**MITRE ATT&CK:** T1190 (Exploit Public-Facing Application), T1133 (External Remote Services)  
**Data Sources:** Nginx Access  
**Analytic Stories:** Log4Shell CVE-2021-44228, CISA AA22-257A, CISA AA22-320A

**Description:**
Detects Log4j JNDI injection attempts in web traffic using regex pattern matching for JNDI lookup strings.

**SPL Search:**
```spl
| from datamodel Web.Web 
| regex _raw="[jJnNdDiI]{4}(\:|\%3A|\/|\%2F)\w+(\:\/\/|\%3A\%2F\%2F)(\$\{.*?\}(\.)?)?"
| fillnull 
| stats count by action, category, dest, dest_port, http_content_type, http_method, 
  http_referrer, http_user_agent, site, src, url, url_domain, user 
| `log4shell_jndi_payload_injection_attempt_filter`
```

---

### SQL Injection with Long URLs

**Detection ID:** `e0aad4cf-0790-423b-8328-7564d0d938f9`  
**Type:** TTP  
**MITRE ATT&CK:** T1190 (Exploit Public-Facing Application)  
**Analytic Stories:** SQL Injection, GhostRedirector IIS Module

**Description:**
Detects potential SQL injection attempts based on unusually long URLs containing multiple SQL command keywords.

**SPL Search:**
```spl
| tstats `security_content_summariesonly` count from datamodel=Web 
  where Web.dest_category=web_server AND (Web.url_length > 1024 OR Web.http_user_agent_length > 200) 
  by Web.src Web.dest Web.url Web.url_length Web.http_user_agent 
| `drop_dm_object_name("Web")`
| eval url=lower(url) 
| eval num_sql_cmds=mvcount(split(url, "alter%20table")) + mvcount(split(url, "between")) + 
  mvcount(split(url, "create%20table")) + mvcount(split(url, "create%20database")) + 
  mvcount(split(url, "create%20index")) + mvcount(split(url, "create%20view")) + 
  mvcount(split(url, "delete")) + mvcount(split(url, "drop%20database")) + 
  mvcount(split(url, "drop%20index")) + mvcount(split(url, "drop%20table")) + 
  mvcount(split(url, "exists")) + mvcount(split(url, "exec")) + mvcount(split(url, "group%20by")) + 
  mvcount(split(url, "having")) + mvcount(split(url, "insert%20into")) + 
  mvcount(split(url, "inner%20join")) + mvcount(split(url, "left%20join")) + 
  mvcount(split(url, "right%20join")) + mvcount(split(url, "full%20join")) + 
  mvcount(split(url, "select")) + mvcount(split(url, "distinct")) + 
  mvcount(split(url, "select%20top")) + mvcount(split(url, "union")) + 
  mvcount(split(url, "xp_cmdshell")) - 24 
| where num_sql_cmds > 3 
| `sql_injection_with_long_urls_filter`
```

---

## Application Detections

### Okta Suspicious Activity Reported

**Detection ID:** `bfc840f5-c9c6-454c-aa13-b46fd0bf1e79`  
**Type:** TTP  
**MITRE ATT&CK:** T1078.001 (Valid Accounts: Default Accounts)  
**Data Sources:** Okta  
**Analytic Stories:** Okta Account Takeover

**Description:**
Detects when an end user reports suspicious activity on their Okta account, which may indicate credential compromise or account takeover.

**SPL Search:**
```spl
`okta` eventType=user.account.report_suspicious_activity_by_enduser 
| stats count min(_time) as firstTime max(_time) as lastTime values(displayMessage) by user
  dest src eventType client.userAgent.rawUserAgent client.userAgent.browser 
  client.geographicalContext.city client.geographicalContext.country
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` 
| `okta_suspicious_activity_reported_filter`
```

---

## MITRE ATT&CK Reference

### Technique Mapping Summary

| Technique ID | Technique Name | Detection Categories |
|--------------|----------------|---------------------|
| T1003.001 | OS Credential Dumping: LSASS Memory | Endpoint |
| T1003.008 | /etc/passwd and /etc/shadow | Endpoint (Linux) |
| T1036.002 | Right-to-Left Override | Endpoint |
| T1048.003 | Exfiltration Over DNS | Network |
| T1055.002 | Process Injection | Endpoint |
| T1071.002 | File Transfer Protocols (SMB) | Network |
| T1078.001 | Default Accounts | Application |
| T1090.003 | Multi-hop Proxy (TOR) | Network |
| T1098 | Account Manipulation | Cloud (AWS) |
| T1098.003 | Additional Cloud Roles | Cloud (Azure) |
| T1110 | Brute Force | Cloud |
| T1133 | External Remote Services | Endpoint, Web |
| T1190 | Exploit Public-Facing Application | Web |
| T1204 | User Execution | Application, Cloud |
| T1204.002 | Malicious File | Cloud (O365) |
| T1486 | Data Encrypted for Impact | Endpoint |
| T1505.003 | Web Shell | Endpoint, Web |
| T1562.001 | Impair Defenses | Endpoint |
| T1580 | Cloud Infrastructure Discovery | Cloud |

---

## Data Source Requirements

### Endpoint Data Sources

| Source | Events | Use Case |
|--------|--------|----------|
| **Sysmon EventID 1** | Process Creation | Process execution monitoring |
| **Sysmon EventID 8** | CreateRemoteThread | Process injection detection |
| **Sysmon EventID 11** | FileCreate | File creation monitoring |
| **Sysmon EventID 13** | RegistryEvent | Registry modification tracking |
| **Sysmon EventID 22** | DNSEvent | DNS query logging |
| **Windows Security 4688** | Process Creation | Process execution (native) |
| **CrowdStrike ProcessRollup2** | Process telemetry | EDR data |
| **Linux Auditd** | System calls | Linux endpoint monitoring |

### Cloud Data Sources

| Source | Integration | Use Case |
|--------|-------------|----------|
| **AWS CloudTrail** | cloudtrail macro | AWS API activity |
| **Amazon Security Lake (ASL)** | amazon_security_lake macro | Normalized AWS logs |
| **Azure AD Audit Logs** | azure_monitor_aad macro | Azure AD activity |
| **O365 Management Activity** | o365_management_activity macro | Microsoft 365 events |
| **Kubernetes Audit Logs** | kube_container_falco macro | Container security |

### Network Data Sources

| Source | Data Model | Use Case |
|--------|------------|----------|
| **Palo Alto Firewall** | Network_Traffic | Network flow analysis |
| **Cisco Secure Firewall** | Network_Traffic | Connection events |
| **DNS Servers** | Network_Resolution | DNS query analysis |

### Web Data Sources

| Source | Data Model | Use Case |
|--------|------------|----------|
| **Nginx Access Logs** | Web | Web application traffic |
| **Apache Access Logs** | Web | Web application traffic |
| **F5/Load Balancer** | Web | Application delivery |

---

## Implementation Guide

### Prerequisites

1. **Splunk Enterprise or Splunk Cloud** with Enterprise Security (recommended)
2. **Splunk Common Information Model (CIM)** Add-on installed and configured
3. **Data Model Acceleration** enabled for relevant data models
4. **Security Content** app installed (ES Content Update or standalone)

### Macro Configuration

Most detections use macros that require configuration:

```conf
# macros.conf
[security_content_summariesonly]
definition = summariesonly=true

[security_content_ctime(1)]
args = field
definition = convert timeformat="%Y-%m-%d %H:%M:%S" ctime($field$) AS $field$

[cloudtrail]
definition = index=aws sourcetype="aws:cloudtrail"

[azure_monitor_aad]
definition = index=azure sourcetype="azure:monitor:aad"

[o365_management_activity]
definition = index=o365 sourcetype="o365:management:activity"

[sysmon]
definition = index=wineventlog source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"

[okta]
definition = index=okta sourcetype="OktaIM2:log"
```

### Filter Macro Pattern

Each detection has a corresponding filter macro for tuning false positives:

```conf
[windows_process_injection_remote_thread_filter]
definition = search *
# Customize to exclude known legitimate processes

[windows_defender_exclusion_registry_entry_filter]
definition = search *
# Exclude known admin activities
```

### Data Model Requirements

Enable acceleration for these data models:

- `Endpoint.Processes`
- `Endpoint.Filesystem`
- `Endpoint.Registry`
- `Network_Traffic`
- `Network_Resolution`
- `Web`

### Risk-Based Alerting (RBA)

Most detections include RBA components:

- **Risk Score**: Numeric value (1-100) based on severity
- **Risk Objects**: Users, systems, or processes to correlate
- **Threat Objects**: Indicators like process names, file hashes

---

## Additional Resources

- **Splunk Security Content GitHub:** https://github.com/splunk/security_content
- **MITRE ATT&CK Coverage Map:** https://mitremap.splunkresearch.com/
- **Splunk Attack Range:** https://github.com/splunk/attack_range
- **Contentctl CLI:** https://github.com/splunk/contentctl
- **Attack Data Repository:** https://github.com/splunk/attack_data

---

## Version Information

| Field | Value |
|-------|-------|
| Document Version | 1.0 |
| Last Updated | February 2026 |
| Source Repository Version | develop branch |
| Detection Count | 800+ active detections |

---

*This document was generated from the Splunk Security Content repository to support RAG-based knowledge retrieval for security analysts and engineers.*
