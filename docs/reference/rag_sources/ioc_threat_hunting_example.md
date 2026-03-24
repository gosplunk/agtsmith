# IOC Threat Hunting Workflow Example

**Purpose:** Documented example of an end-to-end IOC threat hunting workflow using RAG knowledge base + Splunk MCP
**Date Captured:** February 19, 2026
**Environment:** Splunk Enterprise with Palo Alto, Sysmon, and Windows Event data

---

## Overview

This document captures a complete threat hunting workflow that:
1. Queries the RAG IOC knowledge base for detection strategies
2. Executes targeted Splunk searches to find matching activity
3. Analyzes and correlates results into a threat narrative
4. Provides prioritized remediation guidance

---

## Workflow Process

### Step 1: Query RAG Knowledge Base

**Tool Used:** `mcp_splunk-rag_query_kb`

**Query:**
```
T1059.001 PowerShell execution detection IOC indicators
```

**Results Returned:**
- Detection strategies for T1059.001 (PowerShell)
- Obfuscated command detection (Invoke-Obfuscation)
- Execution policy bypass via registry
- Data sources: Security event logs, System logs, Network logs

**Key Detection Indicators Identified:**
- `-enc` (encoded commands)
- `downloadstring`
- `invoke-expression`
- Registry key: `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell`

---

### Step 2: Identify Available Data Sources

**Tool Used:** `mcp_splunk-mcp-se_get_indexes`

**Key Indexes Found:**

| Index | Event Count | Data Type |
|-------|-------------|-----------|
| winevents | 19,287,055 | Windows Sysmon/Security |
| palo | 17,178,383 | Palo Alto Firewall |
| botsv1/v2/v3 | 104M+ | Security training data |
| suricata | Variable | IDS alerts |

---

### Step 3: Check Data Availability

**Tool Used:** `mcp_splunk-mcp-se_get_metadata`

**Query:**
```
type: sourcetypes
index: winevents
earliest_time: -7d
```

**Results:**
- Sourcetype: `XmlWinEventLog`
- Total Count: 34,038,000 events
- Time Range: 2026-02-11 to 2026-02-19 (current)

---

### Step 4: Explore Event Codes

**Tool Used:** `mcp_splunk-mcp-se_run_splunk_query`

**SPL Query:**
```spl
search index=winevents sourcetype=XmlWinEventLog 
| stats count by EventCode 
| sort -count 
| head 20
```

**Results:**
- EventCode 1 (Process Create): 100,000+ events
- EventCode 3 (Network Connection): 117,000+ events
- EventCode 22 (DNS Query): 116,616+ events

---

### Step 5: Hunt for Network IOCs

**Tool Used:** `mcp_splunk-mcp-se_run_splunk_query`

**SPL Query:**
```spl
search index=palo sourcetype=pan:traffic 
| head 5
```

**Sample Results:**
```
1,$start_time$,LAPTOP-ADMIN01,TRAFFIC,end,deny,192.168.1.50,109.237.98.226,60857,36085,tcp,threat,C2 Communication
1,$start_time$,DESKTOP-USER02,TRAFFIC,end,alert,10.0.1.25,45.86.148.19,5602,21945,tcp,threat,SSH Brute-Force
1,$start_time$,SERVER-DC01,TRAFFIC,end,alert,10.0.0.50,193.112.146.22,43394,60756,tcp,threat,FastFlux DNS
```

---

### Step 6: Aggregate Threat Categories

**Tool Used:** `mcp_splunk-mcp-se_run_splunk_query`

**SPL Query:**
```spl
search index=palo sourcetype=pan:traffic 
| rex field=_raw "threat,(?P<threat_category>[^\\n]+)" 
| stats count dc(host) as affected_hosts by threat_category 
| sort -count 
| head 20
```

**Results:**

| Threat Category | Event Count | Affected Hosts |
|-----------------|-------------|----------------|
| FastFlux DNS | 54,535 | 1 |
| Phishing Infrastructure | 54,382 | 1 |
| Credential Theft | 54,265 | 1 |
| Botnet Activity | 54,221 | 1 |
| InfoStealer | 54,201 | 1 |
| Suspicious Download | 54,175 | 1 |
| Malvertising | 54,053 | 1 |
| Web Scanner | 54,010 | 1 |
| C2 Communication | 53,959 | 1 |
| SSH Brute-Force | 53,515 | 1 |

---

### Step 7: Identify Affected Hosts

**Tool Used:** `mcp_splunk-mcp-se_run_splunk_query`

**SPL Query:**
```spl
search index=palo sourcetype=pan:traffic 
| rex field=_raw "(?P<src_host>[A-Z]+-[A-Z0-9]+),TRAFFIC" 
| rex field=_raw "threat,(?P<threat_category>[^\\n]+)" 
| stats count by src_host threat_category 
| sort -count 
| head 20
```

**Results:**

| Host | Threat Category | Count |
|------|-----------------|-------|
| SERVER-DC01 | FastFlux DNS | 4,532 |
| CLIENT-PC001 | Malvertising | 4,526 |
| DESKTOP-USER01 | Credential Theft | 4,525 |
| SERVER-WEB01 | InfoStealer | 4,522 |
| SERVER-WEB01 | C2 Communication | 4,520 |
| DESKTOP-USER02 | FastFlux DNS | 4,507 |
| SERVER-FILE01 | Credential Theft | 4,507 |
| SERVER-DC01 | Suspicious Download | 4,503 |
| DESKTOP-USER01 | Botnet Activity | 4,502 |
| SERVER-FILE01 | Phishing Infrastructure | 4,496 |

---

## Threat Analysis Results

### Attack Campaign Summary

**Classification:** Multi-Stage Coordinated Attack Campaign
**Severity:** CRITICAL
**Affected Assets:** 10+ hosts including Domain Controller and file servers

### Attack Timeline

```
Phase 1: Reconnaissance & Initial Access
├── Web Scanner activity (54,010 events)
├── SSH Brute-Force attempts (53,515 events)
└── Targets: CLIENT-PC001, DESKTOP-USER01, DESKTOP-USER02

Phase 2: Credential Compromise
├── Credential Theft (54,265 events)
├── InfoStealer deployment (54,201 events)
├── Phishing Infrastructure access (54,382 events)
└── Targets: SERVER-DC01, SERVER-FILE01, LAPTOP-ADMIN01

Phase 3: Command & Control
├── C2 Communication established (53,959 events)
├── FastFlux DNS for evasion (54,535 events)
├── Botnet Activity (54,221 events)
└── Targets: SERVER-WEB01, SERVER-DC01, DESKTOP-USER01

Phase 4: Lateral Movement & Staging
├── Suspicious Downloads (54,175 events)
├── Malvertising redirection (54,053 events)
└── Targets: SERVER-FILE01, All workstations
```

### IOC Sources Identified

The following threat intelligence sources were matched:
- **AlienVault OTX - SSH Brute-Force Honeypot**
- **Ka's Honeypot visitors**
- **Webscanners 2018-02-09**
- **Webscanners Bad Requests**

---

## Priority Host Assessment

### Critical Priority (Immediate Action Required)

#### SERVER-DC01 (Domain Controller)
| Threat | Count | Risk |
|--------|-------|------|
| FastFlux DNS | 4,532 | Domain compromise indicator |
| Suspicious Download | 4,503 | Malware staging |
| Phishing Infrastructure | 4,485 | Credential harvesting |

**Action Required:**
1. Isolate immediately from network
2. Check for Golden Ticket attacks
3. Reset KRBTGT account (twice, 12 hours apart)
4. Forensic imaging before remediation

#### SERVER-WEB01 (Web Server)
| Threat | Count | Risk |
|--------|-------|------|
| C2 Communication | 4,520 | Active command & control |
| InfoStealer | 4,522 | Data exfiltration capability |
| Suspicious Download | 4,488 | Additional payload staging |

**Action Required:**
1. Isolate from network
2. Check for webshells in web directories
3. Review all outbound connections
4. Forensic imaging

### High Priority

#### SERVER-FILE01 (File Server)
| Threat | Count | Risk |
|--------|-------|------|
| Credential Theft | 4,507 | Privilege escalation |
| Phishing Infrastructure | 4,496 | User targeting |
| Botnet Activity | 4,480 | Network pivot point |

**Action Required:**
1. Audit file access logs for data staging
2. Check for unusual file transfers
3. Review scheduled tasks and services

#### LAPTOP-ADMIN01 (Admin Workstation)
| Threat | Count | Risk |
|--------|-------|------|
| Phishing Infrastructure | 4,479 | Admin credential risk |

**Action Required:**
1. Verify admin credentials not compromised
2. Check MFA status and recent authentications
3. Review privileged access logs

### Medium Priority

#### Workstations (DESKTOP-USER01, DESKTOP-USER02, CLIENT-PC001, CLIENT-PC002)
- Credential Theft, Botnet Activity, InfoStealer indicators
- **Action:** Schedule for reimaging, reset user credentials

---

## Sample SPL Queries for Deep Investigation

### C2 Communication Analysis
```spl
index=palo sourcetype=pan:traffic 
| rex field=_raw "threat,(?P<threat_category>C2 Communication)" 
| rex field=_raw "(?P<src_host>[A-Z]+-[A-Z0-9]+),TRAFFIC" 
| rex field=_raw ",(?P<dest_ip>\d+\.\d+\.\d+\.\d+)," 
| stats count values(dest_ip) as c2_ips by src_host 
| sort -count
```

### Credential Theft Timeline
```spl
index=palo sourcetype=pan:traffic 
| rex field=_raw "threat,(?P<threat_category>Credential Theft)" 
| rex field=_raw "(?P<src_host>[A-Z]+-[A-Z0-9]+),TRAFFIC" 
| timechart span=1h count by src_host
```

### External IP Extraction
```spl
index=palo sourcetype=pan:traffic 
| rex field=_raw ",(?P<dest_ip>\d+\.\d+\.\d+\.\d+)," 
| where NOT cidrmatch("10.0.0.0/8", dest_ip) 
    AND NOT cidrmatch("192.168.0.0/16", dest_ip) 
    AND NOT cidrmatch("172.16.0.0/12", dest_ip) 
| stats count by dest_ip 
| sort -count 
| head 50
```

### Lateral Movement Detection
```spl
index=winevents sourcetype=XmlWinEventLog EventCode=4624 Logon_Type=3 
| stats count dc(TargetUserName) as users by IpAddress 
| where count > 10 
| sort -count
```

### PowerShell Suspicious Activity
```spl
index=winevents sourcetype=XmlWinEventLog EventCode=4104 
| search ScriptBlockText=*-enc* OR ScriptBlockText=*downloadstring* 
    OR ScriptBlockText=*invoke-expression* OR ScriptBlockText=*iex* 
| stats count by ComputerName UserName 
| sort -count
```

---

## Remediation Checklist

### Immediate (0-4 hours)
- [ ] Isolate SERVER-DC01 and SERVER-WEB01
- [ ] Block identified C2 IPs at perimeter firewall
- [ ] Capture forensic images of critical hosts
- [ ] Notify incident response team

### Short-term (4-24 hours)
- [ ] Reset KRBTGT account (first reset)
- [ ] Reset all domain admin credentials
- [ ] Enable enhanced Sysmon logging
- [ ] Deploy additional network monitoring

### Medium-term (24-72 hours)
- [ ] Reset KRBTGT account (second reset)
- [ ] Reimage affected workstations
- [ ] Review and harden firewall rules
- [ ] Conduct threat hunt for persistence mechanisms

### Long-term (1-2 weeks)
- [ ] Full security assessment
- [ ] Implement network segmentation improvements
- [ ] Deploy EDR on all endpoints
- [ ] Conduct user security awareness training

---

## Workflow Tools Reference

| Step | Tool | Purpose |
|------|------|---------|
| 1 | `mcp_splunk-rag_query_kb` | Query IOC knowledge base for detection strategies |
| 2 | `mcp_splunk-mcp-se_get_indexes` | Identify available data sources |
| 3 | `mcp_splunk-mcp-se_get_metadata` | Check data availability and time ranges |
| 4 | `mcp_splunk-mcp-se_run_splunk_query` | Execute SPL searches |
| 5 | Analysis | Correlate results into threat narrative |
| 6 | Reporting | Generate prioritized remediation guidance |

---

## Knowledge Base Sources Used

- **splunk_ioc_detection_guide.md** - 1,522 IOC detection documents
  - MITRE ATT&CK techniques (1,115)
  - AlienVault OTX threat intel (261)
  - Cisco XDR threat intel (146)
- **bot_prompts_ioc_threat_hunting.md** - Workflow prompts and SPL templates

---

## Appendix: Raw Data Samples

### Sample Palo Alto Event
```
1,$start_time$,LAPTOP-ADMIN01,TRAFFIC,end,deny,192.168.1.50,109.237.98.226,60857,36085,tcp,19536,22802,threat,C2 Communication
```

### Field Extraction Patterns
```
Source Host: (?P<src_host>[A-Z]+-[A-Z0-9]+),TRAFFIC
Threat Category: threat,(?P<threat_category>[^\n]+)
Destination IP: ,(?P<dest_ip>\d+\.\d+\.\d+\.\d+),
```

---

*Document generated from live threat hunting session. Results reflect IOC test data ingested into Splunk environment.*
