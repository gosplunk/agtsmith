# ESCU Correlation Searches and Data Sources Guide

**Document Type**: Reference Guide | Security Content
**Audience**: Security Analysts, Detection Engineers, Content Developers
**Topics**: ESCU, Security Content, Detection Rules, Data Sources, CIM
**Keywords**: ESCU, enterprise security content update, security content, detection rules, splunk attack range, MITRE ATT&CK, data sources, CIM, endpoint detection, network detection

**Last Updated**: 2025-12-22

---

## Quick Summary

Guide to ESCU (Enterprise Security Content Update) correlation searches and required data sources. Covers Splunk Security Content repository structure, detection categories (endpoint, network, cloud), data source requirements, and enabling ESCU rules.

**Find this document by searching for**: ESCU, security content, detection rules, MITRE ATT&CK mapping, data source requirements, endpoint detection, network detection, cloud detection

---

## Overview

ESCU (Enterprise Security Content Update) provides pre-built correlation searches for threat detection in Splunk Enterprise Security. These rules are part of the [Splunk Security Content](https://github.com/splunk/security_content) project and are disabled by default.

## Splunk Security Content Structure

The Splunk Security Content repository contains detection rules organized by domain:

| Directory | Description | Examples |
|-----------|-------------|----------|
| `detections/endpoint` | Endpoint-based detections | Process execution, registry changes, file operations |
| `detections/network` | Network traffic analysis | SMB, LDAP, DNS traffic, port scans |
| `detections/cloud` | Cloud platform detections | AWS, Azure, GCP, O365 |
| `detections/application` | Application-level detections | Web application attacks |
| `detections/web` | Web traffic detections | Web shells, SQL injection |

## Data Sources Mapping

Data sources define the telemetry needed for each detection. Located in [data_sources/](https://github.com/splunk/security_content/tree/develop/data_sources).

### Network Data Sources

| Data Source | Sourcetype | Key Fields | Use Cases |
|-------------|------------|------------|-----------|
| Palo Alto Network Traffic | `pan:traffic` | `src_ip`, `dest_ip`, `dest_port`, `app`, `action` | Firewall traffic analysis, outbound connections |
| Cisco ASA Logs | `cisco:asa` | `src_ip`, `dest_ip`, `dest_port`, `action`, `protocol` | Firewall events, VPN activity |
| Cisco Secure Firewall | `cisco:sfw:estreamer` | `src_ip`, `dest_ip`, `dest_port`, `action` | Next-gen firewall events |
| Suricata | `suricata` | `src_ip`, `dest_ip`, `src_port`, `dest_port`, `proto`, `app_proto` | IDS alerts, flow data |
| Zeek/Bro | `bro:conn`, `bro:dns`, `bro:http` | `id.orig_h`, `id.resp_h`, `id.resp_p` | Network monitoring |

### Endpoint Data Sources

| Data Source | Sourcetype | Key Fields | Use Cases |
|-------------|------------|------------|-----------|
| Sysmon EventID 1 | `XmlWinEventLog` | `Image`, `CommandLine`, `ParentImage`, `User` | Process creation |
| Sysmon EventID 3 | `XmlWinEventLog` | `SourceIp`, `DestinationIp`, `DestinationPort`, `Image` | Network connections |
| Sysmon EventID 11 | `XmlWinEventLog` | `TargetFilename`, `Image` | File creation |
| Sysmon EventID 22 | `XmlWinEventLog` | `QueryName`, `QueryResults`, `Image` | DNS queries |
| Windows Security | `WinEventLog:Security` | `EventCode`, `Account_Name`, `Logon_Type` | Authentication, process tracking |
| PowerShell Script Block | `XmlWinEventLog` | `ScriptBlockText`, `ScriptBlockId` | PowerShell execution |

### Cloud Data Sources

| Data Source | Sourcetype | Key Fields | Use Cases |
|-------------|------------|------------|-----------|
| AWS CloudTrail | `aws:cloudtrail` | `eventName`, `userIdentity`, `sourceIPAddress` | API activity |
| Azure AD | `azure:aad` | `operationName`, `identity`, `result` | Identity events |
| O365 | `o365:management:activity` | `Operation`, `UserId`, `ClientIP` | Office 365 activity |
| GCP Audit | `google:gcp:pubsub:message` | `methodName`, `principalEmail` | GCP API calls |

## Common ESCU Network Detections

| Rule Name | Data Model | Data Sources | MITRE ATT&CK | Description |
|-----------|------------|--------------|--------------|-------------|
| Detect Outbound SMB Traffic | Network_Traffic | `pan:traffic`, `cisco:asa`, `cisco:sfw:estreamer` | T1071.002 | Detects SMB connections (ports 139, 445) to external IPs |
| Detect Outbound LDAP Traffic | Network_Traffic | `pan:traffic`, `cisco:sfw:estreamer` | T1190, T1059 | Detects LDAP connections (ports 389, 636) to external IPs - Log4Shell indicator |
| Prohibited Network Traffic Allowed | Network_Traffic | `pan:traffic`, `cisco:asa`, `cisco:sfw:estreamer` | T1048 | Detects traffic on prohibited ports allowed through firewall |

## Common ESCU Endpoint Detections

| Rule Name | Data Model | Data Sources | MITRE ATT&CK | Description |
|-----------|------------|--------------|--------------|-------------|
| LOLBAS With Network Traffic | Network_Traffic, Endpoint | Sysmon EventID 1, 3 (`XmlWinEventLog`) | T1105, T1567, T1218 | Detects Living Off The Land binaries making external network connections |
| Outbound Network Connection from Java | Endpoint, Network_Traffic | Sysmon EventID 1, 3 (`XmlWinEventLog`) | T1190, T1133 | Detects Java processes connecting to LDAP/RMI ports - Log4Shell indicator |

## Detection YAML Structure

Each detection in security_content follows this structure:

```yaml
name: Detect Outbound SMB Traffic
id: 1bed7774-304a-4e8f-9d72-d80e45ff492b
version: 12
date: '2025-06-10'
author: Bhavin Patel, Stuart Hopkins
status: production
type: TTP
description: Detects outbound SMB connections from internal hosts to external servers
data_source:
- Cisco Secure Firewall Threat Defense Connection Event
- Palo Alto Network Traffic
search: |
  | tstats `security_content_summariesonly` count 
  from datamodel=Network_Traffic 
  where All_Traffic.action IN ("allowed", "allow")
  AND (All_Traffic.dest_port=139 OR All_Traffic.dest_port=445)
  ...
how_to_implement: Requires Network_Traffic data model populated
known_false_positives: Legitimate internal SMB traffic
tags:
  analytic_story:
  - Hidden Cobra Malware
  - DHS Report TA18-074A
  mitre_attack_id:
  - T1071.002
tests:
- name: True Positive Test
  attack_data:
  - data: https://media.githubusercontent.com/media/splunk/attack_data/...
    sourcetype: pan:traffic
```

## Data Source YAML Structure

```yaml
name: Palo Alto Network Traffic
id: 182a83bc-c31a-4817-8c7a-263744cec52a
version: 2
date: '2025-01-23'
author: Patrick Bareiss, Splunk
description: Logs network traffic events from Palo Alto Networks devices
sourcetype: pan:traffic
supported_TA:
- name: Palo Alto Networks Add-on
  url: https://splunkbase.splunk.com/app/2757
fields:
- src_ip
- dest_ip
- dest_port
- action
- app
- bytes
output_fields:
- action
- app
- bytes
- dest
- dest_ip
- dest_port
- src
- src_ip
- src_port
field_mappings:
- data_model: cim
  data_set: All_Traffic
  mapping:
    app: All_Traffic.app
    action: All_Traffic.action
    dest_ip: All_Traffic.dest_ip
```

## Attack Data Mapping

The [splunk/attack_data](https://github.com/splunk/attack_data) repository provides test datasets for validating detections.

### Dataset to Detection Mapping

| Detection | Attack Data | Sourcetype | IOC/Indicators |
|-----------|-------------|------------|----------------|
| Detect Outbound SMB Traffic | `connection_events.log` | `cisco:sfw:estreamer` | SMB on ports 139, 445 to external IP |
| Detect Outbound LDAP Traffic | `pantraffic.log` | `pan:traffic` | LDAP ports 389, 636 to external IP |
| LOLBAS With Network Traffic | `lolbas_with_network_traffic.log` | `XmlWinEventLog` | Sysmon EID 3 from LOLBAS binaries |
| Outbound Network Connection from Java | `windows-sysmon.log` | `XmlWinEventLog` | Java.exe connecting to LDAP/RMI ports |

### Test Data Format

Attack data is typically stored in these formats:
- **Raw logs**: Actual log events in vendor-native format
- **JSON**: Structured data for API-based sources
- **XML**: Windows Event Logs (Sysmon)

## Common MITRE ATT&CK Mappings

| Technique ID | Name | Common Detections |
|--------------|------|-------------------|
| T1071.001 | Web Protocols | DNS tunneling, C2 over HTTP/S |
| T1071.002 | File Sharing Protocols | Outbound SMB traffic |
| T1048 | Exfiltration Over Alternative Protocol | Prohibited traffic allowed |
| T1105 | Ingress Tool Transfer | LOLBAS network traffic |
| T1190 | Exploit Public-Facing Application | Log4Shell, Java outbound |
| T1218 | System Binary Proxy Execution | LOLBAS execution |
| T1567 | Exfiltration Over Web Service | Data upload to cloud services |

## Run Correlation Searches Manually

```spl
# Run a saved search by name
| savedsearch "ESCU - Detect Outbound SMB Traffic - Rule"

# List all ESCU rules
| rest /services/saved/searches 
| search title="ESCU*" 
| table title, disabled, next_scheduled_time
```

## Check Data Model Population

```spl
# Verify Network_Traffic data model has data
| tstats count from datamodel=Network_Traffic by sourcetype

# Verify Endpoint data model has data
| tstats count from datamodel=Endpoint by sourcetype
```

## References

- [Splunk Security Content GitHub](https://github.com/splunk/security_content) - Detection rules and data sources
- [Splunk Attack Data GitHub](https://github.com/splunk/attack_data) - Test datasets
- [MITRE ATT&CK](https://attack.mitre.org/) - Adversary tactics and techniques
- [Splunk ES Content Update](https://splunkbase.splunk.com/app/3449) - DA-ESS-ContentUpdate app
- [LOLBAS Project](https://lolbas-project.github.io/) - Living Off The Land Binaries
- [Splunk CIM Documentation](https://docs.splunk.com/Documentation/CIM/latest/User/Overview) - Common Information Model
