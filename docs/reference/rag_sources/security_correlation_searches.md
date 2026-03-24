# Splunk Enterprise Security - Correlation Searches Guide

---
tags: [splunk, es, correlation-search, notable-event, risk-score, security, detection]
category: security
last_updated: 2026-02-20
related_docs: [splunk_ioc_detection_guide.md, escu_correlation_searches.md, splunk_security_content_detections_complete.md]
---

**Document Type**: Reference Guide | Security
**Audience**: Security Analysts, Detection Engineers, SOC Teams
**Topics**: Correlation Searches, Notable Events, Risk Scoring, Adaptive Response, ES
**Keywords**: correlation search, notable event, risk score, adaptive response, ES, enterprise security, detection, threat detection, SPL, correlation rule

---

## Quick Summary

Comprehensive guide to Splunk Enterprise Security correlation searches. Covers search anatomy (logic, scheduling, notable events, risk scoring), SPL patterns, notable event creation, risk framework integration, and adaptive response actions.

**Find this document by searching for**: correlation search, notable event creation, risk scoring, adaptive response, ES detection rules, threat detection SPL, correlation search examples

---

## Overview

Correlation searches are the core detection mechanism in Splunk Enterprise Security (ES). They analyze events across multiple data sources to identify security threats and create Notable Events for SOC investigation.

## Correlation Search Anatomy

A correlation search consists of:
1. **Search Logic** - SPL query to detect threats
2. **Scheduling** - How often it runs
3. **Notable Event Creation** - When threshold met
4. **Risk Scoring** - Points assigned to entities
5. **Adaptive Response Actions** - Automated responses

## Basic Structure

```spl
# Pattern: Search → Filter → Aggregate → Threshold → Action
index=<data_source>
| <filtering and enrichment>
| stats <aggregation> by <entity_fields>
| where <threshold_condition>
```

## Notable Event Creation

### Using collect command (Traditional)
```spl
index=firewall action=blocked
| stats count as blocked_count by src_ip
| where blocked_count > 100
| collect index=notable marker="search_name=\"High Blocked Traffic\""
```

### Using sendalert command (Modern ES)
```spl
index=firewall action=blocked
| stats count as blocked_count by src_ip
| where blocked_count > 100
| sendalert notable param.security_domain="network" 
            param.severity="high"
            param.rule_title="High Blocked Traffic from $src_ip$"
```

## Risk-Based Alerting (RBA)

### Add Risk Score
```spl
index=auth action=failure
| stats count as failure_count by user
| where failure_count > 10
| eval risk_score=failure_count*5
| eval risk_object=user
| eval risk_object_type="user"
| collect index=risk marker="search_name=\"Multiple Auth Failures\""
```

### Risk Score Guidelines
| Severity | Risk Score | Use Case |
|----------|------------|----------|
| Info | 1-20 | Suspicious but common activity |
| Low | 21-40 | Potentially malicious |
| Medium | 41-60 | Likely malicious activity |
| High | 61-80 | Confirmed malicious activity |
| Critical | 81-100 | Active threat/breach |

## Common Correlation Search Examples

### 1. Brute Force Detection
```spl
index=auth sourcetype=*auth* action=failure
| bucket _time span=5m
| stats count as failure_count dc(src) as unique_sources by user, _time
| where failure_count > 20
| eval risk_score=if(failure_count>50, 80, 60)
| eval risk_object=user, risk_object_type="user"
| eval rule_name="Brute Force Attack - ".user
| sendalert notable param.security_domain="access" 
            param.severity="high"
            param.rule_title="$rule_name$"
```

### 2. Impossible Travel
```spl
index=auth action=success
| iplocation src_ip
| sort user, _time
| streamstats current=false last(_time) as prev_time, last(lat) as prev_lat, last(lon) as prev_lon by user
| eval distance_km=round(haversin(lat, lon, prev_lat, prev_lon),2)
| eval time_diff_hours=round((_time-prev_time)/3600,2)
| eval speed_kmh=round(distance_km/time_diff_hours,2)
| where speed_kmh > 800 AND time_diff_hours < 24
| eval risk_score=70
| sendalert notable param.security_domain="access" 
            param.severity="high"
            param.rule_title="Impossible Travel Detected - $user$"
```

### 3. Lateral Movement Detection
```spl
index=winevents EventCode=4624 Logon_Type=3
| bucket _time span=10m
| stats dc(dest) as unique_dests values(dest) as destinations by user, src, _time
| where unique_dests > 5
| eval risk_score=65
| eval risk_object=user, risk_object_type="user"
| sendalert notable param.security_domain="endpoint" 
            param.severity="medium"
            param.rule_title="Potential Lateral Movement - $user$"
```

### 4. Data Exfiltration
```spl
index=proxy OR index=firewall
| stats sum(bytes_out) as total_bytes by src_ip, user
| eval total_gb=round(total_bytes/1024/1024/1024,2)
| where total_gb > 5
| eval risk_score=75
| eval risk_object=user, risk_object_type="user"
| sendalert notable param.security_domain="network" 
            param.severity="high"
            param.rule_title="Potential Data Exfiltration - $user$ - $total_gb$GB"
```

### 5. Suspicious Process Execution
```spl
index=winevents EventCode=4688 
| search (New_Process_Name="*powershell*" OR New_Process_Name="*cmd.exe*")
| rex field=Process_Command_Line "(?<encoded>-enc|-encodedcommand)"
| where isnotnull(encoded)
| eval risk_score=80
| eval risk_object=dest, risk_object_type="system"
| sendalert notable param.security_domain="endpoint" 
            param.severity="high"
            param.rule_title="Encoded PowerShell Detected on $dest$"
```

### 6. Malware C2 Beacon Detection
```spl
index=proxy OR index=firewall
| bucket _time span=1h
| stats count as request_count, dc(_time) as time_buckets by src_ip, dest, dest_port
| where request_count > 100 AND time_buckets >= 20
| eval beacon_score=round((time_buckets/24)*100,2)
| where beacon_score > 80
| eval risk_score=85
| sendalert notable param.security_domain="network" 
            param.severity="critical"
            param.rule_title="Potential C2 Beaconing - $src_ip$ to $dest$"
```

### 7. Privilege Escalation
```spl
index=winevents (EventCode=4672 OR EventCode=4728 OR EventCode=4732)
| eval event_type=case(
    EventCode=4672, "Special Privileges Assigned",
    EventCode=4728, "Added to Security Group",
    EventCode=4732, "Added to Local Group")
| stats count values(event_type) as events by user, dest
| where count > 3
| eval risk_score=70
| sendalert notable param.security_domain="identity" 
            param.severity="high"
            param.rule_title="Privilege Escalation Activity - $user$"
```

### 8. Anomalous Login Time
```spl
index=auth action=success
| eval hour=strftime(_time, "%H")
| eval day=strftime(_time, "%w")
| where (hour < 6 OR hour > 22) OR (day=0 OR day=6)
| stats count by user, src_ip, hour, day
| lookup user_work_schedule.csv user OUTPUT expected_hours
| where NOT match(hour, expected_hours)
| eval risk_score=40
| sendalert notable param.security_domain="access" 
            param.severity="low"
            param.rule_title="After Hours Login - $user$"
```

## MITRE ATT&CK Mapping

### Add MITRE Annotations
```spl
index=winevents EventCode=4688 New_Process_Name="*mimikatz*"
| eval mitre_technique="T1003"
| eval mitre_tactic="Credential Access"
| eval risk_score=95
| sendalert notable param.security_domain="endpoint" 
            param.severity="critical"
            param.rule_title="Mimikatz Detected - $dest$"
            param.mitre_attack="T1003 - Credential Dumping"
```

### Common MITRE Techniques in Correlation Searches
| Technique ID | Name | Detection Approach |
|--------------|------|-------------------|
| T1078 | Valid Accounts | Failed/anomalous logins |
| T1003 | Credential Dumping | Process monitoring |
| T1059 | Command Line Interface | PowerShell/CMD monitoring |
| T1071 | Application Layer Protocol | C2 traffic patterns |
| T1021 | Remote Services | Lateral movement |
| T1486 | Data Encrypted for Impact | Ransomware behavior |

## Adaptive Response Actions

### Configure Alert Actions
```spl
# Send to Splunk SOAR (Phantom)
| sendalert phantom_forward param.playbook="investigate_endpoint"

# Send email
| sendalert email param.to="soc@company.com" param.subject="Security Alert"

# Run script
| sendalert script param.filename="block_ip.py"

# Add to threat list
| sendalert modifyable_lookup param.lookup_name="blocklist.csv"
```

## Performance Optimization

### Efficient Correlation Searches
```spl
# Good - Filter early, specific indexes
index=auth sourcetype=linux_secure action=failure earliest=-1h
| stats count by user
| where count > 10

# Bad - Wildcard index, no time constraint
index=* action=failure
| stats count by user
| where count > 10
```

### Scheduling Best Practices
| Search Type | Recommended Schedule |
|-------------|---------------------|
| Real-time threats | Every 1-5 minutes |
| Aggregated activity | Every 15-30 minutes |
| Daily reports | Daily |
| Low-priority | Hourly |

### Use Datamodels for Speed
```spl
# MCP-Compatible - Uses data model with stats
| from datamodel:"Authentication"."Failed_Authentication"
| stats count by user, src
| where count > 10

# Alternative: datamodel flat + stats
| datamodel Authentication Failed_Authentication flat
| stats count by user, src
| where count > 10

# ⚠️ AVOID in MCP - tstats with 'by' clause fails validation
# | tstats count from datamodel=Authentication.Authentication 
#   where Authentication.action=failure by Authentication.user
```

## Creating in Splunk ES

### Via UI
1. Configure → Content → Content Management
2. Click "Create New Content"
3. Select "Correlation Search"
4. Fill in search logic, schedule, response actions

### Via Configuration Files
```ini
# savedsearches.conf
[Correlation - Brute Force Detection]
search = index=auth action=failure | stats count by user | where count > 20
cron_schedule = */5 * * * *
enableSched = 1
action.correlationsearch.enabled = 1
action.correlationsearch.label = Brute Force Detection
action.notable = 1
action.notable.param.security_domain = access
action.notable.param.severity = high
action.notable.param.rule_title = Brute Force Attack Detected - $user$
action.risk = 1
action.risk.param._risk_score = 70
action.risk.param._risk_object = user
action.risk.param._risk_object_type = user
```

## Testing Correlation Searches

### Validate Search Logic
```spl
# Test without creating notable
index=auth action=failure
| stats count by user
| where count > 5
| eval would_alert="Yes"
| table _time user count would_alert
```

### Check for False Positives
```spl
# Look back at what would have triggered
index=auth action=failure earliest=-7d
| bucket _time span=1h
| stats count by user, _time
| where count > 10
| stats count as alert_count by user
| sort - alert_count
```

## MCP Compatibility

✅ **Supported via MCP**: Basic correlation search queries work
- Search logic testing executes normally
- Stats/aggregation functions work
- Results return for validation

⚠️ **Limited via MCP**:
- sendalert action blocked
- collect to notable index blocked
- Adaptive response actions blocked

### MCP Example Prompts
- "search for failed logins over 10 per user in auth index"
- "find users with multiple failed logins then success in 5 minutes"
- "detect lateral movement with multiple destinations per user"
- "analyze login patterns for anomaly detection"

## Quick Reference

```spl
# Basic correlation pattern
index=<index> <filter>
| stats count by <entity>
| where count > <threshold>
| eval risk_score=<score>
| eval risk_object=<entity>, risk_object_type="<type>"

# Notable event fields
param.security_domain = access|endpoint|network|identity|audit
param.severity = informational|low|medium|high|critical
param.rule_title = "Alert Title with $field$ substitution"

# Risk scoring
| eval risk_score=<1-100>
| eval risk_object=user          # or src_ip, dest, etc.
| eval risk_object_type="user"   # user, system, other
```

### Security Domains
- **access**: Authentication, authorization
- **endpoint**: Host-based detections
- **network**: Network traffic, firewall
- **identity**: User/account management
- **audit**: Compliance, policy violations
