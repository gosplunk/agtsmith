# Splunk Props and Transforms Configuration Guide

---
tags: [splunk, props-conf, transforms-conf, field-extraction, regex, parsing, sourcetype]
category: administration
last_updated: 2026-02-20
related_docs: [admin_indexes.md, admin_forwarders.md, search_commands_rex.md]
---

**Document Type**: Configuration Reference & Best Practices
**Audience**: Splunk Administrators, Data Engineers, Add-on Developers
**Topics**: props.conf, transforms.conf, Field Extraction, Data Parsing, Routing
**Keywords**: props.conf, transforms.conf, field extraction, regex, SEDCMD, TRANSFORMS, sourcetype, line breaking, timestamp, MCP

**Quick Links:**
- Props.conf Documentation: https://docs.splunk.com/Documentation/Splunk/latest/Admin/Propsconf
- Transforms.conf Documentation: https://docs.splunk.com/Documentation/Splunk/latest/Admin/Transformsconf
- Field Extraction: https://docs.splunk.com/Documentation/Splunk/latest/Knowledge/Aboutfieldextractions

**Description:** Comprehensive guide to configuring props.conf and transforms.conf for data parsing, field extraction, and event processing in Splunk

**Last Updated:** 2025-12-02

## Search Keywords & Index Terms

**This document covers:** props.conf, transforms.conf, field extraction, regex extraction, SEDCMD, TRANSFORMS, sourcetype configuration, line breaking, timestamp extraction, event routing, data masking, field aliasing

**Find this document by searching for:** props conf, transforms conf, field extraction, regex splunk, sourcetype config, line breaking, timestamp format, data parsing, SEDCMD, TRANSFORMS

---

## Overview

### props.conf
Defines how Splunk processes data at index-time and search-time:
- Timestamp extraction
- Line breaking
- Character encoding
- Field extractions
- Event segmentation

### transforms.conf
Defines reusable transformations referenced by props.conf:
- Regex-based field extractions
- Index-time field extraction
- Data routing and filtering
- Field lookups
- Data masking/anonymization

---

## File Locations

| Location | Purpose | Precedence |
|----------|---------|------------|
| `$SPLUNK_HOME/etc/system/local/` | System-wide custom configs | Highest |
| `$SPLUNK_HOME/etc/apps/<app>/local/` | App-specific custom configs | High |
| `$SPLUNK_HOME/etc/apps/<app>/default/` | App defaults | Medium |
| `$SPLUNK_HOME/etc/system/default/` | System defaults | Lowest |

---

## Props.conf Configuration

### Basic Stanza Structure

```ini
# Match by sourcetype (most common)
[sourcetype_name]
setting = value

# Match by source path
[source::/path/to/file]
setting = value

# Match by host
[host::hostname]
setting = value

# Default settings for all data
[default]
setting = value
```

### Timestamp Extraction

```ini
[my_sourcetype]
# Enable timestamp extraction
DATETIME_CONFIG = 
TIME_PREFIX = ^
TIME_FORMAT = %Y-%m-%d %H:%M:%S
MAX_TIMESTAMP_LOOKAHEAD = 30

# For logs with timestamp at start of line
TIME_PREFIX = ^
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%6N%:z

# For logs with labeled timestamp
TIME_PREFIX = timestamp=
TIME_FORMAT = %s

# Disable timestamp extraction (use index time)
DATETIME_CONFIG = CURRENT
```

### Common Time Formats

| Format Code | Description | Example |
|-------------|-------------|---------|
| `%Y` | 4-digit year | 2025 |
| `%m` | Month (01-12) | 12 |
| `%d` | Day (01-31) | 02 |
| `%H` | Hour (00-23) | 15 |
| `%M` | Minute (00-59) | 30 |
| `%S` | Second (00-59) | 45 |
| `%3N` | Milliseconds | 123 |
| `%6N` | Microseconds | 123456 |
| `%z` | Timezone offset | +0000 |
| `%:z` | Timezone with colon | +00:00 |
| `%s` | Unix epoch seconds | 1733184645 |

### Line Breaking

```ini
[my_sourcetype]
# Break before pattern (new event starts with pattern)
SHOULD_LINEMERGE = true
LINE_BREAKER = ([\r\n]+)(?=\d{4}-\d{2}-\d{2})

# Break after pattern
LINE_BREAKER = ([\r\n]+)

# Disable line merging (each line is an event)
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)

# Merge continuation lines (lines starting with whitespace)
SHOULD_LINEMERGE = true
BREAK_ONLY_BEFORE = ^\S

# Multi-line events with specific end pattern
MUST_BREAK_AFTER = ;\s*$

# Maximum event size (bytes)
TRUNCATE = 100000
MAX_EVENTS = 256
```

### Line Breaking Examples

```ini
# Java stack traces (merge lines starting with whitespace or "at")
[java_logs]
SHOULD_LINEMERGE = true
BREAK_ONLY_BEFORE = ^\d{4}-\d{2}-\d{2}
MAX_EVENTS = 1000

# Syslog (each line is an event)
[syslog]
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)

# XML events (break on closing tag)
[xml_events]
SHOULD_LINEMERGE = true
LINE_BREAKER = ([\r\n]+)(?=<event>)

# JSON events (one JSON object per line)
[json_logs]
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)
```

### Character Encoding

```ini
[my_sourcetype]
# UTF-8 (default)
CHARSET = UTF-8

# Windows encoding
CHARSET = CP1252

# Latin-1
CHARSET = ISO-8859-1

# Auto-detect
CHARSET = AUTO
```

### Search-Time Field Extractions (EXTRACT)

```ini
[my_sourcetype]
# Inline regex extraction
EXTRACT-username = user=(?<username>\w+)
EXTRACT-ip_address = src_ip=(?<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})
EXTRACT-status_code = status=(?<status_code>\d{3})

# Multiple fields in one extraction
EXTRACT-auth_fields = user=(?<user>\w+)\s+action=(?<action>\w+)\s+result=(?<result>\w+)

# Key-value extraction
KV_MODE = auto
```

### Search-Time Field Extractions (REPORT - references transforms.conf)

```ini
[my_sourcetype]
# Reference transforms.conf stanzas
REPORT-extract_user = extract_username
REPORT-extract_multiple = extract_src_dest, extract_status
```

### Index-Time Field Extractions (TRANSFORMS)

```ini
[my_sourcetype]
# Index-time extraction (use sparingly - impacts performance)
TRANSFORMS-extract_critical = index_time_extraction
```

### Data Modification with SEDCMD

```ini
[my_sourcetype]
# Replace sensitive data
SEDCMD-mask_ssn = s/\d{3}-\d{2}-\d{4}/XXX-XX-XXXX/g
SEDCMD-mask_credit_card = s/\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}/XXXX-XXXX-XXXX-XXXX/g

# Remove unwanted text
SEDCMD-remove_debug = s/DEBUG:.*//g

# Normalize data
SEDCMD-lowercase_host = s/HOST=([A-Z]+)/HOST=\L\1/g

# Multiple replacements (order matters)
SEDCMD-clean1 = s/password=\S+/password=REDACTED/g
SEDCMD-clean2 = s/api_key=\S+/api_key=HIDDEN/g
```

### Field Aliases and Calculated Fields

```ini
[my_sourcetype]
# Field aliases (CIM compliance)
FIELDALIAS-src = source_ip AS src
FIELDALIAS-dest = destination_ip AS dest
FIELDALIAS-user = username AS user

# Calculated fields (search-time)
EVAL-bytes_kb = bytes / 1024
EVAL-duration_minutes = duration / 60
EVAL-is_error = if(status >= 400, "true", "false")
```

### Event Types and Tags

```ini
[my_sourcetype]
# Assign sourcetype based on content
TRANSFORMS-set_sourcetype = set_sourcetype_by_content
```

---

## Transforms.conf Configuration

### Basic Field Extraction

```ini
[extract_username]
REGEX = user[=:][\s"]*(?<user>[^\s"]+)
FORMAT = user::$1

[extract_ip_addresses]
REGEX = src[=:](?<src>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*dest[=:](?<dest>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})

[extract_key_value]
REGEX = (\w+)=([^\s,]+)
FORMAT = $1::$2
```

### Index-Time Extraction

```ini
[index_time_extraction]
REGEX = critical_field=(?<critical_field>\w+)
FORMAT = critical_field::$1
WRITE_META = true
```

### Data Routing and Filtering

```ini
# Route events to different indexes
[route_to_security]
REGEX = (failed|denied|blocked)
DEST_KEY = _MetaData:Index
FORMAT = security

[route_by_severity]
REGEX = severity=(?<severity>critical|high|medium|low)
DEST_KEY = _MetaData:Index
FORMAT = $1_events

# Null queue (drop events)
[drop_debug_events]
REGEX = ^DEBUG
DEST_KEY = queue
FORMAT = nullQueue

# Filter specific events
[filter_healthcheck]
REGEX = healthcheck|heartbeat|keepalive
DEST_KEY = queue
FORMAT = nullQueue
```

### Sourcetype Override

```ini
[set_sourcetype_by_content]
REGEX = <syslog>
DEST_KEY = MetaData:Sourcetype
FORMAT = sourcetype::syslog_xml

[detect_json]
REGEX = ^\s*\{
DEST_KEY = MetaData:Sourcetype
FORMAT = sourcetype::_json
```

### Host Extraction

```ini
[extract_host_from_path]
REGEX = /var/log/(?<host>[^/]+)/
DEST_KEY = MetaData:Host
FORMAT = host::$1

[extract_host_from_event]
REGEX = hostname[=:](?<host>\S+)
DEST_KEY = MetaData:Host
FORMAT = host::$1
```

### Data Masking/Anonymization

```ini
[mask_passwords]
REGEX = (password|passwd|pwd)[=:]\s*(\S+)
FORMAT = $1=********
DEST_KEY = _raw

[mask_email]
REGEX = ([a-zA-Z0-9_.+-]+)@([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)
FORMAT = [EMAIL_REDACTED]@$2
DEST_KEY = _raw

[hash_user_id]
REGEX = user_id=(\d+)
FORMAT = user_id=HASH_$1
DEST_KEY = _raw
```

### Lookup Transforms

```ini
[user_lookup]
filename = users.csv
match_type = WILDCARD(user)
max_matches = 1
min_matches = 1
default_match = unknown
case_sensitive_match = false

[geo_lookup]
filename = geo_ip.csv
max_matches = 1
min_matches = 0
```

---

## Common Use Cases

### 1. Custom Application Logs

**props.conf:**
```ini
[myapp:application]
TIME_PREFIX = \[
TIME_FORMAT = %Y-%m-%d %H:%M:%S,%3N
MAX_TIMESTAMP_LOOKAHEAD = 30
SHOULD_LINEMERGE = true
BREAK_ONLY_BEFORE = ^\[
TRUNCATE = 50000

# Field extractions
EXTRACT-level = \[(?<log_level>INFO|WARN|ERROR|DEBUG)\]
EXTRACT-class = \[(?:[^\]]+)\]\s+(?<class>[\w.]+)\s+-
REPORT-app_fields = extract_app_user, extract_app_session

# CIM compliance
FIELDALIAS-src = client_ip AS src
EVAL-severity = case(log_level="ERROR", "high", log_level="WARN", "medium", 1=1, "low")
```

**transforms.conf:**
```ini
[extract_app_user]
REGEX = user=(?<user>[^\s,]+)

[extract_app_session]
REGEX = session_id=(?<session_id>[a-f0-9-]+)
```

### 2. Firewall Logs with Routing

**props.conf:**
```ini
[firewall:traffic]
TIME_FORMAT = %Y-%m-%dT%H:%M:%S%:z
SHOULD_LINEMERGE = false

TRANSFORMS-route = route_blocked_to_security, drop_allow_logs
REPORT-fw_fields = extract_fw_src_dest, extract_fw_action
```

**transforms.conf:**
```ini
[route_blocked_to_security]
REGEX = action=(blocked|denied|dropped)
DEST_KEY = _MetaData:Index
FORMAT = security

[drop_allow_logs]
REGEX = action=allow.*category=internal
DEST_KEY = queue
FORMAT = nullQueue

[extract_fw_src_dest]
REGEX = src=(?<src>\S+)\s+dst=(?<dest>\S+)\s+port=(?<dest_port>\d+)

[extract_fw_action]
REGEX = action=(?<action>\w+)\s+reason=(?<reason>[^,]+)
```

### 3. Multi-line Java Stack Traces

**props.conf:**
```ini
[java:application]
TIME_PREFIX = ^
TIME_FORMAT = %Y-%m-%d %H:%M:%S.%3N
SHOULD_LINEMERGE = true
BREAK_ONLY_BEFORE = ^\d{4}-\d{2}-\d{2}
MAX_EVENTS = 500
TRUNCATE = 100000

EXTRACT-exception = Exception:\s+(?<exception_class>[\w.]+):\s+(?<exception_message>.+)
EXTRACT-thread = \[(?<thread>[^\]]+)\]
```

### 4. JSON Log Processing

**props.conf:**
```ini
[json:application]
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)
KV_MODE = json
TIME_PREFIX = "timestamp"\s*:\s*"
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%3NZ

# Auto-extract JSON fields
INDEXED_EXTRACTIONS = json
```

### 5. Syslog with Host Extraction

**props.conf:**
```ini
[syslog]
TIME_FORMAT = %b %d %H:%M:%S
SHOULD_LINEMERGE = false
TRANSFORMS-host = extract_syslog_host

EXTRACT-facility = <(?<facility>\d+)>
EXTRACT-process = (?<process>\w+)\[(?<pid>\d+)\]
```

**transforms.conf:**
```ini
[extract_syslog_host]
REGEX = ^<\d+>\w+\s+\d+\s+[\d:]+\s+(?<host>\S+)
DEST_KEY = MetaData:Host
FORMAT = host::$1
```

### 6. Data Masking for Compliance

**props.conf:**
```ini
[sensitive_data]
SEDCMD-mask_ssn = s/\b\d{3}-\d{2}-\d{4}\b/XXX-XX-XXXX/g
SEDCMD-mask_cc = s/\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/XXXX-XXXX-XXXX-XXXX/g
TRANSFORMS-mask_passwords = mask_password_fields
```

**transforms.conf:**
```ini
[mask_password_fields]
INGEST_EVAL = password=if(isnotnull(password), "********", password)
```

---

## Debugging and Validation

### Test Regex Online
Use regex101.com with PCRE flavor to test patterns before deployment.

### Check Configuration

```bash
# Validate props.conf syntax
$SPLUNK_HOME/bin/splunk btool props list --debug | grep -i myapp

# Validate transforms.conf syntax
$SPLUNK_HOME/bin/splunk btool transforms list --debug

# Check effective settings for a sourcetype
$SPLUNK_HOME/bin/splunk btool props list my_sourcetype --debug
```

### SPL for Testing Extractions

```spl
# Test EXTRACT patterns at search time
index=main sourcetype=myapp
| rex field=_raw "user=(?<test_user>\w+)"
| table _raw test_user

# Test field extraction coverage
index=main sourcetype=myapp
| stats count by user
| where isnull(user)

# Validate timestamp parsing
index=main sourcetype=myapp
| eval time_diff = abs(_time - _indextime)
| where time_diff > 300
| table _time _indextime time_diff _raw
```

---

## Best Practices

### Performance

1. **Prefer search-time extractions** over index-time when possible
2. **Use SEDCMD sparingly** - it runs on every event at index time
3. **Anchor regex patterns** with `^` or specific prefixes when possible
4. **Avoid greedy patterns** like `.*` - use non-greedy `.*?` or specific character classes
5. **Test regex performance** with large data volumes before production

### Maintainability

1. **Use descriptive stanza names** in transforms.conf
2. **Comment your configurations** explaining the purpose
3. **Group related settings** together
4. **Version control** all configuration files
5. **Document field naming conventions** for team consistency

### CIM Compliance

1. **Use FIELDALIAS** to map fields to CIM names
2. **Add EVAL fields** for calculated CIM fields
3. **Reference CIM documentation** for correct field names
4. **Test with data model** searches after configuration

---

## Troubleshooting

### Timestamp Issues

| Problem | Solution |
|---------|----------|
| Wrong timezone | Add `TZ = UTC` or appropriate timezone |
| Timestamp not extracted | Verify TIME_PREFIX and TIME_FORMAT match log format |
| Future timestamps | Check MAX_TIMESTAMP_LOOKAHEAD setting |
| Multiple timestamps | Use TIME_PREFIX to identify correct one |

### Line Breaking Issues

| Problem | Solution |
|---------|----------|
| Events split incorrectly | Adjust LINE_BREAKER or BREAK_ONLY_BEFORE |
| Events merged incorrectly | Set SHOULD_LINEMERGE = false |
| Truncated events | Increase TRUNCATE value |
| Multi-line not merging | Check SHOULD_LINEMERGE and MAX_EVENTS |

### Field Extraction Issues

| Problem | Solution |
|---------|----------|
| Fields not extracted | Test regex in SPL with rex command first |
| Partial matches | Check for greedy patterns, add anchors |
| Wrong field names | Verify named capture groups syntax |
| Transforms not applied | Check REPORT/TRANSFORMS reference names match |

---

## Related Topics

- Splunk Add-on Development
- CIM (Common Information Model)
- Field Extraction Methods
- Data Onboarding
- Search-time vs Index-time Operations
- Data Routing and Filtering
- Splunk Regular Expressions
