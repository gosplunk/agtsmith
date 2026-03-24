# Splunk Rex Command - Field Extraction Guide

**Document Type**: Command Reference
**Audience**: Splunk Users, Search Developers, Data Engineers
**Topics**: rex, Regular Expressions, Field Extraction, Parsing
**Keywords**: rex, regex, regular expression, field extraction, named capture group, sed mode, parsing, extract field, pattern matching

**Last Updated**: 2025-12-22

---

## Quick Summary

Guide to the Splunk rex command for field extraction using regular expressions. Covers named capture groups, sed mode for replacement, common patterns (IP, email, username), and troubleshooting regex issues.

**Find this document by searching for**: rex command, regex extraction, named capture group, field extraction, sed mode, regular expression, extract IP, extract username

---

## Overview

The `rex` command extracts fields from raw event data using regular expressions. It's one of the most commonly used commands for parsing unstructured data.

## Basic Syntax

```spl
| rex field=<field_name> "(?<new_field>regex_pattern)"
```

## Named Capture Groups

Extract fields using `(?<field_name>pattern)` syntax:

```spl
# Extract IP address from raw events
index=main sourcetype=access_combined
| rex field=_raw "(?<client_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"

# Extract username from log message
index=main sourcetype=syslog
| rex field=_raw "user=(?<username>\w+)"

# Extract multiple fields at once
index=main sourcetype=firewall
| rex field=_raw "src=(?<src_ip>\d+\.\d+\.\d+\.\d+)\s+dst=(?<dst_ip>\d+\.\d+\.\d+\.\d+)\s+port=(?<port>\d+)"
```

## Common Regex Patterns

| Pattern | Description | Example Match |
|---------|-------------|---------------|
| `\d+` | One or more digits | 12345 |
| `\w+` | Word characters | username123 |
| `\S+` | Non-whitespace | any-text_here |
| `[^"]+` | Anything except quote | value in quotes |
| `[^\s]+` | Non-space characters | single_word |
| `.*?` | Non-greedy any char | minimal match |
| `\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}` | IPv4 address | 192.168.1.1 |

## Rex Mode: sed

Use `mode=sed` for search and replace operations:

```spl
# Replace text in a field
index=main
| rex field=message mode=sed "s/ERROR/CRITICAL/g"

# Remove unwanted characters
index=main
| rex field=hostname mode=sed "s/\.example\.com//g"

# Multiple replacements
index=main
| rex field=status mode=sed "s/0/inactive/g"
| rex field=status mode=sed "s/1/active/g"
```

### Sed Flags
- `g` - Global replacement (all occurrences)
- `i` - Case insensitive
- No flag - First occurrence only

## Max Match Parameter

Extract multiple occurrences into a multivalue field:

```spl
# Extract all IP addresses (default max_match=1)
index=main
| rex field=_raw "(?<all_ips>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})" max_match=0

# max_match=0 means unlimited matches
# max_match=5 means up to 5 matches
```

## Offset Capture

Use `offset_field` to track where matches occur:

```spl
index=main
| rex field=_raw "(?<error_msg>ERROR.*)" offset_field=error_position
```

## Real-World Examples

### Extract Email Addresses
```spl
index=main
| rex field=_raw "(?<email>[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"
| stats count by email
```

### Parse URL Components
```spl
index=web_logs
| rex field=url "https?://(?<domain>[^/]+)(?<path>/[^?]*)?\??(?<query>.*)?"
| stats count by domain
```

### Extract Windows Event User
```spl
index=winevents EventCode=4624
| rex field=Message "Account Name:\s+(?<logon_user>[^\s]+)"
| stats count by logon_user
```

### Parse Syslog Priority
```spl
index=syslog
| rex field=_raw "^<(?<priority>\d+)>"
| eval facility=floor(priority/8)
| eval severity=priority-(facility*8)
```

### Extract JSON Values (when spath doesn't work)
```spl
index=main sourcetype=json_logs
| rex field=_raw "\"user_id\":\s*\"(?<user_id>[^\"]+)\""
| rex field=_raw "\"action\":\s*\"(?<action>[^\"]+)\""
```

### Parse Key-Value Pairs
```spl
index=app_logs
| rex field=_raw "(?<kv_pair>\w+=\S+)" max_match=0
| mvexpand kv_pair
| rex field=kv_pair "(?<key>\w+)=(?<value>\S+)"
```

### Extract from Multiline Events
```spl
index=main
| rex field=_raw "Exception:\s*(?<exception_type>\S+)[\s\S]*?at\s+(?<stack_location>[^\n]+)"
```

## Performance Tips

1. **Be specific** - Avoid `.*` when possible, use `[^delimiter]+`
2. **Anchor patterns** - Use `^` or context to narrow matches
3. **Test first** - Use `| rex ... | table new_field` to validate
4. **Use field= parameter** - Extract from specific field, not always _raw
5. **Consider transforms.conf** - For repeated extractions, define in props/transforms

## Rex vs Other Extraction Methods

| Method | Use Case | Performance |
|--------|----------|-------------|
| `rex` | Ad-hoc, complex patterns | Search-time |
| `transforms.conf` | Repeated extractions | Index-time |
| `spath` | JSON/XML data | Search-time |
| `kv` | Key=value pairs | Search-time |
| `extract` | Auto field discovery | Search-time |

## Troubleshooting

### Pattern Not Matching
```spl
# Debug by showing raw data
index=main | head 5 | table _raw

# Test regex incrementally
index=main | rex field=_raw "(?<test>partial_pattern)" | table test
```

### Multivalue Results Unexpected
```spl
# Check if field is already multivalue
index=main | stats values(field) as field_values

# Use mvindex to get specific occurrence
| rex field=_raw "(?<ip>\d+\.\d+\.\d+\.\d+)" max_match=0
| eval first_ip=mvindex(ip,0)
```

## MCP Compatibility

✅ **Supported via MCP**: The rex command works fully with MCP Splunk integration
- Field extraction searches execute normally
- Results return extracted fields
- Mode=sed replacements work

### MCP Example Prompts
- "extract IP addresses from firewall logs using rex"
- "parse username from syslog events with rex"
- "use rex to extract email addresses and count them"

## Quick Reference

```spl
# Basic extraction
| rex field=<field> "(?<new_field>pattern)"

# Multiple fields
| rex field=_raw "src=(?<src>\S+)\s+dst=(?<dst>\S+)"

# All matches (multivalue)
| rex field=_raw "(?<field>pattern)" max_match=0

# Search and replace
| rex field=<field> mode=sed "s/old/new/g"

# With offset tracking
| rex field=_raw "(?<field>pattern)" offset_field=pos
```
