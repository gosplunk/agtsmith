# Tstats Command Reference

---
tags: [splunk, tstats, spl, datamodel, acceleration, performance, metrics]
category: search
last_updated: 2026-02-20
related_docs: [search_commands_mstats.md, search_commands_datamodel.md, spl_quick_reference.md]
---

**Document Type**: Search Command Reference
**Audience**: Splunk Power Users, Data Model Developers, Performance Specialists
**Topics**: Tstats, Data Models, Acceleration, Performance, MCP
**Keywords**: tstats, data model, acceleration, metric index, performance optimization, MCP queries

**Quick Links:**
- Splunk Tstats Documentation: https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Tstats
- Data Models Guide: https://docs.splunk.com/Documentation/Splunk/latest/Knowledge/Datamodels
- Acceleration Setup: https://docs.splunk.com/Documentation/Splunk/latest/Knowledge/Accelerateadatamodel
- Performance Tuning: https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Tstatsusage

**Description:** Using tstats for high-performance searches against accelerated data models and metric indexes

**Last Updated:** 2025-12-01

## Overview

Tstats is a powerful command that searches data model acceleration indexes, providing extreme performance improvements compared to regular searches.

## MCP (Model Context Protocol) Limitations

**CRITICAL:** When using tstats via Splunk MCP, the `by` clause is NOT supported:

### Working MCP Queries
```spl
# ✅ Simple count (no by clause)
| tstats count from datamodel=Authentication

# ✅ WHERE clause filtering (no by clause)
| tstats count from datamodel=Authentication WHERE Authentication.action=success

# ✅ values() aggregation (no by clause)
| tstats count values(Authentication.action) from datamodel=Authentication
```

### Failing MCP Queries (Validation Error)
```spl
# ❌ ANY by clause causes "string indices must be integers" error
| tstats count from datamodel=Authentication by Authentication.user

# ❌ by with _time also fails
| tstats count from datamodel=Authentication by _time span=1h

# ❌ Multiple by fields fail
| tstats count from datamodel=Authentication by Authentication.user, Authentication.action

# ❌ by with WHERE clause fails
| tstats count from datamodel=Authentication WHERE Authentication.action IN (success, failure) by Authentication.action
```

### MCP Workaround - Use datamodel + stats
Use the `datamodel` command with `flat` mode and pipe to `stats`:
```spl
# ✅ Works in MCP - equivalent to tstats count by user action
| datamodel Authentication Authentication flat | stats count by user action

# ✅ Works in MCP - with time grouping
| datamodel Authentication Authentication flat | bin _time span=1h | stats count by _time user action

# ✅ Works in MCP - with filtering
| datamodel Authentication Authentication flat | search action IN (success, failure) | stats count by action
```

---

## Basic Tstats Syntax

```spl
| tstats count from datamodel=Network_Traffic by src, dest
```

### Components

- `tstats` - The command
- `count` - Aggregation function
- `from datamodel=<name>` - Data model to search
- `by src, dest` - Group by fields

## Data Model Searches

### Web Traffic Analysis

```spl
| tstats count from datamodel=Web where Web.src="<PLACEHOLDER_IP>" by Web.action, Web.status
```

### Network Connection Analysis

```spl
| tstats count from datamodel=Network_Traffic by Network_Traffic.src, Network_Traffic.dest, Network_Traffic.bytes
| where bytes > 1000000
```

### Endpoint Process Execution

```spl
| tstats count from datamodel=Endpoint.Processes by Processes.user, Processes.process
| search process="*powershell*"
```

## Advanced Tstats Examples

### Timechart with Data Models

```spl
| tstats count from datamodel=Intrusion_Detection by _time, Intrusion_Detection.signature
| timechart count by signature
```

### Multi-Source Data Model Query

```spl
| tstats avg(bytes) as avg_bytes 
        max(bytes) as max_bytes
        count as packet_count
    from datamodel=Network_Traffic
    where Network_Traffic.action="allowed"
    by Network_Traffic.src, Network_Traffic.dest
```

### Data Model with Eval

```spl
| tstats count from datamodel=Authentication 
    where Authentication.action="success"
    by Authentication.user, Authentication.src
| eval status="successful_login"
```

## Aggregation Functions in Tstats

| Function | Description | Example |
|----------|-------------|---------|
| `count` | Count of events | `count` |
| `sum()` | Sum of numeric field | `sum(bytes)` |
| `avg()` | Average value | `avg(latency)` |
| `max()` | Maximum value | `max(response_size)` |
| `min()` | Minimum value | `min(_time)` |
| `dc()` | Distinct count | `dc(user)` |
| `values()` | Unique values | `values(src)` |
| `latest()` | Last value | `latest(_time)` |
| `earliest()` | First value | `earliest(_time)` |

## Data Model Reference

### Common Data Models (CIM)

- **Network_Traffic**: Firewall logs, IDS/IPS data
- **Web**: Web server logs (access, application)
- **Endpoint.Processes**: Process execution data
- **Endpoint.Network_Connections**: Network connection data
- **Authentication**: Login and access events
- **Intrusion_Detection**: IDS/IPS alerts
- **Email**: Email message data

## Performance Benefits

### Tstats vs Regular Search

**Regular Search** (slow):
```spl
index=firewall action="allowed"
| stats count by src, dest
```

**Tstats Search** (fast):
```spl
| tstats count from datamodel=Network_Traffic where Network_Traffic.action="allowed" by src, dest
```

**Performance Improvement**: 10-100x faster on accelerated data models

## Data Model Acceleration

### Enable Acceleration

1. **Open Data Model**
2. **Click Acceleration tab**
3. **Enable Acceleration**
4. **Configure Retention**: How long to keep acceleration indexes
5. **Click Save**

### Monitor Acceleration Status

```spl
| rest /servicesNS/-/-/datamodel | search description="*Network*"
| table title, acceleration.status, acceleration.earliest, acceleration.latest
```

## Tstats WHERE Clause

### Basic WHERE Filtering

```spl
| tstats count from datamodel=Network_Traffic 
    where Network_Traffic.action="blocked" 
    by Network_Traffic.signature
```

### Multiple WHERE Conditions

```spl
| tstats count from datamodel=Authentication
    where Authentication.action="failure" 
    AND Authentication.src="<PLACEHOLDER_IP>"
    by Authentication.user
```

### WHERE with Value Ranges

```spl
| tstats count from datamodel=Web
    where Web.response_code >= 400
    AND Web.response_code < 600
    by Web.dest, Web.status
```

## Tstats Limitations and Solutions

| Limitation | Impact | Solution |
|-----------|--------|----------|
| Cannot use transforming commands | Limited post-processing | Add `| rest /servicesNS` after tstats |
| Cannot search raw events | Only aggregated data | Combine with regular search |
| Requires data model acceleration | Extra setup | Enable acceleration for frequently-searched models |
| Limited field availability | Only model fields | Extend data models with custom fields |

## Common Patterns

### User Activity Summary

```spl
| tstats count as login_attempts
        values(Authentication.src) as source_ips
        latest(_time) as last_login
    from datamodel=Authentication
    where Authentication.action="success"
    by Authentication.user
| where login_attempts > 10
```

### Top Network Conversations

```spl
| tstats sum(Network_Traffic.bytes) as total_bytes
        count as packets
        latest(_time) as last_seen
    from datamodel=Network_Traffic
    by Network_Traffic.src, Network_Traffic.dest
| sort -total_bytes
| head 20
```

### Process Execution Tracking

```spl
| tstats count as execution_count
        values(Processes.src) as source_hosts
        dc(Processes.user) as distinct_users
    from datamodel=Endpoint.Processes
    where Processes.process="*suspicious_process*"
    by Processes.process_name
```

## Best Practices

1. **Always Accelerate**: Enable acceleration for frequently-searched data models
2. **Use WHERE Early**: Filter at tstats level, not after
3. **Limit Output Fields**: Only request fields you need
4. **Monitor Acceleration**: Check acceleration indexes size regularly
5. **Version Control**: Track data model changes in version control
6. **Document Models**: Keep documentation of custom data models
7. **Test Performance**: Compare tstats vs regular search before deployment

## Troubleshooting

### No Data in Tstats Results

**Cause**: Acceleration not built yet  
**Solution**: Wait for acceleration to build or run regular search first

### Tstats Returns Empty

**Cause**: Data model fields don't match actual data  
**Solution**: Verify field names and data model mappings in props.conf

### Slow Tstats Queries

**Cause**: Acceleration not enabled or too much post-processing  
**Solution**: Enable acceleration and minimize post-processing

## Related Topics

- Data Model Configuration and Optimization
- Eval Command and Field Calculations
- Search Performance Optimization
- CIM and Field Mappings
- Acceleration Index Management
