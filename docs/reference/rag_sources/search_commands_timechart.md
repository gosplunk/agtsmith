# Splunk Timechart Command - Time-Series Visualization Guide

**Document Type**: Command Reference
**Audience**: Splunk Users, Dashboard Developers, Analysts
**Topics**: timechart, Time-Series, Visualization, Trend Analysis
**Keywords**: timechart, time series, trend analysis, span, time bucket, visualization, dashboard, chart over time, time aggregation

**Last Updated**: 2025-12-22

---

## Quick Summary

Guide to the Splunk timechart command for time-series visualizations. Covers span options, aggregation functions, split-by fields, limit options, and dashboard integration. Essential for trend analysis and time-based reporting.

**Find this document by searching for**: timechart, time series chart, span option, trend analysis, chart over time, time aggregation, visualization

---

## Overview

The `timechart` command creates time-series charts by aggregating data over time intervals. It's essential for trend analysis, dashboards, and visualizing patterns over time.

## Basic Syntax

```spl
| timechart <span_options> <aggregation_function> [by <split_field>]
```

## Core Aggregations

```spl
# Count events over time
index=main | timechart count

# Sum of a numeric field
index=sales | timechart sum(amount)

# Average response time
index=web_logs | timechart avg(response_time)

# Multiple aggregations
index=web_logs | timechart avg(response_time) as avg_resp, max(response_time) as max_resp, count
```

## Time Span Options

### Automatic Span
```spl
# Splunk auto-selects span based on time range
index=main | timechart count
```

### Fixed Span
```spl
# Per minute
index=main | timechart span=1m count

# Per hour
index=main | timechart span=1h count

# Per day
index=main | timechart span=1d count

# Per week
index=main | timechart span=1w count

# Custom intervals
index=main | timechart span=15m count    # 15 minutes
index=main | timechart span=4h count     # 4 hours
index=main | timechart span=30s count    # 30 seconds
```

### Span Units
| Unit | Description |
|------|-------------|
| `s` | Seconds |
| `m` | Minutes |
| `h` | Hours |
| `d` | Days |
| `w` | Weeks |
| `mon` | Months |

## Split By Field

Create separate series for each value:

```spl
# Count by status code
index=web_logs | timechart count by status

# Average response by host
index=web_logs | timechart span=5m avg(response_time) by host

# Errors by sourcetype
index=main | timechart span=1h count by sourcetype
```

## Limit Results

Control number of series displayed:

```spl
# Top 5 hosts by count
index=main | timechart span=1h count by host limit=5

# Top 10 sourcetypes, group rest as "OTHER"
index=main | timechart count by sourcetype limit=10 useother=true

# Don't show OTHER category
index=main | timechart count by sourcetype limit=10 useother=false

# Show null values
index=main | timechart count by status usenull=true
```

## Aggregation Functions

### Statistical Functions
```spl
# Count
| timechart count
| timechart count(field)     # Count non-null values
| timechart dc(user)         # Distinct count

# Sum and Average
| timechart sum(bytes)
| timechart avg(duration)

# Min/Max
| timechart min(response_time), max(response_time)

# Percentiles
| timechart perc95(response_time)
| timechart p50(latency), p90(latency), p99(latency)

# Standard deviation
| timechart stdev(value)

# First/Last value
| timechart first(status)
| timechart last(value)

# Range
| timechart range(temperature)
```

### Multiple Aggregations
```spl
index=web_logs
| timechart span=5m 
    count as requests,
    avg(response_time) as avg_resp,
    max(response_time) as max_resp,
    dc(client_ip) as unique_users
```

## Real-World Examples

### Traffic Volume Over Time
```spl
index=web_logs
| timechart span=1h count as requests by status
| rename 200 as "Success", 404 as "Not Found", 500 as "Server Error"
```

### Bandwidth Usage
```spl
index=network
| timechart span=15m sum(bytes_in) as inbound, sum(bytes_out) as outbound
| eval inbound_mb=round(inbound/1024/1024,2)
| eval outbound_mb=round(outbound/1024/1024,2)
```

### Error Rate Percentage
```spl
index=web_logs
| eval is_error=if(status>=400,1,0)
| timechart span=1h sum(is_error) as errors, count as total
| eval error_rate=round((errors/total)*100,2)
| fields _time error_rate
```

### Login Activity Analysis
```spl
index=winevents EventCode=4624
| timechart span=1h count by Logon_Type
| rename 2 as "Interactive", 3 as "Network", 10 as "RemoteInteractive"
```

### CPU Utilization Trend
```spl
index=os_metrics sourcetype=cpu
| timechart span=5m avg(cpu_percent) by host limit=10
```

### Security Events Heat Map Data
```spl
index=security
| eval hour=strftime(_time,"%H")
| eval day=strftime(_time,"%A")
| timechart span=1h count by day
```

### Application Performance
```spl
index=apm
| timechart span=10m 
    avg(response_time) as avg_ms,
    perc95(response_time) as p95_ms,
    count as transactions
| eval avg_ms=round(avg_ms,2)
| eval p95_ms=round(p95_ms,2)
```

### Compare Today vs Yesterday
```spl
index=web_logs earliest=-1d@d latest=@d
| eval day="Yesterday"
| append [search index=web_logs earliest=@d latest=now | eval day="Today"]
| timechart span=1h count by day
```

## Null and Gaps

### Handle Missing Data
```spl
# Fill gaps with zeros
index=main | timechart span=1h count | fillnull value=0

# Continuous time series (no gaps)
index=main | timechart span=1h count cont=true

# Partial buckets
index=main | timechart span=1h count partial=true
```

## Format and Output

### Rename Series
```spl
index=web_logs
| timechart count by status
| rename 200 as "OK", 404 as "NotFound", 500 as "Error"
```

### Calculate Additional Fields
```spl
index=web_logs
| timechart span=1h sum(bytes) as total_bytes
| eval total_gb=round(total_bytes/1024/1024/1024,3)
| fields _time total_gb
```

## Timechart vs Chart

| Feature | timechart | chart |
|---------|-----------|-------|
| X-axis | Always _time | Any field |
| Span | Time intervals | N/A |
| Use case | Time trends | Category comparison |

```spl
# timechart - time on X axis
| timechart count by status

# chart - any field on X axis  
| chart count by status over host
```

## Performance Tips

1. **Use appropriate span** - Too granular = slow, too coarse = lose detail
2. **Limit series** - Use `limit=N` to cap split-by cardinality
3. **Filter first** - Reduce data before timechart
4. **Avoid high cardinality** - Don't split by unique fields like user_id

```spl
# Good - filter then aggregate
index=web_logs status>=400
| timechart span=5m count by host limit=10

# Bad - high cardinality split
index=web_logs | timechart count by client_ip   # Avoid!
```

## MCP Compatibility

✅ **Supported via MCP**: Timechart commands execute normally
- Time-series aggregations return tabular data
- Results include _time column and series columns
- Visualizations can be built from returned data

### MCP Example Prompts
- "show me event count over time for the last 24 hours using timechart"
- "timechart errors per hour by sourcetype from main index"
- "create timechart of average response time span 5 minutes"
- "use timechart to show login events by hour"

## Quick Reference

```spl
# Basic count over time
| timechart count

# With time span
| timechart span=1h count

# Split by field
| timechart span=1h count by status

# Multiple aggregations
| timechart avg(field1) max(field2) count

# Limit series
| timechart count by host limit=10 useother=true

# Common patterns
| timechart span=5m count                    # Events per 5 min
| timechart span=1h avg(response_time)       # Hourly average
| timechart span=1d dc(user) as unique_users # Daily unique users
| timechart span=1h sum(bytes) by host       # Hourly bytes per host
```
