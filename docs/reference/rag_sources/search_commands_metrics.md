# Splunk Metrics Search Commands Reference

**Document Type**: Search Command Reference
**Audience**: Splunk Power Users, Observability Specialists, Metrics Engineers
**Topics**: Metrics, mstats, mcatalog, mpreview, mcollect, meventcollect, Time Series Analysis
**Keywords**: mstats, mcatalog, mpreview, mcollect, meventcollect, metrics, metric index, time series, metric aggregation, observability, linux_metrics, windows_metrics, em_metrics

**Quick Links:**
- Splunk Metrics Overview: https://docs.splunk.com/Documentation/Splunk/latest/Metrics/Overview
- mstats Command: https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Mstats
- mcatalog Command: https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Mcatalog
- mpreview Command: https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Mpreview

**Description:** Complete reference for searching, monitoring, and analyzing metrics data in Splunk metrics indexes

**Last Updated:** 2025-12-02

## Overview

Splunk metrics indexes store time-series data optimized for numerical measurements. Unlike event indexes, metrics indexes are designed for high-cardinality, high-volume numerical data like CPU usage, memory utilization, network throughput, and application performance metrics.

### Key Metrics Commands

| Command | Purpose | Use Case |
|---------|---------|----------|
| `mstats` | Aggregate metrics data | Main command for metrics analysis |
| `mcatalog` | Enumerate metric names/dimensions | Discovery and exploration |
| `mpreview` | View individual metric data points | Troubleshooting and onboarding |
| `mcollect` | Write metrics to index | Convert events to metrics |
| `meventcollect` | Write events as metrics | Batch conversion |

## Metric Structure

### Components of a Metric

```
metric_name=cpu_usage _value=45.2 _time=1701475200 host=server01 region=us-east
```

- **metric_name**: Identifier for the metric (e.g., cpu_usage, memory_free)
- **_value**: The numerical measurement
- **_time**: Timestamp of the measurement
- **Dimensions**: Key-value pairs for filtering/grouping (host, region, service, etc.)

## mcatalog - Metrics Discovery

The `mcatalog` command enumerates metric names, dimensions, and values in metrics indexes.

### List All Metric Names

```spl
| mcatalog values(metric_name) WHERE index=*
```

### List All Metric Names in Specific Index

```spl
| mcatalog values(metric_name) WHERE index=linux_metrics
```

```spl
| mcatalog values(metric_name) WHERE index=windows_metrics
```

### List All Dimensions

```spl
| mcatalog values(_dims) WHERE index=*
```

### List Dimensions for Specific Metric

```spl
| mcatalog values(_dims) WHERE index=linux_metrics AND metric_name="cpu.idle"
```

### List Hosts with Metrics

```spl
| mcatalog values(host) WHERE index=linux_metrics
```

### Count Metrics by Name

```spl
| mcatalog values(metric_name) as metric WHERE index=linux_metrics
| stats count by metric
```

## mstats - Metrics Aggregation

The `mstats` command performs statistical aggregations on metrics data.

### Basic Syntax

```spl
| mstats <aggregation>(_value) [as <alias>] 
    WHERE index=<metrics_index> [AND metric_name=<name>]
    [BY <dimensions>]
    [span=<time>]
```

### Simple Metric Count

```spl
| mstats count WHERE index=linux_metrics metric_name=cpu.idle
```

### Average CPU Usage by Host

```spl
| mstats avg(_value) as avg_cpu 
    WHERE index=linux_metrics AND metric_name="cpu.idle"
    BY host
```

### CPU Metrics Over Time (30-second intervals)

```spl
| mstats avg(_value) as avg_cpu
    WHERE index=linux_metrics AND metric_name="cpu.idle"
    span=30s
```

### Wildcard Metric Search with Timechart

```spl
| mstats avg(_value) prestats=t 
    WHERE index=linux_metrics AND metric_name="cpu.*" 
    span=1m 
    BY metric_name
| timechart avg(_value) as "Avg" span=1m by metric_name
```

### Memory Metrics with Conversion

```spl
| mstats avg(_value) as "Avg" 
    WHERE index=linux_metrics AND metric_name="memory.free" 
    span=5s 
| eval mem_gb = Avg / 1024 / 1024 / 1024 
| timechart max("mem_gb") span=5s
```

### Multiple Aggregations

```spl
| mstats avg(_value) as avg_val, max(_value) as max_val, min(_value) as min_val
    WHERE index=linux_metrics AND metric_name="cpu.idle"
    BY host
```

### Count Metrics by Name Over Time

```spl
| mstats count WHERE metric_name=* span=10s BY metric_name
```

## mpreview - Individual Metric Data Points

The `mpreview` command displays individual metric data points without aggregation. Use for troubleshooting and data exploration.

### View Raw Metrics

```spl
| mpreview index=linux_metrics
```

### View Specific Metric Raw Data

```spl
| mpreview index=linux_metrics filter="metric_name=cpu.idle"
```

### View Recent Metrics from Host

```spl
| mpreview index=linux_metrics filter="host=server01"
| head 100
```

## mcollect - Write Metrics to Index

The `mcollect` command converts search results into metrics and writes them to a metrics index.

### Basic mcollect

```spl
index=main sourcetype=access_combined
| stats count as request_count by host
| mcollect index=em_metrics marker="web_requests"
```

### Create Custom Metric from Events

```spl
index=linux sourcetype=syslog
| timechart span=1m count as error_count
| mcollect index=em_metrics metric_name=error_rate split=t
```

## meventcollect - Batch Metrics Collection

The `meventcollect` command writes metrics from events in batch.

### Batch Collect Metrics

```spl
index=main sourcetype=perfmon
| meventcollect index=windows_metrics
```

## Aggregation Functions

| Function | Description | Example |
|----------|-------------|---------|
| `avg(_value)` | Average of values | `avg(_value) as avg_cpu` |
| `sum(_value)` | Sum of values | `sum(_value) as total_bytes` |
| `max(_value)` | Maximum value | `max(_value) as peak_usage` |
| `min(_value)` | Minimum value | `min(_value) as min_usage` |
| `count` | Count of data points | `count as metric_count` |
| `dc(dimension)` | Distinct count | `dc(host) as unique_hosts` |
| `values(dimension)` | List values | `values(host) as hosts` |
| `latest(_value)` | Most recent value | `latest(_value) as current` |
| `earliest(_value)` | Oldest value | `earliest(_value) as first` |
| `median(_value)` | Median value | `median(_value) as median_cpu` |
| `perc95(_value)` | 95th percentile | `perc95(_value) as p95_latency` |
| `stdev(_value)` | Standard deviation | `stdev(_value) as cpu_stddev` |

## Common Metrics Index Queries

### Linux Metrics (Splunk_TA_nix)

```spl
# CPU idle percentage by host
| mstats avg(_value) as cpu_idle 
    WHERE index=linux_metrics AND metric_name="cpu.idle"
    BY host

# Memory free by host
| mstats avg(_value) as mem_free
    WHERE index=linux_metrics AND metric_name="mem.free"
    BY host

# Disk usage
| mstats avg(_value) as disk_used_pct
    WHERE index=linux_metrics AND metric_name="df.*.used_pct"
    BY host, mount

# Network interface statistics
| mstats avg(_value) as bytes_in
    WHERE index=linux_metrics AND metric_name="interfaces.*.bytes_in"
    BY host, interface
```

### Windows Metrics (Splunk_TA_windows)

```spl
# CPU processor time by host
| mstats avg(_value) as cpu_pct
    WHERE index=windows_metrics AND metric_name="Processor.%_Processor_Time"
    BY host

# Memory available bytes
| mstats avg(_value) as mem_available
    WHERE index=windows_metrics AND metric_name="Memory.Available_Bytes"
    BY host

# Disk queue length
| mstats avg(_value) as disk_queue
    WHERE index=windows_metrics AND metric_name="LogicalDisk.Current_Disk_Queue_Length"
    BY host, instance

# Network bytes per second
| mstats avg(_value) as network_bytes
    WHERE index=windows_metrics AND metric_name="Network_Interface.Bytes_Total/sec"
    BY host, instance
```

## WHERE Clause Filtering

### Filter by Metric Name

```spl
| mstats avg(_value) WHERE metric_name="cpu.idle" BY host
```

### Multiple Metric Names (IN operator)

```spl
| mstats avg(_value) 
    WHERE metric_name IN ("cpu.idle", "cpu.user", "cpu.system")
    BY metric_name, host
```

### Wildcard Metric Names

```spl
| mstats avg(_value) WHERE metric_name="cpu.*" BY metric_name
```

### Filter by Dimension Value

```spl
| mstats avg(_value) 
    WHERE metric_name="cpu.idle" AND host="server*"
    BY host
```

### Filter by Value Range

```spl
| mstats avg(_value) as cpu
    WHERE metric_name="cpu.idle" AND _value < 20
    BY host
| where cpu < 20
```

## Time-Based Analysis

### Timechart with Metrics

```spl
| mstats avg(_value) as cpu_percent
    WHERE index=linux_metrics AND metric_name="cpu.idle"
    BY host
| timechart avg(cpu_percent) by host span=5m
```

### Compare Time Periods

```spl
| mstats avg(_value) as current_cpu
    WHERE index=linux_metrics AND metric_name="cpu.idle"
    BY host
| appendcols 
    [| mstats avg(_value) as previous_cpu
        WHERE index=linux_metrics AND metric_name="cpu.idle" earliest=-2h latest=-1h
        BY host]
| eval change = current_cpu - previous_cpu
```

### Trend Detection

```spl
| mstats avg(_value) as cpu
    WHERE index=linux_metrics AND metric_name="cpu.idle"
    BY host, _time span=5m
| streamstats window=12 avg(cpu) as trend_cpu by host
| eval deviation = abs(cpu - trend_cpu)
| where deviation > 10
```

## Alerting on Metrics

### High CPU Alert

```spl
| mstats avg(_value) as cpu_idle
    WHERE index=linux_metrics AND metric_name="cpu.idle"
    BY host
| where cpu_idle < 10
| eval severity = if(cpu_idle < 5, "critical", "warning")
| table host, cpu_idle, severity
```

### Memory Threshold Alert

```spl
| mstats latest(_value) as mem_free_pct
    WHERE index=linux_metrics AND metric_name="mem.free_pct"
    BY host
| where mem_free_pct < 15
| table host, mem_free_pct
```

### Disk Space Warning

```spl
| mstats avg(_value) as disk_used_pct
    WHERE index=linux_metrics AND metric_name="df.*.used_pct"
    BY host, mount
| where disk_used_pct > 85
| table host, mount, disk_used_pct
```

## Metrics Index Configuration

### Create Metrics Index (indexes.conf)

```conf
[linux_metrics]
datatype = metric
homePath = $SPLUNK_DB/linux_metrics/db
coldPath = $SPLUNK_DB/linux_metrics/colddb
thawedPath = $SPLUNK_DB/linux_metrics/thaweddb

[windows_metrics]
datatype = metric
homePath = $SPLUNK_DB/windows_metrics/db
coldPath = $SPLUNK_DB/windows_metrics/colddb
thawedPath = $SPLUNK_DB/windows_metrics/thaweddb

[em_metrics]
datatype = metric
homePath = $SPLUNK_DB/em_metrics/db
coldPath = $SPLUNK_DB/em_metrics/colddb
thawedPath = $SPLUNK_DB/em_metrics/thaweddb
```

## MCP Compatibility (Splunk MCP Server)

### ✅ Supported Commands via MCP

| Command | Status | Notes |
|---------|--------|-------|
| `mstats` | ✅ Works | Full support including span, BY clause, aggregations |
| `mcatalog` | ✅ Works | Full support for metric/dimension discovery |
| `mpreview` | ❌ Blocked | "Forbidden command" - use mstats instead |
| `mcollect` | ❌ Blocked | Write operation not permitted via MCP |
| `meventcollect` | ❌ Blocked | Write operation not permitted via MCP |

### MCP-Safe Metrics Queries

```spl
# List all metric names (works via MCP)
| mcatalog values(metric_name) WHERE index=linux_metrics

# List dimensions (works via MCP)
| mcatalog values(_dims) WHERE index=linux_metrics

# Aggregate metrics (works via MCP)
| mstats avg(_value) as avg_cpu WHERE index=linux_metrics AND metric_name=ps_metric.pctCPU BY host

# Time series with span (works via MCP)
| mstats avg(_value) as disk_avail WHERE index=linux_metrics AND metric_name=df_metric.Avail_KB span=5m BY host

# Multiple aggregations (works via MCP)
| mstats avg(_value) as avg_val, max(_value) as max_val, min(_value) as min_val, count WHERE index=linux_metrics AND metric_name=df_metric.UsePct BY host

# Wildcard metric search (works via MCP)
| mstats count WHERE index=linux_metrics AND metric_name=df_metric.* BY metric_name
```

## Important Notes

1. **Case Sensitivity**: As of Splunk 8.0+, metrics indexing and search is case-sensitive
2. **Reserved Fields**: `source`, `sourcetype`, `host` used as dimensions become `extracted_source`, etc.
3. **Underscore Dimensions**: Dimensions starting with `_` are not indexed and not searchable
4. **No Automatic Lookups**: Lookups don't work with metrics (applied to aggregates, not events)
5. **No Search-Time Extractions**: Field extractions don't work on metrics indexes
6. **MCP Restrictions**: `mpreview`, `mcollect`, `meventcollect` are blocked via MCP API

## REST API for Metrics

### List Metric Names
```
GET /services/catalog/metricstore/metrics
```

### List Dimensions
```
GET /services/catalog/metricstore/dimensions
```

### List Dimension Values
```
GET /services/catalog/metricstore/dimensions/{dimension-name}/values
```

## Troubleshooting

### No Data from mstats

**Check**: Verify metric_name exists
```spl
| mcatalog values(metric_name) WHERE index=linux_metrics
```

### Verify Metrics Are Being Indexed

```spl
| mpreview index=linux_metrics | head 10
```

### Check Index Type

```spl
| rest /services/data/indexes/linux_metrics
| table title, datatype
```

## Related Documentation

- [search_commands_mstats.md](search_commands_mstats.md) - Detailed mstats examples
- [search_commands_tstats.md](search_commands_tstats.md) - tstats for accelerated data models
- Splunk Metrics Documentation: https://docs.splunk.com/Documentation/Splunk/latest/Metrics/Overview
