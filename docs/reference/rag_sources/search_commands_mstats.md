# Mstats Command Reference

**Document Type**: Search Command Reference
**Audience**: Splunk Power Users, Observability Specialists, Metrics Engineers
**Topics**: Mstats, Metrics, Observability, Time Series Analysis
**Keywords**: mstats, metrics, time series, metric aggregation, observability, linux_metrics, windows_metrics, em_metrics

**Quick Links:**
- Splunk Mstats Documentation: https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Mstats
- Metrics Ingestion: https://docs.splunk.com/Documentation/Splunk/latest/Metrics/Overview
- Time Series Analysis: https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Timechart
- Observability Best Practices: https://docs.splunk.com/Documentation/Splunk/latest/Observability/Welcome

**Description:** Using mstats for querying metric indexes and time series data in Splunk Observability

**Last Updated:** 2025-12-02

## Overview

Mstats is a command designed for querying metrics indexes, enabling high-performance time series analysis and observability searches.

## CRITICAL: Correct Syntax

**IMPORTANT**: The mstats command uses `WHERE index=<index_name>` syntax, NOT `from <index>`.

### ✅ Correct Syntax
```spl
| mstats avg(_value) as cpu_percent WHERE index=linux_metrics AND metric_name="cpu.idle" BY host
```

### ❌ Incorrect Syntax (DO NOT USE)
```spl
| mstats avg(_value) as cpu_percent from default where metric_name="cpu_usage" by host
```

## Basic Mstats Syntax

```spl
| mstats <aggregation>(_value) [as <alias>] 
    WHERE index=<metrics_index> [AND metric_name=<name>]
    [BY <dimensions>]
    [span=<time>]
```

### Components

- `mstats` - The command
- `avg(_value)` - Aggregation function on metric value
- `WHERE index=linux_metrics` - Metrics index to search (REQUIRED)
- `AND metric_name="cpu.idle"` - Metric name filter
- `BY host` - Group by dimension

## Metric Basics

### Metric Structure

Metrics consist of:
- **Metric Name**: cpu.idle, mem.free, df_metric.UsePct, etc.
- **_time**: Timestamp
- **_value**: The metric measurement
- **Dimensions**: host, region, service, etc.

### Example Metrics

```
metric_name=cpu.idle _value=45.2 host=server01 region=us-east
metric_name=mem.free _value=78.5 host=server01 region=us-east
metric_name=interfaces_metric.RXbytes _value=1024000 host=server01
```

## Common Mstats Examples

### CPU Usage by Host

```spl
| mstats avg(_value) as avg_cpu, max(_value) as max_cpu
    WHERE index=linux_metrics AND metric_name="ps_metric.pctCPU"
    BY host
```

### Memory Utilization Trend

```spl
| mstats avg(_value) as memory_pct
    WHERE index=linux_metrics AND metric_name="ps_metric.pctMEM"
    BY host
| timechart avg(memory_pct) by host
```

### Disk Usage Analysis

```spl
| mstats avg(_value) as disk_used_pct
    WHERE index=linux_metrics AND metric_name="df_metric.UsePct"
    BY host
```

### Network Traffic Analysis

```spl
| mstats sum(_value) as bytes_in
    WHERE index=linux_metrics AND metric_name="interfaces_metric.RXbytes"
    BY host
```

### Multi-Metric Aggregation

```spl
| mstats avg(_value) as value
    WHERE index=linux_metrics AND metric_name IN ("ps_metric.pctCPU", "ps_metric.pctMEM")
    BY metric_name, host
```

## Aggregation Functions

| Function | Usage | Example |
|----------|-------|---------|
| `avg(_value)` | Average metric value | `avg(_value) as avg_cpu` |
| `sum(_value)` | Sum metric values | `sum(_value) as total_bytes` |
| `max(_value)` | Maximum value | `max(_value) as peak_usage` |
| `min(_value)` | Minimum value | `min(_value) as min_usage` |
| `count` | Count of metrics | `count as metric_count` |
| `dc(dimension)` | Distinct dimensions | `dc(host) as unique_hosts` |
| `values(dimension)` | List of dimensions | `values(host) as hosts` |
| `latest(_value)` | Most recent value | `latest(_value) as current_value` |

## WHERE Clause Filtering

### Filter by Metric Name

```spl
| mstats avg(_value) as cpu
    WHERE index=linux_metrics AND metric_name="ps_metric.pctCPU"
    BY host
```

### Multiple Metric Names

```spl
| mstats avg(_value) as value
    WHERE index=linux_metrics AND metric_name IN ("df_metric.UsePct", "df_metric.Avail_KB")
    BY metric_name, host
```

### Filter by Dimension

```spl
| mstats avg(_value) as cpu
    WHERE index=linux_metrics AND metric_name="ps_metric.pctCPU" AND host="server*"
    BY host
```

### Wildcard Metric Names

```spl
| mstats count 
    WHERE index=linux_metrics AND metric_name="df_metric.*"
    BY metric_name
```

## Time Series Analysis

### Timechart Metric Data

```spl
| mstats avg(_value) as cpu_percent
    WHERE index=linux_metrics AND metric_name="ps_metric.pctCPU"
    BY host
| timechart avg(cpu_percent) by host span=5m
```

### Time Series with Span

```spl
| mstats avg(_value) as disk_avail
    WHERE index=linux_metrics AND metric_name="df_metric.Avail_KB"
    span=5m
    BY host
```

### Trend Analysis

```spl
| mstats avg(_value) as cpu
    WHERE index=linux_metrics AND metric_name="ps_metric.pctCPU"
    span=1h
    BY host
| streamstats window=12 avg(cpu) as trend_cpu by host
```

## Advanced Patterns

### Alert on Metric Thresholds

```spl
| mstats avg(_value) as disk_used_pct
    WHERE index=linux_metrics AND metric_name="df_metric.UsePct"
    BY host
| where disk_used_pct > 80
| eval severity=if(disk_used_pct > 90, "critical", "warning")
```

### Multiple Aggregations

```spl
| mstats avg(_value) as avg_val, max(_value) as max_val, min(_value) as min_val, count
    WHERE index=linux_metrics AND metric_name="df_metric.UsePct"
    BY host
```

### Windows Metrics Examples

```spl
| mstats avg(_value) as cpu_pct
    WHERE index=windows_metrics AND metric_name="Processor.%_Processor_Time"
    BY host

| mstats avg(_value) as mem_available
    WHERE index=windows_metrics AND metric_name="Memory.Available_Bytes"
    BY host
```

## Available Metrics Indexes

| Index | Description | Source |
|-------|-------------|--------|
| `linux_metrics` | Linux/Unix performance metrics | Splunk_TA_nix |
| `windows_metrics` | Windows performance metrics | Splunk_TA_windows |
| `em_metrics` | Enterprise monitoring metrics | Custom |
| `_metrics` | Internal Splunk metrics | Built-in |

## Discover Available Metrics

Use `mcatalog` to discover what metrics are available:

```spl
# List all metric names in linux_metrics
| mcatalog values(metric_name) WHERE index=linux_metrics

# List all dimensions
| mcatalog values(_dims) WHERE index=linux_metrics

# List hosts with metrics
| mcatalog values(host) WHERE index=linux_metrics
```

## MCP Compatibility

The mstats command works via Splunk MCP with the correct syntax:

### ✅ Works via MCP
```spl
| mstats avg(_value) as avg_cpu WHERE index=linux_metrics AND metric_name="ps_metric.pctCPU" BY host
| mstats count WHERE index=linux_metrics AND metric_name="df_metric.*" BY metric_name
| mcatalog values(metric_name) WHERE index=linux_metrics
```

### ❌ Blocked via MCP
- `mpreview` - Forbidden command
- `mcollect` - Write operation blocked
- `meventcollect` - Write operation blocked

## Performance Considerations

1. **Always specify index**: `WHERE index=linux_metrics` is required
2. **Use Dimensions Wisely**: Only include necessary dimension tags
3. **Filter Early**: Use WHERE clause at mstats level
4. **Limit Time Range**: Specify time range in search
5. **Use Appropriate Span**: Balance granularity and performance

## Troubleshooting

### Error: "Cannot use aggregations without arguments"

**Cause**: Missing or invalid index specification  
**Solution**: Use correct syntax `WHERE index=<metrics_index>`

### No Data from Mstats

**Cause**: Metrics index doesn't contain requested metric  
**Solution**: Use `mcatalog` to verify metric_name exists:
```spl
| mcatalog values(metric_name) WHERE index=linux_metrics
```

### Slow Mstats Queries

**Cause**: Too many dimensions or large time range  
**Solution**: Reduce dimensions, narrow time range, or add span

## Related Topics

- [search_commands_metrics.md](search_commands_metrics.md) - Comprehensive metrics reference
- Timechart and Time Series Visualization
- Metric Index Configuration
- Observability Best Practices
