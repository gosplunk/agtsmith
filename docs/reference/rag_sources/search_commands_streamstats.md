# Splunk Streamstats Command - Running Calculations Guide

**Document Type**: Command Reference
**Audience**: Splunk Users, Search Developers, Analysts
**Topics**: streamstats, Running Calculations, Windowing, Sequential Analysis
**Keywords**: streamstats, running total, running count, window, cumulative sum, rolling average, streaming statistics, reset_on_change, sequential events

**Last Updated**: 2025-12-22

---

## Quick Summary

Guide to the Splunk streamstats command for streaming/running calculations. Covers running totals, cumulative counts, rolling windows, reset_on_change, and differences from stats command. Essential for sequential event analysis.

**Find this document by searching for**: streamstats, running total, cumulative sum, rolling average, window statistics, reset_on_change, streaming calculations

---

## Overview

The `streamstats` command calculates statistics in a streaming manner, processing events in order. Unlike `stats` which aggregates all events, `streamstats` maintains running totals and calculations across events.

## Basic Syntax

```spl
| streamstats <aggregation> [by <field>] [window=N] [reset_on_change=<bool>]
```

## Key Concept: Streaming vs Aggregating

```spl
# stats - Single row result (aggregates all)
index=main | stats sum(bytes) as total_bytes

# streamstats - Running total on each row
index=main | streamstats sum(bytes) as running_total
```

## Common Use Cases

### Running Count
```spl
# Count events as they process
index=main
| streamstats count as event_number

# Running count by host
index=main
| streamstats count as host_event_num by host
```

### Running Sum/Total
```spl
# Running sum of bytes transferred
index=web_logs
| sort _time
| streamstats sum(bytes) as cumulative_bytes

# Running sum by user
index=sales
| sort _time
| streamstats sum(amount) as running_total by user
```

### Running Average
```spl
# Running average response time
index=web_logs
| sort _time
| streamstats avg(response_time) as running_avg

# Moving average (last 10 events)
index=web_logs
| sort _time
| streamstats avg(response_time) as moving_avg window=10
```

## Window Parameter

Calculate over a sliding window of N events:

```spl
# Moving average over last 5 events
index=metrics
| sort _time
| streamstats avg(cpu_percent) as moving_avg window=5

# Moving sum over last 10 events
index=sales
| sort _time
| streamstats sum(amount) as sum_last_10 window=10

# Min/Max in last 20 events
index=metrics
| sort _time
| streamstats min(value) as min_20, max(value) as max_20 window=20
```

### Window Types
```spl
# Fixed window (N events before current)
| streamstats avg(value) window=10 current=false

# Include current event (default)
| streamstats avg(value) window=10 current=true

# Global window (no window - all previous events)
| streamstats sum(value)  # No window specified
```

## Reset Controls

### Reset on Change
```spl
# Reset running count when host changes
index=main
| sort host, _time
| streamstats count as count_per_host reset_on_change=true by host
```

### Reset After
```spl
# Reset after specific condition
index=main
| sort _time
| streamstats sum(errors) as error_sum reset_after=(error_sum>100)
```

### Reset Before
```spl
# Reset before a condition is met
index=main
| sort _time
| streamstats count reset_before=(status="restart")
```

## Aggregation Functions

All stats functions work with streamstats:

```spl
# Count and distinct count
| streamstats count
| streamstats dc(user) as unique_users_so_far

# Sum, average, min, max
| streamstats sum(bytes), avg(bytes), min(bytes), max(bytes)

# Standard deviation
| streamstats stdev(value) as running_stdev

# First/Last seen values
| streamstats first(status) as first_status, last(status) as latest_status

# Percentiles
| streamstats perc95(response_time) as running_p95

# Range
| streamstats range(value) as value_range

# Values (list)
| streamstats values(user) as users_seen
```

## Real-World Examples

### Detect Anomalies with Moving Average
```spl
index=web_logs
| sort _time
| streamstats avg(response_time) as moving_avg window=100
| eval deviation=abs(response_time-moving_avg)
| where deviation > (moving_avg * 2)
| table _time response_time moving_avg deviation
```

### Track Session Events
```spl
index=web_logs
| sort session_id, _time
| streamstats count as event_in_session by session_id
| where event_in_session=1
| stats count as new_sessions by _time span=1h
```

### Running Total of Sales
```spl
index=sales
| sort _time
| streamstats sum(amount) as cumulative_sales
| timechart span=1d last(cumulative_sales) as daily_cumulative
```

### Time Between Events
```spl
index=main
| sort _time
| streamstats current=false last(_time) as prev_time
| eval time_diff=_time-prev_time
| eval time_diff_sec=round(time_diff,2)
| table _time prev_time time_diff_sec
```

### Identify First Event Per User
```spl
index=web_logs
| sort user, _time
| streamstats count as user_event_num by user
| where user_event_num=1
| table _time user action
```

### Calculate Rate of Change
```spl
index=metrics
| sort _time
| streamstats current=false last(value) as prev_value, last(_time) as prev_time
| eval rate_of_change=(value-prev_value)/(_time-prev_time)
| table _time value rate_of_change
```

### Running Distinct Count
```spl
index=web_logs
| sort _time
| streamstats dc(client_ip) as unique_visitors_cumulative
| timechart span=1h last(unique_visitors_cumulative)
```

### Burst Detection
```spl
index=firewall
| sort src_ip, _time
| streamstats count as request_count window=60 by src_ip
| where request_count > 100
| table _time src_ip request_count
```

### Moving Percentile
```spl
index=apm
| sort _time
| streamstats perc95(response_time) as p95_moving window=1000
| timechart span=5m last(p95_moving)
```

### Login Sequence Analysis
```spl
index=auth action=login
| sort user, _time
| streamstats count as login_num by user
| streamstats current=false last(_time) as prev_login by user
| eval hours_since_last=round((_time-prev_login)/3600,2)
| table _time user login_num hours_since_last
```

## Performance Considerations

1. **Always sort first** - streamstats processes in order received
2. **Use time_window for large datasets** - More efficient than event window
3. **Limit window size** - Large windows = more memory
4. **Filter early** - Reduce events before streamstats

```spl
# Good - filter and sort before streamstats
index=web_logs status>=400 earliest=-24h
| sort _time
| streamstats count window=100

# Time window (more efficient for time-based windows)
| streamstats sum(bytes) time_window=1h
```

## Streamstats vs Eventstats

| Feature | streamstats | eventstats |
|---------|-------------|------------|
| Processing | Sequential, running | All events at once |
| Window | Sliding window | All events |
| Output | Cumulative/rolling values | Same value per group |
| Use case | Running totals, sequences | Add group stats to each event |

```spl
# streamstats - running count (1,2,3,4...)
| sort _time | streamstats count

# eventstats - total count (same on all rows)
| eventstats count as total_count
```

## MCP Compatibility

✅ **Supported via MCP**: Streamstats commands execute normally
- Running calculations return per-event results
- Window-based aggregations work correctly
- Sort order is preserved in results

### MCP Example Prompts
- "use streamstats to show running count of events by host"
- "calculate moving average of response time over last 10 events using streamstats"
- "show cumulative sum of bytes transferred using streamstats"
- "detect burst traffic using streamstats with window"

## Quick Reference

```spl
# Running count
| sort _time | streamstats count

# Running sum
| sort _time | streamstats sum(field) as running_total

# Moving average (window)
| sort _time | streamstats avg(field) window=10 as moving_avg

# Running calculations by group
| sort group, _time | streamstats sum(value) by group

# Time between events
| sort _time | streamstats current=false last(_time) as prev_time
| eval gap=_time-prev_time

# Reset on condition
| streamstats sum(value) reset_after=(value>threshold)

# Exclude current event
| streamstats avg(value) window=10 current=false
```
