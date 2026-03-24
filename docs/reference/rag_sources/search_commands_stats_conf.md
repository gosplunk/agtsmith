# Stats Configuration Reference

**Document Type**: Configuration Reference
**Audience**: Splunk Administrators, Search Developers, Performance Tuning Specialists
**Topics**: Stats Commands, Aggregation, Summary Indexing, Performance Tuning
**Keywords**: stats, aggregation, summary index, performance, configuration

**Quick Links:**
- Splunk Stats Command: https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Stats
- Props and Transforms: https://docs.splunk.com/Documentation/Splunk/latest/Admin/Propsconf
- Performance Monitoring: https://docs.splunk.com/Documentation/Splunk/latest/DMC/MonitoringPerformance
- Best Practices: https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Statsusage

**Description:** Configuration and optimization guidance for stats command aggregation, summary index performance, and statistical function tuning

**Last Updated:** 2025-11-25

## Overview

Stats configuration in Splunk allows you to optimize aggregation performance, define summary indexes, and tune statistical calculations for maximum efficiency.

## Configuration Directives

### Basic Stats Configuration

```conf
# props.conf - Define stats behavior for sourcetype
[sourcetype_name]
TRANSFORMS = summary_transform
```

### Summary Index Configuration

```conf
# transforms.conf - Define stats outputs
[summary_transform]
REGEX = ^(.*)$
FORMAT = _raw::$1
DEST_KEY = _raw
TARGET_INDEX = summary
```

## Performance Tuning Parameters

### Memory Optimization

```conf
[stats]
# Limit stats operations memory usage
stats_maxresults = 50000
stats_timeout = 300

# Stream stats memory settings
streamstats_maxmem = 50MB
```

### Aggregation Parameters

```conf
# Configure aggregation bucket sizes
[aggregation]
max_mem_mb = 200
maxkbps = 0
default_agg_chunk_size = 1000
```

## Common Stats Configuration Examples

### Event Count Aggregation

```conf
[events_summary]
TRANSFORMS = event_summary
REPORT = event_stats
```

### Time-Based Aggregation

```conf
[time_aggregation]
# Group events by time
bucket_time = 5m
TRANSFORMS = time_summary
```

### User Activity Stats

```conf
[user_stats]
TRANSFORMS = user_activity_summary
REPORT = user_statistics
```

## Monitoring Stats Performance

### Check Stats Operation Metrics

```splunk
index=_internal group=stats
| stats count by host, component
| sort -count
```

### Identify Slow Stats Operations

```splunk
index=_internal source=*metrics.log* group=stats
| eval duration=round(duration/1000,2)
| where duration > 1
| stats count by command, duration
| sort -duration
```

### Monitor Summary Index Activity

```splunk
index=summary
| timechart count
| eval _time=strftime(_time,"%Y-%m-%d %H:%M:%S")
```

## Advanced Configuration

### Custom Aggregation Functions

```conf
[custom_stats]
TRANSFORMS = custom_aggregate
eval_function = custom_eval
```

### Distributed Stats Operations

```conf
[distributed_stats]
# Enable distributed aggregation
parallel = true
max_threads = 4
TRANSFORMS = distributed_aggregate
```

### Stats Caching

```conf
[stats_cache]
cache_timeout = 300
cache_size = 100MB
TRANSFORMS = cached_aggregate
```

## Performance Best Practices

1. **Limit Fields**: Only aggregate fields you need
2. **Use Summary Indexes**: Pre-aggregate high-volume data
3. **Optimize BY Clause**: Group by indexed fields when possible
4. **Monitor Performance**: Track stats execution time regularly
5. **Set Reasonable Limits**: Configure maxresults and timeout appropriately
6. **Use Streamstats Carefully**: Memory-intensive for large datasets
7. **Cache Results**: Use summary indexes for frequently-run stats

## Troubleshooting

### Stats Operation Timeout

**Problem**: Stats queries timing out  
**Solution**: Increase timeout setting or reduce data volume

```conf
[stats]
stats_timeout = 600
```

### Memory Exhaustion

**Problem**: "Out of memory" errors during aggregation  
**Solution**: Reduce aggregation scope or increase system memory

```conf
[aggregation]
max_mem_mb = 500
```

### Slow Aggregation

**Problem**: Stats taking too long  
**Solution**: Use distributed processing or summary indexes

## Related Topics

- Eval Command and Expression Optimization
- Streamstats for Running Calculations
- Data Aggregation Techniques
- Summary Index Design
- Search Performance Optimization
