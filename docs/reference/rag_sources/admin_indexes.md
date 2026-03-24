# Splunk Index Administration Guide

---
tags: [splunk, indexes, storage, buckets, retention, indexes-conf, clustering]
category: administration
last_updated: 2026-02-20
related_docs: [admin_forwarders.md, splunk_sizing_guide.md, splunk_performance_reference.md]
---

**Document Type**: Administration Guide
**Audience**: Splunk Administrators, System Engineers, Data Architects
**Topics**: Indexes, Data Retention, Storage, Buckets, indexes.conf, Clustering
**Keywords**: index, indexes, indexes.conf, bucket, hot, warm, cold, frozen, thawed, retention, maxTotalDataSizeMB, frozenTimePeriodInSecs, homePath, coldPath, data retention, storage optimization

---

## Quick Summary

This guide covers Splunk index administration including configuration, bucket lifecycle, retention policies, and clustering. Key topics: indexes.conf settings, bucket states (hot/warm/cold/frozen), size-based vs time-based retention, SmartStore, and index replication.

**Find this document by searching for**: index configuration, bucket lifecycle, data retention, storage optimization, indexes.conf, frozenTimePeriodInSecs, maxTotalDataSizeMB, hot warm cold buckets

---

## Overview

Indexes are the repositories where Splunk stores ingested data. Understanding index management is critical for data retention, performance, and storage optimization.

## Index Types

| Type | Description | Use Case |
|------|-------------|----------|
| Events | Default, stores raw log data | Logs, events, text data |
| Metrics | Optimized for numeric measurements | Performance metrics, IoT data |

## Index Configuration (indexes.conf)

Location: `$SPLUNK_HOME/etc/system/local/indexes.conf` or `$SPLUNK_HOME/etc/apps/<app>/local/indexes.conf`

### Basic Index Definition
```ini
[myindex]
homePath = $SPLUNK_DB/myindex/db
coldPath = $SPLUNK_DB/myindex/colddb
thawedPath = $SPLUNK_DB/myindex/thaweddb
maxDataSize = auto_high_volume
maxTotalDataSizeMB = 500000
frozenTimePeriodInSecs = 7776000
```

### Index Settings Explained

| Setting | Description | Default |
|---------|-------------|---------|
| `homePath` | Hot/Warm buckets location | Required |
| `coldPath` | Cold buckets location | Required |
| `thawedPath` | Restored buckets location | Required |
| `maxDataSize` | Max bucket size | auto |
| `maxTotalDataSizeMB` | Max index size | 500000 |
| `frozenTimePeriodInSecs` | Retention period | 188697600 (~6 years) |
| `maxHotBuckets` | Max simultaneous hot buckets | 3 |
| `maxWarmDBCount` | Max warm buckets | 300 |

## Bucket Lifecycle

```
Hot → Warm → Cold → Frozen (deleted or archived)
```

### Bucket States
1. **Hot**: Actively being written to, searchable
2. **Warm**: No longer written to, searchable
3. **Cold**: Older data, searchable, can be on cheaper storage
4. **Frozen**: Removed from index (deleted or archived)
5. **Thawed**: Restored frozen buckets, searchable

### Bucket Transitions
```ini
# Hot to Warm: When bucket is full or maxHotIdleSecs reached
maxHotIdleSecs = 86400
maxHotBuckets = 3

# Warm to Cold: Based on age or count
maxWarmDBCount = 300

# Cold to Frozen: Based on age or size
frozenTimePeriodInSecs = 7776000  # 90 days
maxTotalDataSizeMB = 500000
```

## Retention Configuration

### Time-Based Retention
```ini
[security_index]
homePath = $SPLUNK_DB/security_index/db
coldPath = $SPLUNK_DB/security_index/colddb
thawedPath = $SPLUNK_DB/security_index/thaweddb

# Keep for 1 year (31536000 seconds)
frozenTimePeriodInSecs = 31536000
```

### Size-Based Retention
```ini
[high_volume_index]
homePath = $SPLUNK_DB/high_volume_index/db
coldPath = $SPLUNK_DB/high_volume_index/colddb
thawedPath = $SPLUNK_DB/high_volume_index/thaweddb

# Max 100GB, delete oldest when exceeded
maxTotalDataSizeMB = 100000
frozenTimePeriodInSecs = 188697600
```

### Archive Instead of Delete
```ini
[archive_index]
homePath = $SPLUNK_DB/archive_index/db
coldPath = $SPLUNK_DB/archive_index/colddb
thawedPath = $SPLUNK_DB/archive_index/thaweddb

# Script to archive frozen buckets
coldToFrozenScript = $SPLUNK_HOME/bin/scripts/archive_bucket.sh

# Or copy to archive path
coldToFrozenDir = /archive/splunk/archive_index
```

## Common Index Configurations

### Security/Compliance (Long Retention)
```ini
[security]
homePath = $SPLUNK_DB/security/db
coldPath = $SPLUNK_DB/security/colddb
thawedPath = $SPLUNK_DB/security/thaweddb
maxTotalDataSizeMB = 1000000
frozenTimePeriodInSecs = 94608000  # 3 years
maxDataSize = auto_high_volume
```

### High Volume (Short Retention)
```ini
[netflow]
homePath = $SPLUNK_DB/netflow/db
coldPath = $SPLUNK_DB/netflow/colddb
thawedPath = $SPLUNK_DB/netflow/thaweddb
maxTotalDataSizeMB = 200000
frozenTimePeriodInSecs = 604800  # 7 days
maxDataSize = auto_high_volume
maxHotBuckets = 10
```

### Metrics Index
```ini
[my_metrics]
homePath = $SPLUNK_DB/my_metrics/db
coldPath = $SPLUNK_DB/my_metrics/colddb
thawedPath = $SPLUNK_DB/my_metrics/thaweddb
datatype = metric
frozenTimePeriodInSecs = 7776000  # 90 days
maxTotalDataSizeMB = 50000
```

## SmartStore Configuration

For cloud/object storage backends:

```ini
# server.conf
[cachemanager]
max_cache_size = 500000  # MB

# indexes.conf
[smartstore_index]
homePath = $SPLUNK_DB/smartstore_index/db
coldPath = $SPLUNK_DB/smartstore_index/colddb
thawedPath = $SPLUNK_DB/smartstore_index/thaweddb
remotePath = volume:remote_store/$_index_name

[volume:remote_store]
storageType = remote
path = s3://mybucket/splunk
remote.s3.access_key = <key>
remote.s3.secret_key = <secret>
remote.s3.endpoint = https://s3.amazonaws.com
```

## CLI Commands

### Index Management
```bash
# List indexes
splunk list index

# Show index info
splunk show index main

# Create index
splunk add index myindex

# Remove index (dangerous!)
splunk remove index myindex

# Check bucket info
splunk list iceberg
```

### Bucket Management
```bash
# List buckets
ls -la $SPLUNK_DB/<index>/db/
ls -la $SPLUNK_DB/<index>/colddb/

# Freeze bucket manually
splunk freeze <bucket_path>

# Thaw frozen bucket
splunk thaw <bucket_path> -index <index_name>

# Rebuild bucket metadata
splunk rebuild <bucket_path>
```

### Verify Configuration
```bash
# Check indexes.conf settings
splunk btool indexes list --debug

# Validate configuration
splunk validate indexes
```

## SPL for Index Analysis

### Index Size and Event Count
```spl
| rest /services/data/indexes datatype=all
| table title totalEventCount currentDBSizeMB maxTotalDataSizeMB
| sort - currentDBSizeMB
```

### Index Growth Over Time
```spl
| tstats count where index=* by index, _time span=1d
| timechart span=1d sum(count) by index
```

### Storage by Index
```spl
| dbinspect index=*
| stats sum(sizeOnDiskMB) as total_size_mb by index
| sort - total_size_mb
```

### Bucket Statistics
```spl
| dbinspect index=main
| stats count as bucket_count, sum(sizeOnDiskMB) as total_mb, 
        min(startEpoch) as oldest, max(endEpoch) as newest by state
| eval oldest_date=strftime(oldest, "%Y-%m-%d")
| eval newest_date=strftime(newest, "%Y-%m-%d")
```

### Data Volume by Sourcetype
```spl
index=_internal source=*license_usage.log type=Usage
| stats sum(b) as bytes by idx
| eval GB=round(bytes/1024/1024/1024,2)
| sort - GB
```

### Find Indexes Not Receiving Data
```spl
| rest /services/data/indexes datatype=all
| where totalEventCount=0
| table title disabled
```

### Retention Compliance Check
```spl
| rest /services/data/indexes datatype=all
| eval retention_days=frozenTimePeriodInSecs/86400
| table title retention_days currentDBSizeMB maxTotalDataSizeMB
| sort retention_days
```

## Index Cluster Configuration

### Indexer Cluster Member
```ini
# server.conf on indexer
[replication_port://9887]

[clustering]
mode = peer
manager_uri = https://cluster-manager:8089
pass4SymmKey = your_secret_key

# indexes.conf
[main]
repFactor = auto
```

### Cluster-Specific Index Settings
```ini
[clustered_index]
homePath = $SPLUNK_DB/clustered_index/db
coldPath = $SPLUNK_DB/clustered_index/colddb
thawedPath = $SPLUNK_DB/clustered_index/thaweddb
repFactor = auto
searchableFactor = 2
```

## Storage Optimization

### Compression
```ini
[myindex]
# Enable tsidx reduction (reduces index size ~30%)
enableTsidxReduction = true

# Journal compression (default is gzip)
journalCompression = zstd
```

### Volume-Based Management
```ini
# Define volumes
[volume:hot_volume]
path = /fast_storage/splunk
maxVolumeDataSizeMB = 500000

[volume:cold_volume]
path = /slow_storage/splunk
maxVolumeDataSizeMB = 2000000

# Use volumes
[myindex]
homePath = volume:hot_volume/myindex/db
coldPath = volume:cold_volume/myindex/colddb
thawedPath = $SPLUNK_DB/myindex/thaweddb
```

## Troubleshooting

### Index Not Receiving Data
```bash
# Check inputs routing to index
splunk btool inputs list --debug | grep -A5 "index ="

# Verify index exists
splunk list index | grep myindex

# Check for errors
grep myindex $SPLUNK_HOME/var/log/splunk/splunkd.log
```

### Bucket Issues
```spl
# Check for corrupted buckets
index=_internal source=*splunkd.log "bucket" "corrupt"
| table _time message

# Monitor bucket rolling
index=_internal source=*splunkd.log "rolling hot"
| table _time message
```

### Storage Full
```spl
# Find largest indexes
| rest /services/data/indexes
| eval pct_used=round(currentDBSizeMB/maxTotalDataSizeMB*100,2)
| where pct_used > 80
| table title pct_used currentDBSizeMB maxTotalDataSizeMB
```

## Best Practices

1. **Plan Retention Early** - Set frozenTimePeriodInSecs based on compliance needs
2. **Use Volumes** - Manage storage across multiple disks
3. **Monitor Growth** - Track index sizes and adjust limits
4. **Separate by Data Type** - Different indexes for different retention needs
5. **Test Archival** - Verify coldToFrozenScript works before relying on it
6. **Document Index Purpose** - Use comments in indexes.conf
7. **Enable SmartStore** - For cloud deployments

## MCP Compatibility

✅ **Supported via MCP**: Index monitoring queries work
- REST API calls for index metadata
- dbinspect for bucket analysis
- License usage queries

### MCP Example Prompts
- "show all indexes and their sizes using rest"
- "list indexes with event counts and disk usage"
- "check which indexes are using the most storage"
- "show bucket count by index using dbinspect"

## Quick Reference

```ini
# Basic index
[myindex]
homePath = $SPLUNK_DB/myindex/db
coldPath = $SPLUNK_DB/myindex/colddb
thawedPath = $SPLUNK_DB/myindex/thaweddb
frozenTimePeriodInSecs = 7776000      # 90 days
maxTotalDataSizeMB = 500000           # 500GB

# Metrics index
[metrics_index]
datatype = metric
homePath = $SPLUNK_DB/metrics_index/db
coldPath = $SPLUNK_DB/metrics_index/colddb
thawedPath = $SPLUNK_DB/metrics_index/thaweddb
```

```spl
# List all indexes
| rest /services/data/indexes datatype=all | table title totalEventCount currentDBSizeMB

# Check bucket info
| dbinspect index=main | stats count by state, index
```
