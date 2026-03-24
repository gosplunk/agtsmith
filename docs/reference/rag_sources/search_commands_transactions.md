# Transactions Command Reference

**Document Type**: Search Command Reference
**Audience**: Splunk Analysts, SOC Teams, Threat Hunters
**Topics**: Transaction Grouping, Event Correlation, Session Analysis
**Keywords**: transaction, event grouping, correlation, session, user tracking

**Quick Links:**
- Splunk Transaction Documentation: https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Transaction
- Event Correlation: https://docs.splunk.com/Documentation/Splunk/latest/Knowledge/Abouteventcorrelation
- Sessions and User Tracking: https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Sessionalize
- Best Practices: https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Transactionusage

**Description:** Grouping related events into transactions for correlation and session analysis

**Last Updated:** 2025-11-25

## Overview

Transaction groups events into logical units based on common field values and time constraints, enabling analysis of multi-event sequences.

## Basic Transaction Syntax

```spl
index=_internal
| transaction startswith="scheduler" endswith="completed" maxpause=5m
```

### Components

- `transaction` - The command
- `startswith="scheduler"` - Event that starts transaction
- `endswith="completed"` - Event that ends transaction
- `maxpause=5m` - Maximum time between events (5 minutes)

## Common Transaction Examples

### Web Session Tracking

```spl
index=web
| transaction user_session_id maxpause=30m
| where duration > 60
| stats count by user, duration
```

### Login to Logout Session

```spl
index=authentication
| transaction user startswith="login" endswith="logout" maxpause=8h
| table user, duration, sessionid
```

### Error Event Grouping

```spl
index=application sourcetype=app_error
| transaction request_id maxpause=10s
| where eventcount > 1
| sort -eventcount
```

## Transaction Parameters

### Grouping Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `by <field>` | Group by field values | `by user, host` |
| `startswith=<string>` | Event that starts transaction | `startswith="login"` |
| `endswith=<string>` | Event that ends transaction | `endswith="logout"` |
| `fields <field> [<field2>...]` | Fields within transaction | `fields user, action` |

### Timing Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `maxpause=<time>` | Max time between events | No limit |
| `maxspan=<time>` | Max duration of transaction | No limit |
| `keepevicted=true\|false` | Keep orphaned events | false |

## Transaction Examples

### Database Connection Session

```spl
index=database
| transaction connection_id 
    startswith="CONNECTED" 
    endswith="CLOSED" 
    maxpause=1h
| eval duration=round(duration, 2)
| where duration > 300
```

### Multi-Step Process Tracking

```spl
index=process
| transaction process_id 
    maxpause=5m
    maxspan=1h
| stats count as event_count by process_id, process_name
| where event_count > 5
```

### Payment Processing

```spl
index=payment
| transaction order_id 
    startswith="ORDER_RECEIVED" 
    endswith="PAYMENT_COMPLETE" 
    maxpause=30m
| where duration < 300
```

## Transaction Output Fields

### Auto-Generated Fields

| Field | Description | Example |
|-------|-------------|---------|
| `duration` | Transaction duration in seconds | 45.3 |
| `eventcount` | Number of events in transaction | 5 |
| `linecount` | Total lines in transaction | 12 |

### Original Fields

All original event fields are included with transaction data.

## Advanced Patterns

### Multi-Condition Transactions

```spl
index=security
| transaction user, host
    startswith="login_attempt"
    endswith="logout" 
    maxpause=1h
| search eventcount >= 10 AND duration > 60
```

### Nested Transaction Analysis

```spl
index=api
| transaction request_id maxpause=5s
| stats count by transaction_id, duration
| where duration > 10
```

### Transaction Filtering

```spl
index=web
| transaction user_id maxpause=30m
| where eventcount BETWEEN 5 AND 20
| search action="*suspicious*"
```

## Performance Considerations

### Memory Impact

Transaction command loads all grouped events into memory. Large transactions can consume significant resources.

**Optimize with:**
- Restrictive startswith/endswith conditions
- Smaller maxpause values
- Filter before transaction command
- Use BY clause to limit grouping

### Query Optimization

```spl
# GOOD: Filter first, then transaction
index=web status=4* 
| transaction user_id maxpause=30m 
| where eventcount > 5

# POOR: Transaction first, then filter (inefficient)
index=web 
| transaction user_id maxpause=30m 
| search status=4*
```

## Real-World Use Cases

### Detect Session Hijacking

```spl
index=authentication
| transaction user_id startswith="login" endswith="logout" maxpause=8h
| where eventcount > 1
| eval is_hijacked=if(duration > 86400, "long_session", "normal")
| where is_hijacked="long_session"
```

### Track Multi-Step Attack

```spl
index=network_ids
| transaction src, dest maxpause=10m maxspan=1h
| where eventcount >= 5
| stats count by src, dest, alert_name
```

### Monitor Application Workflow

```spl
index=app_logs
| transaction user, session_id maxpause=30m
| eval workflow_duration=round(duration/60, 2)
| where workflow_duration > 5
| table user, eventcount, workflow_duration
```

## Comparison: Transaction vs Streamstats

### Transaction
- Groups related events
- All events in memory
- Better for discrete sessions
- Shows eventcount, duration
- Higher memory usage

### Streamstats
- Running calculations
- Streaming (lower memory)
- Better for trends
- No event grouping
- More efficient for large datasets

## Best Practices

1. **Use startswith/endswith**: Limits transaction size
2. **Set maxpause**: Prevents unbounded transactions
3. **Set maxspan**: Limits total transaction duration
4. **Filter First**: Reduce data before transaction
5. **BY Clause**: Group logically related events
6. **Monitor Performance**: Track memory usage
7. **Test Timing**: Verify maxpause/maxspan values
8. **Document Logic**: Comment on transaction purpose

## Troubleshooting

### Out of Memory Error

**Cause**: Too many events per transaction  
**Solution**: Add startswith/endswith or reduce maxpause

### Missing Events

**Cause**: Orphaned events outside transaction boundaries  
**Solution**: Adjust maxpause or use keepevicted=true

### Slow Queries

**Cause**: Large transaction groups  
**Solution**: Filter before transaction, reduce time window

## Related Topics

- Streamstats for Running Calculations
- Event Correlation Techniques
- Session Detection and Analysis
- User Behavior Analytics
- Search Performance Optimization
