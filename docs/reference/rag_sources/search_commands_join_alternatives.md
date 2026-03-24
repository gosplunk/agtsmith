# Splunk Join Command Alternatives - Best Practices

**Document Type**: SPL Performance Reference
**Audience**: Splunk Users, Search Developers, Analysts
**Topics**: join alternatives, stats, append, performance optimization, distributed search, map reduce
**Keywords**: join, append, appendcols, stats, lookup, subsearch, performance, distributed reporting, map reduce, prestats, search head, indexer
**Source**: .conf2020 TRU1761C - "Master Joining Datasets Without Using Join" by Nick Mealy (Sideview, LLC)

**Last Updated**: 2026-02-18

---

## Quick Summary

The `join`, `append`, and `appendcols` commands should be **last resorts** in Splunk. They are fundamentally inefficient and break Splunk's distributed architecture. Use `stats`, `eval`, and `lookup` instead.

| Command | Status | Alternative |
|---------|--------|-------------|
| `join` | ❌ Avoid | `stats` with `OR` in search |
| `append` | ❌ Avoid | `stats` with `OR` in search |
| `appendcols` | ❌ Avoid | `stats` with conditional `eval` |
| `transaction` | ⚠️ Chaotic Neutral | `stats` when possible |

---

## Why Join/Append Are Inefficient

### Core Problems

| Problem | Impact |
|---------|--------|
| **50,000 row limit** | Subsearch results silently truncated |
| **Auto-finalize** | Execution time limits cause silent truncation |
| **2 jobs instead of 1** | Double processing overhead |
| **Same data from disk twice** | I/O inefficiency |
| **Breaks Map/Reduce** | Forces all data back to Search Head |
| **Memory-bound** | Subsearch results held entirely in memory |
| **Not streaming** | Cannot distribute across indexers |

### The Architecture Problem

Splunk's power comes from **distributed reporting** - indexers do most of the work and send small summary tables to the Search Head. Join/append break this:

```
Good: Indexers → small tables → Search Head (minimal work)
Bad:  Indexers → ALL events → Search Head (overloaded)
```

When you use `join`:
- Subsearch runs first, completely
- Results held in memory (max 50,000 rows)
- Outer search runs, pulling data to Search Head
- Join happens on Search Head only
- Indexers are underutilized

---

## The Solution: Use Stats with OR

### Pattern

Instead of joining two sourcetypes, search for both and let `stats` sort them out:

```spl
# BAD - uses join
sourcetype=db
| join pid [search sourcetype=app]
| stats sum(rows) sum(cputime) by pid

# GOOD - uses stats with OR
sourcetype=db OR sourcetype=app
| stats sum(rows) sum(cputime) by pid
```

### Why This Works

- Single search job (not two)
- Distributed to all indexers
- Each indexer runs `prestats` locally
- Only small summary tables sent to Search Head
- Full Map/Reduce efficiency

---

## Common Patterns and Solutions

### Pattern 1: Simple Join of Two Sourcetypes

**Problem**: Need to combine data from two sourcetypes by a common field.

```spl
# BAD
sourcetype=db | stats sum(rows) by pid
| join pid [search sourcetype=app | stats sum(cputime) by pid]

# GOOD
sourcetype=db OR sourcetype=app
| stats sum(rows) sum(cputime) by pid
```

### Pattern 2: Need Stats After Join

**Problem**: Need to join first, then aggregate.

```spl
# BAD
sourcetype=cucm_cdr
| join callId [search sourcetype=cucm_cmr]
| stats perc5(MLQK) by type

# GOOD - use stats twice
sourcetype=cucm_cdr OR sourcetype=cucm_cmr
| stats values(MLQK) as MLQK, last(type) as type by callId
| stats perc5(MLQK) by type
```

**Note**: `values()` is underrated for single-valued fields.

### Pattern 3: Different Field Names

**Problem**: One sourcetype uses `pid`, another uses `processId`.

```spl
# BAD
sourcetype=db
| rename processId as pid
| join pid [search sourcetype=app]
| stats sum(rows) sum(cputime) by pid

# GOOD - conditional eval
sourcetype=db OR sourcetype=app
| eval pid=if(sourcetype=="db", processId, pid)
| stats sum(rows) sum(cputime) by pid
```

### Pattern 4: Need to Clean Up One Side

**Problem**: Need to apply rex/replace to one sourcetype but not the other.

```spl
# BAD
sourcetype=db
| rex field=pid mode=sed "s/cruft//g"
| join pid [search sourcetype=app]
| stats sum(rows) sum(cputime) by pid

# GOOD - conditional eval
sourcetype=db OR sourcetype=app
| eval pid=if(sourcetype=="db", replace(pid, "cruft", ""), pid)
| stats sum(rows) sum(cputime) by pid
```

---

## When Lookup is the Right Choice

### Pattern: Static or Slowly-Changing Reference Data

When one dataset changes rarely (daily, weekly), bake it into a lookup:

```spl
# Step 1: Create lookup (schedule daily)
index=flexlm sourcetype=flexlm:expire
| stats max(Licenses) as Licenses, last(Expiration) as Expiration 
    by Tool Feature Lic_Ver
| outputlookup flexlm_expire.csv

# Step 2: Use lookup instead of join
index=flexlm sourcetype=flexlm:lmstat
| stats max(Max_Concurrent) as Max_Concurrent, sum(Total_Checkout) as Total_Checkout 
    by Tool Feature Lic_Ver Client_Ver
| lookup flexlm_expire.csv Tool Feature Lic_Ver OUTPUT Licenses Expiration
| table Tool Feature Licenses Expiration Lic_Ver Client_Ver Max_Concurrent Total_Checkout
```

### Why Lookup is Better Than Join

| Aspect | Join | Lookup |
|--------|------|--------|
| Execution | Real-time subsearch | Pre-computed, cached |
| Row limit | 50,000 max | No practical limit |
| Performance | Slow (runs each time) | Fast (indexed) |
| Search Head load | High | Minimal |

---

## Checking Your Search Performance

### Use Job Inspector

1. Click "Job" → "Inspect Job"
2. Scroll to bottom, click "search job properties"
3. Look for:
   - `remoteSearch` - what goes to indexers
   - `reportSearch` - what stays on Search Head

### Signs of Inefficient Search

- Large `reportSearch` section
- Small or empty `remoteSearch` 
- High Search Head CPU/memory
- Long execution times

---

## When Join Might Be Acceptable

| Scenario | Reason |
|----------|--------|
| Small data, fast searches | Overhead is negligible |
| Rows << 50,000 | No truncation risk |
| Few indexers | Less to gain from distribution |
| High cardinality `by id` | Even prestats outputs many rows |

**But**: Always test the `stats` approach first.

---

## Streamstats and Eventstats Warning

Despite the name, `streamstats` and `eventstats` are **not** distributable streaming commands:

- They force data back to Search Head
- They break Map/Reduce efficiency
- Sometimes `transaction` is actually better

**Always test both approaches!**

---

## Advanced Tips

### Tip 1: Front-load the Heavy Lifting

Put the most powerful `stats` command first to reduce data volume early:

```spl
| eval {type}_duration=duration
| eval {type}_callId=callId
| stats dc(incoming_callId) as incoming 
        dc(outgoing_callId) as outgoing
        sum(incoming_duration) as incoming_duration 
        sum(outgoing_duration) as outgoing_duration
        values(name) as name 
    by number
```

### Tip 2: Break Into Two Problems

For rarely-changing data, create a lookup:

```spl
# Find phones that haven't called in a week

# BAD: Join all-time with last week
<all time search> | join [<last week search>]

# GOOD: Bake "all phones ever" into lookup, then:
<last week terms> 
| eval present=1
| inputlookup all_phones_ever append=t
| stats values(present) as present by extension
| search NOT present=1
```

---

## Quick Reference: Join to Stats Conversion

| Join Pattern | Stats Equivalent |
|--------------|------------------|
| `\| join field [search ...]` | `sourcetype=A OR sourcetype=B \| stats ... by field` |
| `\| join field [search ... \| stats ...]` | `... OR ... \| stats ... by field` |
| `\| append [search ...]` | `... OR ... \| stats ...` |
| Different field names | `eval field=if(sourcetype=="A", fieldA, fieldB)` |
| Clean one side only | `eval field=if(sourcetype=="A", replace(...), field)` |

---

## Resources

- **.conf2020 Session**: TRU1761C - "Master Joining Datasets Without Using Join"
- **Presenter**: Nick Mealy, CEO/Chief Mad Scientist, Sideview LLC
- **Slack Channels**: #search-help, #tinfoilstats
- **Splunk Docs**: Search command flowchart

---

## Related Topics

- Stats Command Configuration and Optimization
- Lookup Command and Configuration
- Search Performance Optimization
- Distributed Search Architecture
- Summary Indexing Best Practices
