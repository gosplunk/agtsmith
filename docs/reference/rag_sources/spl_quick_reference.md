# SPL Quick Reference Cheat Sheet

---
tags: [spl, search, quick-reference, cheat-sheet, commands, spl-reference]
category: search
last_updated: 2026-02-20
---

**Document Type**: Reference Guide  
**Audience**: Splunk Users, Analysts  
**Topics**: SPL Commands, Search Syntax  
**Keywords**: SPL quick reference, SPL cheat sheet, search commands, Splunk search syntax, SPL reference guide

**Find this document by searching for**: SPL quick reference, SPL cheat sheet, Splunk search commands, SPL syntax

---

## Basic Search Structure

```spl
index=<index> sourcetype=<sourcetype> <search terms>
| <command1>
| <command2>
| ...
```

---

## Time Modifiers

| Modifier | Description | Example |
|----------|-------------|---------|
| `earliest=-1h` | Last 1 hour | `earliest=-1h latest=now` |
| `earliest=-24h` | Last 24 hours | `earliest=-24h@h` |
| `earliest=-7d` | Last 7 days | `earliest=-7d@d` |
| `earliest=-30d@d` | Last 30 days, snap to day | `earliest=-30d@d latest=@d` |
| `earliest=@d` | Start of today | `earliest=@d` |
| `earliest=-1w@w` | Start of last week | |
| `earliest=-1mon@mon` | Start of last month | |

---

## Stats Commands

| Task | Command |
|------|---------|
| Count events | `\| stats count` |
| Count by field | `\| stats count by field` |
| Count unique values | `\| stats dc(field) as unique_count` |
| Sum values | `\| stats sum(bytes) as total_bytes` |
| Average | `\| stats avg(duration) as avg_duration` |
| Min/Max | `\| stats min(value) max(value)` |
| First/Last value | `\| stats first(field) last(field)` |
| List values | `\| stats values(field) as field_values` |
| List unique | `\| stats list(field) as field_list` |
| Multiple stats | `\| stats count avg(duration) sum(bytes) by host` |

---

## Timechart

| Task | Command |
|------|---------|
| Count over time | `\| timechart count` |
| By field over time | `\| timechart count by status` |
| Custom span | `\| timechart span=1h count` |
| Limit series | `\| timechart limit=10 count by host` |
| Average over time | `\| timechart avg(response_time)` |

---

## Eval Functions

| Task | Command |
|------|---------|
| Create field | `\| eval new_field=field1 + field2` |
| Conditional | `\| eval status=if(code>=400, "error", "ok")` |
| Case statement | `\| eval level=case(code<200,"info", code<400,"warn", true(),"error")` |
| Coalesce | `\| eval name=coalesce(hostname, ip, "unknown")` |
| String concat | `\| eval fullname=user." - ".department` |
| Lower/Upper | `\| eval name=lower(name)` |
| Length | `\| eval len=len(message)` |
| Substring | `\| eval short=substr(field,1,10)` |
| Replace | `\| eval clean=replace(field, "pattern", "replacement")` |
| Round | `\| eval rounded=round(value, 2)` |
| Ceiling/Floor | `\| eval up=ceiling(value)` |
| Now timestamp | `\| eval current=now()` |
| Time conversion | `\| eval epoch=strptime(date, "%Y-%m-%d")` |
| Format time | `\| eval readable=strftime(_time, "%Y-%m-%d %H:%M:%S")` |
| Null check | `\| eval result=if(isnull(field), "missing", field)` |
| In list | `\| eval match=if(field IN("a","b","c"), 1, 0)` |
| Math | `\| eval pct=round((part/total)*100, 2)` |
| MV to string | `\| eval combined=mvjoin(mvfield, ", ")` |

---

## Field Extraction

| Task | Command |
|------|---------|
| Rex extract | `\| rex field=_raw "user=(?<username>\w+)"` |
| Rex multiple | `\| rex "src=(?<src_ip>\d+\.\d+\.\d+\.\d+).*dst=(?<dst_ip>\d+\.\d+\.\d+\.\d+)"` |
| Rex mode=sed | `\| rex mode=sed "s/oldvalue/newvalue/g"` |
| Extract key=value | `\| extract pairdelim="," kvdelim="="` |

---

## Filtering & Manipulation

| Task | Command |
|------|---------|
| Where clause | `\| where count > 100` |
| Where like | `\| where like(field, "%pattern%")` |
| Where match | `\| where match(field, "regex")` |
| Search filter | `\| search status=error` |
| Dedup | `\| dedup host` |
| Dedup keep last | `\| dedup host sortby -_time` |
| Head/Tail | `\| head 10` or `\| tail 10` |
| Sort | `\| sort -count` (descending) |
| Sort multi | `\| sort host -count` |
| Rename | `\| rename old_name as new_name` |
| Table | `\| table _time host status message` |
| Fields include | `\| fields host status count` |
| Fields exclude | `\| fields - _raw _time` |

---

## Lookups

| Task | Command |
|------|---------|
| Basic lookup | `\| lookup users_lookup username OUTPUT department` |
| Output all | `\| lookup users_lookup username` |
| Input lookup | `\| inputlookup my_lookup.csv` |
| Output lookup | `\| outputlookup my_lookup.csv` |
| Append lookup | `\| outputlookup append=t my_lookup.csv` |

---

## Join Alternatives (Preferred)

| Task | Command |
|------|---------|
| Stats + eval | `\| stats values(field) as all_values by key \| eval ...` |
| Lookup | `\| lookup reference_table key_field OUTPUT value_field` |
| Subsearch | `[search index=other \| fields key_field]` |
| Append + stats | `\| append [search ...] \| stats values(*) by key` |

---

## Subsearch

| Task | Command |
|------|---------|
| Basic subsearch | `index=main [search index=alerts \| fields src_ip]` |
| Return format | `index=main [search index=alerts \| return 100 src_ip]` |
| Format subsearch | `index=main [search index=alerts \| fields src_ip \| format]` |

---

## Transaction

| Task | Command |
|------|---------|
| By field | `\| transaction session_id` |
| With time limits | `\| transaction session_id maxspan=30m maxpause=5m` |
| Start/End | `\| transaction startswith="login" endswith="logout"` |
| Keep evicted | `\| transaction session_id keepevicted=t` |

---

## Streamstats

| Task | Command |
|------|---------|
| Running count | `\| streamstats count` |
| Running sum | `\| streamstats sum(bytes) as running_total` |
| Window | `\| streamstats window=5 avg(value) as moving_avg` |
| By field | `\| streamstats count by host` |
| Reset | `\| streamstats reset_after=(status="completed") count` |

---

## Eventstats

| Task | Command |
|------|---------|
| Global stats | `\| eventstats avg(response_time) as global_avg` |
| By group | `\| eventstats avg(response_time) as group_avg by host` |
| Percentage | `\| eventstats sum(count) as total \| eval pct=round((count/total)*100,2)` |

---

## tstats (Accelerated)

| Task | Command |
|------|---------|
| Basic count | `\| tstats count where index=main by host` |
| Time-based | `\| tstats count where index=main by _time span=1h` |
| Datamodel | `\| tstats count from datamodel=Network_Traffic by All_Traffic.dest` |
| Summaries only | `\| tstats summariesonly=t count from datamodel=...` |
| Prestats | `\| tstats prestats=t count where index=main by host \| stats count by host` |

---

## mstats (Metrics)

| Task | Command |
|------|---------|
| Basic | `\| mstats avg(cpu.usage) where index=metrics by host` |
| Time span | `\| mstats avg(cpu.usage) where index=metrics by host span=5m` |
| Fill nulls | `\| mstats avg(cpu.usage) where index=metrics by host span=5m fillnull_value=0` |

---

## Multivalue Fields

| Task | Command |
|------|---------|
| Count MV | `\| eval count=mvcount(mvfield)` |
| Index into MV | `\| eval first=mvindex(mvfield, 0)` |
| Filter MV | `\| eval filtered=mvfilter(match(mvfield, "pattern"))` |
| Join MV | `\| eval joined=mvjoin(mvfield, ",")` |
| Expand MV | `\| mvexpand mvfield` |
| Dedup MV | `\| eval unique=mvdedup(mvfield)` |
| Sort MV | `\| eval sorted=mvsort(mvfield)` |

---

## Formatting Output

| Task | Command |
|------|---------|
| Table | `\| table field1 field2 field3` |
| Rename | `\| rename field1 as "Display Name"` |
| Convert time | `\| convert ctime(_time) as time` |
| Format number | `\| eval formatted=tostring(bytes, "commas")` |
| Fillnull | `\| fillnull value="N/A"` |
| Transpose | `\| transpose` |

---

## Macros

| Task | Command |
|------|---------|
| Use macro | `` `my_macro` `` |
| With args | `` `my_macro(arg1, arg2)` `` |
| Define (in macros.conf) | `[my_macro]` `definition = index=main sourcetype=syslog` |

---

## Common Patterns

### Count by status code
```spl
index=web
| stats count by status
| sort -count
```

### Top 10 talkers
```spl
index=network
| stats sum(bytes) as total_bytes by src_ip
| sort -total_bytes
| head 10
```

### Error rate over time
```spl
index=app
| eval is_error=if(status>=500, 1, 0)
| timechart span=5m sum(is_error) as errors count as total
| eval error_rate=round((errors/total)*100, 2)
```

### Unique users per day
```spl
index=auth action=login
| timechart span=1d dc(user) as unique_users
```

### Compare today vs yesterday
```spl
index=web earliest=-1d@d latest=@d
| eval day="yesterday"
| append [search index=web earliest=@d | eval day="today"]
| stats count by day
```

### Find outliers
```spl
index=metrics
| stats avg(value) as avg stdev(value) as stdev by host
| eval upper=avg+(2*stdev) lower=avg-(2*stdev)
```

---

## Performance Tips

1. **Be specific with time** - Always use `earliest` and `latest`
2. **Use indexed fields first** - `index`, `sourcetype`, `host`, `source`
3. **Avoid wildcards at start** - `*error` is slow, `error*` is fast
4. **Use tstats when possible** - 10-100x faster with acceleration
5. **Limit fields early** - `| fields host status` removes unneeded data
6. **Use stats instead of transaction** - Much more efficient
7. **Avoid join** - Use lookups or subsearches instead
8. **Filter before stats** - Reduce data before aggregation

---

## Common Questions

**Q: How to get the latest event per host?**
```spl
| stats latest(_time) as latest_time latest(_raw) as latest_event by host
```

**Q: How to calculate percentage of total?**
```spl
| stats count by status
| eventstats sum(count) as total
| eval pct=round((count/total)*100, 2)
```

**Q: How to find events with a field missing?**
```spl
| where isnull(field) OR field=""
```

**Q: How to search multiple values?**
```spl
| where status IN (200, 201, 204)
```
or
```spl
(status=200 OR status=201 OR status=204)
```
