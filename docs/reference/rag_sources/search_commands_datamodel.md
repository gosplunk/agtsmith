# Splunk Data Model Search and Configuration

**Document Type**: Search Reference & Data Model Guide
**Audience**: Splunk Power Users, Analytics Engineers, Security Analysts
**Topics**: Data Models, tstats Command, Datamodel Command, Acceleration, CIM
**Keywords**: datamodel, tstats, acceleration, tsidx, summariesonly, CIM, field extractions, data model searches, MCP

**Quick Links:**
- Data Models Documentation: https://docs.splunk.com/Documentation/Splunk/latest/Knowledge/Aboutdatamodels
- tstats Command Reference: https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Tstats
- CIM Documentation: https://docs.splunk.com/Documentation/CIM/latest

**Description:** Comprehensive guide to searching Splunk data models using datamodel and tstats commands for optimized performance

**Last Updated:** 2025-12-01

## Search Keywords & Index Terms

**This document covers:** data model, tstats command, datamodel command, acceleration, tsidx, summariesonly, CIM, Common Information Model, field extractions, pivots, dataset, MCP queries

**Find this document by searching for:** data model search, tstats, datamodel command, CIM search, accelerated search, tsidx, how to search data model, MCP datamodel

---

## Overview

Data models organize raw data into a structured, hierarchical format that makes searching easier and faster. The Splunk Common Information Model (CIM) provides standard data models for security and IT operations.

### Key Benefits

- **Performance**: Searches run faster using accelerated summaries
- **Consistency**: Standardized field names and structures
- **Ease of Use**: Pre-configured searches and visualizations
- **Scalability**: Better performance with large datasets

---

## MCP (Model Context Protocol) Considerations

When executing data model searches via Splunk MCP, be aware of these limitations:

### Working MCP Queries

```spl
# tstats count without by clause
| tstats count from datamodel=Authentication

# tstats with WHERE clause (no by)
| tstats count from datamodel=Authentication WHERE Authentication.action=success

# tstats with values() aggregation (no by clause)
| tstats count values(Authentication.action) from datamodel=Authentication

# datamodel command with search mode
| datamodel Authentication Authentication search

# datamodel with flat mode (removes field prefixes)
| datamodel Authentication Authentication flat

# datamodel + stats (RECOMMENDED for MCP when grouping needed)
| datamodel Authentication Authentication search | stats count by Authentication.user Authentication.action

# datamodel flat + stats (BEST for MCP - clean field names + grouping)
| datamodel Authentication Authentication flat | stats count by user action

# summariesonly for accelerated data
| datamodel Authentication Authentication summariesonly=true search | stats count by Authentication.user
```

### MCP Validation Errors

**CRITICAL:** The tstats `by` clause causes validation errors in MCP regardless of field count:

```spl
# ❌ FAILS in MCP - ANY by clause fails
| tstats count from datamodel=Authentication by Authentication.user

# ❌ FAILS in MCP - by with _time
| tstats count from datamodel=Authentication by _time span=1h

# ❌ FAILS in MCP - multiple by fields
| tstats count from datamodel=Authentication by Authentication.user, Authentication.action

# ❌ FAILS in MCP - by with WHERE clause
| tstats count from datamodel=Authentication WHERE Authentication.action IN (success, failure) by Authentication.action
```

**Error Message:** `Validation error: string indices must be integers`

**Workaround:** Use `| datamodel` command with `flat` mode, then pipe to `stats`:

```spl
# ✅ WORKS in MCP - datamodel flat + stats for grouping
| datamodel Authentication Authentication flat | stats count by user action src

# ✅ WORKS in MCP - with time grouping
| datamodel Authentication Authentication flat | bin _time span=1h | stats count by _time action
```

### Field Names in MCP Results

- **`search` mode**: Fields have prefixes like `Authentication.user`, `Authentication.action`
- **`flat` mode**: Fields are simplified like `user`, `action` (no prefix)

---

## Using the datamodel Command

The `datamodel` command is a **generating command** and requires a leading pipe (`|`).

### Basic Data Model Search

Retrieve data from a specific dataset within a data model:

```spl
| datamodel Authentication Successful_Authentication flat summariesonly=true 
| stats count by app
```

### Components

- `datamodel`: Command to query data models
- `Authentication`: Name of the data model
- `Successful_Authentication`: Name of the dataset within the model
- `flat`: Returns results in flat format (all fields at same level)
- `summariesonly=true`: Uses only accelerated summary data (tsidx)

### Search Events from Data Model

To retrieve raw events instead of accelerated summaries:

```spl
| datamodel Authentication Failed_Authentication search
```

### Search with Specific Filters

```spl
| datamodel Change Accounts_Created search 
| search All_Changes.user_name = svcvnc
```

---

## Using the tstats Command

The `tstats` command performs fast statistical searches against tsidx (time series index) data.

### Basic tstats Syntax

```spl
| tstats count as count values(Authentication.user) 
from datamodel="Authentication"."Authentication" 
by Authentication.user, Authentication.src
```

### tstats vs. Regular Search

| Feature | tstats | Regular Search |
|---------|--------|-----------------|
| **Speed** | Very fast (tsidx) | Slower (raw data) |
| **Data Source** | Accelerated summaries | Raw events |
| **Field Access** | CIM fields only | All fields |
| **Aggregations** | Fast | Slower |
| **Filters** | Via WHERE clause | Via pipe commands |

### Comprehensive tstats Example

```spl
| tstats count as count 
  values(Authentication.tag)
  values(Authentication.user)
  values(Authentication.dest)
  values(Authentication.src)
  values(Authentication.action) as action
  values(Authentication.signature)
from datamodel="Authentication"."Authentication"  
by Authentication.user, Authentication.src, _time
```

### tstats with WHERE Clause

```spl
| tstats count 
from datamodel=Authentication 
WHERE Authentication.action IN (success, failure) 
by Authentication.action
```

---

## Optimization Techniques

### summariesonly Parameter

```spl
| datamodel Authentication Successful_Authentication flat summariesonly=true
```

**Effect**: Returns results ONLY from accelerated summary data (tsidx), maximizing search speed.

**Trade-off**: May miss recent data not yet summarized in acceleration buckets.

### Using tstats for Maximum Performance

```spl
| tstats `security_content_summariesonly` 
  values(All_Changes.result_id) as result_id count 
  min(_time) as firstTime 
  max(_time) as lastTime 
from datamodel=Change 
where All_Changes.result_id=4720 
by All_Changes.user, All_Changes.dest
```

---

## Common Data Model Searches

### Authentication Data Model

Count successful logins by app:

```spl
| datamodel Authentication Successful_Authentication flat summariesonly=true 
| stats count by app
```

Count events by action status:

```spl
| tstats count from datamodel=Authentication 
WHERE Authentication.action IN (success, failure) 
by Authentication.action
```

### Change Data Model

Search for account creation events:

```spl
| datamodel Change Accounts_Created search
```

Find accounts created by specific user:

```spl
| tstats values(All_Changes.result_id) as result_id count 
from datamodel=Change 
where All_Changes.result_id=4720 
by All_Changes.user, All_Changes.dest
```

### Combining Multiple Data Models

Merge user lists from Authentication and Change models:

```spl
| tstats values(Authentication.user) as user 
from datamodel=Authentication.Authentication 
where Authentication.user=* 
by Authentication.user
| eval source="Authentication"
| append 
  [| tstats values(All_Changes.user) as user 
    from datamodel=Change.All_Changes 
    where All_Changes.user=* 
    by All_Changes.user
   | eval source="All_Changes"]
| stats values(source) as sources by user
| eval in_Authentication=if(match(sources, "Authentication"), "yes", "no")
| eval in_All_Changes=if(match(sources, "All_Changes"), "yes", "no")
| table user in_Authentication in_All_Changes
```

---

## Field Reference Examples

### Authentication Data Model Fields

```
Authentication.user           - Username
Authentication.src            - Source IP address
Authentication.dest           - Destination/target system
Authentication.action         - Success/failure action
Authentication.tag            - Event tags
Authentication.signature       - Signature or event type
Authentication.response_time   - Response time
Authentication.duration        - Session duration
Authentication.src_bunit       - Source business unit
Authentication.dest_bunit      - Destination business unit
```

### Change Data Model Fields

```
All_Changes.user               - User who made change
All_Changes.result_id          - Change result ID (e.g., 4720 for account creation)
All_Changes.user_name          - Account name
All_Changes.dest               - Destination system
All_Changes.src_user_name      - Source user
All_Changes.Account_Management - Account management category
```

---

## Data Model Acceleration

### Enabling Acceleration

1. Open the data model in Splunk
2. Click **Acceleration** > **Enable Acceleration**
3. Select acceleration options
4. Click **Save**

### Acceleration Best Practices

- Enable acceleration for frequently-used data models
- Monitor acceleration summary size and performance
- Set appropriate acceleration time ranges
- Test searches with and without acceleration

---

## Troubleshooting Data Model Searches

### No Results from Data Model

1. Verify data model is accelerated and summaries are built
2. Check that field mappings are correct
3. Ensure data exists in the specified time range
4. Use `summariesonly=false` to include raw data

### Slow Data Model Searches

1. Use `summariesonly=true` to force tsidx usage
2. Switch to `tstats` for better performance
3. Add time range filters to reduce data scope
4. Verify acceleration is enabled and current

### Field Not Found

1. Check correct field name (case-sensitive)
2. Verify field exists in data model definition
3. Use correct datamodel and dataset path
4. Check CIM field mappings

---

## MCP-Compatible Authentication & Security Searches

### Using `from datamodel` Syntax (RECOMMENDED for MCP)

The `from datamodel:"Model"."Dataset"` syntax works best with MCP and allows full flexibility:

#### Authentication Failures by User
```spl
| from datamodel:"Authentication"."Failed_Authentication"
| stats count by user, src
| where count > 5
```

#### Successful Logins Over Time
```spl
| from datamodel:"Authentication"."Successful_Authentication"
| bin _time span=1h
| stats count by _time, app
```

#### Account Management Events
```spl
| from datamodel:"Change"."Accounts_Created"
| stats values(tag) as tags, count by user, dest
```

#### Brute Force Detection (MCP-Safe)
```spl
| from datamodel:"Authentication"."Failed_Authentication"
| stats values(tag) as tag, dc(user) as user_count, dc(dest) as dest_count, count by app, src
| where count >= 6
```

#### Access Over Time By Action/App
```spl
| from datamodel:"Authentication"."Authentication"
| bin _time span=1h
| stats count by _time, action, app
```

#### Authentication Failures By Hour/Day/User
```spl
| from datamodel:"Authentication"."Failed_Authentication"
| eval hour=strftime(_time, "%H")
| eval day=strftime(_time, "%A")
| stats count by hour, day, user
| sort -count
```

#### Default Account Usage Tracking
```spl
| from datamodel:"Authentication"."Authentication"
| search user IN ("admin", "root", "administrator", "guest")
| stats count, values(src) as sources, values(dest) as destinations by user
```

#### Privileged Account Usage Monitoring
```spl
| from datamodel:"Authentication"."Privileged_Authentication"
| stats count, values(app) as apps, dc(src) as unique_sources by user
| sort -count
```

#### Inactive Accounts Detection
```spl
| from datamodel:"Authentication"."Authentication"
| stats latest(_time) as last_login by user
| eval days_inactive=round((now()-last_login)/86400, 1)
| where days_inactive > 90
| sort -days_inactive
```

### Alternative: datamodel flat + stats Pattern

For simpler queries, use `datamodel` with `flat` mode:

#### Failed Logins with Clean Field Names
```spl
| datamodel Authentication Failed_Authentication flat
| stats count by user, src, dest
| where count > 3
```

#### Successful Authentication by App
```spl
| datamodel Authentication Successful_Authentication flat summariesonly=true
| stats count, values(user) as users by app
| sort -count
```

#### Account Changes Tracking
```spl
| datamodel Change All_Changes flat
| search result_id=4720
| stats count, values(dest) as affected_systems by user
```

### Field Aliasing in Results

When using `from datamodel:`, fields retain their full names. Use `rename` or `eval` to clean them:

```spl
| from datamodel:"Authentication"."Failed_Authentication"
| rename "Authentication.user" as user, "Authentication.src" as src_ip
| stats count by user, src_ip
```

---

## Related Topics

- Common Information Model (CIM)
- Data Model Acceleration
- Search Performance Optimization
- Pivot Tables
- tstats Command Details
- CIM Field Mappings
- MCP Query Validation
