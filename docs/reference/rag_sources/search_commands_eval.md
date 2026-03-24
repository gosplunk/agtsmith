# Splunk Eval Commands: Ingest-Time vs Search-Time

**Document Type**: Configuration Reference & SPL Guide
**Audience**: Splunk Power Users, Data Analysis Engineers, Developers
**Topics**: Eval Command, Field Extraction, Calculated Fields, Props.conf, Fields.conf
**Keywords**: eval, calculated field, ingest-time eval, search-time eval, EVAL-, props.conf, fields.conf

**Quick Links:**
- Splunk Eval Documentation: https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Eval
- Props.conf Reference: https://docs.splunk.com/Documentation/Splunk/latest/Admin/Propsconf
- Fields.conf Reference: https://docs.splunk.com/Documentation/Splunk/latest/Admin/Fieldsconf
- Ingest-Time Eval Guide: https://docs.splunk.com/Documentation/Splunk/latest/Data/IngestEval

**Description:** Guide for using eval commands at ingest-time (props.conf) and search-time (SPL) for field calculations

**Last Updated:** 2025-11-25

## Search Keywords & Index Terms

**This document covers:** eval command, calculated fields, EVAL-, props.conf configuration, fields.conf, ingest-time eval, search-time eval, field extraction, field transformation

**Find this document by searching for:** eval command, calculated field, how to calculate field, EVAL-, ingest-time calculation, search-time eval

---

## Overview

The `eval` command creates new fields by performing calculations or transformations on existing fields. There are two contexts for using eval:

1. **Search-Time Eval**: Run during search execution (SPL queries)
2. **Ingest-Time Eval**: Run during data ingestion (props.conf configuration)

---

## Search-Time Eval

Search-time eval is the most common approach. Use it in your Splunk searches to create calculated fields.

### Basic Syntax

```spl
| eval field_name = expression
```

### Concatenate Strings

Combine first and last names into a full name:

```spl
index=your_index sourcetype=my_sourcetype
| eval full_name = first_name . " " . last_name
| table first_name last_name full_name
```

### Convert to Lowercase

```spl
| eval eval_user = lower(username)
```

### Combined Search with Multiple Calculations

```spl
| eval first_name="John", last_name="Doe", username="TestUser"
| append [| makeresults | eval first_name="Jane", last_name="Smith", username="User6"]
| eval full_name = first_name . " " . last_name
| eval eval_user = lower(username)
| table first_name last_name full_name eval_user
```

### Field Operations

| Operation | Example | Description |
|-----------|---------|-------------|
| **Concatenation** | `first_name . " " . last_name` | Combine strings |
| **Lowercase** | `lower(username)` | Convert to lowercase |
| **Uppercase** | `upper(host)` | Convert to uppercase |
| **Substring** | `substr(field, 0, 5)` | Extract substring |
| **Math** | `field1 + field2` | Arithmetic operations |
| **Conditional** | `if(condition, true_value, false_value)` | Conditional logic |

---

## Ingest-Time Eval (props.conf)

For calculations that should be performed once during ingest, use the `EVAL-` setting in props.conf.

### Props.conf Configuration

Define calculated fields in your props.conf:

```ini
[my_sourcetype]
EVAL-eval_user = lower(username)
```

### Multiple Calculated Fields

```ini
[WinEventLog]
EVAL-upper_case1 = upper(host)
EVAL-lower_case = lower(product)
EVAL-event_time = strftime(_time, "%Y-%m-%d %H:%M:%S")
```

### Search Using Ingest-Time Calculated Fields

```spl
sourcetype=WinEventLog
| table host upper_case1 lower_case event_time
```

---

## Declaring Calculated Fields in fields.conf

Once you've created a calculated field, declare it in fields.conf to optimize indexing.

### Mark Field as Non-Indexed

For calculated fields that don't need to be indexed:

```ini
[eval_user]
INDEXED = False
```

### Field Declaration Example

```ini
[full_name]
INDEXED = False
REQUIRED = False

[eval_user]
INDEXED = False
REQUIRED = False
```

---

## Important Considerations

### Avoid Circular Dependencies

**Wrong** ❌ - Don't use a calculated field as input to another calculated field:

```ini
[my_sourcetype]
EVAL-field1 = lower(username)
EVAL-field2 = upper(field1)  # Don't reference field1 if it's calculated
```

**Correct** ✅ - Reference original fields only:

```ini
[my_sourcetype]
EVAL-field1 = lower(username)
EVAL-field2 = upper(username)
```

### Performance Considerations

**Ingest-Time (props.conf):**
- ✅ Calculated once during indexing
- ✅ Faster searches
- ❌ Requires changes to indexers
- ❌ Cannot be changed without re-indexing

**Search-Time (SPL):**
- ✅ Flexible and easy to change
- ✅ No need to re-index data
- ❌ Calculated every search
- ❌ Slower for frequently-used fields

---

## Common Eval Expressions

### String Operations

```spl
# Concatenate
| eval result = field1 . " - " . field2

# Extract substring (start position 0, length 5)
| eval short = substr(field_name, 0, 5)

# Replace text
| eval cleaned = replace(raw_data, "bad_string", "good_string")

# Uppercase
| eval upper_field = upper(field_name)

# Lowercase
| eval lower_field = lower(field_name)
```

### Numeric Operations

```spl
# Addition
| eval sum = field1 + field2

# Division and percentage
| eval percentage = round((success / total) * 100, 2)

# Absolute value
| eval abs_value = abs(field_name)

# Rounding
| eval rounded = round(field_name, 2)
```

### Conditional Logic

```spl
# If-then-else
| eval severity = if(count > 100, "high", if(count > 50, "medium", "low"))

# Multiple conditions
| eval status = if(status="success" AND user="admin", "approved", "pending")

# Case statement
| eval category = case(
    priority > 80, "critical",
    priority > 60, "high",
    priority > 40, "medium",
    1=1, "low"
  )
```

### Time Operations

```spl
# Format timestamp
| eval formatted_time = strftime(_time, "%Y-%m-%d %H:%M:%S")

# Calculate time difference (in seconds)
| eval time_diff = latest_time - earliest_time

# Convert epoch to human readable
| eval event_date = strftime(_time, "%A, %B %d, %Y at %H:%M:%S")
```

---

## Best Practices

1. **Use Search-Time First**: Start with search-time eval for flexibility
2. **Move to Ingest-Time Later**: Once proven, move frequently-used calculations to props.conf
3. **Document Calculations**: Comment your eval expressions for maintainability
4. **Test Thoroughly**: Test calculated fields on sample data before production use
5. **Monitor Performance**: Watch search performance when adding many calculated fields
6. **Avoid Redundancy**: Don't calculate fields that Splunk already provides
7. **Use Meaningful Names**: Name calculated fields clearly to indicate their purpose
8. **Version Control**: Keep props.conf changes in version control

---

## Related Topics

- Field Extraction and Parsing
- Props.conf Configuration
- Transforms.conf for Field Transformations
- Search Performance Optimization
- Calculated Fields for Visualization
