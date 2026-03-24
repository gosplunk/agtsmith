# Known-Good Expected Outputs (Lab Baseline)

Use this page to quickly validate whether core checks are behaving normally.

## 1) Connectivity Smoke Check
Command:
```bash
python scripts/smoke_lab_connectivity.py
```

Expected success pattern:
- `[PASS] ollama_tags`
- `[PASS] ollama_generate`
- `[PASS] splunk_auth_signal`
- JSON summary contains: `"all_passed": true`

## 2) Splunk MCP Auth Probe
Command:
```bash
python scripts/test_splunk_mcp_auth.py
```

Expected success pattern:
- GET may return `405 Method not allowed`
- POST should return JSON-RPC-shaped response (commonly `200`)
- Output includes: `PASS: Endpoint reached with authenticated request`

## 3) MCP Discovery (`initialize` + `tools/list`)
Command:
```bash
python scripts/discover_splunk_mcp_tools.py
```

Expected success pattern:
- `initialize` HTTP `200`
- `tools/list` HTTP `200`
- non-empty tool list printed
- Output includes: `PASS: initialize + tools/list discovery succeeded.`

## 4) First Read-Only Tool Calls
Command:
```bash
python scripts/run_splunk_mcp_readonly_calls.py
```

Expected success pattern:
- `tools/call: splunk_get_user_info` HTTP `200`
- `tools/call: splunk_get_indexes` HTTP `200`
- Output includes: `PASS: First read-only tool calls succeeded.`

## 5) Non-Zero Retrieval Proof
Command:
```bash
python scripts/run_splunk_mcp_nonzero_query.py
```

Expected success pattern:
- `tools/call: splunk_run_query` HTTP `200`
- `rows_returned` greater than `0`
- Output includes: `PASS: Retrieved non-zero query results from Splunk MCP.`

## 6) Template Safety Check
Command:
```bash
python scripts/check_query_templates.py
```

Expected success pattern:
- `templates=3`
- `status=PASS`
- each template line shows bounded `row_limit` and time window

## 7) Regression Runner
Command:
```bash
python scripts/run_template_regression.py
```

Expected success pattern:
- template self-check block shows `status=PASS`
- one row summary line per intent
- final `status=PASS`
- artifacts printed:
  - `report=docs/logs/template_regression_latest.json`
  - `snapshot=docs/logs/template_regression_history/template_regression_<UTCSTAMP>.json`

## 8) Trend Summary
Command:
```bash
python scripts/summarize_regression_trends.py --max-abs-delta 0
```

Expected success pattern:
- latest snapshot metadata shown
- per-intent deltas shown
- final `status=PASS` when drift is within threshold

## 9) One-Command Wrapper
Command:
```bash
./scripts/run_lab_checks.sh 0
```

Expected success pattern:
- Stage `[1/3] Template preflight` completes
- Stage `[2/3] Regression run` completes
- Stage `[3/3] Trend threshold check` completes
- Final line: `All checks completed successfully.`

## Notes
- Minor numeric drift can occur in live data counts over time.
- Focus on structural success signals first (HTTP status, JSON-RPC shape, PASS/FAIL lines), then investigate count changes.
