# Weekly Maintenance Checklist (Lab)

Use this checklist once per week to keep artifact storage and baselines healthy.

## 1) Refresh Current Reports First
```bash
make ops
```

Expected:
- refresh, freshness check, and docs index all pass

## 1a) Environment Profile and Field Inventory
Scheduled maintenance should already refresh this weekly at `04:00` Sunday local time. Manual verification:
```bash
make env-profile-check
make env-profile-schedule-show
```

If you need to force a fresh run:
```bash
make env-profile-refresh
```

Notes:
- each run refreshes one sourcetype field inventory entry
- the next queued sourcetype is tracked in `artifacts/environment/environment_profile_latest.json`

## 2) Review Artifact Volumes
```bash
find docs/logs/template_regression_history -maxdepth 1 -name 'template_regression_*.json' | wc -l
find docs/logs/operator_snapshot/history -maxdepth 1 -type d -name 'snapshot_*' | wc -l
find docs/logs/langgraph_runs -maxdepth 1 -name 'langgraph_run_*.json' | wc -l
```

## 3) Apply Retention Policy (Suggested)
Suggested keep counts:
- Template regression history: keep latest 100
- Operator snapshot history: keep latest 50
- LangGraph run artifacts: keep latest 200

## 4) Prune Old Artifacts (Manual, Controlled)
Preferred scripted dry-run:
```bash
make prune-ops
# one-shot: summary + snapshot + trend + freshness
make prune-summary
# writes docs/logs/prune_summary.json
make prune-snapshot
# writes docs/logs/prune_summary_history/prune_summary_<UTCSTAMP>.json
make prune-trend
# writes docs/logs/prune_summary_history/latest_trend.csv
make prune-freshness
python scripts/prune_artifacts.py
make prune-dry-run
```

Apply deletions only after review:
```bash
python scripts/prune_artifacts.py --apply
make prune-apply
```

Optional keep-count overrides:
```bash
python scripts/prune_artifacts.py --keep-regression 100 --keep-snapshots 50 --keep-langgraph 200
make prune-summary KEEP_REGRESSION=100 KEEP_SNAPSHOTS=50 KEEP_LANGGRAPH=200
make prune-dry-run KEEP_REGRESSION=100 KEEP_SNAPSHOTS=50 KEEP_LANGGRAPH=200
```

Manual listing examples (if needed):

Template regression history prune example:
```bash
ls -1 docs/logs/template_regression_history/template_regression_*.json | sort | head -n -100
```

Operator snapshot history prune example:
```bash
ls -1d docs/logs/operator_snapshot/history/snapshot_* | sort | head -n -50
```

LangGraph run prune example:
```bash
ls -1 docs/logs/langgraph_runs/langgraph_run_*.json | sort | head -n -200
```

Important:
- Review candidate lists before deleting.
- Delete only after confirmation in your terminal workflow.

## 5) Rebuild Summary Artifacts After Prune
```bash
make langgraph-status
make docs-index
make report-freshness
```

## 6) LangGraph Weekly Review
Run the lightweight LangGraph ops bundle:
```bash
make langgraph-ops
make langgraph-ops POLICY_MAX_ABS_DELTA=2
make langgraph-policy-snapshot
make langgraph-policy-trend
make langgraph-policy-freshness POLICY_SUMMARY_MAX_AGE_MINUTES=60
make langgraph-policy-trend-freshness
make langgraph-policy-trend-anomaly
make langgraph-policy-trend-freshness POLICY_TREND_MAX_AGE_MINUTES=1440
make langgraph-artifacts-check
make langgraph-tool-routing-check
make langgraph-session-check
make langgraph-metadata-demo
make langgraph-chain-demo
make langgraph-session-demo
make langgraph-demo-ready
make langgraph-thresholds
make langgraph-ops-strict
make agentic-check
make agentic-demo
make agentic-session-demo
make agentic-status
make agentic-case-report
make agentic-demo-ready
make model-show
make model-smoke
```

Optional weekly topology comparison:
```bash
make langgraph-gold-build
make langgraph-eval-prompts
make langgraph-topology-eval
make langgraph-topology-optimize
```

Use this when you are actively tuning the LangGraph stage layout and want a fresh empirical comparison against the current prompt set.

Review policy summary:
- File: `docs/logs/langgraph_runs/latest_policy_summary.json`
- Key interpretation points:
  - `supported_false` should mostly be expected blocked cases (for example non-read-only phrasing).
  - `query_policy_ok_false` should map to intentional policy-fail demos (for example `row_limit_exceeds_max:200`) unless you are testing new controls.
  - unexpected increases in `guardrail_reason_counts` or new `policy_reason_counts` values should be investigated and noted.

Optional detail review:
- File: `docs/logs/langgraph_runs/latest_policy_rows.csv`
- Spot-check the newest blocked rows and confirm each has an expected `query_policy_reason` or `guardrail_reason`.

History snapshots:
- Directory: `docs/logs/langgraph_policy_summary_history/`
- Use snapshot files for week-over-week policy telemetry comparisons.
- Trend CSV: `docs/logs/langgraph_policy_summary_history/latest_trend.csv`

## 7) Verify Documentation Links and Runbooks
- Confirm these remain up-to-date:
  - `README.md`
  - `docs/runbooks/daily_ops.md`
  - `docs/runbooks/health_check.md`
  - `docs/runbooks/weekly_maintenance.md`

## 8) Record Weekly Notes
Append summary notes to:
- `docs/build_log.md`

Include:
- counts before/after prune
- files pruned
- any unusual drift seen in trend/status outputs
- any unexpected LangGraph policy summary changes
