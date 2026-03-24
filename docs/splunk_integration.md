# Splunk Integration

## Current Endpoint Details
- Splunk host IP: `<splunk-host-ip>`
- Management/API port: `8089`
- MCP endpoint: `https://<splunk-host-ip>:8089/services/mcp`

## Current Status
- Network connectivity from controller to Splunk is confirmed.
- Unauthenticated checks showed expected auth/verb behavior:
  - `GET /services/mcp` -> `405 Method not allowed`
  - `POST /services/mcp` -> `401` (auth required signal)
- Authenticated lab bearer probe succeeded at transport/auth layer:
  - `POST /services/mcp` -> `200` with JSON-RPC error `Method 'None' not found` (expected when no method is supplied).

## Interpretation of Current Auth Error
The earlier auth error still proved:
- Pi reached Splunk host
- Port 8089 was reachable
- API endpoint responded
- Authentication flow was being processed

Current interpretation after authenticated probe:
- Bearer auth format is accepted by the endpoint in this lab.
- Next requirement is sending a valid JSON-RPC method payload (read-only first).

## Official MCP Server Notes (Validated Against Splunk Docs)
- Splunk MCP server is now documented as GA for Splunk Enterprise and Splunk Cloud Platform.
- Tools are exposed under the MCP server namespace (for example: `splunk-mcp-server.splunk_get_indexes`).
- Splunk docs show `mcp-remote` client patterns with auth header forwarding to the MCP endpoint.

### Documented Tool Set
- `splunk_run_query`: run SPL and return results.
- `splunk_get_info`: basic Splunk instance info.
- `splunk_get_indexes`: list accessible indexes.
- `splunk_get_index_info`: details for one index.
- `splunk_get_metadata`: hosts/sources/sourcetypes for an index.
- `splunk_get_user_info`: current authenticated user details.
- `splunk_get_knowledge_objects`: list objects such as saved searches, macros, data models.
- `splunk_prompt_to_query`: convert natural language prompt to SPL.
- `splunk_explain_query`: explain SPL behavior.
- `splunk_optimize_query`: optimize SPL.
- `splunk_get_mltk_algorithm_info`: list MLTK algorithms and parameters.

### Platform Prerequisites to Track
- Splunk MCP server app must be installed and enabled on the target Splunk platform.
- TLS must be configured for trusted certificates (self-signed requires explicit trust handling in clients).
- User/service account should have least-privilege permissions for read-only lab flows first.
- For search execution tool usage, relevant `search` and index permissions are required.

### Recommended First Read-Only Discovery Flow
1. `initialize` JSON-RPC handshake.
2. `tools/list` to enumerate server-exposed tools in this environment.
3. `splunk-mcp-server.splunk_get_user_info`.
4. `splunk-mcp-server.splunk_get_indexes`.
5. `splunk-mcp-server.splunk_get_metadata` on a known index.

## Lab-Observed MCP Discovery Results (2026-03-08)
Using `scripts/discover_splunk_mcp_tools.py` with lab bearer auth:
- `initialize` returned HTTP `200`
- Server protocol version: `2025-03-26`
- Server info: `Splunk_MCP_Server` version `0.1.0`
- `tools/list` returned HTTP `200` with 9 tools:
  - `splunk_get_info`
  - `splunk_get_indexes`
  - `splunk_get_index_info`
  - `splunk_get_user_list`
  - `splunk_get_user_info`
  - `splunk_run_query`
  - `splunk_get_metadata`
  - `splunk_get_kv_store_collections`
  - `splunk_get_knowledge_objects`

Notes:
- Tool inventory in this environment differs slightly from the static docs list.
- We should treat `tools/list` output as runtime source of truth for implementation.

## Current LangGraph Tool Routing Coverage (Lab)
- `splunk_run_query`: default read-only analytical question path.
- `splunk_get_indexes`: index inventory wording path.
- `splunk_get_metadata`: metadata inventory wording path (`hosts|sources|sourcetypes`).
- `splunk_get_info`: Splunk instance information wording path.

Current metadata planner defaults:
- `index=*`
- `earliest_time=-24h`
- `latest_time=now`
- `row_limit=20`

Current metadata policy guardrail:
- allows only metadata types `hosts|sources|sourcetypes`
- requires both time bounds
- blocks metadata `row_limit > 200`

Current two-tool chain coverage:
- question phrase examples:
  - `Investigate top index with metadata drilldown`
  - `index drilldown`
- execution chain:
  1. `splunk_get_indexes`
  2. `splunk_get_metadata` (auto-focused to top index from step 1)

Current MCP reliability control:
- MCP wrapper now retries tool calls up to 3 attempts with short backoff.

Current iterative agentic loop coverage:
- Script: `scripts/langgraph_agentic_soc.py`
- Current bounded pivot sequence examples:
  - failed-login query -> hosts metadata -> top-host sourcetype distribution
  - index inventory -> top-index sourcetype metadata -> top-sourcetype host distribution
- Loop bounds:
  - default `max_steps=3`
- Deeper-investigation controls:
  - one automatic continuation pass is allowed when the continuation reviewer produces a planner-safe next question
  - duplicate pivots are blocked
  - continuation confidence and depth are enforced before another round can run
  - any continuation beyond the first automatic follow-up requires analyst approval in the UI
- All pivoted run-query calls are validated through query policy before execution.

## Lab-Observed First Read-Only Tool Calls (2026-03-08)
Using `scripts/run_splunk_mcp_readonly_calls.py`:
- JSON-RPC method used: `tools/call`
- Calls executed:
  - `splunk_get_user_info` with empty arguments
  - `splunk_get_indexes` with `row_limit=20`

### Observed Response Shape
Both calls returned:
- HTTP `200`
- JSON-RPC `result.content` (human-readable status text)
- JSON-RPC `result.structuredContent` (machine-usable payload)

`splunk_get_user_info` structured fields observed:
- `results` (array)
- `truncated` (boolean)
- `total_rows` (integer)
- sample result keys:
  - `username`
  - `roles`
  - `defaultApp`
  - `capabilitiesCount`
  - `last_successful_loginIso`

`splunk_get_indexes` structured fields observed:
- `results` (array)
- `truncated` (boolean)
- `total_rows` (integer)
- sample result keys:
  - `title`
  - `disabled`
  - `currentDBSizeMB`
  - `totalEventCount`
  - `splunk_server`

Implementation note:
- For agent logic, parse `result.structuredContent` as the primary data source.
- Treat `result.content` as user-facing execution status text.

## Lab-Observed First Safe Query Call (2026-03-08)
Using `scripts/run_splunk_mcp_safe_query.py` with:
- tool: `splunk_run_query`
- query: `search index=* | stats count by index | sort - count`
- `earliest_time=-24h`
- `latest_time=now`
- `row_limit=20`

Observed response:
- HTTP `200`
- JSON-RPC `result.content` text: `Tool executed successfully (0 results).`
- JSON-RPC `result.structuredContent`:
  - `results: []`
  - `truncated: false`
  - `total_rows: 0`

Interpretation:
- Query execution path is working end-to-end.
- Zero rows are a data-window/query outcome, not a transport or protocol failure.

## Lab-Observed Non-Zero Retrieval Proof (2026-03-08)
Using `scripts/run_splunk_mcp_nonzero_query.py` with:
- tool: `splunk_run_query`
- query: `search index=_internal | stats count by sourcetype | sort - count`
- `earliest_time=-24h`
- `latest_time=now`
- `row_limit=10`

Observed response:
- HTTP `200`
- JSON-RPC `result.content` text: `Tool executed successfully (10 results).`
- JSON-RPC `result.structuredContent`:
  - `results`: 10 rows returned
  - `truncated: true`
  - `total_rows: 23`

Sample returned fields:
- `sourcetype`
- `count`

Interpretation:
- Splunk MCP data retrieval is now proven with non-zero results in this lab.
- We can proceed to question -> tool selection -> summary generation workflows.

## Lab-Observed Minimal Question -> Query -> Summary Flow (2026-03-08)
Using `scripts/minimal_question_to_answer.py`:
1. Accept natural-language question.
2. Map question to a safe bounded Splunk query template.
3. Execute `splunk_run_query` via MCP.
4. Summarize structured results with Ollama HTTP API.

Default question used:
- `What sourcetypes generated the most _internal events in the last 24 hours?`

Observed outcome:
- Splunk retrieval returned non-zero data (`rows_returned=10`, `total_rows=23`).
- Ollama produced a readable SOC-style summary from retrieved rows.

Current limitation:
- Question-to-query routing is template-based and intentionally narrow.
- Next step is controlled expansion of mappings while keeping read-only safeguards.

## Query Authoring Fixes (2026-03-11)
- Linux first-seen privilege-escalation questions now route to a dedicated read-only template instead of the generic failed-sudo template.
- The current template looks for successful or meaningful sudo/su session signals and surfaces `first_seen` / `last_seen` behavior by host, user, tty, and source IP.
- Query policy now blocks transport controls embedded inside SPL text:
  - `earliest_time=...`
  - `latest_time=...`
  - `row_limit=...`
- This prevents malformed queries where tool arguments leak into the SPL body.
- Query routing now uses question-family dimensions in addition to keyword matching:
  - platform
  - activity
  - analytical shape
- This reduces drift where explicitly Windows- or Linux-scoped authentication questions fall back to the generic cross-domain failed-login template.

## Current Question Template Map (Baseline)
- Implementation location: `scripts/minimal_question_to_answer.py`
- Template data module: `scripts/query_templates.py`
- Template configuration now uses explicit metadata per template:
  - `intent`
  - `keywords`
  - `query`
  - bounded controls (`earliest_time`, `latest_time`, `row_limit`)
  - `summary_hint`

- Template A (sourcetypes / internal activity):
  - Trigger keywords: `sourcetype`, `internal`
  - Intent: `internal_sourcetypes`
  - Query: `search index=_internal | stats count by sourcetype | sort - count`
  - Bounds: `earliest_time=-24h`, `latest_time=now`, `row_limit=10`
- Template B (top indexes):
  - Trigger keywords: `index`, `indexes`
  - Intent: `top_indexes`
  - Query: `search index=_internal OR index=_audit | stats count by index | sort - count`
  - Bounds: `earliest_time=-24h`, `latest_time=now`, `row_limit=10`
- Template C (authentication / failed logins):
  - Trigger keywords: `failed login`, `failed authentication`, `authentication failure`
  - Intent: `failed_login_activity`
  - Query: `search index=_audit (action=failure OR info=failed_login OR "failed") | stats count by user src | sort - count`
  - Bounds: `earliest_time=-24h`, `latest_time=now`, `row_limit=10`
- Template D (Linux auth failures):
  - Trigger keywords: `linux failed login`, `linux auth failure`, `linux ssh failure`, `secure log`
  - Intent: `linux_auth_failures`
  - Query: `search sourcetype=linux_secure (failed password OR authentication failure OR invalid user) | stats count by host user src | sort - count`
  - Bounds: `earliest_time=-24h`, `latest_time=now`, `row_limit=10`
- Template E (Linux privilege escalation failures):
  - Trigger keywords: `linux sudo`, `failed sudo`, `sudo failure`, `privilege escalation linux`, `su failed`
  - Intent: `linux_privilege_escalation`
  - Query: `search sourcetype=linux_secure (sudo OR su) (failure OR failed OR incorrect password) | stats count by host user tty src | sort - count`
  - Bounds: `earliest_time=-24h`, `latest_time=now`, `row_limit=10`
- Template F (Apache access top IPs):
  - Trigger keywords: `apache access top ips`, `top client ips`, `top source ips web`, `web access logs`
  - Intent: `apache_access_top_ips`
  - Query: `search sourcetype=access_combined | stats count by clientip status method | sort - count`
  - Bounds: `earliest_time=-24h`, `latest_time=now`, `row_limit=10`
- Template G (Apache 404 spike view):
  - Trigger keywords: `apache 404`, `404 spike`, `not found web`, `access_combined 404`
  - Intent: `apache_404_spike`
  - Query: `search sourcetype=access_combined status=404 | timechart span=1h count by host limit=10`
  - Bounds: `earliest_time=-24h`, `latest_time=now`, `row_limit=10`
- Template H (Apache suspicious user agents):
  - Trigger keywords: `suspicious user agents`, `apache user agent`, `access_combined user agents`, `bot scanning`
  - Intent: `apache_suspicious_user_agents`
  - Query: `search sourcetype=access_combined | stats count by useragent clientip | sort - count | head 20`
  - Bounds: `earliest_time=-24h`, `latest_time=now`, `row_limit=10`

Lab validation:
- Template A returned non-zero results (`rows_returned=10`).
- Template B returned non-zero results (`rows_returned=2`).
- Template C returned non-zero results (`rows_returned=1`).
- Templates D-H currently return zero rows in this lab dataset snapshot, but end-to-end retrieval succeeds (`rows_returned=0`, no execution error), confirming routing and query execution paths are operational for Linux and Apache intents.

## Template Safety Validation
- Script: `scripts/check_query_templates.py`
- Current checks:
  - unique template intents
  - non-empty keywords
  - no keyword collisions across templates
  - bounded `row_limit` safety threshold
  - explicit `earliest_time` and `latest_time` values
- Current result (2026-03-09): `status=PASS` for all 8 templates.

## Template Regression Validation
- Script: `scripts/run_template_regression.py`
- Purpose:
  - run template self-check
  - run one read-only smoke retrieval per intent
- Output artifact:
  - `docs/logs/template_regression_latest.json`
  - `docs/logs/template_regression_history/template_regression_<UTCSTAMP>.json`
- Current result (2026-03-09): `status=PASS`
  - `failed_login_activity`: rows returned `1`
  - `top_indexes`: rows returned `2`
  - `internal_sourcetypes`: rows returned `10`
  - `linux_auth_failures`: rows returned `0`
  - `linux_privilege_escalation`: rows returned `0`
  - `apache_access_top_ips`: rows returned `0`
  - `apache_404_spike`: rows returned `0`
  - `apache_suspicious_user_agents`: rows returned `0`

## Regression Trend Reporting
- Script: `scripts/summarize_regression_trends.py`
- Inputs:
  - `docs/logs/template_regression_history/template_regression_<UTCSTAMP>.json`
- Output:
  - latest snapshot status/time
  - rows by intent
  - delta vs previous snapshot (when available)
- Alert option:
  - `--max-abs-delta <N>` to fail when absolute per-intent delta exceeds threshold
- CSV option:
  - `--csv-out docs/logs/trend_latest.csv`
  - `--csv-meta-out docs/logs/trend_meta_latest.csv`
- Current observed deltas (2026-03-08):
  - `failed_login_activity`: `+0`
  - `top_indexes`: `+0`
  - `internal_sourcetypes`: `+0`

## Unified Validation Wrapper
- Script: `scripts/run_lab_checks.sh`
- Usage:
  - `./scripts/run_lab_checks.sh 0`
  - `./scripts/run_lab_checks.sh 0 1` (enable operator snapshot bundle at end)
  - `./scripts/run_lab_checks.sh 0 1 1` (also refresh `latest_status.json` before snapshot)
  - `./scripts/run_lab_checks.sh 0 0 1 1` (quick mode: skip live checks, use artifacts)
  - `./scripts/run_lab_checks.sh --max-abs-delta 0 --snapshot --refresh-status`
  - `./scripts/run_lab_checks.sh --quick --no-snapshot --refresh-status`
- Behavior:
  - runs template safety check
  - runs regression (writes latest + snapshot reports)
  - runs trend threshold alert mode
  - optional `latest_status.json` refresh
  - optional operator snapshot bundle write
  - optional quick mode (artifact-only status check path)

## Artifact-Only Status View
- Script: `scripts/show_lab_status.py`
- Purpose:
  - read `docs/logs` artifacts only (no live Splunk/Ollama calls)
  - display latest status, per-intent rows, and delta vs previous snapshot
- CSV option:
  - `--csv-out docs/logs/status_latest.csv`
  - `--csv-meta-out docs/logs/status_meta_latest.csv`
- JSON option:
  - `--json-out docs/logs/latest_status.json`

## Operator Snapshot Bundle
- Script: `scripts/write_operator_snapshot.py`
- Purpose:
  - collect latest CSV/JSON status artifacts into one bundle directory
  - keep both rolling latest bundle and timestamped history bundles
- Outputs:
  - `docs/logs/operator_snapshot/latest/`
  - `docs/logs/operator_snapshot/history/snapshot_<UTCSTAMP>/`
  - `manifest.json` in each bundle

## Integration Plan
1. Send a valid JSON-RPC initialize/list-tools style read-only request.
2. Enumerate available MCP tools.
3. Execute first safe read-only tool call.
4. Capture request/response examples in docs/logs for reproducibility.

## Safety and Scope
- Lab is educational and isolated.
- Credentials/tokens used for examples are temporary and lab-only.
- All examples must be clearly labeled as not production-safe.
