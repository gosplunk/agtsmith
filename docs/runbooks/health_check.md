# Health Check

Use this after A.G.E.N.T. Smith is already installed and configured. This is not the first-time setup path. For a new deployment, use `Initial Setup Guide`.

## Goal
Confirm that the current runtime is healthy enough for an operator to use.

## Fast Check
1. Start or restart the runtime.

Docker deployment:
```bash
make docker-deploy-up
```

2. Open `/login` and sign in.
3. Open `/configure` from `Control Center`.
4. Run `Validate Current Config`.
5. Confirm:
   - Ollama is healthy
   - Splunk Base is healthy
   - Splunk MCP is healthy
   - at least one expected UI user is present
6. Run one known-good investigation in `/investigation`.
7. Sign in as `ops` and confirm `Configuration` actions work.
8. Sign in as `admin`, open `Users`, and confirm recent query audit entries are being recorded.

## Optional CLI Checks
```bash
python scripts/smoke_lab_connectivity.py
python scripts/test_splunk_mcp_auth.py
python scripts/discover_splunk_mcp_tools.py
```

## Recommended First Investigation
```text
Investigate repeated failed SSH login activity in the last 24 hours on my linux systems. Identify the top source IPs, usernames targeted, ports used, and which host is being targeted most.
```

## Expected Outcome
- the UI serves correctly
- model roles are assigned
- Splunk queries run read-only
- evidence returns in the Investigation UI
- Data Domains and personalization are already present from setup
- `ops` can manage runtime controls without needing full admin authority
- query audit entries are recorded under `artifacts/audit/query_runs.jsonl`

## Optional Optimization Check
If you are changing LangGraph stage layout or reviewer behavior, run the offline eval loop before changing the live default path:

```bash
make langgraph-gold-build
make langgraph-eval-prompts
make langgraph-topology-eval
make langgraph-topology-optimize
```
