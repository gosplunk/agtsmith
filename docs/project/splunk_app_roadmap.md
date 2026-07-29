# Splunk App Roadmap (Fork)

Upstream base: **v1.5.1** (`gosplunk/agtsmith`)

## Goal

Wrap agtsmith as a **native Splunk app** (`agent_smith`) while keeping the LangGraph engine as a colocated sidecar on `127.0.0.1:8787`.

## Local environment

| Item | Value |
|------|-------|
| Splunk Web | `http://127.0.0.1:8000` |
| Splunk API / MCP | `https://127.0.0.1:8089` |
| Splunk home | `/opt/splunk` |
| App install | `/opt/splunk/etc/apps/agent_smith` |
| Sandbox user | `dev` (temporary — delete when done) |

## Milestones

- [x] Phase 0 — Cursor skills, rules, hooks, screenshot tooling
- [x] Phase 2 scaffold — `core/case_store/`, `services/ui/server.py`
- [x] Phase 3 MVP — `splunk_app/agent_smith` nav + iframe investigate view
- [x] Phase 4 scaffold — KV Store backend (`AGTSMITH_CASE_BACKEND=kvstore`), `collections.conf`
- [x] Makefile — package, screenshots, preflight, `docker-deploy-manual`, `setup-local-ui-env`
- [x] `make check` passes (artifact quick mode; live MCP regression still needs token)
- [ ] Phase 1 — Live validation: `setup-local-ui-env`, `docker-deploy-manual`, first investigation
- [ ] Phase 1 — Ollama running with required models
- [ ] Splunk app installed to `/opt/splunk/etc/apps/agent_smith` (requires sudo)
- [ ] Screenshots captured after sidecar + Splunk app live

## Fork-only vs upstream

| Path | Upstream PR? |
|------|----------------|
| `splunk_app/` | No |
| `.cursor/` | No |
| `core/` engine fixes | Yes |
| `scripts/` policy/SPL fixes | Yes |
