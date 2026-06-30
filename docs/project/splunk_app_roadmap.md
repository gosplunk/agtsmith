# Splunk App Roadmap (Fork)

Upstream base: **v1.4.1** (`gosplunk/agtsmith`)

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
- [ ] Phase 1 — Validate upstream docker-deploy against local MCP
- [ ] Phase 2 — Extract `core/` and `services/ui/`
- [ ] Phase 3 — Splunk app MVP (nav + iframe proxy)
- [ ] Phase 4 — KV Store case backend, audit index
- [ ] Phase 5 — Release package + screenshots

## Fork-only vs upstream

| Path | Upstream PR? |
|------|----------------|
| `splunk_app/` | No |
| `.cursor/` | No |
| `core/` engine fixes | Yes |
| `scripts/` policy/SPL fixes | Yes |
