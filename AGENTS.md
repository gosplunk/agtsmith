# A.G.E.N.T. Smith — Agent Orchestration

This fork extends [gosplunk/agtsmith](https://github.com/gosplunk/agtsmith) with a native Splunk app wrapper. Use the specialist roles below when work spans multiple areas.

## Specialist Roles

| Role | Scope | Skills / commands |
|------|-------|-------------------|
| **SplunkAppEngineer** | `splunk_app/**`, Splunk conf, install/reload | `agtsmith-splunk-app` |
| **CoreEngineer** | `core/**`, `scripts/langgraph_*`, query policy | `agtsmith-spl-quality`, `make check` |
| **IntegrationQA** | End-to-end MCP, benchmarks, docker deploy | `agtsmith-local-lab`, `agtsmith-benchmark` |
| **VisualDocs** | README screenshots, release visuals | `agtsmith-screenshots`, `make screenshots` |
| **SecurityGuard** | Any config/secrets change | Block commits of `config/ui.env`, tokens |

## Local Lab Defaults

| Service | URL |
|---------|-----|
| Splunk Web | `http://127.0.0.1:8000` |
| Splunk API / MCP | `https://127.0.0.1:8089` / `https://127.0.0.1:8089/services/mcp` |
| agtsmith sidecar | `http://127.0.0.1:8787` |
| Splunk home | `/opt/splunk` |
| App install path | `/opt/splunk/etc/apps/agent_smith` |

Credentials live in gitignored `config/ui.env` or Splunk `passwords.conf` only.

## Parallel Workflow (after UI changes)

1. **IntegrationQA** — `make check` and one live investigation
2. **VisualDocs** — `make screenshots SCREENSHOT_VERSION=<version>`
3. **SplunkAppEngineer** — `make splunk-app-install-local` and verify Splunk nav

## Fork Boundaries

- **Upstreamable**: SPL quality, LangGraph, query policy, benchmarks, core engine fixes
- **Fork-only**: `splunk_app/`, Splunk auth bridge, KV Store adapter, local lab runbooks

## Project Skills

See [.cursor/skills/README.md](.cursor/skills/README.md).
