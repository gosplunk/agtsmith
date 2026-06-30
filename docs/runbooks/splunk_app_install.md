# Splunk App Install

Install `agent_smith` to local Splunk Enterprise.

## Package

```bash
make splunk-app-package
```

Produces `dist/agent_smith-<version>.tgz`.

## Install

```bash
make splunk-app-install-local
# or manually:
sudo -u splunk /opt/splunk/bin/splunk install app dist/agent_smith-*.tgz -update 1
sudo -u splunk /opt/splunk/bin/splunk restart
```

## Verify

1. Open http://127.0.0.1:8000
2. Apps → A.G.E.N.T. Smith → Investigate
3. Confirm iframe loads agtsmith sidecar at `127.0.0.1:8787`

## Prerequisites

- `Splunk_MCP_Server` app enabled
- agtsmith sidecar running (`make docker-deploy-up`)
- MCP bearer token configured in sidecar `config/ui.env` (not in Splunk app `default/`)

## Troubleshooting

| Issue | Check |
|-------|-------|
| Blank iframe | Sidecar up? `curl http://127.0.0.1:8787/login` |
| 404 in Splunk nav | `splunk btool check` and app enable state |
| MCP failures | Token in ui.env; `mcp` role on token user |
