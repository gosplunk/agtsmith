# agent_smith Splunk App

Native Splunk shell for A.G.E.N.T. Smith. The investigation engine runs as a **sidecar** on `http://127.0.0.1:8787`; this app provides Splunk nav, RBAC, and an embedded investigate view.

## Install (local)

```bash
make splunk-app-package
make splunk-app-install-local
sudo -u splunk /opt/splunk/bin/splunk restart
```

Dev symlink:

```bash
make splunk-app-symlink-dev
sudo -u splunk /opt/splunk/bin/splunk restart
```

## Prerequisites

- Splunk Enterprise with `Splunk_MCP_Server` app
- agtsmith sidecar: `make docker-deploy-up`
- MCP bearer token in sidecar `config/ui.env` (not in this app's `default/`)

## Capabilities

- `agent_smith_use` — open investigate view
- `agent_smith_admin` — future setup/config REST endpoints

See [docs/runbooks/splunk_app_install.md](../docs/runbooks/splunk_app_install.md).
