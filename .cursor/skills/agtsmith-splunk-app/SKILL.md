---
name: agtsmith-splunk-app
description: >-
  Scaffold, configure, package, and install the agent_smith Splunk app under
  splunk_app/. Use when editing app.conf, web.conf, restmap.conf, Splunk nav,
  authorize.conf, splunk install, or /opt/splunk/etc/apps/agent_smith.
---

# agtsmith Splunk App

## Layout

```
splunk_app/agent_smith/
├── default/app.conf, web.conf, restmap.conf, authorize.conf
├── default/data/ui/nav/default.xml
├── appserver/templates/, appserver/static/
├── bin/                     # REST bridge scripts
└── metadata/default.meta
```

## Local install loop

```bash
make splunk-app-package
make splunk-app-install-local
sudo -u splunk /opt/splunk/bin/splunk restart
```

Dev symlink (faster iteration):

```bash
sudo ln -sfn "$(pwd)/splunk_app/agent_smith" /opt/splunk/etc/apps/agent_smith
sudo -u splunk /opt/splunk/bin/splunk restart
```

## web.conf proxy pattern

Proxy Splunk nav view to agtsmith sidecar on `127.0.0.1:8787`. Never embed bearer tokens in `default/` — use `passwords.conf` via setup.

## Capabilities

- `agent_smith_use` — run investigations
- `agent_smith_admin` — configuration and setup

See [reference/splunk-conf-patterns.md](reference/splunk-conf-patterns.md).
