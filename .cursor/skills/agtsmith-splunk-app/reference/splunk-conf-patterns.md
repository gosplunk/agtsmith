# Splunk Conf Patterns

## app.conf (minimal)

```ini
[install]
state = enabled

[launcher]
author = gosplunk
description = A.G.E.N.T. Smith — Splunk analyst copilot (sidecar + native shell)
version = 0.2.0-splunk

[ui]
is_visible = 1
label = A.G.E.N.T. Smith

[package]
id = agent_smith
```

## authorize.conf

```ini
[capability::agent_smith_use]
displayName = Use A.G.E.N.T. Smith investigations

[capability::agent_smith_admin]
displayName = Administer A.G.E.N.T. Smith configuration

[role_admin]
agent_smith_use = enabled
agent_smith_admin = enabled
```

## Nav (default.xml)

Single collection pointing at the investigate dashboard/view.
