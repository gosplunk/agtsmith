# Security Policy

## Scope
A.G.E.N.T. Smith is a homelab and research project centered on guarded, read-only Splunk investigation workflows. It is not marketed as a production security control plane.

## Supported Use
This repository is intended for:
- local lab deployments
- controlled testing
- development and benchmarking
- educational and research use

It is not intended to imply:
- enterprise support guarantees
- production-grade secret management
- production-ready HA / SLA posture
- autonomous response or recovery actions

## Reporting A Vulnerability
For now, do not open a public issue with exploit details.

Instead:
- contact the maintainer privately through the channel listed in the repository profile, or
- if no private channel is available yet, open a minimal issue that only states a security concern exists and requests a private contact path

When reporting, include:
- affected file or component
- reproduction steps
- expected impact
- whether credentials, tokens, or local network exposure are involved

## Sensitive Data Handling
Do not commit:
- `config/ui.env`
- real bearer tokens
- real passwords
- personal environment profiles
- generated runtime artifacts that contain live evidence or infrastructure details

Use:
- `config/ui.env.example`
- sanitized screenshots
- sanitized benchmark material

## Current Security Boundary
The current project emphasizes:
- read-only Splunk access
- deterministic validation before query execution
- fail-closed behavior on unsafe requests
- bounded continuation and analyst approval for deeper pivots

Those controls reduce risk, but they do not make the system a substitute for full production security engineering.
