---
name: agtsmith-spl-quality
description: >-
  Improve SPL generation, repair, playbooks, and environment profile grounding
  in agtsmith. Use when editing query_policy.py, spl_query_repair.py,
  investigation_playbooks.py, environment_profile.py, or query_templates.py.
---

# agtsmith SPL Quality

## Principles (from upstream CONTRIBUTING)

- Splunk access stays **read-only**
- Prefer **deterministic checks** over trusting model output
- Environment profile must ground queries to discovered indexes/sourcetypes

## Key files

| File | Role |
|------|------|
| `scripts/query_policy.py` | Blocks unsafe SPL before MCP |
| `scripts/query_templates.py` | Deterministic template map |
| `scripts/spl_query_repair.py` | Repairs failed SPL |
| `scripts/environment_profile.py` | Data Domains / field inventory |
| `scripts/investigation_playbooks.py` | Intent playbooks |

## Validation

```bash
make check
make env-profile-refresh    # after Splunk env changes
make spl-hardening-benchmark
```

After extraction, these move under `core/` — update imports incrementally.
