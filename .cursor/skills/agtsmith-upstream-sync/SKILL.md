---
name: agtsmith-upstream-sync
description: >-
  Sync the fork with upstream gosplunk/agtsmith main while keeping Splunk app
  changes isolated in splunk_app/. Use when rebasing, merging upstream fixes,
  or preparing upstream PRs from engine changes.
---

# agtsmith Upstream Sync

## Remotes

```bash
git remote add upstream https://github.com/gosplunk/agtsmith.git  # once
git fetch upstream
git rebase upstream/main
```

## Merge zones

| Zone | Upstream PR? |
|------|----------------|
| `scripts/`, `core/` engine fixes | Yes |
| `splunk_app/` | No — fork only |
| `.cursor/` | No — fork tooling |
| `docs/project/splunk_app_roadmap.md` | No |

## Conflict hotspots

- `Makefile` — keep fork targets at end of file
- `scripts/web_ui_server.py` — large; prefer extracting to `services/ui/` before big upstream merges
- `docs/` — merge upstream docs; keep fork runbooks separate

See [reference/merge-zones.md](reference/merge-zones.md).
