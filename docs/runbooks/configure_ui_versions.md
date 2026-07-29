# Configure UI Version Tags

Named tags link Configuration page UI iterations to screenshots, tests, and artifact manifests.

## Tag convention

Format: `configure-ui-p{N}` where N is the phase gate (0–3).

| Tag | Phase | Description |
|-----|-------|-------------|
| `configure-ui-p0` | 0 | Screenshot auth, test scaffold, tagging infrastructure |
| `configure-ui-p1` | 1 | Sticky footer, dropdown pickers, dynamic Next Action |
| `configure-ui-p2` | 2 | Four Setup Lanes layout with hash routing |
| `configure-ui-p3` | 3 | Core-only toggle, pull-missing UX, polish |

During active development use `configure-ui-dev` (default env override).

## Surfaces

- **UI badge** — `#cfg-ui-tag` on `/configure` hero
- **API** — `configure_ui_tag` in `GET /api/config/runtime`
- **Screenshots** — `docs/images/screenshots/{SCREENSHOT_VERSION}/agtsmith-*-configure-*.png`
- **Manifest** — `artifacts/configure_ui/{tag}/manifest.json`

## Commands

```bash
# Show current tag metadata
make configure-tag-show CONFIGURE_UI_TAG=configure-ui-p1

# Record gate manifest after tests + screenshots
make configure-tag-record CONFIGURE_UI_TAG=configure-ui-p1 \
  SCREENSHOT_VERSION=v1.5.2-config-p1 \
  CONFIGURE_UI_TESTS=configure-check

# Optional git pointer (manual, not pushed by Makefile)
git tag -a configure-ui-p1 -m "Configure UI Phase 1 gate"
```

## Gate history

| Tag | App version | Screenshot dir | Gate date | Notes |
|-----|-------------|----------------|-----------|-------|
| `configure-ui-p0` | 1.5.1 | — | 2026-07-27 | Tooling scaffold (tag script, Makefile, tests) |
| `configure-ui-p1` | 1.5.1 | `v1.5.2-config-p1` | 2026-07-27 | Sticky footer, dropdowns, dynamic Next Action |
| `configure-ui-p2` | 1.5.1 | `v1.5.2-config-p2` | 2026-07-27 | Four Setup Lanes with hash routing |
| `configure-ui-p3` | 1.5.1 | `v1.5.2-config-p3` | 2026-07-27 | Core-only toggle, pull-missing UX, polish |

Update this table when each phase gate passes.
