# Screenshot Capture

Automated UI captures for README and release notes.

## Install capture deps

```bash
pip install -r .cursor/skills/agtsmith-screenshots/scripts/requirements.txt
playwright install chromium
```

## Capture

```bash
# Optional for Splunk-embedded targets
export SPLUNK_USER=dev SPLUNK_PASS='...'

# Optional for /configure lane targets (agtsmith login)
export AGTSMITH_UI_USER=dev AGTSMITH_UI_PASS='...'

make screenshots SCREENSHOT_VERSION=v1.5.1
```

## Configure lane captures

```bash
export AGTSMITH_UI_USER=dev AGTSMITH_UI_PASS='...'

make configure-screenshots \
  CONFIGURE_UI_TAG=configure-ui-p2 \
  CONFIGURE_SCREENSHOT_VERSION=v1.5.2-config-p2

make configure-screenshots-diff \
  CONFIGURE_SCREENSHOT_VERSION=v1.5.2-config-p2 \
  CONFIGURE_UI_BASELINE=v1.5.2-config-p1
```

Configure UI version tags are documented in [configure_ui_versions.md](configure_ui_versions.md).

Output: `docs/images/screenshots/v1.5.1/`

Expected README assets:
- `agtsmith-v1.5.1-login.png`
- `agtsmith-v1.5.1-investigation.png`
- `agtsmith-v1.5.1-architecture.png`
- `agtsmith-v1.5.1-data-domains.png`
- `agtsmith-v1.5.1-learning.png`

## Manifest

Edit `.cursor/skills/agtsmith-screenshots/manifest.yaml` to add views.

## Visual diff

```bash
make screenshots-diff SCREENSHOT_VERSION=v1.5.1
```

Diff images: `output/playwright/diff/v1.5.1/`

## Manual fallback

Use Playwright trace or cursor-ide-browser MCP when selectors break after UI refactors.
