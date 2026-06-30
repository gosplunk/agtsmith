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

make screenshots SCREENSHOT_VERSION=0.2.0-splunk
```

Output: `docs/images/screenshots/v0.2.0-splunk/`

## Manifest

Edit `.cursor/skills/agtsmith-screenshots/manifest.yaml` to add views.

## Visual diff

```bash
make screenshots-diff SCREENSHOT_VERSION=0.2.0-splunk
```

Diff images: `output/playwright/diff/v0.2.0-splunk/`

## Manual fallback

Use Playwright trace or cursor-ide-browser MCP when selectors break after UI refactors.
