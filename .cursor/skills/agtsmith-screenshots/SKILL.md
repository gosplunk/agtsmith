---
name: agtsmith-screenshots
description: >-
  Capture versioned UI screenshots for README and release docs using Playwright
  and a declarative manifest. Use when updating docs images, release notes, or
  after Investigation UI or Splunk app view changes.
---

# agtsmith Screenshots

## Quick start

```bash
export SPLUNK_USER=dev SPLUNK_PASS='...'   # optional, for Splunk-embedded targets
pip install -r .cursor/skills/agtsmith-screenshots/scripts/requirements.txt
playwright install chromium
make screenshots SCREENSHOT_VERSION=v1.5.1
```

## Manifest

Edit [manifest.yaml](manifest.yaml) to add targets. Credentials only via environment variables.

## Compare to baseline

```bash
make screenshots-diff SCREENSHOT_VERSION=v1.5.1
```

## Output

`docs/images/screenshots/v<version>/`

See [docs/runbooks/screenshot_capture.md](../../docs/runbooks/screenshot_capture.md).
