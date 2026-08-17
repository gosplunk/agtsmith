# v1.5.3 Patch Notes

`v1.5.3` is a documentation delivery fix. Engine behavior is unchanged from `v1.5.2`.

## Why This Release Exists

GitHub web preview for individual files in `gosplunk/agtsmith` (`/blob/main/...` URLs) was returning server errors for operators trying to read the Initial Setup Guide and other docs in the browser.

`v1.5.3` adds a **published documentation site** so setup and operator runbooks are always readable without relying on GitHub blob preview.

## What Changed

### Published docs site (GitHub Pages)

- MkDocs site built from `docs/` on every push to `main`
- Workflow: [`.github/workflows/publish-docs.yml`](../../.github/workflows/publish-docs.yml)
- Public URL: **https://gosplunk.github.io/agtsmith/**
- Initial Setup Guide: **https://gosplunk.github.io/agtsmith/runbooks/initial_setup/**

### Repository shortcuts

- Root [`SETUP.md`](../../SETUP.md) points to the canonical setup runbook for clone-only workflows
- [`docs/README.md`](../README.md) index updated with Pages-first links
- Removed dev-only `docs/images/screenshots/verify-scheduler/` artifacts from the repo

### Link hygiene

- Relative markdown links validated across the repo
- README and docs index prefer the published site over GitHub blob links

## Upgrade Notes

1. Pull `main` at tag **`v1.5.3`**
2. Bookmark **https://gosplunk.github.io/agtsmith/runbooks/initial_setup/**
3. No sidecar rebuild required unless you also want `v1.5.2` engine changes you have not deployed yet

## Related

- [Initial Setup Guide](../runbooks/initial_setup.md)
- [v1.5.2 Release Highlights](v1_5_2_delta.md)
- [CHANGELOG.md](../../CHANGELOG.md)
