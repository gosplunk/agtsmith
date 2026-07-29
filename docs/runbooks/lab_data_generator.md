# Lab Data Generator Runbook

Inject time-fresh, benchmark-aligned synthetic events into Splunk for row-level SPL validation. Layout profiles map logical domains to physical indexes per environment.

## Prerequisites

### Splunk HEC (one-time)

1. Splunk Web → **Settings → Data Inputs → HTTP Event Collector**
2. Enable HEC globally if disabled
3. Create a token:
   - Name: `agtsmith-lab-generator`
   - Index: allow `linux`, `botsv3`, and/or layout-specific indexes (`soc_linux`, `soc_windows`, `agtsmith_test`)
   - Source type: leave as token default (overridden per event)
4. Copy token into gitignored `config/ui.env`:

```bash
SPLUNK_HEC_URL=https://127.0.0.1:8088/services/collector/event
SPLUNK_HEC_TOKEN=replace-with-hec-token
SPLUNK_HEC_INSECURE=1   # self-signed lab cert
LAB_DATA_LAYOUT=existing_lab
LAB_DATA_ENABLED=0      # set 1 to enforce verify gate in spl-autonomy-check
```

See [config/ui.env.example](../../config/ui.env.example) for placeholders.

### MCP token (verify step)

Existing `SPLUNK_LAB_BEARER_TOKEN` in `config/ui.env` is used by `lab_data_verify.py` to confirm events via MCP search.

**Note:** MCP tokens must be minted for Splunk user `mcp` (not `dev`). Use `MCP_TOKEN_USER=mcp` when running `mcp-token.sh`. A stale `SPLUNK_LAB_BEARER_TOKEN` in your shell environment overrides `config/ui.env` — run verify with `env -u SPLUNK_LAB_BEARER_TOKEN make lab-data-verify` if auth fails.

## Layout profiles

| Layout | Use when |
|--------|----------|
| `existing_lab` | Current machine: `index=linux` + `index=botsv3` |
| `multi_index_ideal` | Clean separation: `soc_linux`, `soc_windows` |
| `minimal_ci` | Single `agtsmith_test` index (requires provision) |

Config: [config/lab_data_layout.yaml](../../config/lab_data_layout.yaml)

Auto-detect: if profile has `soc_linux` + `soc_windows` → `multi_index_ideal`; elif `linux` + `botsv3` → `existing_lab`; else → `minimal_ci`.

## Commands

```bash
# New multi-index environment
make lab-data-provision LAYOUT=multi_index_ideal
make lab-data-generate LAYOUT=multi_index_ideal HOURS=6 COUNT=50
make lab-data-verify
make env-profile-refresh
make live-domain-benchmark

# Existing lab (linux + botsv3)
make lab-data-generate LAYOUT=existing_lab
make lab-data-verify
make live-domain-benchmark

# Full bootstrap chain
make lab-data-bootstrap LAYOUT=existing_lab

# Teardown tagged events (last 7 days in layout indexes)
make lab-data-cleanup
```

## Event catalog

[config/lab_data_events.yaml](../../config/lab_data_events.yaml) defines:

- `linux_failed_ssh` — Failed password / Invalid user (auth benchmark)
- `linux_sudo` — sudo privilege escalation
- `apache_access` — web top IPs
- `apache_404` — 404 spike
- `win_4625` — Windows failed logon EventCode 4625

All events include `lab_data_source=agtsmith_generator` for cleanup.

## Verify manifest

`make lab-data-verify` writes:

`artifacts/spl_autonomy/lab_data/verify_latest.json`

Used by `run_live_domain_benchmark.py` when `expected_min_rows_from_manifest: true` on strict cases.

## Integration with autonomy loop

When `LAB_DATA_ENABLED=1`:

- `make spl-autonomy-check` runs `lab-data-verify` before live-domain benchmark
- `make spl-autonomy-nightly` runs `lab-data-generate` before full loop

## New environment bootstrap

```bash
cp config/ui.env.example config/ui.env   # fill MCP + HEC tokens
make lab-data-provision LAYOUT=multi_index_ideal
make lab-data-bootstrap LAYOUT=multi_index_ideal
make spl-autonomy-check
```

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| HEC 403 | Token missing index permission; add target indexes to HEC token |
| `sudo -u splunk` permission errors | This lab runs `splunkd` as **root** — use `sudo /opt/splunk/bin/splunk edit user dev ...` or REST via `SPLUNK_ADMIN_*` |
| `make lab-data-install` not found | Run from repo: `cd ~/ai_projects/agtsmith && make lab-data-install` |
| Verify 0 rows | Wait 30s for indexing; widen `--hours`; run `make lab-data-generate` again |
| Wrong index in SPL | Run `make env-profile-refresh` after generate |
| Cleanup incomplete | Events outside `-7d` window; run cleanup with `--hours 168` |
