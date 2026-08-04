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

**Note:** MCP tokens must be minted for Splunk user `mcp` (not `dev`). `make lab-data-refresh-mcp-token` **reuses** the existing token when MCP auth still works; it only rotates when the token is missing or rejected. Pass `FORCE_ROTATE=1` to deliberately invalidate the old token. `config/ui.env` is always preferred over a stale `SPLUNK_LAB_BEARER_TOKEN` exported in your shell.

## Layout profiles

| Layout | Use when |
|--------|----------|
| `existing_lab` | Current machine: `index=linux` + `index=botsv3` |
| `multi_index_ideal` | Clean separation: `soc_linux`, `soc_windows` |
| `minimal_ci` | Single `agtsmith_test` index (requires provision) |
| `cloud_only` | AWS CloudTrail and Microsoft 365 activity |
| `expanded_lab` | All on-premises, multi-index, test, and cloud mappings |

Config: [config/lab_data_layout.yaml](../../config/lab_data_layout.yaml)

Auto-detect: if profile has `soc_linux` + `soc_windows` → `multi_index_ideal`; elif `linux` + `botsv3` → `existing_lab`; else → `minimal_ci`.

## Commands

```bash
# New multi-index environment
make lab-data-provision LAB_DATA_LAYOUT=multi_index_ideal
make lab-data-generate LAB_DATA_LAYOUT=multi_index_ideal LAB_DATA_HOURS=6 LAB_DATA_COUNT=50
make lab-data-verify
make env-profile-refresh
make live-domain-benchmark

# Existing lab (linux + botsv3)
make lab-data-extractions
make lab-data-generate LAB_DATA_LAYOUT=existing_lab
make lab-data-verify
make live-domain-benchmark

# Full bootstrap chain
make lab-data-bootstrap LAB_DATA_LAYOUT=existing_lab

# Teardown tagged events (last 7 days in layout indexes)
make lab-data-cleanup
```

## Visual data studio

Launch the local browser UI:

```bash
make lab-data-ui
```

The studio opens at `http://127.0.0.1:8790`. It provides:

- A layout selector with every mapped index and sourcetype.
- Searchable event-family cards and a rendered sample for each generatable sourcetype.
- Bounded event-count and timestamp-spread controls.
- Multi-select generation through the existing HEC client.
- A completion result showing accepted and sent event counts.

Use a different port or suppress automatic browser opening when needed:

```bash
make lab-data-ui LAB_DATA_UI_PORT=8890
make lab-data-ui LAB_DATA_UI_NO_BROWSER=1
```

The server binds to loopback only, validates Host/Origin and CSRF tokens, and never returns
the HEC token to the browser. Generation inputs are restricted to catalog event-set IDs and
bounded to 10,000 events per request.

## Event fidelity and field provenance

The current catalog uses `lab_data_version=fidelity_v2`. Its synthetic values are fictional,
but event structure follows the native source:

- Windows Security and Sysmon events use full Windows Event XML with `System`, `EventData`,
  provider GUIDs, event-specific task/version metadata, record IDs, process/logon GUIDs, and
  native field names.
- Linux authentication uses RFC 3164 envelopes; Linux system events use RFC 5424.
- Apache access and error events use their native timestamp and line formats.
- CloudTrail and Microsoft 365 events use coherent service/operation-specific JSON records.
- `stream:dns` uses arrays and DNS transaction fields compatible with Splunk Stream searches.

HEC only adds `lab_data_source` and `lab_data_version` as provenance metadata for raw text/XML.
It does not duplicate semantic fields such as `EventID`, `TargetUserName`, or `DestinationIp`.
This prevents malformed `_raw` data from appearing valid because of HEC-supplied fields.

Install the local search-time extraction pack before generation or verification:

```bash
make lab-data-extractions
```

This configures dynamic Windows `<Data Name="...">` extraction plus JSON extraction for
CloudTrail, Microsoft 365, and Stream DNS through Splunk's REST API. `lab-data-verify` requires
event-specific fields, so a count-only pass cannot hide broken raw extraction.

Use HEC for production-shaped raw/XML generation. The receivers/simple fallback intentionally
rejects raw events with provenance fields because appending those fields would corrupt the
source-native event format.

## Event catalog

[config/lab_data_events.yaml](../../config/lab_data_events.yaml) defines:

- `linux_failed_ssh` — Failed password / Invalid user (auth benchmark)
- `linux_sudo` — sudo privilege escalation
- `linux_su_success` / `linux_su_failure` — realistic PAM and `su` session/authentication records
- `linux_non_sudoer` — native sudoers-denial evidence for a synthetic test account
- `apache_access` — web top IPs
- `apache_404` — 404 spike
- `win_4625` — Windows failed logon EventCode 4625

All events include `lab_data_source=agtsmith_generator` and
`lab_data_version=fidelity_v2` for cleanup and isolated validation.

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
make lab-data-provision LAB_DATA_LAYOUT=multi_index_ideal
make lab-data-bootstrap LAB_DATA_LAYOUT=multi_index_ideal
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
