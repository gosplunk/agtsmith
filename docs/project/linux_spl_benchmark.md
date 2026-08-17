# Linux Index SPL Benchmark

Environment-portable benchmark for Linux dataset questions scoped to `index=linux` (auth, sudo, session, audit, inventory). Phase 1 uses data already present in the local lab Splunk instance.

## Purpose

Validate that agtsmith produces near-perfect SPL for Linux-index questions:

- auth failures and successful logins
- sudo / privilege escalation activity
- session and auditd telemetry
- sourcetype and host inventory on `index=linux`

The harness compares **canonical SPL** (hand-validated oracle) against the **template/deterministic path** on every run, and optionally the **full LLM-assisted pipeline** on demand.

## Oracle corpus

Committed cases live in [`benchmarks/linux_spl_oracles.json`](../../benchmarks/linux_spl_oracles.json).

Seed new cases offline with catalog + briefs:

```bash
make linux-spl-discover
PYTHONPATH=.:scripts .venv/bin/python scripts/build_linux_spl_oracles.py --merge-existing
```

## Run instructions

```bash
make linux-spl-discover
make check-linux-spl-oracles
make linux-spl-accuracy-offline
make linux-spl-accuracy
make linux-spl-accuracy-multimodel   # on demand (~30 min)
make linux-sourcetype-cards
```

Artifacts:

- Catalog: `artifacts/environment/linux_index_catalog.json`
- Benchmark report: `artifacts/spl_autonomy/linux_benchmark/latest.json`
- History: `artifacts/spl_autonomy/linux_benchmark/history/run_*.json`
- Improvement log: `artifacts/spl_autonomy/linux_benchmark/improvement_log.json`

## CI integration

`make check` runs offline oracle validation and template-path structure checks for Linux cases (same gate pattern as internal SPL).
