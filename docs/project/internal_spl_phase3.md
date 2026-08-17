# Internal SPL Quality Program — Phase 3 (Deferred)

Phase 3 work starts **only after Phase 2 SLOs are met**:

- 100% template-path pass rate on `benchmarks/internal_spl_oracles.json`
- ≥95% full LLM path pass rate on the same corpus

Until then, do not expand ingest, pretrained sourcetype coverage, or BOTSv3 inventory into the internal benchmark gate.

## Track 3A — More internal depth

**Data source:** existing `_internal`, `_audit`, `_introspection` logs on the deployment.

Add oracle cases for:

- search job failures and scheduler job details
- pipeline / queue metrics (`metrics`, `metric` sourcetypes)
- `_introspection` resource and performance signals

Reuse the same harness: update `internal_spl_oracles.json`, run `make internal-spl-accuracy`, classify failures with the existing taxonomy.

## Track 3B — Lab data generator

**Data source:** [`config/lab_data_events.yaml`](../../config/lab_data_events.yaml) via [`scripts/lab_data_generate.py`](../../scripts/lab_data_generate.py).

Use when internal indexes have zero or sparse signal for a Tier 1 sourcetype cluster. Generate minimal HEC payloads only for gaps identified by `discover_internal_index_catalog.py` (`data_present: false`).

Do **not** enable lab ingest in Phase 1 CI gates.

## Track 3C — Splunk pretrained sourcetype list

**Data source:** Splunk 9.4+ pretrained sourcetype documentation.

Expand beyond internal indexes to Tier 2 operational sourcetypes (auth, web, cloud, network)—roughly 20–40 sourcetypes. Each cluster gets briefs in a new YAML file and optional sourcetype cards; oracles follow the same JSON schema as internal cases but with `index_scope` resolved from the environment profile.

## Track 3D — BOTSv3 inventory at scale

**Data source:** [`scripts/botsv3_catalog.py`](../../scripts/botsv3_catalog.py) and existing BOTSv3 hardening cases.

Security and cross-domain inventory SPL at scale. Reuse `run_*_spl_accuracy.py` + oracle JSON + failure taxonomy—no new architecture.

## Entry criteria checklist

Before opening any Phase 3 track:

- [ ] `make check-internal-spl-oracles` green
- [ ] `make internal-spl-accuracy` template path 100%
- [ ] `make internal-spl-accuracy-multimodel` ≥95% on internal corpus
- [ ] Failure taxonomy trend stable for two consecutive nightly runs
