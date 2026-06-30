# agtsmith Core (extraction in progress)

LangGraph engine, query policy, SPL repair, environment profile, and case store adapters.

## Current state

Engine code still lives in `scripts/`. Extract incrementally:

1. `case_store` adapter interface (`postgres` | `kvstore`)
2. `runtime_config` (from `scripts/runtime_config.py`)
3. LangGraph pipeline modules
4. API route handlers → `services/ui/`

Each extraction step must keep `make check` green.
