# SPL LoRA export recipe (stub)

This document describes how to export approved SPL writer examples from the autonomy loop into JSONL for fine-tuning.

## Export source

- Approved learning records from `artifacts/learning/`
- Gold templates from `benchmarks/spl_cases.json`
- Sourcetype cards from `artifacts/environment/sourcetype_cards.json`

## JSONL record shape

```json
{
  "instruction": "Write read-only SPL for: <question>",
  "input": {
    "intent": "failed_logins",
    "field_bind_output": {},
    "sourcetype_cards": []
  },
  "output": {
    "write_plan": {},
    "query": "search ..."
  }
}
```

## Training notes

- Train with `AGTSMITH_WRITER_MODE=constrained` targets (WritePlan slots) when possible.
- Keep `AGTSMITH_TEMPLATE_OVERRIDE=fallback` during eval to measure real writer quality.
- Plateau detection in `spl_autonomy_loop.py --long-horizon` appends stub rows to `artifacts/learning/spl_lora_export.jsonl`.

## Next steps

1. Run `make spl-autonomy-loop LONG_HORIZON=1`
2. Review `artifacts/spl_autonomy/long_horizon_final_report.json`
3. Filter export JSONL to cases with validation_ok and writer_avg gains
