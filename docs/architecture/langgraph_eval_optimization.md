# LangGraph Eval And Optimization Loop

## Purpose

This subsystem exists to compare LangGraph workflow layouts empirically instead of by opinion.

The live runtime stays the same. The eval harness runs beside it and answers:
- which topology produces the best SPL and evidence behavior
- which stages are worth the latency cost
- whether reviewer, peer review, repair, and summary stages are helping or hurting

## Workflow

1. Build a gold corpus from seed questions using the current live workflow.
2. Generate prompt variants from those gold cases.
3. Run topology experiments against the eval prompt set.
4. Score support rate, intent match, tool choice, query shape, field overlap, row behavior, and latency.
5. Rank the experiments and keep only changes that hold up empirically.

## Files

- [langgraph_gold_seed_questions.json](/home/joe/splunk-soc-agent/benchmarks/langgraph_gold_seed_questions.json)
- [langgraph_topology_experiments.json](/home/joe/splunk-soc-agent/benchmarks/langgraph_topology_experiments.json)
- [build_langgraph_gold_corpus.py](/home/joe/splunk-soc-agent/scripts/build_langgraph_gold_corpus.py)
- [generate_langgraph_eval_prompts.py](/home/joe/splunk-soc-agent/scripts/generate_langgraph_eval_prompts.py)
- [run_langgraph_topology_eval.py](/home/joe/splunk-soc-agent/scripts/run_langgraph_topology_eval.py)
- [optimize_langgraph_topology.py](/home/joe/splunk-soc-agent/scripts/optimize_langgraph_topology.py)

## Topology Flags

The experiment runner varies the graph through environment flags:

- `LANGGRAPH_ENABLE_SECURITY_REVIEW`
- `LANGGRAPH_ENABLE_PEER_REVIEW`
- `LANGGRAPH_ENABLE_EVIDENCE_REVIEW`
- `LANGGRAPH_ENABLE_FINAL_SUMMARY`
- `LANGGRAPH_ENABLE_QUERY_REPAIR`

These are meant for offline experimentation, not casual runtime toggling.

## Commands

```bash
make langgraph-gold-build
make langgraph-eval-prompts
make langgraph-topology-eval
make langgraph-topology-optimize
```

## Output

Artifacts are written under:

- `artifacts/evals/langgraph/gold_corpus_latest.json`
- `artifacts/evals/langgraph/eval_prompts_latest.json`
- `artifacts/evals/langgraph/topology/langgraph_topology_eval_latest.json`
- `artifacts/evals/langgraph/topology/langgraph_topology_eval_latest.md`

## Current Boundary

This is an optimization harness, not a self-modifying runtime. It creates the evidence needed for Codex to compare workflow layouts safely before any topology change becomes the default.
