# A.G.E.N.T. Smith

A.G.E.N.T. Smith is a guarded Splunk analyst copilot built for detection, triage, and investigation work. The project takes a natural-language question, plans a search strategy, writes bounded read-only SPL, validates that plan before it can touch Splunk, pulls back evidence through Splunk MCP, and returns the result with the executed query, evidence, and model reasoning visible. The goal is not blind autonomy. The goal is to help an analyst move faster without losing control of the workflow.

This repository is published as a clean starting point. It ships with example configuration, not live environment secrets or local runtime state.

## Start Here
If you are trying to get the platform running for the first time, read the [Initial Setup Guide](docs/runbooks/initial_setup.md) alongside the quick start below.

If you want the shortest explanation of the project before you install anything, start with:
- [One-Page White Paper](docs/whitepapers/project_one_page_white_paper.md)
- [Technical Deep Dive](docs/whitepapers/technical_deep_dive.md)

## Quick Start
For a clean first run, use the deployment container:

```bash
sudo apt-get update
sudo apt-get install -y git make docker.io docker-compose-plugin
sudo usermod -aG docker $USER
newgrp docker
```

Then:

```bash
git clone https://github.com/gosplunk/agtsmith.git
cd agtsmith
make docker-deploy-build
make docker-deploy-up
```

Then:
- open `http://HOST_IP:8787/login`
- complete first-run setup
- follow the [Initial Setup Guide](docs/runbooks/initial_setup.md) if you need the full environment checklist
- validate Ollama, Splunk Base, and Splunk MCP in `Control Center -> Configuration`
- pull and assign any missing models
- refresh Data Domains
- run the first investigation

## How It Works
The default SPL path is a two-model pipeline:

1. `Planner`
   - default: `hf.co/MaziyarPanahi/Qwen3-30B-A3B-Instruct-2507-GGUF:Q4_K_M`
   - interprets the question and builds a structured search plan
2. `SPL Writer`
   - default: `deepseek-coder-v2:lite`
   - turns the plan into bounded read-only SPL
3. `Security Reviewer`
   - default: `hf.co/MaziyarPanahi/Qwen3-30B-A3B-Instruct-2507-GGUF:Q4_K_M`
   - critiques the writer output before deterministic validation

If the reviewer approves the query cleanly, the controller can skip extra adjudication and move straight to validation.

An optional small-model helper on an edge device can also be enabled for low-cost routing or split-query hints. It is not the main writer or reviewer path.

## What This Project Is
- A Splunk-centric analyst augmentation project
- Read-only by design
- Controller-hosted orchestration with visible decision steps
- Grounded in local environment metadata, Data Domains, and curated SPL references
- Built to be tuned empirically with benchmarks and evals

## What It Is Not
- Autonomous response or recovery
- A SOAR platform
- Enterprise IAM or secret-management infrastructure
- HA/SLA-hardened production software

## Running It
There are three supported ways to run A.G.E.N.T. Smith.

1. Host runtime
- Runs the app directly from the local Python environment on the current machine.
- Best for development, debugging, and fast iteration when you are changing code often.

```bash
make dev
```

2. Docker wrapper
- Runs A.G.E.N.T. Smith in Docker, but still uses the local working tree.
- Best when you want containerized execution without giving up live local code changes.

```bash
make docker-build
make docker-up
```

3. Docker deployment image
- Builds and runs the cleaner deployment-style version of A.G.E.N.T. Smith.
- Uses isolated config and artifact volumes instead of your host runtime state.
- This is the recommended path for a fresh install, a demo box, or a handoff to another machine.

```bash
make docker-deploy-build
make docker-deploy-up
```

If your host user is not UID/GID `1000`, set:
```bash
export AGTSMITH_UID=$(id -u)
export AGTSMITH_GID=$(id -g)
```

## First-Time Setup
The recommended path is Docker-first.

1. Start the deployment container.
2. Open `http://HOST_IP:8787/login`.
3. Complete first-run bootstrap if prompted.
4. Open `Control Center`.
5. Follow the Initial Setup Guide from the Configuration page.
6. Validate Ollama, Splunk Base, and Splunk MCP.
7. Pull and assign any missing models.
8. Run `Refresh Data Domains` and let the initial environment build complete.
9. Run the first investigation.

Deployment notes:
- the deploy image uses its own config volume
- the deploy image uses its own artifact volume
- it does not read the host `config/ui.env` unless you deliberately change the compose file
- it does not inherit host-built Data Domains or personalization artifacts

## Key Routes
- Investigation UI: `/investigation`
- MCP Chat: `/mcp`
- Configuration: `/configure`
- Architecture: `/architecture`
- LangGraph Graph: `/langgraph-graph`
- Documentation: `/docs`
- Data Domains: `/environment`

## Configuration
Tracked example config:
- `config/ui.env.example`

Local operator config:
- `config/ui.env`

Public repo rule:
- do not commit a live `config/ui.env`
- a clean deployment should enter first-run setup and be configured locally

Runtime query audit:
- `artifacts/audit/query_runs.jsonl`

Role model:
- `analyst` can investigate but cannot change runtime settings
- `ops` can manage runtime configuration, models, validation, and Data Domains
- `admin` includes `ops` access plus user management and query audit visibility

For the two-model SPL path:
- `OLLAMA_MODEL_QUERY_PLANNER` should point to the reasoning/planning model
- `OLLAMA_MODEL_QUERY_WRITER` should point to the coding-focused SPL writer
- `OLLAMA_MODEL_QUERY_REPAIR` can use the same coding model as the writer
- `EDGE_LLM_ENABLED=1` is only for the optional edge helper path

To start from the example file:
```bash
cp config/ui.env.example config/ui.env
```

## Benchmarks And Evals
The project includes two main feedback loops.

### SPL hardening
```bash
make spl-hardening-benchmark
```

You can target a specific family or case while tuning:
```bash
python3 scripts/run_spl_hardening_benchmark.py --family linux_auth_failures
python3 scripts/run_spl_hardening_benchmark.py --case-id windows_failed_logons_24h
```

### LangGraph topology evals
```bash
make langgraph-gold-build
make langgraph-eval-prompts
make langgraph-topology-eval
make langgraph-topology-optimize
```

These runs are meant to answer a practical question: does the workflow actually improve when you change the topology, prompts, or model split?

## BOTSv3
BOTSv3 is included as a separate benchmark track, not as a production assumption. Its timestamps are historical, so those cases use explicit all-time handling only when the question says so.

Run it with:
```bash
make spl-hardening-benchmark-botsv3
make spl-hardening-benchmark-botsv3-inventory
```

## Docs Reading Order
1. `docs/whitepapers/project_one_page_white_paper.md`
2. `docs/whitepapers/technical_deep_dive.md`
3. `docs/runbooks/initial_setup.md`
4. `docs/runbooks/health_check.md`
5. `docs/architecture/two_model_spl_pipeline.md`
6. `docs/architecture/system_design.md`

## Default Model Assignments
```bash
export OLLAMA_MODEL_QUERY_PLANNER="hf.co/MaziyarPanahi/Qwen3-30B-A3B-Instruct-2507-GGUF:Q4_K_M"
export OLLAMA_MODEL_QUERY_WRITER="deepseek-coder-v2:lite"
export OLLAMA_MODEL_SECURITY_REVIEWER="hf.co/MaziyarPanahi/Qwen3-30B-A3B-Instruct-2507-GGUF:Q4_K_M"
export OLLAMA_MODEL_EVIDENCE_REVIEWER="hf.co/MaziyarPanahi/Qwen3-30B-A3B-Instruct-2507-GGUF:Q4_K_M"
export OLLAMA_MODEL_QUERY_REPAIR="deepseek-coder-v2:lite"
```

Pull the default local model set:
```bash
ollama pull hf.co/MaziyarPanahi/Qwen3-30B-A3B-Instruct-2507-GGUF:Q4_K_M
ollama pull deepseek-coder-v2:lite
ollama pull hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q8_0-GGUF:latest
```

## License
This project is licensed under the Apache License 2.0. See `LICENSE`.
