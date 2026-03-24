# A.G.E.N.T. Smith
## Documentation Overview

This page is the reader's starting point. It does not try to explain the whole platform again. It tells you which document to read next based on what you need.

## Start Here
If you want the shortest explanation of what A.G.E.N.T. Smith is, read:
- [`docs/whitepapers/project_one_page_white_paper.md`](/docs/view?path=whitepapers/project_one_page_white_paper.md)

If you are trying to stand the platform up for the first time, read:
- [`docs/runbooks/initial_setup.md`](/docs/view?path=runbooks/initial_setup.md)

If you want the technical explanation of how the runtime actually works, read:
- [`docs/whitepapers/technical_deep_dive.md`](/docs/view?path=whitepapers/technical_deep_dive.md)

If you want the technical explanation of how workflow changes are evaluated offline, read:
- [`docs/architecture/langgraph_eval_optimization.md`](/docs/view?path=architecture/langgraph_eval_optimization.md)

If you are installing or configuring the platform, read:
- [`docs/runbooks/initial_setup.md`](/docs/view?path=runbooks/initial_setup.md)

If you want the live workflow view in the UI, open:
- Control Center -> LangGraph Graph

## Read By Audience
- Business or leadership reader:
  - [`docs/whitepapers/project_one_page_white_paper.md`](/docs/view?path=whitepapers/project_one_page_white_paper.md)
  - [`docs/whitepapers/executive_white_paper.md`](/docs/view?path=whitepapers/executive_white_paper.md)
- Security engineer or architect:
  - [`docs/whitepapers/technical_deep_dive.md`](/docs/view?path=whitepapers/technical_deep_dive.md)
  - [`docs/architecture/system_design.md`](/docs/view?path=architecture/system_design.md)
  - [`docs/architecture/network_diagram.md`](/docs/view?path=architecture/network_diagram.md)
- Operator or installer:
  - [`docs/runbooks/initial_setup.md`](/docs/view?path=runbooks/initial_setup.md)
  - [`docs/runbooks/health_check.md`](/docs/view?path=runbooks/health_check.md)
  - [`docs/runbooks/weekly_maintenance.md`](/docs/view?path=runbooks/weekly_maintenance.md)

## What Exists Today
- Authenticated web UI for LAN users
- First-run credential bootstrap for a fresh deployment
- Local managed user store in Configuration
- Distinct local roles for `analyst`, `ops`, and `admin`
- Query audit log showing who ran which investigation
  - admin-only visibility
- Splunk MCP-backed read-only investigations
- Multi-model review workflow
- Bounded agentic continuation workflow
- Executed SPL, sampled rows, and model transparency in the UI
- Data Domains and environment-aware SPL personalization
- Docker deployment path with first-run setup sequencing
- Offline LangGraph eval and topology optimization harness
- Control Center page for canonical graph, active topology, and latest executed path

## Scope Boundary
- Detect, Triage, and Investigate are implemented
- Respond and Recover are still manual
- SOAR is planned, not active
- The current system is a guarded MVP analyst augmentation platform, not yet a production control plane

## Recommended Reading Order
1. [`docs/whitepapers/project_one_page_white_paper.md`](/docs/view?path=whitepapers/project_one_page_white_paper.md)
2. [`docs/whitepapers/technical_deep_dive.md`](/docs/view?path=whitepapers/technical_deep_dive.md)
3. [`docs/runbooks/initial_setup.md`](/docs/view?path=runbooks/initial_setup.md)
4. [`docs/runbooks/health_check.md`](/docs/view?path=runbooks/health_check.md)
5. [`docs/architecture/system_design.md`](/docs/view?path=architecture/system_design.md)
6. [`docs/architecture/langgraph_eval_optimization.md`](/docs/view?path=architecture/langgraph_eval_optimization.md)

## Advanced Material
The `docs/reference/` tree is the advanced knowledge and RAG support library. It is useful for model grounding and implementation work, but it is not the main reader path for understanding the platform.
