# A.G.E.N.T. Smith
## Documentation Overview

This page is the reader's starting point. It does not try to explain the whole platform again. It tells you which document to read next based on what you need.

## Start Here
If you are standing up A.G.E.N.T. Smith for the first time, read:
- [Initial Setup Guide](runbooks/initial_setup.md) (canonical runbook)
- [Initial Setup Guide entry point](Initial_Setup_Guide.md) (GitHub-friendly alias)

If you want the short explanation of what changed in `v1.5.2`, read:
- [v1.5.2 Release Highlights](project/v1_5_2_delta.md)

If you want the shortest explanation of what A.G.E.N.T. Smith is, read:
- [What A.G.E.N.T. Smith Is](whitepapers/project_one_page_white_paper.md)

If you want the technical explanation of how the runtime actually works, read:
- [Technical Deep Dive](whitepapers/technical_deep_dive.md)

If you want the technical explanation of how workflow changes are evaluated offline, read:
- [LangGraph Eval Optimization](architecture/langgraph_eval_optimization.md)

If you want the live workflow view in the UI, open:
- Control Center -> LangGraph Graph

## Read By Audience
- Business or leadership reader:
  - [What A.G.E.N.T. Smith Is](whitepapers/project_one_page_white_paper.md)
  - [Executive Summary](whitepapers/executive_white_paper.md)
- Security engineer or architect:
  - [Technical Deep Dive](whitepapers/technical_deep_dive.md)
  - [System Design](architecture/system_design.md)
  - [Two-Model SPL Pipeline](architecture/two_model_spl_pipeline.md)
  - [Model Strategy](model_strategy.md)
  - [Network Diagram](architecture/network_diagram.md)
- Operator or installer:
  - [Initial Setup Guide](runbooks/initial_setup.md)
  - [Health Check](runbooks/health_check.md)
  - [Laptop Model Profile](runbooks/laptop_model_profile.md)
  - [Weekly Maintenance](runbooks/weekly_maintenance.md)

## What Exists Today
- Authenticated web UI for LAN users
- First-run credential bootstrap for a fresh deployment
- Local managed user store in Configuration
- Distinct local roles for `analyst`, `ops`, and `admin`
- Query audit log showing who ran which investigation
  - admin-only visibility
- Splunk MCP-backed read-only investigations
- Multi-model review workflow with split planner / writer roles (`v1.5.1` defaults)
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
1. [What A.G.E.N.T. Smith Is](whitepapers/project_one_page_white_paper.md)
2. [Technical Deep Dive](whitepapers/technical_deep_dive.md)
3. [Initial Setup Guide](runbooks/initial_setup.md)
4. [Health Check](runbooks/health_check.md)
5. [Two-Model SPL Pipeline](architecture/two_model_spl_pipeline.md)
6. [Model Strategy](model_strategy.md)
7. [System Design](architecture/system_design.md)
8. [LangGraph Eval Optimization](architecture/langgraph_eval_optimization.md)

## Advanced Material
The `docs/reference/` tree is the advanced knowledge and RAG support library. It is useful for model grounding and implementation work, but it is not the main reader path for understanding the platform.
