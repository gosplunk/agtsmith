# Playbook overlay layout variants

Three alternate node placements for the LangGraph playbook overlay (Concept A horizontal spine). Topology, phase colors, icons, edge routing patterns, and legend are unchanged — only coordinates differ. The canonical layout remains the runtime default.

| Preset | PNG | URL param |
|--------|-----|-----------|
| Variant A | `assets/playbook-render-variant-a.png` | `?playbook_preset=variant-a` |
| Variant B | `assets/playbook-render-variant-b.png` | `?playbook_preset=variant-b` |
| Variant C | `assets/playbook-render-variant-c.png` | `?playbook_preset=variant-c` |

## Variant A — gates in bottom-left quadrant

Scope?, Clean?, Approved?, and Evidence diamonds move into the unused space left of the legend (x ≈ 80–280, y ≈ 390–555). The main spine shortens to Ingest → Guardrail → Planner → Writer on the top row, while the security peer-review column stays on the right. Blocked shortcuts still ride the left perimeter into Summarize.

## Variant B — lower security column, wider evidence fan

The security stack drops ~50px and shifts slightly right (x ≈ 1020) so it clears the upper spine. Evidence branches spread wider (META 220, OP 520, SEC 880). Approved? sits at the left margin above the legend, and blocked paths emphasize the x = 20 perimeter gutter for clearer “escape” routing.

## Variant C — two-tier spine with left gutter gates

Ingest through Writer stay on an upper row (y ≈ 52); Validate, Run Tool, and the finish merge sit on a lower row (y ≈ 230). Scope?, Clean?, Approved?, and Evidence occupy a left gutter (x ≈ 70) between the tiers, making gate decisions visually separate from the forward spine while Summarize/Finalize remain bottom-aligned with the legend.

## API

- `PLAYBOOK_LAYOUT_PRESETS` in `scripts/investigation_progress.py` — keys: `canonical`, `variant-a`, `variant-b`, `variant-c`
- `get_playbook_layout_preset(name)` / `list_playbook_layout_presets()`
- Capture all variants: `source .venv-screenshots/bin/activate && python3 scripts/capture_playbook_layout_variants.py`
