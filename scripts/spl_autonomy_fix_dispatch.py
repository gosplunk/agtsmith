#!/usr/bin/env python3
"""Dispatch autonomy-loop fixes based on failure classification."""

from __future__ import annotations

from typing import Any


def classify_failure(reason: str) -> str:
    text = str(reason or "").strip().lower()
    if not text:
        return "unknown"
    if "invented_sourcetype" in text or "environment" in text:
        return "environment_binding"
    if "platform_coherence" in text or "platform_mix" in text or "platform_scope" in text:
        return "platform_coherence"
    if "intent_contract" in text or "structure" in text:
        return "structure"
    if "policy" in text:
        return "policy"
    if "empty" in text or "writer" in text:
        return "writer_quality"
    return "unknown"


def dispatch_actions(failure_class: str) -> list[str]:
    mapping = {
        "environment_binding": ["rebuild_cards", "refresh_profile", "field_bind"],
        "platform_coherence": ["rebuild_cards", "structure_validate"],
        "structure": ["structure_validate", "writer_constrained"],
        "policy": ["query_repair", "writer_constrained"],
        "writer_quality": ["rebuild_embedding_index", "writer_constrained", "learning_export"],
        "unknown": ["phase_gate", "writer_eval"],
    }
    return list(mapping.get(failure_class, mapping["unknown"]))


def build_fix_plan(failures: list[dict[str, Any]]) -> dict[str, Any]:
    classes: dict[str, int] = {}
    for row in failures:
        reason = str(row.get("reason", row.get("validation_reason", "")))
        cls = classify_failure(reason)
        classes[cls] = classes.get(cls, 0) + 1
    ordered = sorted(classes.items(), key=lambda item: item[1], reverse=True)
    primary = ordered[0][0] if ordered else "unknown"
    actions = dispatch_actions(primary)
    return {"primary_class": primary, "class_counts": classes, "actions": actions}
