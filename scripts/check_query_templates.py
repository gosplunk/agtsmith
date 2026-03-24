#!/usr/bin/env python3
"""Validate query template definitions for safety and consistency.

Checks:
- unique intent names
- non-empty keyword lists
- unique keywords across templates
- bounded query controls (row_limit/time fields)
"""

from __future__ import annotations

import sys
from collections import Counter

from minimal_question_to_answer import map_question_to_template
from query_templates import TEMPLATES


MAX_SAFE_ROW_LIMIT = 50


def main() -> int:
    errors: list[str] = []

    if not TEMPLATES:
        errors.append("No templates defined.")

    intents = [t.intent for t in TEMPLATES]
    duplicate_intents = [name for name, count in Counter(intents).items() if count > 1]
    if duplicate_intents:
        errors.append(f"Duplicate template intents found: {duplicate_intents}")

    keyword_to_intent: dict[str, str] = {}
    for t in TEMPLATES:
        if not t.intent.strip():
            errors.append("Found template with empty intent.")

        if not t.keywords:
            errors.append(f"Template '{t.intent}' has no keywords.")

        for keyword in t.keywords:
            kw = keyword.strip().lower()
            if not kw:
                errors.append(f"Template '{t.intent}' has an empty keyword entry.")
                continue

            if kw in keyword_to_intent and keyword_to_intent[kw] != t.intent:
                errors.append(
                    f"Keyword collision: '{kw}' used by '{keyword_to_intent[kw]}' and '{t.intent}'."
                )
            else:
                keyword_to_intent[kw] = t.intent

        if not t.query.strip():
            errors.append(f"Template '{t.intent}' has an empty query.")

        if t.earliest_time.strip() == "" or t.latest_time.strip() == "":
            errors.append(f"Template '{t.intent}' must define earliest_time and latest_time.")

        if t.row_limit < 1:
            errors.append(f"Template '{t.intent}' has invalid row_limit={t.row_limit}; must be >= 1.")
        if t.row_limit > MAX_SAFE_ROW_LIMIT:
            errors.append(
                f"Template '{t.intent}' has row_limit={t.row_limit}; exceeds safety max {MAX_SAFE_ROW_LIMIT}."
            )

    routing_cases = (
        ("Show linux failed login activity in the last 24 hours", "linux_auth_failures"),
        ("Show failed login activity in the last 24 hours in windows", "windows_auth_failures"),
        ("Which Windows hosts had the most authentication failures today", "windows_auth_failures"),
        ("Show authentication failures on my linux servers today", "linux_auth_failures"),
        ("Show failed login activity in the last 24 hours", "failed_login_activity"),
        ("Show failed login activity in the last 7 days on my windows or linux machines", "failed_login_activity"),
        ("Show failed sudo activity on linux in the last 24 hours", "linux_privilege_escalation"),
        ("Investigate first time privilege escalation in the last 7 days on my linux machines", "linux_privilege_escalation_first_seen"),
        ("Show top client IPs in apache access logs (access_combined) in the last 24 hours", "apache_access_top_ips"),
        ("Show 404 spike behavior in apache access_combined logs in the last 24 hours", "apache_404_spike"),
        ("Show suspicious user agents in apache access_combined logs", "apache_suspicious_user_agents"),
    )
    for question, expected_intent in routing_cases:
        actual_intent = map_question_to_template(question).intent
        if actual_intent != expected_intent:
            errors.append(
                f"Routing mismatch for question={question!r}: expected={expected_intent} got={actual_intent}"
            )

    print("=== Query Template Self-Check ===")
    print(f"templates={len(TEMPLATES)}")

    if errors:
        print("status=FAIL")
        for idx, err in enumerate(errors, start=1):
            print(f"{idx}. {err}")
        return 1

    print("status=PASS")
    for t in TEMPLATES:
        print(
            f"- intent={t.intent} keywords={len(t.keywords)} row_limit={t.row_limit} "
            f"window=({t.earliest_time},{t.latest_time})"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
