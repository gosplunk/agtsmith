#!/usr/bin/env python3
"""Bake-off Hailo GenAI models on Raspberry Pi AI HAT+ 2 (hailo-ollama).

Uses Ollama-compatible HTTP without ``format: json`` or ``think: false`` — both
break hailo-ollama. Scores SPL writer and edge-router style tasks with the same
rule-based rubrics as the lab bake-offs.
"""

from __future__ import annotations

import argparse
import json
import re
import statistics
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_HAILO_HOST = "http://192.168.169.49:11434"
DEFAULT_HAILO_SSH = "joe@192.168.169.49"
DEFAULT_INTER_REQUEST_DELAY_SEC = 12.0

FORBIDDEN_TERMS = ("delete", "drop", "outputlookup", "| outputcsv", "| sendemail", "| map ", " collect ")

ORIGIN_BY_KEY: tuple[tuple[str, str], ...] = (
    ("deepseek", "CN / DeepSeek"),
    ("qwen", "CN / Alibaba"),
    ("codegemma", "US / Google"),
    ("gemma", "US / Google"),
    ("llama", "US / Meta"),
    ("mistral", "FR / Mistral AI"),
    ("granite", "US / IBM"),
    ("phi", "US / Microsoft"),
)

TEST_CASES: list[dict[str, Any]] = [
    {
        "id": "failed_login",
        "question": "Write a read-only Splunk SPL query for failed login activity in the last 24 hours.",
        "required_terms": ["failed", "stats", "user"],
    },
    {
        "id": "linux_auth",
        "question": "Write a read-only Splunk SPL query for Linux authentication failures in index=linux over last 24 hours.",
        "required_terms": ["index=linux", "auth.log", "failed", "stats"],
    },
    {
        "id": "linux_priv_esc",
        "question": "Write a read-only Splunk SPL query for failed sudo or su activity in Linux logs over last 24 hours.",
        "required_terms": ["index=linux", "sudo", "su", "stats"],
    },
    {
        "id": "apache_top_ips",
        "question": "Write a read-only Splunk SPL query for top client IPs in index=linux sourcetype=access_combined over last 24 hours.",
        "required_terms": ["index=linux", "access_combined", "clientip", "stats"],
    },
    {
        "id": "apache_404",
        "question": "Write a read-only Splunk SPL query for 404 spikes in index=linux sourcetype=access_combined over last 24 hours.",
        "required_terms": ["index=linux", "access_combined", "404", "timechart"],
    },
]


def model_origin(tag: str) -> str:
    lower = tag.lower()
    for key, origin in ORIGIN_BY_KEY:
        if key in lower:
            return origin
    return "unknown"


def score_candidate(candidate: dict[str, Any], required_terms: list[str]) -> tuple[int, list[str]]:
    score = 0
    notes: list[str] = []
    query = str(candidate.get("query", "")).strip()
    lower = query.lower()
    if query:
        score += 10
    else:
        notes.append("missing_query")
    if lower.startswith("search "):
        score += 20
    else:
        notes.append("query_not_search_prefix")
    hit_terms = sum(1 for term in required_terms if term.lower() in lower)
    term_score = int((hit_terms / max(1, len(required_terms))) * 30)
    score += term_score
    if hit_terms < len(required_terms):
        notes.append(f"required_term_hits:{hit_terms}/{len(required_terms)}")
    if all(term not in lower for term in FORBIDDEN_TERMS):
        score += 20
    else:
        notes.append("forbidden_term_present")
    earliest = str(candidate.get("earliest_time", "")).strip()
    latest = str(candidate.get("latest_time", "")).strip().lower()
    if earliest and latest in {"now", "now()"}:
        score += 10
    else:
        notes.append("missing_or_bad_time_bounds")
    try:
        row_limit = int(candidate.get("row_limit", 10))
        if 1 <= row_limit <= 200:
            score += 10
        else:
            notes.append("row_limit_out_of_bounds")
    except Exception:
        notes.append("row_limit_not_int")
    return max(0, min(100, score)), notes

EDGE_ROUTER_CASES: list[dict[str, Any]] = [
    {
        "id": "failed_login",
        "question": "Investigate failed login attempts in the last 24 hours.",
        "expected_route": "auth",
    },
    {
        "id": "apache_top_ips",
        "question": "Show top client IPs from Apache access logs over the last day.",
        "expected_route": "network",
    },
    {
        "id": "linux_sudo_fail",
        "question": "Find failed sudo or su attempts on Linux hosts.",
        "expected_route": "auth",
    },
    {
        "id": "disk_capacity",
        "question": "Which hosts are running low on disk space?",
        "expected_route": "endpoint",
    },
    {
        "id": "list_indexes",
        "question": "What Splunk indexes exist in this environment?",
        "expected_route": "inventory",
    },
    {
        "id": "windows_logon_fail",
        "question": "Hunt Windows Event 4625 failed logon activity.",
        "expected_route": "auth",
    },
]

EDGE_SYSTEM = (
    "You are an edge routing helper for a Splunk SOC assistant. "
    "Reply with JSON containing route, confidence, split_needed. "
    "route must be one of: auth, network, endpoint, inventory, web, cloud, unknown."
)

ROUTE_KEYWORDS: dict[str, tuple[str, ...]] = {
    "auth": ("auth", "login", "logon", "sudo", "4625", "credential"),
    "network": ("network", "ip", "apache", "dns", "firewall", "client"),
    "endpoint": ("disk", "cpu", "memory", "host", "performance", "capacity"),
    "inventory": ("index", "indexes", "metadata", "inventory", "sourcetype list"),
}


def _extract_json(text: str) -> dict[str, Any]:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
    except Exception:
        pass
    match = re.search(r"\{[\s\S]*\}", text)
    if not match:
        return {}
    try:
        obj = json.loads(match.group(0))
        return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}


def _http_post(host: str, path: str, payload: dict[str, Any], timeout: float) -> tuple[dict[str, Any], int]:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        f"{host.rstrip('/')}{path}",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = json.loads(resp.read().decode("utf-8"))
        return body, int(getattr(resp, "status", 200))


def list_models(host: str, timeout: float = 20.0) -> list[str]:
    base = host.rstrip("/")
    for path in ("/hailo/v1/list", "/api/tags"):
        try:
            req = urllib.request.Request(f"{base}{path}")
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
            if path.endswith("/list"):
                models = payload.get("models", [])
                return [str(name).strip() for name in models if str(name).strip()]
            out: list[str] = []
            for item in payload.get("models", []):
                name = str(item.get("name", "")).strip()
                if name:
                    out.append(name)
            if out:
                return out
        except Exception:
            continue
    return []


def restart_hailo_service(ssh_target: str, *, password: str = "") -> None:
    if not ssh_target.strip():
        return
    try:
        import paramiko
    except ImportError:
        print("[hailo-bakeoff] paramiko unavailable; skipping service restart", flush=True)
        return
    user_host = ssh_target.split("@", 1)
    if len(user_host) != 2:
        return
    user, host = user_host
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, username=user, password=password, timeout=15)
    stdin, stdout, stderr = client.exec_command(
        "sudo systemctl restart hailo-ollama hailo-proxy && sleep 4 && systemctl is-active hailo-ollama hailo-proxy",
        timeout=60,
    )
    status = stdout.read().decode().strip()
    client.close()
    print(f"[hailo-bakeoff] restarted hailo services: {status}", flush=True)


def hailo_generate(
    host: str,
    *,
    model: str,
    prompt: str,
    timeout: float,
) -> tuple[str, int]:
    payload = {"model": model, "prompt": prompt, "stream": False}
    body, _ = _http_post(host, "/api/generate", payload, timeout)
    return str(body.get("response", "")).strip(), int(body.get("total_duration", 0) // 1_000_000)


def hailo_chat(
    host: str,
    *,
    model: str,
    system: str,
    user: str,
    timeout: float,
) -> tuple[str, int]:
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "stream": False,
    }
    body, _ = _http_post(host, "/api/chat", payload, timeout)
    content = str((body.get("message") or {}).get("content", "")).strip()
    return content, int(body.get("total_duration", 0) // 1_000_000)


def generate_spl_candidate(
    host: str,
    model: str,
    question: str,
    *,
    timeout: float,
) -> tuple[dict[str, Any], int]:
    prompt = (
        f"{question} "
        "Output JSON with keys query, earliest_time, latest_time, row_limit. "
        "The query value must be read-only Splunk SPL and start with search followed by a space."
    )
    raw, duration_ms = hailo_generate(host, model=model, prompt=prompt, timeout=timeout)
    parsed = _extract_json(raw)
    candidate = {
        "query": str(parsed.get("query", "")).strip(),
        "earliest_time": str(parsed.get("earliest_time", "")).strip(),
        "latest_time": str(parsed.get("latest_time", "")).strip(),
        "row_limit": parsed.get("row_limit", 10),
        "raw_preview": raw[:500],
    }
    return candidate, duration_ms


def infer_route_from_text(text: str) -> str:
    lower = text.lower()
    best_route = ""
    best_hits = 0
    for route, keywords in ROUTE_KEYWORDS.items():
        hits = sum(1 for keyword in keywords if keyword in lower)
        if hits > best_hits:
            best_hits = hits
            best_route = route
    return best_route


def score_edge_route(parsed: dict[str, Any], expected_route: str, raw_text: str = "") -> tuple[int, list[str]]:
    score = 0
    notes: list[str] = []
    route = str(parsed.get("route", "")).strip().lower()
    if not route:
        route = infer_route_from_text(raw_text)
        if route:
            notes.append("route_inferred_from_text")
    expected = expected_route.strip().lower()

    if route == expected:
        score += 70
    elif route and route in {"auth", "network", "endpoint", "inventory", "web", "cloud"}:
        score += 25
        notes.append(f"route_mismatch:{route}->{expected}")
    else:
        notes.append(f"route_missing_or_invalid:{route or 'empty'}")

    try:
        confidence = float(parsed.get("confidence", 0))
        if 0.0 <= confidence <= 1.0:
            score += 15
        else:
            notes.append("confidence_out_of_range")
    except Exception:
        notes.append("confidence_not_float")

    if "split_needed" in parsed:
        score += 15
    else:
        notes.append("split_needed_missing")

    return max(0, min(100, score)), notes


def evaluate_spl_writer(host: str, model: str, *, timeout: float, delay_sec: float) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    durations: list[int] = []
    total = 0
    for case in TEST_CASES:
        try:
            candidate, duration_ms = generate_spl_candidate(
                host,
                model,
                str(case["question"]),
                timeout=timeout,
            )
            score, notes = score_candidate(candidate, list(case["required_terms"]))
        except Exception as exc:
            candidate = {"query": "", "raw_preview": ""}
            score, notes = 0, [f"model_error:{type(exc).__name__}"]
            duration_ms = 0
        total += score
        durations.append(duration_ms)
        rows.append(
            {
                "case_id": case["id"],
                "score": score,
                "notes": notes,
                "duration_ms": duration_ms,
                "candidate": candidate,
            }
        )
        if delay_sec > 0:
            time.sleep(delay_sec)
    return {
        "avg_score": round(total / len(TEST_CASES), 2),
        "median_duration_ms": int(statistics.median(durations)) if durations else 0,
        "cases": rows,
    }


def evaluate_edge_router(host: str, model: str, *, timeout: float, delay_sec: float) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    durations: list[int] = []
    route_hits = 0
    total = 0
    for case in EDGE_ROUTER_CASES:
        user = f"Classify this SOC question. Question: {case['question']}"
        try:
            raw, duration_ms = hailo_chat(
                host,
                model=model,
                system=EDGE_SYSTEM,
                user=user,
                timeout=timeout,
            )
            parsed = _extract_json(raw)
            score, notes = score_edge_route(parsed, str(case["expected_route"]), raw)
            actual_route = str(parsed.get("route", "")).strip().lower() or infer_route_from_text(raw)
            if actual_route == str(case["expected_route"]).strip().lower():
                route_hits += 1
        except Exception as exc:
            parsed = {}
            raw = ""
            score, notes = 0, [f"model_error:{type(exc).__name__}"]
            duration_ms = 0
        total += score
        durations.append(duration_ms)
        rows.append(
            {
                "case_id": case["id"],
                "expected_route": case["expected_route"],
                "actual_route": parsed.get("route") or infer_route_from_text(raw),
                "score": score,
                "notes": notes,
                "duration_ms": duration_ms,
                "raw_preview": raw[:400],
            }
        )
        if delay_sec > 0:
            time.sleep(delay_sec)
    count = len(EDGE_ROUTER_CASES)
    return {
        "avg_score": round(total / count, 2),
        "route_match_rate_pct": round((route_hits / count) * 100, 2),
        "median_duration_ms": int(statistics.median(durations)) if durations else 0,
        "cases": rows,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Bake-off Hailo GenAI models on Pi AI HAT+ 2")
    parser.add_argument("--host", default=DEFAULT_HAILO_HOST, help="hailo-ollama proxy URL")
    parser.add_argument("--models", nargs="*", default=[], help="Explicit model tags (default: all installed)")
    parser.add_argument("--timeout-sec", type=float, default=180.0, help="Per-request timeout")
    parser.add_argument("--delay-sec", type=float, default=DEFAULT_INTER_REQUEST_DELAY_SEC, help="Pause between requests")
    parser.add_argument("--restart-ssh", default=DEFAULT_HAILO_SSH, help="SSH target for hailo-ollama restart between models")
    parser.add_argument("--restart-password", default="", help="SSH password for restart (optional)")
    parser.add_argument("--no-restart", action="store_true", help="Skip hailo-ollama restart between models")
    parser.add_argument("--out-dir", default="artifacts/model_eval/hailo_bakeoff")
    args = parser.parse_args()

    host = str(args.host).strip().rstrip("/")
    timeout = float(args.timeout_sec)
    delay_sec = float(args.delay_sec)
    models = list(args.models) or list_models(host)
    if not models:
        raise SystemExit("no_models_found")

    ranked: list[dict[str, Any]] = []
    started = time.time()
    for i, model in enumerate(models, 1):
        print(f"[hailo-bakeoff] {i}/{len(models)} model={model}", flush=True)
        if not args.no_restart and args.restart_ssh.strip():
            restart_hailo_service(args.restart_ssh.strip(), password=str(args.restart_password))
            time.sleep(4)
        spl = evaluate_spl_writer(host, model, timeout=timeout, delay_sec=delay_sec)
        edge = evaluate_edge_router(host, model, timeout=timeout, delay_sec=delay_sec)
        combined = round((spl["avg_score"] + edge["avg_score"]) / 2, 2)
        ranked.append(
            {
                "model": model,
                "origin": model_origin(model),
                "backend": "hailo-ollama",
                "format": "hef",
                "spl_writer_avg": spl["avg_score"],
                "spl_writer_median_ms": spl["median_duration_ms"],
                "edge_router_avg": edge["avg_score"],
                "edge_router_route_match_pct": edge["route_match_rate_pct"],
                "edge_router_median_ms": edge["median_duration_ms"],
                "combined_avg": combined,
                "spl_writer_cases": spl["cases"],
                "edge_router_cases": edge["cases"],
            }
        )

    ranked.sort(key=lambda row: (-row["combined_avg"], -row["edge_router_avg"], -row["spl_writer_avg"]))

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    payload = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "hailo_host": host,
        "elapsed_sec": round(time.time() - started, 1),
        "tested_models": models,
        "spl_writer_case_count": len(TEST_CASES),
        "edge_router_case_count": len(EDGE_ROUTER_CASES),
        "lab_baseline_reference": {
            "spl_writer_granite4_3b_vanilla": 85.8,
            "spl_writer_granite4_3b_rag": 94.4,
            "spl_writer_qwen2_5_coder_1_5b_vanilla_lab_cpu": 70.4,
            "planner_granite3_moe_3b_avg": 56.2,
        },
        "recommended_edge_router_model": ranked[0]["model"] if ranked else "",
        "recommended_spl_writer_model": max(ranked, key=lambda r: r["spl_writer_avg"])["model"] if ranked else "",
        "ranked": ranked,
        "method": "hailo_rule_scoring_v1",
        "notes": [
            "hailo-ollama rejects Ollama format=json and think=false; prompts only.",
            "SPL writer uses vanilla prompts (no RAG) for apples-to-apples with lab vanilla scores.",
            "Model load latency is included in per-request duration_ms.",
        ],
    }

    out_json = out_dir / f"hailo_bakeoff_{stamp}.json"
    latest_json = out_dir / "hailo_bakeoff_latest.json"
    out_md = out_dir / f"hailo_bakeoff_{stamp}.md"
    latest_md = out_dir / "hailo_bakeoff_latest.md"
    out_json.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    latest_json.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    lines = [
        "# Hailo AI HAT+ 2 Model Bake-off",
        "",
        f"- Timestamp (UTC): `{payload['timestamp_utc']}`",
        f"- Host: `{host}`",
        f"- Elapsed: `{payload['elapsed_sec']}s`",
        f"- Models tested: `{len(models)}`",
        "",
        "## Ranked (combined SPL writer + edge router)",
        "",
        "| Rank | Model | SPL avg | Edge avg | Route match | SPL med ms | Edge med ms | Combined |",
        "|------|-------|---------|----------|-------------|------------|-------------|----------|",
    ]
    for i, row in enumerate(ranked, 1):
        lines.append(
            f"| {i} | `{row['model']}` | {row['spl_writer_avg']} | {row['edge_router_avg']} | "
            f"{row['edge_router_route_match_pct']}% | {row['spl_writer_median_ms']} | "
            f"{row['edge_router_median_ms']} | {row['combined_avg']} |"
        )
    lines.extend(
        [
            "",
            "## Lab baselines (RTX 1000 Ada, for comparison)",
            "",
            "- `granite4:3b` SPL writer vanilla: **85.8** / RAG: **94.4**",
            "- `qwen2.5-coder:1.5b` SPL writer vanilla on lab CPU Ollama: **70.4**",
            "",
            f"Recommended edge router: `{payload['recommended_edge_router_model']}`",
            f"Recommended Hailo SPL writer (best of zoo): `{payload['recommended_spl_writer_model']}`",
        ]
    )
    md = "\n".join(lines) + "\n"
    out_md.write_text(md, encoding="utf-8")
    latest_md.write_text(md, encoding="utf-8")

    print(json.dumps({"recommended_edge_router": payload["recommended_edge_router_model"], "ranked": ranked}, indent=2))
    print(f"json={out_json}")
    print(f"md={out_md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
