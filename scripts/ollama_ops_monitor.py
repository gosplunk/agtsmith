#!/usr/bin/env python3
"""Local Ollama ops telemetry: GPU metrics, runtime status, and log source detection."""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import time
from typing import Any

import httpx

from ollama_log_stream import utc_now_iso

LOCAL_LOG_MODES = {"local_systemd", "local_docker", "local_command", "remote_windows", "disabled"}
REMOTE_REQUIRED_VARS = ("OLLAMA_LOG_REMOTE_URL",)
NVIDIA_SMI_CANDIDATES = ("/usr/bin/nvidia-smi", "/usr/local/bin/nvidia-smi", "nvidia-smi")


def _run_command(argv: list[str], *, timeout: float = 8.0) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except FileNotFoundError:
        return 127, "", f"command_not_found:{argv[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"


def journalctl_available(unit: str = "ollama.service") -> bool:
    if not shutil.which("journalctl"):
        return False
    code, _, _ = _run_command(["journalctl", "-u", unit, "-n", "1", "--no-pager"], timeout=4.0)
    return code == 0


def docker_log_available(container: str = "ollama") -> bool:
    if not shutil.which("docker"):
        return False
    code, _, _ = _run_command(["docker", "inspect", container], timeout=4.0)
    return code == 0


def resolve_log_source_mode(explicit: str = "") -> str:
    mode = (explicit or os.getenv("OLLAMA_LOG_SOURCE", "")).strip().lower()
    if mode in LOCAL_LOG_MODES:
        return mode
    if os.getenv("OLLAMA_LOG_LOCAL_CMD", "").strip():
        return "local_command"
    if os.getenv("OLLAMA_LOG_REMOTE_URL", "").strip():
        return "remote_windows"
    unit = os.getenv("OLLAMA_LOG_SYSTEMD_UNIT", "ollama.service").strip() or "ollama.service"
    if journalctl_available(unit):
        return "local_systemd"
    container = os.getenv("OLLAMA_LOG_DOCKER_CONTAINER", "ollama").strip() or "ollama"
    if docker_log_available(container):
        return "local_docker"
    return "disabled"


def ollama_log_config_status() -> dict[str, Any]:
    mode = resolve_log_source_mode()
    missing_vars: list[str] = []
    required_vars: list[str] = []

    if mode == "remote_windows":
        required_vars = list(REMOTE_REQUIRED_VARS)
        if not os.getenv("OLLAMA_LOG_REMOTE_URL", "").strip():
            missing_vars.append("OLLAMA_LOG_REMOTE_URL")
    elif mode == "local_command":
        required_vars = ["OLLAMA_LOG_LOCAL_CMD"]
        if not os.getenv("OLLAMA_LOG_LOCAL_CMD", "").strip():
            missing_vars.append("OLLAMA_LOG_LOCAL_CMD")
    elif mode == "local_docker":
        required_vars = ["OLLAMA_LOG_DOCKER_CONTAINER"]
    elif mode == "local_systemd":
        required_vars = ["OLLAMA_LOG_SYSTEMD_UNIT"]

    config_ok = not missing_vars and mode != "disabled"
    return {
        "mode": mode,
        "config_ok": config_ok,
        "missing_vars": missing_vars,
        "required_vars": required_vars,
        "systemd_unit": os.getenv("OLLAMA_LOG_SYSTEMD_UNIT", "ollama.service").strip() or "ollama.service",
        "docker_container": os.getenv("OLLAMA_LOG_DOCKER_CONTAINER", "ollama").strip() or "ollama",
        "local_command": os.getenv("OLLAMA_LOG_LOCAL_CMD", "").strip(),
        "cli_hints": {
            "gpu_watch": "watch -n 1 nvidia-smi",
            "gpu_once": "nvidia-smi",
            "logs_systemd": "journalctl -u ollama -f -n 200 --output=cat",
            "logs_docker": "docker logs -f --tail 200 ollama",
        },
    }


def build_local_log_command(mode: str) -> list[str]:
    custom = os.getenv("OLLAMA_LOG_LOCAL_CMD", "").strip()
    if custom:
        return shlex.split(custom)
    if mode == "local_systemd":
        unit = os.getenv("OLLAMA_LOG_SYSTEMD_UNIT", "ollama.service").strip() or "ollama.service"
        return ["journalctl", "-u", unit, "-f", "-n", "200", "--output=cat", "--no-pager"]
    if mode == "local_docker":
        container = os.getenv("OLLAMA_LOG_DOCKER_CONTAINER", "ollama").strip() or "ollama"
        return ["docker", "logs", "-f", "--tail", "200", container]
    raise ValueError(f"unsupported local log mode: {mode}")


def _resolve_nvidia_smi_argv(cmd_env: str) -> list[str]:
    if cmd_env:
        argv = shlex.split(cmd_env)
        if argv:
            return argv
    for candidate in NVIDIA_SMI_CANDIDATES:
        if candidate == "nvidia-smi":
            if shutil.which(candidate):
                return [candidate]
            continue
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return [candidate]
    return ["nvidia-smi"]


def query_nvidia_smi(timeout: float = 5.0) -> dict[str, Any]:
    cmd_env = os.getenv("OLLAMA_GPU_METRICS_CMD", "").strip()
    argv = _resolve_nvidia_smi_argv(cmd_env)
    if not shutil.which(argv[0]) and not (os.path.isfile(argv[0]) and os.access(argv[0], os.X_OK)):
        return {
            "available": False,
            "reason": f"{argv[0]} not found (mount host nvidia-smi into the sidecar or set OLLAMA_GPU_METRICS_CMD)",
            "gpus": [],
            "command": argv,
        }

    query = [
        *argv,
        "--query-gpu=index,name,memory.used,memory.total,memory.free,utilization.gpu,utilization.memory,temperature.gpu,power.draw",
        "--format=csv,noheader,nounits",
    ]
    code, stdout, stderr = _run_command(query, timeout=timeout)
    if code != 0:
        return {
            "available": False,
            "reason": (stderr or stdout or f"exit_{code}").strip()[:300],
            "gpus": [],
        }

    gpus: list[dict[str, Any]] = []
    for line in stdout.splitlines():
        parts = [part.strip() for part in line.split(",")]
        if len(parts) < 9:
            continue
        try:
            used_mib = float(parts[2])
            total_mib = float(parts[3])
            free_mib = float(parts[4])
        except ValueError:
            used_mib = total_mib = free_mib = 0.0
        gpus.append(
            {
                "index": int(parts[0]) if parts[0].isdigit() else parts[0],
                "name": parts[1],
                "memory_used_mib": used_mib,
                "memory_total_mib": total_mib,
                "memory_free_mib": free_mib,
                "utilization_gpu_pct": _safe_float(parts[5]),
                "utilization_memory_pct": _safe_float(parts[6]),
                "temperature_c": _safe_float(parts[7]),
                "power_draw_w": _safe_float(parts[8]),
            }
        )
    return {
        "available": bool(gpus),
        "reason": "" if gpus else "no_gpu_rows",
        "gpus": gpus,
        "command": argv,
    }


def _safe_float(value: str) -> float | None:
    text = (value or "").strip()
    if not text or text.upper() in {"N/A", "[N/A]"}:
        return None
    try:
        return float(text)
    except ValueError:
        return None


def _non_negative_float(value: Any) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if number >= 0 else None


def _read_cpu_totals(path: str = "/proc/stat") -> tuple[int, int] | None:
    try:
        with open(path, encoding="utf-8") as handle:
            fields = handle.readline().split()
    except (OSError, UnicodeError):
        return None
    if not fields or fields[0] != "cpu" or len(fields) < 5:
        return None
    try:
        values = [int(value) for value in fields[1:]]
    except ValueError:
        return None
    idle = values[3] + (values[4] if len(values) > 4 else 0)
    return sum(values), idle


def query_cpu_usage(sample_interval: float = 0.05) -> dict[str, Any]:
    first = _read_cpu_totals()
    if first is None:
        return {"available": False, "reason": "/proc/stat unavailable", "utilization_pct": None}
    time.sleep(max(0.0, min(float(sample_interval), 0.25)))
    second = _read_cpu_totals()
    if second is None:
        return {"available": False, "reason": "/proc/stat unavailable", "utilization_pct": None}
    total_delta = second[0] - first[0]
    idle_delta = second[1] - first[1]
    if total_delta <= 0:
        return {"available": False, "reason": "no CPU sample delta", "utilization_pct": None}
    utilization = max(0.0, min(100.0, 100.0 * (total_delta - idle_delta) / total_delta))
    return {
        "available": True,
        "reason": "",
        "utilization_pct": round(utilization, 1),
        "logical_cores": os.cpu_count() or 1,
    }


def infer_compute_engagement(models_loaded: list[dict[str, Any]]) -> dict[str, Any]:
    rows = [row for row in models_loaded if isinstance(row, dict)]
    total_size = sum(_non_negative_float(row.get("size")) or 0.0 for row in rows)
    total_vram = sum(_non_negative_float(row.get("size_vram")) or 0.0 for row in rows)
    gpu_engaged = total_vram > 0
    cpu_engaged = bool(rows) and (total_size <= 0 or total_vram < total_size)
    target = (
        "hybrid"
        if cpu_engaged and gpu_engaged
        else "gpu"
        if gpu_engaged
        else "cpu"
        if cpu_engaged
        else "idle"
    )
    return {
        "target": target,
        "cpu_engaged": cpu_engaged,
        "gpu_engaged": gpu_engaged,
        "model_size_bytes": int(total_size),
        "model_vram_bytes": int(total_vram),
    }


def probe_ollama_host(ollama_host: str, timeout: float = 5.0) -> dict[str, Any]:
    base = (ollama_host or "").strip().rstrip("/")
    if not base:
        return {
            "connected": False,
            "host": "",
            "detail": "OLLAMA_HOST is not configured",
        }

    result: dict[str, Any] = {
        "connected": False,
        "host": base,
        "version": "",
        "models_installed": 0,
        "models_loaded": [],
        "detail": "",
    }
    try:
        with httpx.Client(timeout=timeout) as client:
            version_resp = client.get(f"{base}/api/version")
            tags_resp = client.get(f"{base}/api/tags")
            ps_resp = client.get(f"{base}/api/ps")
        if version_resp.status_code == 200:
            result["version"] = str(version_resp.json().get("version", ""))
        if tags_resp.status_code == 200:
            tags_payload = tags_resp.json()
            models = tags_payload.get("models", []) if isinstance(tags_payload, dict) else []
            result["models_installed"] = len(models) if isinstance(models, list) else 0
        loaded: list[dict[str, Any]] = []
        if ps_resp.status_code == 200:
            ps_payload = ps_resp.json()
            rows = ps_payload.get("models", []) if isinstance(ps_payload, dict) else []
            if isinstance(rows, list):
                for row in rows:
                    if not isinstance(row, dict):
                        continue
                    loaded.append(
                        {
                            "name": str(row.get("name", "")),
                            "size_vram": row.get("size_vram"),
                            "size": row.get("size"),
                            "expires_at": row.get("expires_at"),
                        }
                    )
        result["models_loaded"] = loaded
        api_ok = version_resp.status_code == 200
        partial_ok = bool(loaded) or tags_resp.status_code == 200 or ps_resp.status_code == 200
        result["connected"] = api_ok or partial_ok
        if api_ok:
            result["detail"] = "ok"
        elif partial_ok:
            result["detail"] = f"version_http_{version_resp.status_code}_partial"
        else:
            result["detail"] = f"version_http_{version_resp.status_code}"
        return result
    except Exception as exc:
        result["detail"] = f"{type(exc).__name__}:{exc}"
        return result


def collect_ops_snapshot(ollama_host: str) -> dict[str, Any]:
    ollama = probe_ollama_host(ollama_host)
    loaded = ollama.get("models_loaded") if isinstance(ollama.get("models_loaded"), list) else []
    return {
        "ts": utc_now_iso(),
        "ollama": ollama,
        "gpu": query_nvidia_smi(),
        "cpu": query_cpu_usage(),
        "compute": infer_compute_engagement(loaded),
        "log_source": ollama_log_config_status(),
    }


def resolve_ollama_connection_state(
    ollama: dict[str, Any],
    *,
    gpu_vram_used_gb: float | None = None,
) -> tuple[bool, str]:
    """Infer UI connection state when the HTTP probe and host GPU signals disagree."""
    if bool(ollama.get("connected")):
        return True, "connected"
    loaded = ollama.get("models_loaded") if isinstance(ollama.get("models_loaded"), list) else []
    if loaded:
        return True, "degraded"
    if gpu_vram_used_gb is not None and float(gpu_vram_used_gb) >= 0.5:
        return True, "degraded"
    return False, "offline"


def collect_analyst_ops_summary(ollama_host: str) -> dict[str, Any]:
    """Minimal analyst-safe runtime snapshot without logs or full model payloads."""
    snapshot = collect_ops_snapshot(ollama_host)
    ollama = snapshot.get("ollama") if isinstance(snapshot.get("ollama"), dict) else {}
    gpu_block = snapshot.get("gpu") if isinstance(snapshot.get("gpu"), dict) else {}
    cpu_block = snapshot.get("cpu") if isinstance(snapshot.get("cpu"), dict) else {}
    compute = snapshot.get("compute") if isinstance(snapshot.get("compute"), dict) else {}
    gpus = gpu_block.get("gpus") if isinstance(gpu_block.get("gpus"), list) else []
    first_gpu = gpus[0] if gpus and isinstance(gpus[0], dict) else {}
    used_gb: float | None = None
    total_gb: float | None = None
    gpu_utilization_pct: float | None = None
    if first_gpu:
        used_mib = _non_negative_float(first_gpu.get("memory_used_mib"))
        total_mib = _non_negative_float(first_gpu.get("memory_total_mib"))
        if used_mib is not None:
            used_gb = round(used_mib / 1024, 1)
        if total_mib is not None:
            total_gb = round(total_mib / 1024, 1)
        gpu_utilization_pct = _non_negative_float(first_gpu.get("utilization_gpu_pct"))
    loaded = ollama.get("models_loaded") if isinstance(ollama.get("models_loaded"), list) else []
    loaded_names = [
        str(row.get("name", "")).strip()
        for row in loaded
        if isinstance(row, dict) and str(row.get("name", "")).strip()
    ]
    if used_gb is None and loaded:
        ollama_vram_bytes = sum(
            _non_negative_float(row.get("size_vram")) or 0.0
            for row in loaded
            if isinstance(row, dict)
        )
        if ollama_vram_bytes > 0:
            used_gb = round(ollama_vram_bytes / (1024**3), 1)
    host = str(ollama.get("host", "")).strip()
    display_host = host.replace("http://", "").replace("https://", "")
    connected, connection_state = resolve_ollama_connection_state(ollama, gpu_vram_used_gb=used_gb)
    return {
        "connected": connected,
        "connection_state": connection_state,
        "host": display_host,
        "models_loaded": len(loaded),
        "models_loaded_names": loaded_names[:8],
        "gpu_vram_used_gb": used_gb,
        "gpu_vram_total_gb": total_gb,
        "gpu_utilization_pct": gpu_utilization_pct,
        "gpu_metrics_available": bool(gpu_block.get("available")),
        "gpu_metrics_reason": str(gpu_block.get("reason", "")).strip(),
        "gpu_metrics_source": "nvidia_smi" if first_gpu else ("ollama_api" if used_gb is not None else "unavailable"),
        "cpu_utilization_pct": _non_negative_float(cpu_block.get("utilization_pct")),
        "cpu_metrics_available": bool(cpu_block.get("available")),
        "cpu_metrics_reason": str(cpu_block.get("reason", "")).strip(),
        "cpu_engaged": bool(compute.get("cpu_engaged")),
        "gpu_engaged": bool(compute.get("gpu_engaged")),
        "compute_target": str(compute.get("target", "idle")).strip() or "idle",
        "updated_at": str(snapshot.get("ts", "")),
    }
