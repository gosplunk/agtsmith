#!/usr/bin/env python3
"""Local Ollama ops telemetry: GPU metrics, runtime status, and log source detection."""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
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
        result["connected"] = version_resp.status_code == 200
        if not result["connected"]:
            result["detail"] = f"version_http_{version_resp.status_code}"
        else:
            result["detail"] = "ok"
        return result
    except Exception as exc:
        result["detail"] = f"{type(exc).__name__}:{exc}"
        return result


def collect_ops_snapshot(ollama_host: str) -> dict[str, Any]:
    return {
        "ts": utc_now_iso(),
        "ollama": probe_ollama_host(ollama_host),
        "gpu": query_nvidia_smi(),
        "log_source": ollama_log_config_status(),
    }
