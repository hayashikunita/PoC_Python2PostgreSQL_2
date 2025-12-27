from __future__ import annotations

import base64
import os
import platform
import socket
from datetime import datetime, timezone
from typing import Any, Dict, List

import psutil

import subprocess
import json


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_windows() -> bool:
    return platform.system().lower() == "windows"


def _run_powershell_base64_json(command: str, timeout_s: int = 10) -> List[Dict[str, Any]]:
    """PowerShellでBase64(JSON)を返してもらい、Python側で復号してdict配列にする。"""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=timeout_s,
        )
    except Exception:
        return []

    if result.returncode != 0:
        return []

    raw = (result.stdout or "").strip()
    if not raw:
        return []

    try:
        data = base64.b64decode(raw.encode("ascii"), validate=False)
        text = data.decode("utf-8", errors="strict")
        parsed = json.loads(text)
        if isinstance(parsed, list):
            return [x for x in parsed if isinstance(x, dict)]
        if isinstance(parsed, dict):
            return [parsed]
        return []
    except Exception:
        return []


def _gpu_info_windows() -> List[Dict[str, Any]]:
    # Win32_VideoController の主要項目
    ps = (
        "$g=Get-CimInstance Win32_VideoController | "
        "Select-Object Name, DriverVersion, AdapterRAM, VideoProcessor, "
        "CurrentHorizontalResolution, CurrentVerticalResolution, CurrentRefreshRate; "
        "$json=@($g) | ConvertTo-Json -Depth 3 -Compress; "
        "[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($json))"
    )
    return _run_powershell_base64_json(ps, timeout_s=10)


def _safe_cpu_freq() -> Dict[str, Any]:
    try:
        f = psutil.cpu_freq()
        if not f:
            return {}
        return {
            "current_mhz": getattr(f, "current", None),
            "min_mhz": getattr(f, "min", None),
            "max_mhz": getattr(f, "max", None),
        }
    except Exception:
        return {}


def _disk_overview() -> List[Dict[str, Any]]:
    disks: List[Dict[str, Any]] = []
    try:
        for p in psutil.disk_partitions(all=False):
            try:
                usage = psutil.disk_usage(p.mountpoint)
                disks.append(
                    {
                        "device": p.device,
                        "mountpoint": p.mountpoint,
                        "fstype": p.fstype,
                        "opts": p.opts,
                        "total": int(usage.total),
                        "used": int(usage.used),
                        "free": int(usage.free),
                        "percent": float(usage.percent),
                    }
                )
            except Exception:
                disks.append(
                    {
                        "device": p.device,
                        "mountpoint": p.mountpoint,
                        "fstype": p.fstype,
                        "opts": p.opts,
                    }
                )
    except Exception:
        pass
    return disks


def collect_system_specs() -> Dict[str, Any]:
    """PCスペック（OS/CPU/メモリ/ディスクなど）の概要を返す。"""

    uname = platform.uname()

    # メモリ
    mem_total = None
    mem_available = None
    try:
        vm = psutil.virtual_memory()
        mem_total = int(vm.total)
        mem_available = int(vm.available)
    except Exception:
        pass

    # ブート時刻
    boot_time_iso = None
    try:
        bt = psutil.boot_time()
        boot_time_iso = datetime.fromtimestamp(bt, tz=timezone.utc).isoformat()
    except Exception:
        pass

    payload: Dict[str, Any] = {
        "collected_at": _now_iso(),
        "hostname": socket.gethostname(),
        "os": {
            "system": uname.system,
            "node": uname.node,
            "release": uname.release,
            "version": uname.version,
            "machine": uname.machine,
            "processor": uname.processor,
            "platform": platform.platform(),
        },
        "cpu": {
            "physical_cores": psutil.cpu_count(logical=False),
            "logical_cores": psutil.cpu_count(logical=True),
            "freq": _safe_cpu_freq(),
            "env_processor_identifier": os.getenv("PROCESSOR_IDENTIFIER"),
        },
        "memory": {
            "total": mem_total,
            "available": mem_available,
        },
        "boot_time": boot_time_iso,
        "disks": _disk_overview(),
    }

    if _is_windows():
        payload["gpu"] = _gpu_info_windows()
    else:
        payload["gpu"] = []

    return payload
