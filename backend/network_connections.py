from __future__ import annotations

import ipaddress
import platform
import socket
import subprocess
import time
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import psutil


_FIRST_SEEN: Dict[str, float] = {}
_SIG_CACHE: Dict[str, Dict[str, Any]] = {}


def _is_windows() -> bool:
    return platform.system().lower() == "windows"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _format_addr(addr: Any) -> Optional[Dict[str, Any]]:
    if not addr:
        return None
    try:
        ip = getattr(addr, "ip", None) or addr[0]
        port = getattr(addr, "port", None) or addr[1]
        return {"ip": ip, "port": int(port) if port is not None else None}
    except Exception:
        return None


def _is_private_ip(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return bool(a.is_private or a.is_loopback or a.is_link_local)
    except Exception:
        return False


def _is_common_port(port: Optional[int]) -> bool:
    if not isinstance(port, int):
        return False
    common = {
        20,
        21,
        22,
        23,
        25,
        53,
        67,
        68,
        80,
        110,
        123,
        135,
        137,
        138,
        139,
        143,
        389,
        443,
        445,
        465,
        587,
        636,
        993,
        995,
        1433,
        1521,
        3306,
        3389,
        5432,
        5985,
        5986,
        8080,
        8443,
    }
    return port in common


def _is_ephemeral_local_port(port: Optional[int]) -> bool:
    if not isinstance(port, int):
        return False
    # Windows default ephemeral range is typically 49152-65535.
    return 49152 <= port <= 65535


def _first_seen_key(item: Dict[str, Any]) -> str:
    pid = item.get("pid")
    proto = item.get("proto")
    raddr = item.get("raddr") if isinstance(item.get("raddr"), dict) else {}
    rip = raddr.get("ip")
    rport = raddr.get("port")
    return f"{pid}:{proto}:{rip}:{rport}"


def _prune_first_seen(now: float, *, max_items: int = 50000, max_age_s: float = 24 * 3600) -> None:
    if len(_FIRST_SEEN) <= max_items:
        # Still prune old ones occasionally
        keys = [k for k, ts in _FIRST_SEEN.items() if (now - ts) > max_age_s]
        for k in keys[:2000]:
            _FIRST_SEEN.pop(k, None)
        return

    # Aggressive prune
    keys = sorted(_FIRST_SEEN.items(), key=lambda kv: kv[1])
    for k, _ts in keys[: int(max_items * 0.2)]:
        _FIRST_SEEN.pop(k, None)


def _escape_ps_single_quotes(s: str) -> str:
    return (s or "").replace("'", "''")


def _authenticode_signature_status(exe_path: str, *, timeout_s: float = 2.5) -> Dict[str, Any]:
    """Best-effort Authenticode signature status for a file path (Windows only)."""
    if not exe_path:
        return {"ok": False, "error": "missing path"}
    if not _is_windows():
        return {"ok": False, "error": "not windows"}

    cached = _SIG_CACHE.get(exe_path)
    if cached:
        return cached

    p = _escape_ps_single_quotes(exe_path)
    ps = (
        "try { "
        f"$s = Get-AuthenticodeSignature -FilePath '{p}' -ErrorAction Stop; "
        "$o = [ordered]@{ Status = $s.Status; StatusMessage=$s.StatusMessage; "
        "SignerCertificateSubject = ($s.SignerCertificate.Subject); "
        "SignerCertificateIssuer = ($s.SignerCertificate.Issuer) }; "
        "$o | ConvertTo-Json -Depth 4 } catch { '{}' }"
    )

    started = time.monotonic()
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=timeout_s,
        )
        elapsed_ms = int((time.monotonic() - started) * 1000)
        out = (proc.stdout or "").strip()
        parsed = None
        if out.startswith("{") and out.endswith("}"):
            try:
                parsed = json.loads(out)
            except Exception:
                parsed = None

        result = {
            "ok": proc.returncode == 0,
            "elapsed_ms": elapsed_ms,
            "raw": out[:4000],
            "parsed": parsed,
        }
        _SIG_CACHE[exe_path] = result
        # Small cache bound
        if len(_SIG_CACHE) > 2000:
            for k in list(_SIG_CACHE.keys())[:200]:
                _SIG_CACHE.pop(k, None)
        return result
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "timeout"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def list_connections(
    *,
    limit: int = 500,
    include_listen: bool = True,
    include_flags: bool = True,
    include_signature: bool = False,
) -> Dict[str, Any]:
    """Return current TCP/UDP connections (inet) with process names and heuristics."""

    hostname = socket.gethostname()
    collected_at = _now_iso()

    limit_i = max(50, min(5000, int(limit)))

    started = time.monotonic()
    conns = psutil.net_connections(kind="inet")

    items: List[Dict[str, Any]] = []
    now = time.time()
    _prune_first_seen(now)

    signature_checks_budget = 50
    for c in conns:
        try:
            status = str(getattr(c, "status", "") or "")
            if not include_listen and status.upper() == "LISTEN":
                continue

            pid = getattr(c, "pid", None)
            proc_name = None
            exe_path = None
            if isinstance(pid, int) and pid > 0:
                try:
                    p = psutil.Process(pid)
                    proc_name = p.name()
                    # exe() can be slow/permission denied
                    try:
                        exe_path = p.exe()
                    except Exception:
                        exe_path = None
                except Exception:
                    proc_name = None

            laddr = _format_addr(getattr(c, "laddr", None))
            raddr = _format_addr(getattr(c, "raddr", None))

            base: Dict[str, Any] = {
                "fd": getattr(c, "fd", None),
                "family": str(getattr(c, "family", None)),
                "type": str(getattr(c, "type", None)),
                "proto": "TCP" if str(getattr(c, "type", "")).endswith("SOCK_STREAM") else "UDP",
                "laddr": laddr,
                "raddr": raddr,
                "status": status,
                "pid": pid,
                "process": proc_name,
                "exe": exe_path,
            }

            if include_flags:
                rip = (raddr or {}).get("ip") if isinstance(raddr, dict) else None
                rport = (raddr or {}).get("port") if isinstance(raddr, dict) else None
                lport = (laddr or {}).get("port") if isinstance(laddr, dict) else None

                is_external = bool(rip) and not _is_private_ip(str(rip))
                is_common_remote_port = _is_common_port(rport)
                is_ephemeral = _is_ephemeral_local_port(lport)

                key = _first_seen_key(base)
                first = _FIRST_SEEN.get(key)
                if first is None:
                    _FIRST_SEEN[key] = now
                    first = now
                is_new = (now - float(first)) < 300.0

                base["flags"] = {
                    "is_external": is_external,
                    "is_new": is_new,
                    "first_seen_epoch": first,
                    "has_remote": bool(rip),
                    "is_ephemeral_local_port": is_ephemeral,
                    "is_common_remote_port": is_common_remote_port,
                    "is_unusual_remote_port": bool(rip) and (not is_common_remote_port) and isinstance(rport, int),
                }

                # Optional: Authenticode signature status (best-effort)
                if include_signature and signature_checks_budget > 0 and isinstance(exe_path, str) and exe_path:
                    base["signature"] = _authenticode_signature_status(exe_path)
                    signature_checks_budget -= 1
                else:
                    base["signature"] = None

            items.append(base)
        except Exception:
            continue

        if len(items) >= limit_i:
            break

    # Sort: ESTABLISHED first, then LISTEN, then others
    def _rank(s: str) -> int:
        s2 = (s or "").upper()
        if s2 == "ESTABLISHED":
            return 0
        if s2 == "LISTEN":
            return 1
        return 2

    items.sort(
        key=lambda x: (
            _rank(str(x.get("status") or "")),
            str((x.get("process") or "")),
            str(((x.get("raddr") or {}).get("ip") if isinstance(x.get("raddr"), dict) else "") or ""),
        )
    )

    elapsed_ms = int((time.monotonic() - started) * 1000)

    return {
        "collected_at": collected_at,
        "hostname": hostname,
        "summary": {"count": len(items), "limit": limit_i, "elapsed_ms": elapsed_ms},
        "connections": items,
    }
