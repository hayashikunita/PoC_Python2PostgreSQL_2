from __future__ import annotations

import platform
import re
import socket
import subprocess
import time
import ssl
from urllib.parse import urlparse
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import requests


_HOST_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,252}$")
_IP_RE = re.compile(r"^[0-9a-fA-F:.]{2,64}$")


def _is_windows() -> bool:
    return platform.system().lower() == "windows"


def _trim(s: str, *, limit: int) -> str:
    if not s:
        return ""
    s2 = s.strip()
    if len(s2) <= limit:
        return s2
    return s2[:limit] + "\n...(truncated)"


def _run_cmd(cmd: List[str], *, timeout_s: float, stdout_limit: int = 8000, stderr_limit: int = 2000) -> Dict[str, Any]:
    started = time.monotonic()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=timeout_s,
        )
        elapsed_ms = int((time.monotonic() - started) * 1000)
        return {
            "ok": proc.returncode == 0,
            "returncode": proc.returncode,
            "elapsed_ms": elapsed_ms,
            "stdout": _trim(proc.stdout or "", limit=stdout_limit),
            "stderr": _trim(proc.stderr or "", limit=stderr_limit),
        }
    except subprocess.TimeoutExpired:
        elapsed_ms = int((time.monotonic() - started) * 1000)
        return {"ok": False, "elapsed_ms": elapsed_ms, "error": "timeout"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _run_powershell(ps_command: str, *, timeout_s: float = 6.0) -> Dict[str, Any]:
    if not _is_windows():
        return {"ok": False, "error": "not windows"}
    return _run_cmd(["powershell", "-NoProfile", "-Command", ps_command], timeout_s=timeout_s)


def get_default_gateway() -> Dict[str, Any]:
    """Return default gateway (best-effort)."""
    if not _is_windows():
        return {"ok": False, "error": "not windows"}

    # Prefer Get-NetRoute (newer Windows)
    ps = (
        "try { "
        "($r = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop | Sort-Object RouteMetric | Select-Object -First 1); "
        "$r.NextHop } catch { '' }"
    )
    r = _run_powershell(ps, timeout_s=5.0)
    gw = None
    if r.get("ok") and isinstance(r.get("stdout"), str):
        gw_s = r.get("stdout").strip().splitlines()[:1]
        gw = gw_s[0].strip() if gw_s and gw_s[0].strip() else None

    if gw:
        return {"ok": True, "default_gateway": gw, "source": "Get-NetRoute"}

    # Fallback: parse route print output
    rr = _run_cmd(["route", "print", "-4"], timeout_s=5.0, stdout_limit=12000)
    out = rr.get("stdout") if isinstance(rr, dict) else None
    if isinstance(out, str):
        # Very loose parse: find line like "0.0.0.0          0.0.0.0      <gw>"
        for line in out.splitlines():
            if line.strip().startswith("0.0.0.0"):
                parts = line.split()
                if len(parts) >= 3 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                    gw2 = parts[2].strip()
                    if gw2:
                        return {"ok": True, "default_gateway": gw2, "source": "route print"}
    return {"ok": False, "error": "default gateway not found"}


def get_dns_servers() -> Dict[str, Any]:
    if not _is_windows():
        return {"ok": False, "error": "not windows"}
    ps = (
        "try { "
        "Get-DnsClientServerAddress -AddressFamily IPv4 | "
        "Select-Object -ExpandProperty ServerAddresses | Where-Object { $_ } "
        "} catch { }"
    )
    r = _run_powershell(ps, timeout_s=6.0)
    servers: List[str] = []
    if r.get("ok") and isinstance(r.get("stdout"), str):
        for line in r["stdout"].splitlines():
            s = line.strip()
            if s and s not in servers:
                servers.append(s)
    return {"ok": True, "servers": servers, "raw": r}


def nslookup_server(hostname: str, server: str, *, timeout_s: float = 4.0) -> Dict[str, Any]:
    name = (hostname or "").strip()
    srv = (server or "").strip()
    if not _is_reasonable_host(name) or not _is_reasonable_host(srv):
        return {"ok": False, "target": name, "server": srv, "error": "invalid hostname/server"}

    r = _run_cmd(["nslookup", name, srv], timeout_s=timeout_s, stdout_limit=8000)
    stdout = r.get("stdout") if isinstance(r, dict) else ""
    ips: List[str] = []
    if isinstance(stdout, str):
        # collect IPv4/IPv6 address lines
        for line in stdout.splitlines():
            if "Address:" in line:
                v = line.split("Address:", 1)[-1].strip()
                if v and v not in ips:
                    ips.append(v)
    ok = bool(r.get("ok")) and len(ips) > 0
    out = {"ok": ok, "target": name, "server": srv, "addresses": ips}
    out.update({k: r.get(k) for k in ("elapsed_ms", "returncode") if isinstance(r, dict)})
    if not ok:
        out["error"] = r.get("stderr") or "nslookup failed"
        out["raw"] = stdout
    return out


def tracert(target: str, *, max_hops: int = 15, timeout_ms: int = 1000) -> Dict[str, Any]:
    t = (target or "").strip()
    if not _is_reasonable_host(t):
        return {"ok": False, "target": target, "error": "invalid host"}
    if not _is_windows():
        return {"ok": False, "target": t, "error": "tracert is windows-only"}

    hops_i = max(3, min(30, int(max_hops)))
    timeout_i = max(200, min(5000, int(timeout_ms)))

    r = _run_cmd(["tracert", "-d", "-h", str(hops_i), "-w", str(timeout_i), t], timeout_s=30.0, stdout_limit=12000)
    out = r.get("stdout") if isinstance(r, dict) else ""
    lines = out.splitlines() if isinstance(out, str) else []
    # Keep last lines (header can be noisy)
    tail = lines[-80:]
    return {
        "ok": bool(r.get("ok")),
        "target": t,
        "elapsed_ms": r.get("elapsed_ms"),
        "returncode": r.get("returncode"),
        "lines": tail,
        "stderr": r.get("stderr"),
    }


def proxy_pac_info() -> Dict[str, Any]:
    if not _is_windows():
        return {"ok": False, "error": "not windows"}

    # IE/WinINET settings (HKCU)
    ps = (
        "try { "
        "$p = Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -ErrorAction Stop; "
        "$o = [ordered]@{ ProxyEnable=$p.ProxyEnable; ProxyServer=$p.ProxyServer; ProxyOverride=$p.ProxyOverride; AutoConfigURL=$p.AutoConfigURL; AutoDetect=$p.AutoDetect }; "
        "$o | ConvertTo-Json -Depth 4 } catch { '{}' }"
    )
    ie = _run_powershell(ps, timeout_s=6.0)
    winhttp = _run_cmd(["netsh", "winhttp", "show", "proxy"], timeout_s=6.0, stdout_limit=6000)

    return {
        "ok": True,
        "inet_settings_raw": ie.get("stdout"),
        "winhttp_raw": winhttp.get("stdout"),
    }


def tls_handshake(url: str, *, timeout_s: float = 4.0) -> Dict[str, Any]:
    u = (url or "").strip()
    try:
        p = urlparse(u)
    except Exception:
        return {"ok": False, "target": url, "error": "invalid url"}

    if p.scheme.lower() != "https":
        return {"ok": False, "target": u, "error": "https only"}
    host = p.hostname
    port = int(p.port or 443)
    if not host:
        return {"ok": False, "target": u, "error": "missing host"}

    timeout_f = max(1.0, min(15.0, float(timeout_s)))
    started = time.monotonic()

    def _cert_dict(cert: Any) -> Optional[Dict[str, Any]]:
        if not isinstance(cert, dict):
            return None
        out: Dict[str, Any] = {}
        for k in ("subject", "issuer", "notBefore", "notAfter", "serialNumber", "subjectAltName"):
            if k in cert:
                out[k] = cert.get(k)
        return out

    # Verified handshake
    verify_ok = False
    verify_error = None
    cert_info = None
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout_f) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert_info = _cert_dict(ssock.getpeercert())
                verify_ok = True
    except Exception as e:
        verify_error = str(e)

    # If verify failed, try unverified to at least fetch certificate details
    if not verify_ok:
        try:
            ctx2 = ssl.create_default_context()
            ctx2.check_hostname = False
            ctx2.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=timeout_f) as sock:
                with ctx2.wrap_socket(sock, server_hostname=host) as ssock:
                    cert_info = _cert_dict(ssock.getpeercert())
        except Exception:
            pass

    elapsed_ms = int((time.monotonic() - started) * 1000)
    ok = verify_ok
    out = {
        "ok": ok,
        "target": u,
        "host": host,
        "port": port,
        "elapsed_ms": elapsed_ms,
        "verify_ok": verify_ok,
        "verify_error": verify_error,
        "cert": cert_info,
    }
    return out


def _is_reasonable_host(value: str) -> bool:
    if not value or not isinstance(value, str):
        return False
    v = value.strip()
    if not v or len(v) > 255:
        return False
    return bool(_HOST_RE.match(v) or _IP_RE.match(v))


def ping_once(host: str, *, timeout_ms: int = 1000) -> Dict[str, Any]:
    host_s = (host or "").strip()
    if not _is_reasonable_host(host_s):
        return {"ok": False, "target": host, "error": "invalid host"}

    timeout_ms_i = max(200, min(5000, int(timeout_ms)))

    if _is_windows():
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms_i), host_s]
        timeout_s = max(1.0, (timeout_ms_i / 1000.0) + 1.5)
    else:
        # Linux/macOS
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout_ms_i / 1000))), host_s]
        timeout_s = max(1.0, (timeout_ms_i / 1000.0) + 1.5)

    started = time.monotonic()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=timeout_s,
        )
        elapsed_ms = int((time.monotonic() - started) * 1000)
        out = (proc.stdout or "")
        err = (proc.stderr or "")
        # Keep payload small.
        out = out.strip()[:4000]
        err = err.strip()[:2000]
        return {
            "ok": proc.returncode == 0,
            "target": host_s,
            "elapsed_ms": elapsed_ms,
            "returncode": proc.returncode,
            "stdout": out,
            "stderr": err,
        }
    except subprocess.TimeoutExpired:
        elapsed_ms = int((time.monotonic() - started) * 1000)
        return {"ok": False, "target": host_s, "elapsed_ms": elapsed_ms, "error": "timeout"}
    except Exception as e:
        return {"ok": False, "target": host_s, "error": str(e)}


def dns_lookup(hostname: str) -> Dict[str, Any]:
    name = (hostname or "").strip()
    if not _is_reasonable_host(name):
        return {"ok": False, "target": hostname, "error": "invalid hostname"}

    try:
        infos = socket.getaddrinfo(name, None)
        addrs: List[str] = []
        for family, _socktype, _proto, _canonname, sockaddr in infos:
            if not sockaddr:
                continue
            addr = sockaddr[0]
            if isinstance(addr, str):
                addrs.append(addr)
        # unique
        uniq = []
        for a in addrs:
            if a not in uniq:
                uniq.append(a)
        return {"ok": True, "target": name, "addresses": uniq}
    except Exception as e:
        return {"ok": False, "target": name, "error": str(e)}


def http_check(url: str, *, timeout_s: float = 4.0, use_proxy: bool = True) -> Dict[str, Any]:
    u = (url or "").strip()
    if not (u.startswith("http://") or u.startswith("https://")):
        return {"ok": False, "target": url, "error": "url must start with http:// or https://"}

    timeout_f = max(1.0, min(15.0, float(timeout_s)))
    proxies: Optional[Dict[str, Optional[str]]]
    if use_proxy:
        proxies = None  # requests uses env proxies
    else:
        proxies = {"http": None, "https": None}

    started = time.monotonic()
    try:
        resp = requests.get(u, timeout=timeout_f, allow_redirects=True, proxies=proxies)
        elapsed_ms = int((time.monotonic() - started) * 1000)
        ct = resp.headers.get("content-type")
        return {
            "ok": 200 <= int(resp.status_code) < 400,
            "target": u,
            "elapsed_ms": elapsed_ms,
            "status_code": int(resp.status_code),
            "final_url": str(getattr(resp, "url", u)),
            "content_type": ct,
        }
    except requests.exceptions.ProxyError as e:
        elapsed_ms = int((time.monotonic() - started) * 1000)
        return {"ok": False, "target": u, "elapsed_ms": elapsed_ms, "error": f"proxy error: {e}"}
    except requests.exceptions.Timeout:
        elapsed_ms = int((time.monotonic() - started) * 1000)
        return {"ok": False, "target": u, "elapsed_ms": elapsed_ms, "error": "timeout"}
    except Exception as e:
        elapsed_ms = int((time.monotonic() - started) * 1000)
        return {"ok": False, "target": u, "elapsed_ms": elapsed_ms, "error": str(e)}


def run_connectivity_suite(
    *,
    ping_targets: List[str],
    dns_targets: List[str],
    http_targets: List[str],
    ping_timeout_ms: int = 1000,
    http_timeout_s: float = 4.0,
    use_proxy: bool = True,
    deep_checks: bool = False,
    trace_targets: Optional[List[str]] = None,
    tls_targets: Optional[List[str]] = None,
) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "ping": [ping_once(t, timeout_ms=ping_timeout_ms) for t in (ping_targets or [])],
        "dns": [dns_lookup(t) for t in (dns_targets or [])],
        "http": [http_check(t, timeout_s=http_timeout_s, use_proxy=use_proxy) for t in (http_targets or [])],
    }

    if not deep_checks:
        return out

    deep: Dict[str, Any] = {"is_windows": _is_windows()}

    # Default gateway
    gw = get_default_gateway()
    deep["default_gateway"] = gw
    gw_ip = gw.get("default_gateway") if isinstance(gw, dict) else None
    if isinstance(gw_ip, str) and gw_ip:
        deep["gateway_ping"] = ping_once(gw_ip, timeout_ms=ping_timeout_ms)

    # DNS servers + per-server nslookup
    dns_servers = get_dns_servers()
    deep["dns_servers"] = dns_servers
    servers = dns_servers.get("servers") if isinstance(dns_servers, dict) else None
    if isinstance(servers, list) and servers:
        per: List[Dict[str, Any]] = []
        for name in (dns_targets or [])[:5]:
            for s in servers[:5]:
                per.append(nslookup_server(name, s, timeout_s=4.0))
        deep["dns_by_server"] = per

    # Proxy auto detect / PAC
    deep["proxy"] = proxy_pac_info()

    # TLS handshake (https only)
    tls_list = tls_targets if isinstance(tls_targets, list) else None
    if not tls_list:
        tls_list = [u for u in (http_targets or []) if isinstance(u, str) and u.strip().startswith("https://")]
    deep["tls"] = [tls_handshake(u, timeout_s=http_timeout_s) for u in (tls_list or [])[:5]]

    # Traceroute
    trace_list = trace_targets if isinstance(trace_targets, list) else None
    if not trace_list:
        trace_list = (ping_targets or [])[:1]
    deep["traceroute"] = [tracert(t) for t in (trace_list or [])[:2]]

    out["deep"] = deep
    return out
