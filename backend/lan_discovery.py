from __future__ import annotations

import ipaddress
import json
import platform
import re
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from threading import Lock
from typing import Any, Dict, List, Optional

import psutil


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_windows() -> bool:
    return platform.system().lower() == "windows"


def _trim(s: str, *, limit: int) -> str:
    if not s:
        return ""
    s2 = s.strip()
    if len(s2) <= limit:
        return s2
    return s2[:limit] + "\n...(truncated)"


def _run_cmd(cmd: List[str], *, timeout_s: float, stdout_limit: int = 12000, stderr_limit: int = 2000) -> Dict[str, Any]:
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


_NSLOOKUP_NAME_RE = re.compile(r"^\s*(?:Name|名前)\s*:\s*(?P<name>.+?)\s*$", re.IGNORECASE)

_NBTSTAT_NAME_RE = re.compile(r"^\s*(?P<name>[^\s<]{1,32})\s*<00>\s+UNIQUE\s+Registered\s*$", re.IGNORECASE)


def _nbtstat_name_windows(ip: str, *, timeout_s: float) -> Optional[str]:
    if not _is_windows():
        return None
    r = _run_cmd(["nbtstat", "-A", ip], timeout_s=timeout_s, stdout_limit=6000, stderr_limit=1500)
    out = (r.get("stdout") or "") if isinstance(r, dict) else ""
    for line in out.splitlines():
        m = _NBTSTAT_NAME_RE.match(line)
        if m:
            return (m.group("name") or "").strip() or None
    return None


_MAC_HEX_RE = re.compile(r"^[0-9a-fA-F]{12}$")
_VENDOR_OUI_CACHE: Dict[str, Optional[str]] = {}
_VENDOR_CACHE_LOCK = Lock()
_VENDOR_RATE_LOCK = Lock()
_VENDOR_NEXT_ALLOWED_AT = 0.0

_SEEN_LOCK = Lock()
_SEEN_BY_IP: Dict[str, Dict[str, str]] = {}


def _vendor_rate_limit_wait(*, min_interval_s: float) -> None:
    """Serialize vendor API calls to avoid rate limiting (best-effort)."""

    global _VENDOR_NEXT_ALLOWED_AT
    if min_interval_s <= 0:
        return
    with _VENDOR_RATE_LOCK:
        now = time.monotonic()
        wait_s = max(0.0, float(_VENDOR_NEXT_ALLOWED_AT) - now)
        if wait_s > 0:
            time.sleep(wait_s)
        _VENDOR_NEXT_ALLOWED_AT = time.monotonic() + float(min_interval_s)


def _update_seen_times(ip: str, *, now_iso: str) -> Dict[str, str]:
    """Update and return seen times for an IP (process-lifetime cache)."""

    ip_s = (ip or "").strip()
    if not ip_s:
        return {}
    with _SEEN_LOCK:
        cur = _SEEN_BY_IP.get(ip_s)
        if not cur:
            cur = {"first_seen": now_iso, "last_seen": now_iso}
            _SEEN_BY_IP[ip_s] = cur
            return dict(cur)
        cur["last_seen"] = now_iso
        if "first_seen" not in cur:
            cur["first_seen"] = now_iso
        return dict(cur)


def _guess_subnet_and_if(interfaces: List[Dict[str, Any]], ip: str) -> Dict[str, Optional[str]]:
    ip_s = (ip or "").strip()
    if not ip_s:
        return {"subnet": None, "if_guess": None}
    try:
        ip_obj = ipaddress.ip_address(ip_s)
    except Exception:
        return {"subnet": None, "if_guess": None}
    if ip_obj.version != 4:
        return {"subnet": None, "if_guess": None}

    candidates = []
    for itf in interfaces or []:
        if not isinstance(itf, dict):
            continue
        cidr = itf.get("cidr")
        ifname = itf.get("name")
        if not cidr:
            continue
        try:
            net = ipaddress.ip_network(str(cidr), strict=False)
        except Exception:
            continue
        if net.version != 4:
            continue
        if ip_obj in net:
            candidates.append((int(net.prefixlen), str(net), str(ifname or "")))

    if not candidates:
        return {"subnet": None, "if_guess": None}
    # Most specific (largest prefix)
    candidates.sort(key=lambda x: x[0], reverse=True)
    return {"subnet": candidates[0][1], "if_guess": candidates[0][2] or None}


_PING_TIME_RE = re.compile(r"(?:time|時間)\s*[=<]\s*(?P<ms>\d+)", re.IGNORECASE)
_PING_TIME_LT1_RE = re.compile(r"(?:time|時間)\s*<\s*1\s*ms", re.IGNORECASE)
_PING_TTL_RTT_RE = re.compile(r"(?P<ms>\d+)\s*ms\s*TTL=", re.IGNORECASE)
_PING_TTL_LT1_RE = re.compile(r"<\s*1\s*ms\s*TTL=", re.IGNORECASE)


def _ping_one(ip: str, *, timeout_ms: int) -> Dict[str, Any]:
    ip_s = (ip or "").strip()
    if not ip_s:
        return {"ok": False, "ip": ip, "rtt_ms": None}

    timeout_ms_i = max(50, int(timeout_ms))
    if _is_windows():
        r = _run_cmd(["ping", "-n", "1", "-w", str(timeout_ms_i), ip_s], timeout_s=max(1.0, (timeout_ms_i / 1000.0) + 0.9), stdout_limit=3000, stderr_limit=800)
        out = (r.get("stdout") or "") if isinstance(r, dict) else ""
        rtt = None
        if _PING_TIME_LT1_RE.search(out) or _PING_TTL_LT1_RE.search(out):
            rtt = 1
        m = _PING_TIME_RE.search(out) or _PING_TTL_RTT_RE.search(out)
        if m and rtt is None:
            try:
                rtt = int(m.group("ms"))
            except Exception:
                rtt = None
        ok = bool(r.get("ok")) if isinstance(r, dict) else False
        # Windows ping sometimes returns non-zero even when we have RTT; treat RTT as success.
        if rtt is not None:
            ok = True
        return {"ok": ok, "ip": ip_s, "rtt_ms": rtt}

    r = _run_cmd(["ping", "-c", "1", "-W", "1", ip_s], timeout_s=2.0, stdout_limit=3000, stderr_limit=800)
    out = (r.get("stdout") or "") if isinstance(r, dict) else ""
    rtt = None
    if _PING_TIME_LT1_RE.search(out):
        rtt = 1
    m = _PING_TIME_RE.search(out)
    if m:
        try:
            rtt = int(m.group("ms"))
        except Exception:
            rtt = None
    ok = bool(r.get("ok")) if isinstance(r, dict) else False
    if rtt is not None:
        ok = True
    return {"ok": ok, "ip": ip_s, "rtt_ms": rtt}


def _estimate_device_type(*, ip: str, mac: Optional[str], vendor: Optional[str], hostname: Optional[str]) -> str:
    hn = (hostname or "").strip().lower()
    v = (vendor or "").strip().lower()
    mac_n = _normalize_mac(mac)
    oui = _mac_oui(mac_n) if mac_n else None

    # VM / virtual NIC OUIs
    if oui in {"00:15:5d"}:  # Hyper-V
        return "VM/Hyper-V"
    if oui in {"08:00:27"}:
        return "VM/VirtualBox"
    if oui in {"00:0c:29", "00:50:56"}:
        return "VM/VMware"

    if "printer" in hn or any(k in v for k in ["canon", "epson", "brother", "ricoh", "kyocera", "xerox"]):
        return "Printer"
    if any(k in v for k in ["cisco", "juniper", "ubiquiti", "mikrotik", "tp-link", "netgear", "buffalo", "nec platforms", "asustek", "huawei", "aruba"]):
        return "Router/AP/Switch"
    if any(k in v for k in ["apple", "samsung", "xiaomi", "oppo", "vivo", "google"]):
        return "Phone/Tablet"
    if any(k in v for k in ["hikvision", "dahua", "axis", "ring"]):
        return "Camera/IoT"
    if hn.endswith("-pc") or hn.endswith("pc") or "desktop" in hn or "laptop" in hn:
        return "PC"

    return "Unknown"


def _normalize_mac(mac: Optional[str]) -> Optional[str]:
    if not mac:
        return None
    s = str(mac).strip().lower()
    if not s:
        return None
    # Accept common formats: aa:bb:cc:dd:ee:ff / aa-bb-cc-dd-ee-ff
    s = s.replace("-", ":").replace(".", "")
    if ":" in s:
        parts = [p for p in s.split(":") if p]
        if len(parts) == 6 and all(len(p) == 2 for p in parts):
            hex12 = "".join(parts)
            if _MAC_HEX_RE.match(hex12):
                return ":".join(parts)
            return None

    # Raw 12 hex
    s2 = s.replace(":", "")
    if _MAC_HEX_RE.match(s2):
        return ":".join([s2[i : i + 2] for i in range(0, 12, 2)])
    return None


def _mac_oui(mac: Optional[str]) -> Optional[str]:
    m = _normalize_mac(mac)
    if not m:
        return None
    parts = m.split(":")
    if len(parts) != 6:
        return None
    return ":".join(parts[:3])


def _mac_is_broadcast(mac: Optional[str]) -> bool:
    m = _normalize_mac(mac)
    return bool(m and m == "ff:ff:ff:ff:ff:ff")


def _mac_is_multicast(mac: Optional[str]) -> bool:
    m = _normalize_mac(mac)
    if not m:
        return False
    try:
        first_octet = int(m.split(":")[0], 16)
    except Exception:
        return False
    return bool(first_octet & 1)


def _lookup_vendor_via_api(mac: str, *, timeout_s: float) -> Dict[str, Any]:
    """Resolve MAC vendor via external API (best-effort).

    Privacy note: this sends MAC addresses to a third-party service.

    Implementation notes:
    - Cache is per OUI (first 3 bytes) to reduce calls.
    - Do NOT cache temporary failures (429/timeouts).
    """

    mac_norm = _normalize_mac(mac)
    if not mac_norm:
        return {"ok": False, "vendor": None, "status": None, "error": "invalid mac"}

    oui = _mac_oui(mac_norm)
    if not oui:
        return {"ok": False, "vendor": None, "status": None, "error": "invalid oui"}

    with _VENDOR_CACHE_LOCK:
        if oui in _VENDOR_OUI_CACHE:
            v = _VENDOR_OUI_CACHE[oui]
            return {"ok": bool(v), "vendor": v, "status": "cache", "oui": oui}

    try:
        import requests
    except Exception as e:
        return {"ok": False, "vendor": None, "status": None, "error": f"requests not available: {e}", "oui": oui}

    url = f"https://api.macvendors.com/{mac_norm}"
    try:
        # macvendors.com is easily rate limited; keep calls spaced out.
        _vendor_rate_limit_wait(min_interval_s=0.9)
        resp = requests.get(url, timeout=timeout_s, headers={"User-Agent": "PoC_Python2PostgreSQL_2"})
        status = int(resp.status_code)

        if status == 429:
            # Backoff and retry once.
            time.sleep(1.2)
            _vendor_rate_limit_wait(min_interval_s=0.9)
            resp = requests.get(url, timeout=timeout_s, headers={"User-Agent": "PoC_Python2PostgreSQL_2"})
            status = int(resp.status_code)
        if status == 200:
            vendor = (resp.text or "").strip() or None
            with _VENDOR_CACHE_LOCK:
                if len(_VENDOR_OUI_CACHE) > 4096:
                    _VENDOR_OUI_CACHE.clear()
                _VENDOR_OUI_CACHE[oui] = vendor
            return {"ok": bool(vendor), "vendor": vendor, "status": status, "oui": oui}

        if status == 404:
            # Negative cache is ok.
            with _VENDOR_CACHE_LOCK:
                if len(_VENDOR_OUI_CACHE) > 4096:
                    _VENDOR_OUI_CACHE.clear()
                _VENDOR_OUI_CACHE[oui] = None
            return {"ok": False, "vendor": None, "status": status, "oui": oui}

        # 429/5xx/etc: do not cache
        return {"ok": False, "vendor": None, "status": status, "oui": oui, "error": (resp.text or "")[:200]}
    except Exception as e:
        return {"ok": False, "vendor": None, "status": None, "oui": oui, "error": str(e)}


def _reverse_lookup_best_effort(ip: str, *, timeout_s: float) -> Dict[str, Any]:
    """Best-effort reverse lookup.

    We prefer subprocess-based tools to enforce timeouts reliably.
    """

    ip_s = (ip or "").strip()
    if not ip_s:
        return {"ok": False, "ip": ip, "hostname": None, "source": None}

    # Windows: nslookup is generally available and timeoutable.
    if _is_windows():
        r = _run_cmd(["nslookup", ip_s], timeout_s=timeout_s, stdout_limit=6000, stderr_limit=1500)
        out = (r.get("stdout") or "") if isinstance(r, dict) else ""
        hostname = None
        for line in out.splitlines():
            m = _NSLOOKUP_NAME_RE.match(line)
            if m:
                hostname = (m.group("name") or "").strip().rstrip(".")
                break
        if not hostname:
            # Fallback: NetBIOS name table (often available even without PTR)
            nb = _nbtstat_name_windows(ip_s, timeout_s=max(0.3, timeout_s))
            if nb:
                return {"ok": True, "ip": ip_s, "hostname": nb, "source": "nbtstat", "raw": r}

        return {"ok": bool(hostname), "ip": ip_s, "hostname": hostname, "source": "nslookup", "raw": r}

    # Non-Windows: try `getent hosts` first for a bounded timeout.
    r = _run_cmd(["getent", "hosts", ip_s], timeout_s=timeout_s, stdout_limit=2000, stderr_limit=500)
    out = (r.get("stdout") or "") if isinstance(r, dict) else ""
    hostname = None
    # Typical: "192.168.1.10 host.example.local host"
    parts = (out.strip().split() if out else [])
    if len(parts) >= 2:
        hostname = parts[1].strip().rstrip(".")
    return {"ok": bool(hostname), "ip": ip_s, "hostname": hostname, "source": "getent", "raw": r}


def list_local_ipv4_interfaces() -> List[Dict[str, Any]]:
    """Return IPv4 interfaces with ip/netmask/cidr when possible (best-effort)."""

    stats = psutil.net_if_stats()
    addrs = psutil.net_if_addrs()

    out: List[Dict[str, Any]] = []
    for ifname, addr_list in addrs.items():
        st = stats.get(ifname)
        is_up = bool(getattr(st, "isup", False)) if st else False

        for a in addr_list:
            if getattr(a, "family", None) != socket.AF_INET:
                continue
            ip = getattr(a, "address", None)
            netmask = getattr(a, "netmask", None)
            if not ip or not netmask:
                continue

            try:
                ip_obj = ipaddress.ip_address(ip)
                if ip_obj.is_loopback:
                    continue
                net = ipaddress.ip_network(f"{ip}/{netmask}", strict=False)
            except Exception:
                continue

            out.append(
                {
                    "name": ifname,
                    "is_up": is_up,
                    "ip": str(ip_obj),
                    "netmask": str(netmask),
                    "cidr": str(net),
                    "prefixlen": int(net.prefixlen),
                    "is_private": bool(ip_obj.is_private),
                }
            )

    # Prefer up + private first
    out.sort(key=lambda x: (not bool(x.get("is_up")), not bool(x.get("is_private")), str(x.get("name") or "")))
    return out


def _powershell_json(ps_command: str, *, timeout_s: float = 8.0) -> Dict[str, Any]:
    if not _is_windows():
        return {"ok": False, "error": "not windows"}
    return _run_cmd(["powershell", "-NoProfile", "-Command", ps_command], timeout_s=timeout_s)


def _parse_arp_a_windows(text: str) -> List[Dict[str, Any]]:
    """Parse `arp -a` output (Windows) into rows with ip/mac/type.

    Note: Interface alias is not available here; we keep interface as the local interface IP when present.
    """
    if not text:
        return []

    rows: List[Dict[str, Any]] = []
    current_iface = ""
    for line in text.splitlines():
        s = (line or "").strip()
        if not s:
            continue

        # Example: Interface: 192.168.1.100 --- 0x6
        if s.lower().startswith("interface:"):
            # take the 2nd token as interface ip
            parts = s.split()
            if len(parts) >= 2:
                current_iface = parts[1].strip()
            continue

        # Example: 192.168.1.1          00-11-22-33-44-55     dynamic
        parts = s.split()
        if len(parts) >= 3 and parts[0].count(".") == 3 and ("-" in parts[1] or ":" in parts[1]):
            ip_s = parts[0].strip()
            mac_s = parts[1].strip()
            typ = parts[2].strip()
            try:
                ip_obj = ipaddress.ip_address(ip_s)
                if ip_obj.version != 4:
                    continue
            except Exception:
                continue

            rows.append(
                {
                    "ip": str(ip_obj),
                    "mac": mac_s,
                    "state": typ,
                    "interface": current_iface,
                    "is_private": bool(ip_obj.is_private),
                    "source": "arp -a",
                }
            )

    # De-dup by (ip, mac)
    uniq: List[Dict[str, Any]] = []
    seen = set()
    for r in rows:
        k = (r.get("ip"), r.get("mac"))
        if k in seen:
            continue
        seen.add(k)
        uniq.append(r)
    return uniq


def list_neighbors_ipv4() -> Dict[str, Any]:
    """Return neighbor (ARP) table for IPv4 (best-effort)."""

    if _is_windows():
        ps = (
            "try { "
            "Get-NetNeighbor -AddressFamily IPv4 | "
            "Select-Object InterfaceAlias,IPAddress,LinkLayerAddress,State | "
            "ConvertTo-Json -Depth 4 } catch { '[]' }"
        )
        r = _powershell_json(ps, timeout_s=12.0)
        data = []
        if r.get("ok") and isinstance(r.get("stdout"), str):
            s = r["stdout"].strip()
            try:
                data = json.loads(s) if s else []
            except Exception:
                data = []

        # Normalize: ConvertTo-Json returns object for single item
        if isinstance(data, dict):
            data = [data]
        if not isinstance(data, list):
            data = []

        rows: List[Dict[str, Any]] = []
        for item in data:
            if not isinstance(item, dict):
                continue
            ip = item.get("IPAddress")
            mac = item.get("LinkLayerAddress")
            if not ip:
                continue
            try:
                ip_obj = ipaddress.ip_address(str(ip))
            except Exception:
                continue

            rows.append(
                {
                    "ip": str(ip_obj),
                    "mac": str(mac) if mac else None,
                    "state": str(item.get("State") or ""),
                    "interface": str(item.get("InterfaceAlias") or ""),
                    "is_private": bool(ip_obj.is_private),
                    "source": "Get-NetNeighbor",
                }
            )

        rows.sort(key=lambda x: (x.get("interface") or "", x.get("ip") or ""))
        # Fallback: when neighbor table is empty or unhelpful, try arp -a.
        if len([x for x in rows if x.get("mac")]) == 0:
            arp = _run_cmd(["arp", "-a"], timeout_s=6.0, stdout_limit=20000)
            arp_rows: List[Dict[str, Any]] = []
            if isinstance(arp.get("stdout"), str):
                arp_rows = _parse_arp_a_windows(arp["stdout"])
            if arp_rows:
                return {"ok": True, "neighbors": arp_rows, "raw": {"netneighbor": r, "arp": arp}, "source": "arp -a"}

        return {"ok": True, "neighbors": rows, "raw": r, "source": "Get-NetNeighbor"}

    # Fallback (non-Windows): try arp -a parsing
    r = _run_cmd(["arp", "-a"], timeout_s=6.0)
    return {"ok": bool(r.get("ok")), "neighbors": [], "raw": r, "error": "arp parsing not implemented"}


def _ping_windows(ip: str, *, timeout_ms: int = 250) -> None:
    # fire-and-forget within a bounded timeout; return code ignored
    try:
        subprocess.run(
            ["ping", "-n", "1", "-w", str(int(timeout_ms)), ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=max(1.0, (timeout_ms / 1000.0) + 0.8),
        )
    except Exception:
        pass


def ping_sweep(
    cidr: str,
    *,
    max_hosts: int = 256,
    timeout_ms: int = 250,
    max_concurrency: int = 64,
) -> Dict[str, Any]:
    """Populate neighbor table by pinging hosts in the CIDR (best-effort).

    Note: This does NOT guarantee discovery of all devices.
    """

    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except Exception:
        return {"ok": False, "error": "invalid cidr"}

    if net.version != 4:
        return {"ok": False, "error": "ipv4 only"}

    # Avoid huge sweeps
    hosts = list(net.hosts())
    cap = max(16, min(4096, int(max_hosts)))
    if len(hosts) > cap:
        hosts = hosts[:cap]

    started = time.monotonic()

    workers = max(1, min(256, int(max_concurrency)))

    def _ping_one(ip: str) -> None:
        if _is_windows():
            _ping_windows(ip, timeout_ms=timeout_ms)
            return
        try:
            subprocess.run(
                ["ping", "-c", "1", "-W", "1", ip],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2.0,
            )
        except Exception:
            pass

    # Parallel sweep to avoid multi-minute UI hangs.
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(_ping_one, str(h)) for h in hosts]
        for _f in as_completed(futures):
            pass

    elapsed_ms = int((time.monotonic() - started) * 1000)
    return {
        "ok": True,
        "cidr": str(net),
        "attempted": len(hosts),
        "elapsed_ms": elapsed_ms,
        "max_concurrency": workers,
        "timeout_ms": int(timeout_ms),
    }


def collect_lan_devices(
    *,
    sweep: bool = False,
    max_hosts: int = 256,
    timeout_ms: int = 250,
    max_concurrency: int = 64,
    resolve_names: bool = False,
    resolve_timeout_ms: int = 800,
    resolve_max_concurrency: int = 32,
    resolve_max_entries: int = 256,
    resolve_vendors: bool = False,
    vendor_timeout_ms: int = 1200,
    vendor_max_concurrency: int = 2,
    vendor_max_entries: int = 256,
    ping_check: bool = False,
    ping_timeout_ms: int = 600,
    ping_max_concurrency: int = 64,
    ping_max_entries: int = 256,
) -> Dict[str, Any]:
    interfaces = list_local_ipv4_interfaces()
    collected_at = _now_iso()

    sweep_results: List[Dict[str, Any]] = []
    if sweep:
        # Sweep only private/up interfaces to reduce noise
        for itf in interfaces:
            if not itf.get("is_up"):
                continue
            if not itf.get("is_private"):
                continue
            cidr = itf.get("cidr")
            if isinstance(cidr, str) and cidr:
                sweep_results.append(
                    ping_sweep(
                        cidr,
                        max_hosts=max_hosts,
                        timeout_ms=timeout_ms,
                        max_concurrency=max_concurrency,
                    )
                )

    neigh = list_neighbors_ipv4()
    neighbors = neigh.get("neighbors") if isinstance(neigh, dict) else None
    if not isinstance(neighbors, list):
        neighbors = []

    hostname_resolution: Dict[str, Any] = {"requested": bool(resolve_names)}
    if resolve_names and neighbors:
        started = time.monotonic()

        # Unique private IPv4 only.
        ip_list: List[str] = []
        seen = set()
        for n in neighbors:
            if not isinstance(n, dict):
                continue
            ip_s = str(n.get("ip") or "").strip()
            if not ip_s:
                continue
            try:
                ip_obj = ipaddress.ip_address(ip_s)
            except Exception:
                continue
            if ip_obj.version != 4 or not ip_obj.is_private:
                continue
            # Skip non-host targets
            if str(ip_obj) == "255.255.255.255":
                continue
            if ip_obj.is_multicast or ip_obj.is_unspecified or ip_obj.is_loopback or ip_obj.is_link_local:
                continue
            if getattr(ip_obj, "is_reserved", False):
                continue
            if ip_s in seen:
                continue
            seen.add(ip_s)
            ip_list.append(ip_s)
            if len(ip_list) >= max(1, int(resolve_max_entries)):
                break

        timeout_s = max(0.1, float(resolve_timeout_ms) / 1000.0)
        workers = max(1, min(128, int(resolve_max_concurrency)))
        workers = min(workers, max(1, len(ip_list)))

        resolved_map: Dict[str, str] = {}
        # Note: We intentionally do not propagate raw command output per-host to keep payload small.
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = {ex.submit(_reverse_lookup_best_effort, ip, timeout_s=timeout_s): ip for ip in ip_list}
            for f in as_completed(futs):
                try:
                    r = f.result()
                except Exception:
                    continue
                if not isinstance(r, dict):
                    continue
                ip_s = str(r.get("ip") or "").strip()
                hn = r.get("hostname")
                if ip_s and isinstance(hn, str) and hn.strip():
                    resolved_map[ip_s] = hn.strip()

        # Apply back to neighbor list
        for n in neighbors:
            if not isinstance(n, dict):
                continue
            ip_s = str(n.get("ip") or "").strip()
            hn = resolved_map.get(ip_s)
            if hn:
                n["hostname"] = hn
                n["hostname_source"] = "reverse"  # logical marker

        elapsed_ms = int((time.monotonic() - started) * 1000)
        hostname_resolution = {
            "requested": True,
            "attempted": len(ip_list),
            "resolved": len(resolved_map),
            "timeout_ms": int(resolve_timeout_ms),
            "max_concurrency": int(workers),
            "max_entries": int(resolve_max_entries),
            "elapsed_ms": elapsed_ms,
            "method": "nslookup+nbtstat" if _is_windows() else "getent",
        }

    vendor_resolution: Dict[str, Any] = {"requested": bool(resolve_vendors)}
    if resolve_vendors and neighbors:
        started = time.monotonic()

        # Reduce requests: resolve per unique OUI and skip broadcast/multicast.
        mac_list: List[str] = []
        seen_oui = set()
        for n in neighbors:
            if not isinstance(n, dict):
                continue
            mac_norm = _normalize_mac(n.get("mac"))
            if not mac_norm:
                continue
            if _mac_is_broadcast(mac_norm) or _mac_is_multicast(mac_norm):
                continue

            oui = _mac_oui(mac_norm)
            if not oui:
                continue
            if oui in seen_oui:
                continue
            seen_oui.add(oui)
            mac_list.append(mac_norm)
            if len(mac_list) >= max(1, int(vendor_max_entries)):
                break

        timeout_s = max(0.2, float(vendor_timeout_ms) / 1000.0)
        workers = max(1, min(64, int(vendor_max_concurrency)))
        workers = min(workers, max(1, len(mac_list)))

        vendor_by_oui: Dict[str, str] = {}
        status_counts: Dict[str, int] = {}
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = {ex.submit(_lookup_vendor_via_api, mac, timeout_s=timeout_s): mac for mac in mac_list}
            for f in as_completed(futs):
                try:
                    r = f.result()
                except Exception:
                    continue
                if not isinstance(r, dict):
                    continue
                st = r.get("status")
                status_counts[str(st)] = int(status_counts.get(str(st), 0)) + 1

                oui = r.get("oui")
                vendor = r.get("vendor")
                if isinstance(oui, str) and oui and isinstance(vendor, str) and vendor.strip():
                    vendor_by_oui[oui] = vendor.strip()

        for n in neighbors:
            if not isinstance(n, dict):
                continue
            if n.get("vendor"):
                continue
            mac_norm = _normalize_mac(n.get("mac"))
            if not mac_norm:
                continue
            if _mac_is_broadcast(mac_norm) or _mac_is_multicast(mac_norm):
                continue
            oui = _mac_oui(mac_norm)
            if not oui:
                continue
            v = vendor_by_oui.get(oui)
            if v:
                n["vendor"] = v
                n["vendor_source"] = "macvendors"

        elapsed_ms = int((time.monotonic() - started) * 1000)
        vendor_resolution = {
            "requested": True,
            "attempted": len(mac_list),
            "resolved": len(vendor_by_oui),
            "timeout_ms": int(vendor_timeout_ms),
            "max_concurrency": int(workers),
            "max_entries": int(vendor_max_entries),
            "elapsed_ms": elapsed_ms,
            "method": "macvendors.com",
            "privacy": "sends MAC addresses to a third-party API",
            "rate_limited": int(status_counts.get("429", 0)),
            "status_counts": status_counts,
        }

    ping_results: Dict[str, Any] = {"requested": bool(ping_check)}
    if ping_check and neighbors:
        started = time.monotonic()

        ip_list: List[str] = []
        seen = set()
        for n in neighbors:
            if not isinstance(n, dict):
                continue
            ip_s = str(n.get("ip") or "").strip()
            if not ip_s:
                continue
            try:
                ip_obj = ipaddress.ip_address(ip_s)
            except Exception:
                continue
            if ip_obj.version != 4 or not ip_obj.is_private:
                continue
            if str(ip_obj) == "255.255.255.255":
                continue
            if ip_obj.is_multicast or ip_obj.is_unspecified or ip_obj.is_loopback or ip_obj.is_link_local:
                continue
            if getattr(ip_obj, "is_reserved", False):
                continue
            if ip_s in seen:
                continue
            seen.add(ip_s)
            ip_list.append(ip_s)
            if len(ip_list) >= max(1, int(ping_max_entries)):
                break

        workers = max(1, min(256, int(ping_max_concurrency)))
        workers = min(workers, max(1, len(ip_list)))
        timeout_ms_i = max(50, int(ping_timeout_ms))

        ping_map: Dict[str, Dict[str, Any]] = {}
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = {ex.submit(_ping_one, ip, timeout_ms=timeout_ms_i): ip for ip in ip_list}
            for f in as_completed(futs):
                try:
                    r = f.result()
                except Exception:
                    continue
                if not isinstance(r, dict):
                    continue
                ip_s = str(r.get("ip") or "").strip()
                if not ip_s:
                    continue
                ping_map[ip_s] = {"ok": bool(r.get("ok")), "rtt_ms": r.get("rtt_ms")}

        for n in neighbors:
            if not isinstance(n, dict):
                continue
            ip_s = str(n.get("ip") or "").strip()
            pr = ping_map.get(ip_s)
            if pr:
                n["ping_ok"] = bool(pr.get("ok"))
                n["ping_rtt_ms"] = pr.get("rtt_ms")

        elapsed_ms = int((time.monotonic() - started) * 1000)
        ping_results = {
            "requested": True,
            "attempted": len(ip_list),
            "timeout_ms": int(timeout_ms_i),
            "max_concurrency": int(workers),
            "max_entries": int(ping_max_entries),
            "elapsed_ms": elapsed_ms,
        }

    # Enrich rows with seen times / subnet guess / type
    for n in neighbors:
        if not isinstance(n, dict):
            continue
        ip_s = str(n.get("ip") or "").strip()
        if ip_s:
            seen_times = _update_seen_times(ip_s, now_iso=collected_at)
            if seen_times:
                n.update(seen_times)

            guess = _guess_subnet_and_if(interfaces, ip_s)
            if guess.get("subnet") and not n.get("subnet"):
                n["subnet"] = guess.get("subnet")
            if guess.get("if_guess") and not n.get("interface"):
                n["interface"] = guess.get("if_guess")

        n["device_type"] = _estimate_device_type(
            ip=ip_s,
            mac=n.get("mac"),
            vendor=n.get("vendor"),
            hostname=n.get("hostname"),
        )

    return {
        "collected_at": collected_at,
        "hostname": socket.gethostname(),
        "is_windows": _is_windows(),
        "interfaces": interfaces,
        "sweep": {"requested": bool(sweep), "results": sweep_results},
        "hostname_resolution": hostname_resolution,
        "vendor_resolution": vendor_resolution,
        "ping": ping_results,
        "neighbors": neighbors,
        "notes": [
            "近隣機器一覧は ARP/Neighbor テーブル由来のため、必ずしも『ネットワーク内の全機器』を網羅できません（通信履歴がない機器は出ない場合があります）。",
            "必要なら『スキャン（Ping sweep）』で近隣テーブルの更新を促せますが、環境によってはICMPが遮断されます。",
        ],
    }
