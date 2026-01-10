from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


_REPORT_RE = re.compile(r"^Nmap scan report for (?:(?P<host>.+?) \()?(?P<ip>\d+\.\d+\.\d+\.\d+)\)?$")
_MAC_RE = re.compile(r"^MAC Address: (?P<mac>[0-9A-Fa-f:]{17})(?: \((?P<vendor>.+)\))?$")


def _find_nmap() -> Optional[str]:
    # Allow override
    p = shutil.which("nmap")
    return p


def _validate_cidr(cidr: str, *, max_hosts: int = 4096) -> str:
    try:
        net = ipaddress.ip_network((cidr or "").strip(), strict=False)
    except Exception:
        raise ValueError("invalid cidr")

    if net.version != 4:
        raise ValueError("ipv4 only")

    # guardrail: allow only private ranges by default
    if not net.is_private:
        raise ValueError("cidr must be private (RFC1918)")

    # approximate host count
    host_count = max(0, int(net.num_addresses) - 2)
    if host_count > int(max_hosts):
        raise ValueError(f"cidr too large: hosts={host_count} (limit={max_hosts})")

    return str(net)


def _validate_target(target: str) -> str:
    t = (target or "").strip()
    if not t:
        raise ValueError("target required")

    # Prefer strict private IPv4 target. (Hostnames are not accepted to keep guardrails simple.)
    try:
        ip = ipaddress.ip_address(t)
    except Exception:
        raise ValueError("target must be an IPv4 address")

    if ip.version != 4:
        raise ValueError("ipv4 only")
    if not ip.is_private:
        raise ValueError("target must be private (RFC1918)")
    return str(ip)


def _parse_nmap_xml(xml_text: str) -> Dict[str, Any]:
    root = ET.fromstring(xml_text)

    runstats = root.find("runstats")
    finished = runstats.find("finished") if runstats is not None else None
    summary = {
        "elapsed": float(finished.attrib.get("elapsed")) if finished is not None and finished.attrib.get("elapsed") else None,
        "exit": finished.attrib.get("exit") if finished is not None else None,
    }

    hosts: List[Dict[str, Any]] = []
    for h in root.findall("host"):
        status_el = h.find("status")
        status = status_el.attrib.get("state") if status_el is not None else None

        addr_ip = None
        addr_mac = None
        addr_vendor = None
        for a in h.findall("address"):
            if a.attrib.get("addrtype") == "ipv4":
                addr_ip = a.attrib.get("addr")
            if a.attrib.get("addrtype") == "mac":
                addr_mac = (a.attrib.get("addr") or "").lower() or None
                addr_vendor = a.attrib.get("vendor")

        hostnames_el = h.find("hostnames")
        hostname = None
        if hostnames_el is not None:
            hn = hostnames_el.find("hostname")
            if hn is not None:
                hostname = hn.attrib.get("name")

        ports_out: List[Dict[str, Any]] = []
        ports_el = h.find("ports")
        if ports_el is not None:
            for p in ports_el.findall("port"):
                state_el = p.find("state")
                service_el = p.find("service")
                ports_out.append(
                    {
                        "port": int(p.attrib.get("portid")) if p.attrib.get("portid") else None,
                        "proto": p.attrib.get("protocol"),
                        "state": state_el.attrib.get("state") if state_el is not None else None,
                        "reason": state_el.attrib.get("reason") if state_el is not None else None,
                        "service": service_el.attrib.get("name") if service_el is not None else None,
                        "product": service_el.attrib.get("product") if service_el is not None else None,
                        "version": service_el.attrib.get("version") if service_el is not None else None,
                        "extrainfo": service_el.attrib.get("extrainfo") if service_el is not None else None,
                    }
                )

        os_el = h.find("os")
        os_match = None
        if os_el is not None:
            best = None
            for om in os_el.findall("osmatch"):
                try:
                    acc = int(om.attrib.get("accuracy") or 0)
                except Exception:
                    acc = 0
                if best is None or acc > best[0]:
                    best = (acc, om.attrib.get("name"))
            if best is not None:
                os_match = {"accuracy": best[0], "name": best[1]}

        trace_el = h.find("trace")
        hops: List[Dict[str, Any]] = []
        if trace_el is not None:
            for hop in trace_el.findall("hop"):
                hops.append(
                    {
                        "ttl": int(hop.attrib.get("ttl")) if hop.attrib.get("ttl") else None,
                        "ip": hop.attrib.get("ipaddr"),
                        "rtt_ms": float(hop.attrib.get("rtt")) if hop.attrib.get("rtt") else None,
                        "host": hop.attrib.get("host") or None,
                    }
                )

        hosts.append(
            {
                "ip": addr_ip,
                "mac": addr_mac,
                "vendor": addr_vendor,
                "hostname": hostname,
                "status": status,
                "ports": ports_out,
                "os": os_match,
                "trace": hops,
            }
        )

    return {"summary": summary, "hosts": hosts}


def nmap_port_scan(
    *,
    target: str,
    ports: Optional[str] = None,
    top_ports: Optional[int] = None,
    service_version: bool = True,
    os_detect: bool = False,
    traceroute: bool = False,
    no_dns: bool = True,
    timeout_s: float = 180.0,
) -> Dict[str, Any]:
    """Run a TCP port scan using connect scan (-sT) and parse XML output.

    Notes:
    - Uses -sT to avoid requiring raw socket privileges.
    - Target is restricted to private IPv4.
    """

    nmap_path = _find_nmap()
    if not nmap_path:
        return {
            "ok": False,
            "error": "nmap not found in PATH. Please install Nmap (and Npcap if prompted).",
        }

    tgt = _validate_target(target)

    cmd: List[str] = [nmap_path, "-sT"]
    if no_dns:
        cmd.append("-n")
    if service_version:
        cmd.append("-sV")
    if os_detect:
        cmd.append("-O")
    if traceroute:
        cmd.append("--traceroute")

    if top_ports is not None:
        tp = int(top_ports)
        if tp < 1 or tp > 1000:
            raise ValueError("top_ports must be 1..1000")
        cmd += ["--top-ports", str(tp)]
    elif ports:
        p = (ports or "").strip()
        if len(p) > 200:
            raise ValueError("ports too long")
        cmd += ["-p", p]

    # XML to stdout
    cmd += ["-oX", "-", tgt]

    started = time.monotonic()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=float(timeout_s),
        )
    except subprocess.TimeoutExpired:
        elapsed_ms = int((time.monotonic() - started) * 1000)
        return {
            "ok": False,
            "error": "nmap timeout",
            "target": tgt,
            "elapsed_ms": elapsed_ms,
        }
    except Exception as e:
        return {"ok": False, "error": str(e), "target": tgt}

    elapsed_ms = int((time.monotonic() - started) * 1000)
    stdout = proc.stdout or ""
    stderr = proc.stderr or ""

    try:
        parsed = _parse_nmap_xml(stdout)
    except Exception as e:
        return {
            "ok": False,
            "error": f"failed to parse nmap xml: {e}",
            "target": tgt,
            "elapsed_ms": elapsed_ms,
            "stderr": (stderr.strip()[:2000] if stderr else ""),
        }

    # Build a compact response
    hosts = parsed.get("hosts") or []
    # Enrich private flag
    for h in hosts:
        try:
            ip_obj = ipaddress.ip_address(h.get("ip") or "")
            h["is_private"] = bool(ip_obj.is_private)
        except Exception:
            h["is_private"] = None

    return {
        "ok": proc.returncode == 0,
        "collected_at": _now_iso(),
        "target": tgt,
        "elapsed_ms": elapsed_ms,
        "args": {
            "ports": ports,
            "top_ports": top_ports,
            "service_version": service_version,
            "os_detect": os_detect,
            "traceroute": traceroute,
            "no_dns": no_dns,
        },
        "summary": {
            "returncode": proc.returncode,
            "nmap": parsed.get("summary"),
            "host_count": len(hosts),
        },
        "hosts": hosts,
        "stderr": (stderr.strip()[:2000] if stderr else ""),
        "notes": [
            "OS推定(-O)は権限/環境により失敗することがあります。",
            "サービス判定(-sV)は時間がかかる場合があります。",
        ],
    }


def nmap_network_port_scan(
    *,
    cidr: str,
    ports: Optional[str] = None,
    top_ports: Optional[int] = 50,
    service_version: bool = False,
    os_detect: bool = False,
    traceroute: bool = False,
    no_dns: bool = True,
    max_hosts: int = 1024,
    timeout_s: float = 600.0,
) -> Dict[str, Any]:
    """Run a TCP port scan against a private CIDR (guard-railed).

    Intended for internal LAN diagnostics. This can be heavy.
    """

    nmap_path = _find_nmap()
    if not nmap_path:
        return {
            "ok": False,
            "error": "nmap not found in PATH. Please install Nmap (and Npcap if prompted).",
        }

    cidr_norm = _validate_cidr(cidr, max_hosts=max_hosts)

    cmd: List[str] = [nmap_path, "-sT"]
    if no_dns:
        cmd.append("-n")
    if service_version:
        cmd.append("-sV")
    if os_detect:
        cmd.append("-O")
    if traceroute:
        cmd.append("--traceroute")

    if top_ports is not None:
        tp = int(top_ports)
        if tp < 1 or tp > 200:
            raise ValueError("top_ports must be 1..200 for CIDR scan")
        cmd += ["--top-ports", str(tp)]
    elif ports:
        p = (ports or "").strip()
        if len(p) > 200:
            raise ValueError("ports too long")
        cmd += ["-p", p]
    else:
        # safe default
        cmd += ["--top-ports", "50"]

    cmd += ["-oX", "-", cidr_norm]

    started = time.monotonic()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=float(timeout_s),
        )
    except subprocess.TimeoutExpired:
        elapsed_ms = int((time.monotonic() - started) * 1000)
        return {
            "ok": False,
            "error": "nmap timeout",
            "cidr": cidr_norm,
            "elapsed_ms": elapsed_ms,
        }
    except Exception as e:
        return {"ok": False, "error": str(e), "cidr": cidr_norm}

    elapsed_ms = int((time.monotonic() - started) * 1000)
    stdout = proc.stdout or ""
    stderr = proc.stderr or ""

    try:
        parsed = _parse_nmap_xml(stdout)
    except Exception as e:
        return {
            "ok": False,
            "error": f"failed to parse nmap xml: {e}",
            "cidr": cidr_norm,
            "elapsed_ms": elapsed_ms,
            "stderr": (stderr.strip()[:2000] if stderr else ""),
        }

    hosts = parsed.get("hosts") or []
    for h in hosts:
        try:
            ip_obj = ipaddress.ip_address(h.get("ip") or "")
            h["is_private"] = bool(ip_obj.is_private)
        except Exception:
            h["is_private"] = None

        ports_list = h.get("ports") or []
        open_ports = [p for p in ports_list if p.get("state") == "open"]
        h["open_ports"] = open_ports
        h["open_port_count"] = len(open_ports)

    up_hosts = [h for h in hosts if h.get("status") == "up"]
    up_with_open = [h for h in up_hosts if (h.get("open_port_count") or 0) > 0]

    return {
        "ok": proc.returncode == 0,
        "collected_at": _now_iso(),
        "cidr": cidr_norm,
        "elapsed_ms": elapsed_ms,
        "args": {
            "ports": ports,
            "top_ports": top_ports,
            "service_version": service_version,
            "os_detect": os_detect,
            "traceroute": traceroute,
            "no_dns": no_dns,
            "max_hosts": max_hosts,
        },
        "summary": {
            "returncode": proc.returncode,
            "nmap": parsed.get("summary"),
            "host_count": len(hosts),
            "up_count": len(up_hosts),
            "up_with_open_ports": len(up_with_open),
        },
        "hosts": hosts,
        "stderr": (stderr.strip()[:2000] if stderr else ""),
        "notes": [
            "CIDRポートスキャンは負荷が高く時間がかかる場合があります。",
            "まずは top-ports（例: 50〜100）で試すのがおすすめです。",
        ],
    }


def nmap_ping_scan(
    *,
    cidr: str,
    arp: bool = True,
    no_dns: bool = True,
    max_hosts: int = 4096,
    timeout_s: float = 120.0,
) -> Dict[str, Any]:
    """Run `nmap -sn` over a CIDR and parse up hosts (best-effort).

    This is intended for LAN discovery. It does not guarantee full coverage.
    """

    nmap_path = _find_nmap()
    if not nmap_path:
        return {
            "ok": False,
            "error": "nmap not found in PATH. Please install Nmap (and Npcap if prompted).",
        }

    cidr_norm = _validate_cidr(cidr, max_hosts=max_hosts)

    cmd: List[str] = [nmap_path, "-sn"]
    if no_dns:
        cmd.append("-n")
    if arp:
        # ARP discovery (best on same L2)
        cmd.append("-PR")

    cmd.append(cidr_norm)

    started = time.monotonic()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=float(timeout_s),
        )
    except subprocess.TimeoutExpired:
        elapsed_ms = int((time.monotonic() - started) * 1000)
        return {
            "ok": False,
            "error": "nmap timeout",
            "cidr": cidr_norm,
            "elapsed_ms": elapsed_ms,
        }
    except Exception as e:
        return {"ok": False, "error": str(e), "cidr": cidr_norm}

    elapsed_ms = int((time.monotonic() - started) * 1000)
    stdout = proc.stdout or ""
    stderr = proc.stderr or ""

    hosts: List[Dict[str, Any]] = []
    current: Optional[Dict[str, Any]] = None

    for line in stdout.splitlines():
        s = line.strip()
        if not s:
            continue

        m = _REPORT_RE.match(s)
        if m:
            if current:
                hosts.append(current)
            current = {
                "ip": m.group("ip"),
                "hostname": (m.group("host") or "").strip() or None,
                "is_up": None,
                "mac": None,
                "vendor": None,
                "source": "nmap",
            }
            continue

        if current is None:
            continue

        if s.lower().startswith("host is up"):
            current["is_up"] = True
            continue

        mm = _MAC_RE.match(s)
        if mm:
            current["mac"] = mm.group("mac").lower()
            v = mm.group("vendor")
            current["vendor"] = (v or "").strip() or None
            continue

    if current:
        hosts.append(current)

    # Only keep up hosts if marked; if None, assume report implies up.
    for h in hosts:
        if h.get("is_up") is None:
            h["is_up"] = True

        try:
            ip_obj = ipaddress.ip_address(h.get("ip") or "")
            h["is_private"] = bool(ip_obj.is_private)
        except Exception:
            h["is_private"] = None

    up = [h for h in hosts if h.get("is_up")]

    return {
        "ok": proc.returncode == 0,
        "collected_at": _now_iso(),
        "cidr": cidr_norm,
        "summary": {"count": len(up), "elapsed_ms": elapsed_ms, "returncode": proc.returncode},
        "hosts": up,
        "stderr": (stderr.strip()[:2000] if stderr else ""),
        "notes": [
            "nmap はネットワーク機器側の設定（クライアント分離/FW）により見え方が変わります。",
            "同一LANでARPが効く場合は -PR が有効です。",
        ],
    }
