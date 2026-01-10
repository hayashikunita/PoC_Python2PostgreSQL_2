from __future__ import annotations

import asyncio
import ipaddress
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# pysnmp 7.x: HLAPIは asyncio ベースが中心（旧 getCmd/nextCmd は廃止/移動）
from pysnmp.hlapi.v3arch.asyncio import (  # type: ignore
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    get_cmd,
    walk_cmd,
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _mac_from_octets(value: Any) -> Optional[str]:
    try:
        # pysnmp returns OctetString for MAC
        octets = bytes(value.asOctets())
        if not octets:
            return None
        return ":".join(f"{b:02x}" for b in octets)
    except Exception:
        return None


def _safe_ip(value: Any) -> Optional[str]:
    try:
        s = str(value)
        ip = ipaddress.ip_address(s)
        if ip.version != 4:
            return None
        return str(ip)
    except Exception:
        return None


def _walk(
    host: str,
    community: str,
    oid: str,
    *,
    port: int = 161,
    timeout_s: float = 2.0,
    retries: int = 1,
    max_rows: int = 8000,
) -> List[Tuple[str, Any]]:
    async def _run() -> List[Tuple[str, Any]]:
        rows: List[Tuple[str, Any]] = []
        engine = SnmpEngine()
        auth = CommunityData(community, mpModel=1)
        target = await UdpTransportTarget.create((host, int(port)), timeout=float(timeout_s), retries=int(retries))
        ctx = ContextData()

        async for (error_indication, error_status, error_index, var_binds) in walk_cmd(
            engine,
            auth,
            target,
            ctx,
            ObjectType(ObjectIdentity(oid)),
            lexicographicMode=False,
            maxRows=int(max_rows),
        ):
            if error_indication:
                raise RuntimeError(str(error_indication))
            if error_status:
                # error_status is int-like (0 means ok)
                raise RuntimeError(f"SNMP error: {error_status} at {error_index}")

            for vb in var_binds:
                name, val = vb
                rows.append((str(name), val))
                if len(rows) >= max_rows:
                    return rows

        return rows

    return asyncio.run(_run())


def get_sysname(
    host: str,
    community: str,
    *,
    port: int = 161,
    timeout_s: float = 2.0,
    retries: int = 1,
) -> Dict[str, Any]:
    # SNMPv2-MIB::sysName.0
    oid = "1.3.6.1.2.1.1.5.0"
    started = time.monotonic()
    error: Optional[str] = None
    sysname: Optional[str] = None

    async def _run() -> Tuple[Optional[str], Optional[str]]:
        engine = SnmpEngine()
        auth = CommunityData(community, mpModel=1)
        target = await UdpTransportTarget.create((host, int(port)), timeout=float(timeout_s), retries=int(retries))
        ctx = ContextData()

        try:
            error_indication, error_status, error_index, var_binds = await get_cmd(
                engine,
                auth,
                target,
                ctx,
                ObjectType(ObjectIdentity(oid)),
            )
            if error_indication:
                return None, str(error_indication)
            if error_status:
                return None, f"SNMP error: {error_status} at {error_index}"

            value: Optional[str] = None
            for vb in var_binds:
                _name, val = vb
                value = str(val)
            return value, None
        except Exception as e:
            return None, str(e)

    sysname, error = asyncio.run(_run())

    elapsed_ms = int((time.monotonic() - started) * 1000)
    return {
        "ok": bool(sysname) and not error,
        "host": host,
        "sysName": sysname,
        "elapsed_ms": elapsed_ms,
        "error": error,
    }


def fetch_arp_table(
    *,
    host: str,
    community: str,
    port: int = 161,
    timeout_s: float = 2.0,
    retries: int = 1,
    max_rows: int = 8000,
) -> Dict[str, Any]:
    """Fetch ARP table via IP-MIB::ipNetToMediaTable.

    Uses:
      - ipNetToMediaNetAddress (1.3.6.1.2.1.4.22.1.3)
      - ipNetToMediaPhysAddress (1.3.6.1.2.1.4.22.1.2)

    Many routers/switches support this with SNMP v2c.
    """

    host_s = (host or "").strip()
    comm_s = (community or "").strip()
    if not host_s or not comm_s:
        return {"ok": False, "error": "host/community required"}

    started = time.monotonic()

    ip_rows = _walk(host_s, comm_s, "1.3.6.1.2.1.4.22.1.3", port=port, timeout_s=timeout_s, retries=retries, max_rows=max_rows)
    mac_rows = _walk(host_s, comm_s, "1.3.6.1.2.1.4.22.1.2", port=port, timeout_s=timeout_s, retries=retries, max_rows=max_rows)

    # key by trailing index (ifIndex.ip)
    def key(name: str) -> str:
        # last two segments can include ip as dotted; we keep full suffix after base oid
        # name like 1.3.6.1.2.1.4.22.1.3.<ifIndex>.<ip1>.<ip2>.<ip3>.<ip4>
        parts = name.split(".")
        return ".".join(parts[10:])  # after ...4.22.1.3

    ip_map: Dict[str, str] = {}
    for n, v in ip_rows:
        k = key(n)
        ip = _safe_ip(v)
        if ip:
            ip_map[k] = ip

    mac_map: Dict[str, str] = {}
    for n, v in mac_rows:
        k = key(n)
        mac = _mac_from_octets(v)
        if mac:
            mac_map[k] = mac

    neighbors: List[Dict[str, Any]] = []
    for k, ip in ip_map.items():
        mac = mac_map.get(k)
        if not mac:
            continue

        # parse ifIndex from key
        if_index = None
        try:
            if_index = int(k.split(".", 1)[0])
        except Exception:
            if_index = None

        try:
            ip_obj = ipaddress.ip_address(ip)
        except Exception:
            continue

        neighbors.append(
            {
                "ip": ip,
                "mac": mac,
                "interface": str(if_index) if if_index is not None else "",
                "state": "snmp",
                "is_private": bool(ip_obj.is_private),
                "source": "snmp",
            }
        )

    elapsed_ms = int((time.monotonic() - started) * 1000)
    neighbors.sort(key=lambda x: (x.get("ip") or ""))

    return {
        "ok": True,
        "collected_at": _now_iso(),
        "target": {"host": host_s, "port": int(port)},
        "summary": {"count": len(neighbors), "elapsed_ms": elapsed_ms},
        "neighbors": neighbors,
        "sysName": get_sysname(host_s, comm_s, port=port, timeout_s=timeout_s, retries=retries),
    }
