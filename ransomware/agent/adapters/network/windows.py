"""
Cross-Platform Network Adapter (psutil)
========================================
psutil.net_connections() works on Windows, Linux, and macOS.
Each OS-specific class simply registers itself; logic is shared here.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Set

try:
    import psutil
    _PSUTIL_OK = True
except ImportError:
    _PSUTIL_OK = False

from adapters.base import AdapterCapability, CapabilityState
from adapters.network.base import NetworkAdapter
from adapters.registry import register

logger = logging.getLogger("agent.adapters.network")

# Ports that are immediately suspicious regardless of destination
_SUSPICIOUS_PORTS: Set[int] = {4444, 4445, 1337, 31337, 6666, 9001, 6667, 9050}

# Private / loopback prefixes — generally not flagged
_PRIVATE_PREFIXES = ("10.", "192.168.", "172.16.", "172.17.", "172.18.",
                     "172.19.", "172.2", "127.", "::1", "fc", "fd")


def _is_private(ip: str) -> bool:
    return ip.startswith(_PRIVATE_PREFIXES)


def _safe_proc_name(pid: Optional[int]) -> str:
    if pid is None or not _PSUTIL_OK:
        return "unknown"
    try:
        return psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied, ProcessLookupError):
        return "unknown"


def _classify(remote_ip: str, remote_port: int) -> tuple[bool, Optional[str]]:
    """Returns (suspicious_flag, reason)."""
    if remote_port in _SUSPICIOUS_PORTS:
        return True, f"Suspicious port {remote_port} (known C2/backdoor)"
    if not _is_private(remote_ip) and remote_port in (0, 1):
        return True, "Unusual port for external connection"
    return False, None


def _collect_connections() -> List[Dict[str, Any]]:
    """Snapshot all current TCP/UDP connections via psutil."""
    try:
        raw_conns = psutil.net_connections(kind="all")
    except psutil.AccessDenied:
        raise PermissionError("psutil.net_connections requires elevated privileges")

    connections = []
    for conn in raw_conns:
        raddr = conn.raddr
        laddr = conn.laddr
        if not raddr:
            continue  # listening sockets, skip

        remote_ip = raddr.ip
        remote_port = raddr.port
        suspicious, reason = _classify(remote_ip, remote_port)

        proc_name = _safe_proc_name(conn.pid)
        proto = "tcp" if conn.type == 1 else "udp"

        connections.append({
            "protocol": proto,
            "local_ip": laddr.ip if laddr else "",
            "local_port": laddr.port if laddr else None,
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "status": conn.status or "NONE",
            "pid": conn.pid,
            "process_name": proc_name,
            "suspicious_flag": suspicious,
            "reason": reason,
        })

    return connections


class _PsutilNetworkAdapter(NetworkAdapter):
    """Shared implementation for all platforms using psutil."""

    def check_capability(self) -> AdapterCapability:
        if not _PSUTIL_OK:
            return AdapterCapability(
                module=self.MODULE,
                supported=False,
                capability_state=CapabilityState.MISSING_DEPENDENCY,
                dependency="psutil",
                message="psutil not installed: pip install psutil",
            )
        return AdapterCapability(
            module=self.MODULE,
            supported=True,
            capability_state=CapabilityState.SUPPORTED,
            message="psutil available",
        )

    def _collect(self) -> Dict[str, Any]:
        connections = _collect_connections()
        suspicious_count = sum(1 for c in connections if c["suspicious_flag"])
        return {
            "connections": connections,
            "total": len(connections),
            "suspicious_count": suspicious_count,
        }

    def _compute_health(self, data: Dict) -> str:
        if data.get("suspicious_count", 0) > 0:
            return "warning"
        return "healthy"


class WindowsNetworkAdapter(_PsutilNetworkAdapter):
    pass

class LinuxNetworkAdapter(_PsutilNetworkAdapter):
    pass

class MacOSNetworkAdapter(_PsutilNetworkAdapter):
    pass


register("network", "Windows", WindowsNetworkAdapter)
register("network", "Linux",   LinuxNetworkAdapter)
register("network", "Darwin",  MacOSNetworkAdapter)
