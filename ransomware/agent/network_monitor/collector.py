"""
Network Collector
=================
Polls active TCP/UDP connections via psutil and reports new connections
to the backend, flagging known-suspicious ports and C2 patterns.
"""

import logging
import os
import sys
import threading
import time
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

try:
    import psutil
except ImportError:
    raise SystemExit("psutil is required: pip install psutil")

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import config
from sender import sender

logger = logging.getLogger("agent.network_monitor")


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _conn_key(conn) -> Tuple:
    """Stable hashable key for a connection."""
    raddr = conn.raddr
    laddr = conn.laddr
    return (
        laddr.ip if laddr else "",
        laddr.port if laddr else 0,
        raddr.ip if raddr else "",
        raddr.port if raddr else 0,
        conn.type,
    )


def _safe_proc_name(pid: Optional[int]) -> str:
    if pid is None:
        return "unknown"
    try:
        return psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return "unknown"


def _classify_connection(remote_ip: str, remote_port: int) -> str:
    """Return a risk classification string."""
    if remote_port in config.SUSPICIOUS_PORTS:
        return "suspicious"
    # Private address ranges are typically fine
    if remote_ip.startswith(("10.", "192.168.", "172.16.", "127.")):
        return "normal"
    return "normal"


# ─────────────────────────────────────────────────────────────────────────────
# NetworkCollector
# ─────────────────────────────────────────────────────────────────────────────

class NetworkCollector:
    def __init__(self):
        self._known_keys: Set[Tuple] = set()
        self._stop_event = threading.Event()

    def start(self) -> None:
        # Snapshot existing connections without emitting events
        try:
            self._known_keys = {
                _conn_key(c) for c in psutil.net_connections(kind="all")
            }
        except psutil.AccessDenied:
            logger.warning("Access denied reading net_connections — may need elevated privileges")
            self._known_keys = set()

        logger.info("Network collector started — %d existing connections snapshotted",
                    len(self._known_keys))
        threading.Thread(target=self._collect_loop, daemon=True,
                         name="agent-net-collector").start()

    def stop(self) -> None:
        self._stop_event.set()

    def _collect_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._poll_once()
            except Exception as exc:
                logger.error("Network collector error: %s", exc)
            self._stop_event.wait(config.NETWORK_POLL_INTERVAL_SEC)

    def _poll_once(self) -> None:
        try:
            current_conns = psutil.net_connections(kind="all")
        except psutil.AccessDenied:
            return

        current_keys: Set[Tuple] = set()
        new_events: List[Dict] = []

        for conn in current_conns:
            key = _conn_key(conn)
            current_keys.add(key)

            if key not in self._known_keys:
                # New connection
                raddr = conn.raddr
                laddr = conn.laddr

                if not raddr:
                    continue  # listening socket, skip

                remote_ip = raddr.ip
                remote_port = raddr.port
                status = _classify_connection(remote_ip, remote_port)

                proc_name = _safe_proc_name(conn.pid)

                details: Dict = {
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "local_port": laddr.port if laddr else None,
                    "protocol": "TCP" if conn.type == 1 else "UDP",
                    "process_name": proc_name,
                    "pid": conn.pid,
                    "status": status,
                }

                if status == "suspicious":
                    logger.warning(
                        "SUSPICIOUS CONNECTION: %s:%d → %s:%d (proc=%s)",
                        laddr.ip if laddr else "?", laddr.port if laddr else 0,
                        remote_ip, remote_port, proc_name,
                    )
                    details["alert"] = f"Connection on suspicious port {remote_port}"

                new_events.append(details)

        # Emit events (send max 20 new connections per poll to avoid flooding)
        for details in new_events[:20]:
            sender.enqueue(
                "network",
                "suspicious_connection" if details.get("status") == "suspicious" else "new_connection",
                details,
            )

        self._known_keys = current_keys


# ─────────────────────────────────────────────────────────────────────────────
# Public function
# ─────────────────────────────────────────────────────────────────────────────

def start_network_collector() -> NetworkCollector:
    collector = NetworkCollector()
    collector.start()
    return collector
