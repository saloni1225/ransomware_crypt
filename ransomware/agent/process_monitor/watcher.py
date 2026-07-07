"""
Process Monitor
===============
Polls running processes with psutil and detects:
- Newly spawned processes
- Terminated processes
- Suspicious processes (by name or command-line patterns)
"""

import logging
import os
import sys
import threading
import time
from typing import Dict, Optional, Set

try:
    import psutil
except ImportError:
    raise SystemExit("psutil is required: pip install psutil")

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import config
from sender import sender

logger = logging.getLogger("agent.process_monitor")

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _get_proc_info(proc: psutil.Process) -> Optional[Dict]:
    """Safely extract process attributes — returns None if process died mid-read."""
    try:
        with proc.oneshot():
            name = proc.name()
            cmdline = " ".join(proc.cmdline()) if proc.cmdline() else ""
            exe = proc.exe() if hasattr(proc, "exe") else ""
            ppid = proc.ppid()
            username = proc.username() if hasattr(proc, "username") else ""
        return {
            "pid": proc.pid,
            "name": name,
            "command": cmdline or name,
            "exe": exe,
            "ppid": ppid,
            "username": username,
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None


def _is_suspicious(name: str, cmdline: str) -> bool:
    """Return True if name or command matches known-bad patterns."""
    name_lower = name.lower()
    cmd_lower = cmdline.lower()

    for pattern in config.SUSPICIOUS_PROC_NAMES:
        if pattern.lower() in name_lower:
            return True

    for fragment in config.SUSPICIOUS_CMDLINE_FRAGMENTS:
        if fragment.lower() in cmd_lower:
            return True

    return False


# ─────────────────────────────────────────────────────────────────────────────
# ProcessMonitor
# ─────────────────────────────────────────────────────────────────────────────

class ProcessMonitor:
    """
    Polls the process list every PROCESS_POLL_INTERVAL_SEC seconds.
    Compares to the previous snapshot to detect new/exited processes.
    """

    def __init__(self):
        self._known_pids: Set[int] = set()
        self._stop_event = threading.Event()

    def start(self) -> None:
        """Build initial snapshot then start monitoring loop in a daemon thread."""
        # Populate known pids without emitting events for pre-existing processes
        self._known_pids = set(psutil.pids())
        logger.info("Process monitor started — tracking %d existing processes",
                    len(self._known_pids))
        threading.Thread(target=self._monitor_loop, daemon=True,
                         name="agent-proc-monitor").start()

    def stop(self) -> None:
        self._stop_event.set()

    def _monitor_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._poll_once()
            except Exception as exc:
                logger.error("Process monitor error: %s", exc)
            self._stop_event.wait(config.PROCESS_POLL_INTERVAL_SEC)

    def _poll_once(self) -> None:
        current_pids = set(psutil.pids())

        new_pids = current_pids - self._known_pids
        exited_pids = self._known_pids - current_pids

        # Handle new processes
        for pid in new_pids:
            try:
                proc = psutil.Process(pid)
                info = _get_proc_info(proc)
                if info is None:
                    continue  # process already dead

                suspicious = _is_suspicious(info["name"], info["command"])

                if suspicious:
                    logger.warning(
                        "SUSPICIOUS PROCESS: pid=%d name=%s cmd=%s",
                        pid, info["name"], info["command"][:120],
                    )
                    # Elevate to process alert
                    sender.enqueue("process", "suspicious_start", {
                        **info,
                        "risk": "high",
                        "alert": "Suspicious process signature matched",
                    })
                else:
                    logger.debug("New process: pid=%d name=%s", pid, info["name"])
                    sender.enqueue("process", "started", info)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass  # process vanished before we could read it

        # Handle exited processes (brief log only — don't flood the backend)
        for pid in exited_pids:
            logger.debug("Process exited: pid=%d", pid)
            # Only send termination events for a small batch to avoid flooding
            if len(exited_pids) <= 5:
                sender.enqueue("process", "terminated", {"pid": pid})

        self._known_pids = current_pids


# ─────────────────────────────────────────────────────────────────────────────
# Public function
# ─────────────────────────────────────────────────────────────────────────────

def start_process_monitor() -> ProcessMonitor:
    monitor = ProcessMonitor()
    monitor.start()
    return monitor
