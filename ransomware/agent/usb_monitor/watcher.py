"""
USB Monitor
===========
Detects USB device insertion and removal on Windows.

Primary method:  WMI Win32_DeviceChangeEvent (event-driven, zero CPU overhead)
Fallback method: psutil disk_partitions() polling (cross-platform)
"""

import logging
import os
import platform
import sys
import threading
import time
from typing import Dict, Optional, Set

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import config
from sender import sender

logger = logging.getLogger("agent.usb_monitor")


# ─────────────────────────────────────────────────────────────────────────────
# Windows WMI-based watcher
# ─────────────────────────────────────────────────────────────────────────────

def _start_wmi_watcher(stop_event: threading.Event) -> None:
    """
    Uses WMI Win32_DeviceChangeEvent to receive USB plug/unplug notifications.
    Runs in its own daemon thread.
    """
    try:
        import wmi  # type: ignore
        import pythoncom  # type: ignore
    except ImportError:
        logger.warning("wmi/pywin32 not installed — falling back to polling USB monitor")
        _start_polling_watcher(stop_event)
        return

    pythoncom.CoInitialize()
    c = wmi.WMI()

    # We watch Win32_USBControllerDevice to get USB device details
    raw_watcher = c.Win32_DeviceChangeEvent.watch_for()

    logger.info("USB WMI watcher started")
    while not stop_event.is_set():
        try:
            event = raw_watcher(timeout_ms=2000)
            if event:
                # 2 = ConfigChanged (arrival), 3 = ConfigChanged (removal)
                event_type = getattr(event, "EventType", 0)
                _handle_wmi_event(event_type, c)
        except Exception as exc:
            if "timeout" not in str(exc).lower():
                logger.debug("WMI event loop: %s", exc)

    pythoncom.CoUninitialize()


def _handle_wmi_event(event_type: int, c) -> None:
    """Query connected USB disk drives and emit connect/disconnect events."""
    try:
        disks = c.Win32_DiskDrive(InterfaceType="USB")
        for disk in disks:
            details = {
                "name": getattr(disk, "Caption", "Unknown"),
                "model": getattr(disk, "Model", ""),
                "serial": (getattr(disk, "SerialNumber", "") or "").strip(),
                "device_id": getattr(disk, "DeviceID", ""),
                "size_bytes": getattr(disk, "Size", 0),
            }
            if event_type == 2:
                logger.info("USB connected: %s", details["name"])
                sender.enqueue("usb", "connected", details)
                # Check if it's on an authorised list (future: config-driven whitelist)
                sender.enqueue("usb", "mounted", {
                    **details,
                    "authorized": False,  # default deny — admin must whitelist
                    "status": "Unauthorized",
                    "label": details["name"],
                })
            elif event_type == 3:
                logger.info("USB removed: %s", details["name"])
                sender.enqueue("usb", "removed", details)
    except Exception as exc:
        logger.error("USB event handler error: %s", exc)


# ─────────────────────────────────────────────────────────────────────────────
# Cross-platform polling fallback
# ─────────────────────────────────────────────────────────────────────────────

def _start_polling_watcher(stop_event: threading.Event) -> None:
    """
    Polls psutil.disk_partitions() every 3 seconds.
    Detects new and removed partitions (rough USB proxy on all platforms).
    """
    import psutil

    def _partition_key(p) -> str:
        return p.mountpoint

    known: Set[str] = {_partition_key(p) for p in psutil.disk_partitions(all=True)}
    logger.info("USB polling watcher started (fallback mode)")

    while not stop_event.is_set():
        time.sleep(3)
        try:
            current = {_partition_key(p) for p in psutil.disk_partitions(all=True)}
            added = current - known
            removed = known - current

            for mountpoint in added:
                logger.info("USB/drive inserted: %s", mountpoint)
                sender.enqueue("usb", "connected", {"mountpoint": mountpoint})
                sender.enqueue("usb", "mounted", {
                    "mountpoint": mountpoint,
                    "authorized": False,
                    "status": "Unauthorized",
                    "label": mountpoint,
                })

            for mountpoint in removed:
                logger.info("USB/drive removed: %s", mountpoint)
                sender.enqueue("usb", "removed", {"mountpoint": mountpoint})

            known = current
        except Exception as exc:
            logger.error("USB polling error: %s", exc)


# ─────────────────────────────────────────────────────────────────────────────
# Public function
# ─────────────────────────────────────────────────────────────────────────────

def start_usb_monitor() -> threading.Event:
    """Start the USB monitor. Returns the stop event so the caller can signal shutdown."""
    stop_event = threading.Event()

    if platform.system() == "Windows":
        target = _start_wmi_watcher
    else:
        target = _start_polling_watcher

    thread = threading.Thread(
        target=target,
        args=(stop_event,),
        daemon=True,
        name="agent-usb-monitor",
    )
    thread.start()
    logger.info("USB monitor started (platform=%s)", platform.system())
    return stop_event
