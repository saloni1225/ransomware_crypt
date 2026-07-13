"""
Agent Sender
============
Handles all HTTP communication between the local agent and the FastAPI backend.
Saves all telemetry events to a secure local SQLite database first (ACID) before 
flushing them to the backend, protecting against crashes and disconnects.
"""

import json
import logging
import os
import platform
import socket
import threading
import time
import uuid
from typing import Any, Dict, List, Optional

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    raise SystemExit("requests is required: pip install requests")

import config
from offline_db import OfflineDB

logger = logging.getLogger("agent.sender")

# ── Internal helpers ─────────────────────────────────────────────────────────

def _build_session() -> requests.Session:
    """Creates a requests Session with connection-level retry (not our app retry)."""
    session = requests.Session()
    retry = Retry(connect=3, backoff_factor=0.5)
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({"Content-Type": "application/json"})
    return session


def _get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def _get_mac() -> str:
    mac = uuid.UUID(int=uuid.getnode()).hex[-12:]
    return ":".join(mac[i:i+2] for i in range(0, 12, 2))


# ── AgentSender class ────────────────────────────────────────────────────────

class AgentSender:
    """
    Thread-safe event sender that writes telemetry to SQLite first,
    then synchronizes it in a background loop with exponential backoff.
    """

    def __init__(self):
        self._session = _build_session()
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._registered = False
        
        # Initialise SQLite offline DB
        db_path = os.path.join(os.path.dirname(config.__file__), "local_events_buffer.db")
        self._db = OfflineDB(db_path, max_size=5000)

    # ── Public API ───────────────────────────────────────────────────────────

    def enqueue(self, log_type: str, action: str, details: Optional[Dict] = None) -> None:
        """Add a single log event directly to the offline SQLite DB (non-blocking)."""
        event = {
            "device_id": config.DEVICE_ID,
            "type": log_type,
            "action": action,
            "details": details or {},
        }
        # First-to-disk write
        self._db.enqueue(event)
        logger.debug("Successfully enqueued event to disk type=%s action=%s", log_type, action)

    def start(self) -> None:
        """Start background threads. Registration runs in the background so a
        temporarily-unreachable backend never blocks the monitors from starting
        (the backend also auto-registers a device on first telemetry)."""
        threading.Thread(target=self._register_device, daemon=True,
                         name="agent-register").start()
        threading.Thread(target=self._heartbeat_loop, daemon=True,
                         name="agent-heartbeat").start()
        threading.Thread(target=self._sync_loop, daemon=True,
                         name="agent-telemetry-sync").start()
        logger.info("AgentSender started (device_id=%s)", config.DEVICE_ID)

    def stop(self) -> None:
        """Signal threads to stop."""
        self._stop_event.set()
        logger.info("AgentSender stopped")

    # ── Device registration ──────────────────────────────────────────────────

    def _register_device(self) -> bool:
        payload = {
            "id": config.DEVICE_ID,
            "hostname": config.HOSTNAME,
            "ip_address": _get_local_ip(),
            "mac_address": _get_mac(),
            "os_type": platform.system(),
            "firewall_status": self._get_firewall_status(),
        }
        for attempt in range(config.MAX_RETRY_ATTEMPTS):
            try:
                r = self._session.post(
                    f"{config.BACKEND_URL}/devices/register",
                    json=payload,
                    timeout=10,
                )
                if r.status_code in (200, 201):
                    self._registered = True
                    logger.info("Device registered: %s", config.DEVICE_ID)
                    return True
                logger.warning("Registration status %d: %s", r.status_code, r.text[:200])
            except requests.RequestException as exc:
                logger.warning("Registration attempt %d failed: %s", attempt + 1, exc)
                time.sleep(config.RETRY_BASE_DELAY_SEC * (2 ** attempt))
        logger.error("Could not register device after %d attempts — continuing offline",
                     config.MAX_RETRY_ATTEMPTS)
        return False

    @staticmethod
    def _get_firewall_status() -> str:
        """Best-effort Windows firewall status check."""
        if platform.system() != "Windows":
            return "unknown"
        try:
            import subprocess
            result = subprocess.run(
                ["netsh", "advfirewall", "show", "allprofiles", "state"],
                capture_output=True, text=True, timeout=5
            )
            if "ON" in result.stdout.upper():
                return "enabled"
            return "disabled"
        except Exception:
            return "unknown"

    # ── Heartbeat ────────────────────────────────────────────────────────────

    def _heartbeat_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._send_heartbeat()
            except Exception as exc:
                logger.warning("Heartbeat error: %s", exc)
            self._stop_event.wait(config.HEARTBEAT_INTERVAL_SEC)

    def _send_heartbeat(self) -> None:
        payload = {
            "status": "online",
            "firewall_status": self._get_firewall_status(),
        }
        r = self._session.post(
            f"{config.BACKEND_URL}/devices/{config.DEVICE_ID}/heartbeat",
            json=payload,
            timeout=10,
        )
        if r.status_code == 200:
            logger.debug("Heartbeat OK")
        else:
            logger.warning("Heartbeat failed: %d", r.status_code)

    # ── Telemetry Sync Loop ──────────────────────────────────────────────────

    def _sync_loop(self) -> None:
        """Drains events from SQLite DB and posts them with exponential backoff on failure."""
        backoff_delay = 1.0  # seconds
        
        while not self._stop_event.is_set():
            batch_items = self._db.get_batch(config.BATCH_SIZE)
            if not batch_items:
                # No data to send, sleep batch interval
                self._stop_event.wait(config.BATCH_INTERVAL_SEC)
                continue
                
            batch_events = [item["event"] for item in batch_items]
            batch_ids = [item["id"] for item in batch_items]
            
            success = self._post_batch(batch_events)
            if success:
                # Delete sent events from DB
                self._db.delete_batch(batch_ids)
                backoff_delay = 1.0  # reset backoff
                # Loop immediately without delay to drain the remaining queue faster
            else:
                logger.warning("Sync failed. Retrying in %.1fs (exponential backoff)", backoff_delay)
                self._stop_event.wait(backoff_delay)
                backoff_delay = min(backoff_delay * 2, 60.0)

    def _post_batch(self, batch: List[Dict]) -> bool:
        """POST a batch of events. Returns True on success."""
        try:
            r = self._session.post(
                f"{config.BACKEND_URL}/threats/logs/batch",
                json={"events": batch},
                timeout=15,
            )
            if r.status_code in (200, 201):
                logger.info("Batch of %d events synced successfully", len(batch))
                return True
            logger.warning("Batch endpoint returned %d — falling back to individual", r.status_code)
        except requests.RequestException:
            logger.debug("Batch endpoint unreachable — trying individual POSTs")

        # Fallback: post one by one
        all_ok = True
        for event in batch:
            try:
                r = self._session.post(
                    f"{config.BACKEND_URL}/threats/logs",
                    json=event,
                    timeout=10,
                )
                if r.status_code not in (200, 201):
                    all_ok = False
            except requests.RequestException:
                all_ok = False
        return all_ok


# ── Module-level singleton ───────────────────────────────────────────────────
sender = AgentSender()
