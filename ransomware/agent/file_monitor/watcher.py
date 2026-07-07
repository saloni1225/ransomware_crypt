"""
File Monitor
============
Watches configured directories for file system events using watchdog.

Detection capabilities:
- File creation, deletion, modification, rename
- Shannon entropy measurement on modified files (high entropy → likely encryption)
- Rapid-modification rate counter (many files changed quickly → ransomware burst)
- Decoy/honeypot file access detection
"""

import logging
import math
import os
import sys
import threading
import time
from collections import deque
from typing import Optional

# watchdog is required — catch missing dep early
try:
    from watchdog.events import (
        FileCreatedEvent,
        FileDeletedEvent,
        FileModifiedEvent,
        FileMovedEvent,
        FileSystemEventHandler,
    )
    from watchdog.observers import Observer
except ImportError:
    raise SystemExit("watchdog is required: pip install watchdog")

# Add parent dir so we can import agent modules without installing as package
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import config
from sender import sender

logger = logging.getLogger("agent.file_monitor")

# ─────────────────────────────────────────────────────────────────────────────
# Entropy helper
# ─────────────────────────────────────────────────────────────────────────────

def _shannon_entropy(data: bytes) -> float:
    """Compute Shannon entropy of raw bytes (0–8 scale)."""
    if not data:
        return 0.0
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    length = len(data)
    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy


def _file_entropy(path: str, sample_bytes: int = 65536) -> Optional[float]:
    """Read up to sample_bytes from a file and return its entropy."""
    try:
        with open(path, "rb") as f:
            data = f.read(sample_bytes)
        return _shannon_entropy(data)
    except (OSError, PermissionError):
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Rapid-modification tracker
# ─────────────────────────────────────────────────────────────────────────────

class RapidModTracker:
    """
    Tracks the number of file modifications in a rolling time window.
    When the count exceeds the threshold, fires a ransomware-burst event.
    """

    def __init__(self, threshold: int, window_sec: int):
        self._threshold = threshold
        self._window_sec = window_sec
        self._timestamps: deque = deque()
        self._lock = threading.Lock()
        self._alerted = False  # suppress repeated alerts

    def record(self) -> bool:
        """Record one modification. Returns True if threshold is crossed."""
        now = time.monotonic()
        with self._lock:
            self._timestamps.append(now)
            # Prune events outside the window
            cutoff = now - self._window_sec
            while self._timestamps and self._timestamps[0] < cutoff:
                self._timestamps.popleft()

            count = len(self._timestamps)

        if count >= self._threshold:
            if not self._alerted:
                self._alerted = True
                return True   # caller should fire event
        else:
            self._alerted = False
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Watchdog event handler
# ─────────────────────────────────────────────────────────────────────────────

class SecurityEventHandler(FileSystemEventHandler):
    """
    Handles watchdog file-system events and dispatches them to the backend
    via the AgentSender.
    """

    def __init__(self):
        super().__init__()
        self._tracker = RapidModTracker(
            threshold=config.RAPID_MOD_THRESHOLD,
            window_sec=config.RAPID_MOD_WINDOW_SEC,
        )
        # Build a normalised set of decoy file names for O(1) lookup
        self._decoy_names = {d.lower() for d in config.DECOY_FILES}

    # ── watchdog callbacks ────────────────────────────────────────────────────

    def on_created(self, event):
        if event.is_directory:
            return
        path = event.src_path
        logger.debug("File created: %s", path)
        sender.enqueue("file", "created", {
            "path": path,
            "directory": os.path.dirname(path),
            "filename": os.path.basename(path),
        })

    def on_deleted(self, event):
        if event.is_directory:
            return
        path = event.src_path
        logger.debug("File deleted: %s", path)
        sender.enqueue("file", "deleted", {
            "path": path,
            "directory": os.path.dirname(path),
            "filename": os.path.basename(path),
        })

    def on_modified(self, event):
        if event.is_directory:
            return
        path = event.src_path
        basename = os.path.basename(path)
        ext = os.path.splitext(path)[1].lower()

        # Check decoy file access
        if basename.lower() in self._decoy_names:
            logger.warning("DECOY FILE ACCESSED: %s", path)
            sender.enqueue("file", "accessed", {
                "path": path,
                "filename": basename,
                "decoy": True,
                "privileges": "READ/WRITE",
            })
            return

        # Measure entropy for encryption detection
        entropy = _file_entropy(path)

        # Track rapid modification rate
        burst_detected = self._tracker.record()

        # Suspicious extensions added by ransomware
        suspicious_exts = {".locked", ".encrypted", ".enc", ".crypto", ".crypt",
                           ".aaa", ".xyz", ".zzz", ".micro", ".vvv", ".xxx"}
        is_suspicious_ext = ext in suspicious_exts

        details = {
            "path": path,
            "directory": os.path.dirname(path),
            "filename": basename,
            "extension": ext,
            "entropy": round(entropy, 3) if entropy is not None else None,
            "modified_count": config.RAPID_MOD_THRESHOLD if burst_detected else 1,
        }

        # If entropy is very high OR extension is suspicious OR burst → ransomware signal
        if (entropy and entropy > config.ENTROPY_THRESHOLD) or is_suspicious_ext or burst_detected:
            logger.warning(
                "High-risk file modification — path=%s entropy=%.2f burst=%s",
                path, entropy or 0, burst_detected,
            )
            details["risk"] = "high"
            details["entropy_alert"] = entropy and entropy > config.ENTROPY_THRESHOLD
            details["extension_alert"] = is_suspicious_ext
            details["burst_alert"] = burst_detected

        sender.enqueue("file", "modified", details)

    def on_moved(self, event):
        if event.is_directory:
            return
        src = event.src_path
        dest = event.dest_path
        logger.debug("File renamed: %s → %s", src, dest)
        sender.enqueue("file", "renamed", {
            "path": src,
            "destination": dest,
            "old_filename": os.path.basename(src),
            "new_filename": os.path.basename(dest),
            "directory": os.path.dirname(src),
        })


# ─────────────────────────────────────────────────────────────────────────────
# Public function
# ─────────────────────────────────────────────────────────────────────────────

def start_file_monitor() -> Observer:
    """
    Create and start a watchdog Observer for all configured MONITOR_PATHS.
    Returns the Observer so the caller can join or stop it.
    """
    handler = SecurityEventHandler()
    observer = Observer()

    watched = 0
    for path in config.MONITOR_PATHS:
        if os.path.exists(path):
            observer.schedule(handler, path, recursive=True)
            logger.info("Watching: %s", path)
            watched += 1
        else:
            logger.warning("Monitor path does not exist, skipping: %s", path)

    if watched == 0:
        logger.warning("No valid monitor paths found — file watcher idle")

    observer.start()
    logger.info("File monitor started (%d paths)", watched)
    return observer
