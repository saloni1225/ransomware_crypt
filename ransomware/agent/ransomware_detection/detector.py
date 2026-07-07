"""
Ransomware Detector
====================
Standalone stateful detector that analyses file-system metrics published
by the file monitor.

Instead of duplicating watchdog logic, this module is called from the
file-monitor's event handler (already wired in file_monitor/watcher.py).

Additionally provides an independent poll-based scanner that checks the
configured directories for already-encrypted files (e.g. on agent restart
after an attack started while the agent was offline).
"""

import logging
import math
import os
import sys
import threading
import time
from collections import deque
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import config
from sender import sender

logger = logging.getLogger("agent.ransomware_detection")

# Suspicious file extension pairs: (original, ransomware_variant)
KNOWN_RANSOM_EXTS = {
    ".locked", ".encrypted", ".enc", ".crypt", ".crypto",
    ".aaa", ".abc", ".xyz", ".zzz", ".micro", ".vvv", ".xxx",
    ".locky", ".cerber", ".zepto", ".thor", ".odin",
}


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in freq if c)


def _file_entropy(path: str, sample: int = 65536) -> Optional[float]:
    try:
        with open(path, "rb") as f:
            data = f.read(sample)
        return _shannon_entropy(data)
    except (OSError, PermissionError):
        return None


class RansomwareDetector:
    """
    Post-hoc scan of directories for already-encrypted files.
    Runs once at startup to catch attacks that occurred while the agent
    was not running.
    """

    def __init__(self):
        self._stop_event = threading.Event()

    def start_background_scan(self) -> None:
        threading.Thread(target=self._scan, daemon=True,
                         name="agent-ransomware-scan").start()

    def stop(self) -> None:
        self._stop_event.set()

    def _scan(self) -> None:
        logger.info("Background ransomware scan starting …")
        total_scanned = 0
        suspicious_found = 0

        for base_dir in config.MONITOR_PATHS:
            if not os.path.isdir(base_dir):
                continue
            for root, dirs, files in os.walk(base_dir):
                if self._stop_event.is_set():
                    return
                # Skip system/hidden directories
                dirs[:] = [
                    d for d in dirs
                    if not d.startswith(".") and d not in ("System Volume Information",)
                ]
                for filename in files:
                    path = os.path.join(root, filename)
                    ext = os.path.splitext(filename)[1].lower()

                    if ext in KNOWN_RANSOM_EXTS:
                        logger.warning("Ransomware extension found: %s", path)
                        sender.enqueue("file", "modified", {
                            "path": path,
                            "filename": filename,
                            "extension": ext,
                            "risk": "high",
                            "extension_alert": True,
                            "alert": "File with known ransomware extension found",
                        })
                        suspicious_found += 1
                    else:
                        # Spot-check entropy on a subset to keep scan fast
                        if total_scanned % 50 == 0:  # check 1 in 50 files
                            entropy = _file_entropy(path)
                            if entropy and entropy > config.ENTROPY_THRESHOLD:
                                logger.warning(
                                    "High-entropy file found (%.2f): %s", entropy, path
                                )
                                sender.enqueue("file", "modified", {
                                    "path": path,
                                    "filename": filename,
                                    "extension": ext,
                                    "entropy": round(entropy, 3),
                                    "entropy_alert": True,
                                    "risk": "high",
                                    "alert": "Possible encrypted file detected in background scan",
                                })
                                suspicious_found += 1

                    total_scanned += 1
                    time.sleep(0.001)  # yield to other threads

        logger.info(
            "Background ransomware scan complete — scanned=%d suspicious=%d",
            total_scanned, suspicious_found,
        )
        if suspicious_found > 0:
            sender.enqueue("file", "modified", {
                "scan_summary": True,
                "scanned": total_scanned,
                "suspicious": suspicious_found,
                "modified_count": suspicious_found,
                "entropy": config.ENTROPY_THRESHOLD + 0.5,
                "alert": f"Background scan found {suspicious_found} suspicious file(s)",
            })


def start_ransomware_detector() -> RansomwareDetector:
    detector = RansomwareDetector()
    detector.start_background_scan()
    return detector
