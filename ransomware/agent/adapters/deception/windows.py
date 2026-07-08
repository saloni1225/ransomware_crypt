"""
Cross-Platform Deception Engine Adapter
========================================
Wraps the existing file_placer / watchdog deception engine.
Reports the current inventory of decoy files and their active state.
"""
from __future__ import annotations

import logging
import os
import sys
import threading
from typing import Any, Dict, List, Optional

from adapters.base import AdapterCapability, CapabilityState
from adapters.deception.base import DeceptionAdapter
from adapters.registry import register

logger = logging.getLogger("agent.adapters.deception")


class _DeceptionInventoryAdapter(DeceptionAdapter):
    """Reports the current state of all deployed decoy files."""

    def check_capability(self) -> AdapterCapability:
        try:
            # Verify config is importable
            sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))
            import config
            decoy_dir = config.DECOY_DIR
            return AdapterCapability(
                module=self.MODULE, supported=True,
                capability_state=CapabilityState.SUPPORTED,
                message=f"Deception engine monitoring {decoy_dir}",
            )
        except ImportError:
            return AdapterCapability(
                module=self.MODULE, supported=False,
                capability_state=CapabilityState.MISSING_DEPENDENCY,
                dependency="config.py",
                message="config.py not found — cannot determine DECOY_DIR",
            )

    def _collect(self) -> Dict[str, Any]:
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))
        import config

        decoy_dir = config.DECOY_DIR
        decoy_files = config.DECOY_FILES
        decoys: List[Dict] = []

        for filename in decoy_files:
            path = os.path.join(decoy_dir, filename)
            exists = os.path.isfile(path)

            # Try to get last modification time as a proxy for "last triggered"
            last_modified: Optional[str] = None
            if exists:
                try:
                    import datetime
                    mtime = os.path.getmtime(path)
                    last_modified = datetime.datetime.utcfromtimestamp(mtime).isoformat() + "Z"
                except Exception:
                    pass

            decoys.append({
                "path": path,
                "filename": filename,
                "active": exists,
                "last_triggered_at": None,  # Real trigger events come from watchdog
                "file_exists": exists,
                "last_modified": last_modified,
            })

        active_count = sum(1 for d in decoys if d["active"])
        return {
            "decoys": decoys,
            "events": [],  # Events are pushed in real-time by watchdog
            "active_count": active_count,
            "total_configured": len(decoy_files),
            "decoy_dir": decoy_dir,
        }

    def _compute_health(self, data: Dict) -> str:
        if data.get("active_count", 0) == 0:
            return "warning"
        return "healthy"


class WindowsDeceptionAdapter(_DeceptionInventoryAdapter):
    pass

class LinuxDeceptionAdapter(_DeceptionInventoryAdapter):
    pass

class MacOSDeceptionAdapter(_DeceptionInventoryAdapter):
    pass


register("deception", "Windows", WindowsDeceptionAdapter)
register("deception", "Linux",   LinuxDeceptionAdapter)
register("deception", "Darwin",  MacOSDeceptionAdapter)
