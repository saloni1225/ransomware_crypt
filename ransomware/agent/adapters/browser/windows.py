"""
Cross-Platform Browser Process Adapter
=======================================
Uses psutil to discover running browser processes, inspect their
command-line arguments for unsafe flags, and report inventory.
Works on Windows, Linux, and macOS.
"""
from __future__ import annotations

import logging
import os
import re
from typing import Any, Dict, List, Optional

try:
    import psutil
    _PSUTIL_OK = True
except ImportError:
    _PSUTIL_OK = False

from adapters.base import AdapterCapability, CapabilityState
from adapters.browser.base import BrowserAdapter
from adapters.registry import register

logger = logging.getLogger("agent.adapters.browser")

# Known browser process names per OS
_BROWSER_PROCESS_NAMES = {
    "Windows": {
        "chrome.exe": "Chrome",
        "msedge.exe": "Edge",
        "firefox.exe": "Firefox",
        "brave.exe": "Brave",
        "opera.exe": "Opera",
        "iexplore.exe": "Internet Explorer",
    },
    "Linux": {
        "google-chrome": "Chrome",
        "chromium": "Chromium",
        "chromium-browser": "Chromium",
        "firefox": "Firefox",
        "brave-browser": "Brave",
    },
    "Darwin": {
        "Google Chrome": "Chrome",
        "firefox": "Firefox",
        "Safari": "Safari",
        "Brave Browser": "Brave",
        "Microsoft Edge": "Edge",
        "Opera": "Opera",
    },
}

# Cmdline flags that indicate unsafe browser configuration
_RISKY_ARGS = {
    "--disable-web-security": "Web security disabled (CORS bypass)",
    "--no-sandbox": "Sandbox disabled (privilege escalation risk)",
    "--remote-debugging-port": "Remote debugging port open",
    "--remote-allow-origins": "Remote debugging origins allowed",
    "--allow-running-insecure-content": "Insecure content allowed",
    "--disable-features=IsolateOrigins": "Site isolation disabled",
    "--disable-site-isolation-trials": "Site isolation disabled",
}


def _score_risk(suspicious_args: List[str]) -> str:
    if not suspicious_args:
        return "low"
    if any("sandbox" in a or "web-security" in a for a in suspicious_args):
        return "high"
    return "medium"


class _PsutilBrowserAdapter(BrowserAdapter):
    """Shared cross-platform browser adapter."""

    _PLATFORM_NAMES: Dict[str, str] = {}  # override in subclasses

    def check_capability(self) -> AdapterCapability:
        if not _PSUTIL_OK:
            return AdapterCapability(
                module=self.MODULE, supported=False,
                capability_state=CapabilityState.MISSING_DEPENDENCY,
                dependency="psutil",
                message="psutil not installed: pip install psutil",
            )
        return AdapterCapability(
            module=self.MODULE, supported=True,
            capability_state=CapabilityState.SUPPORTED,
            message="psutil available for browser process discovery",
        )

    def _collect(self) -> Dict[str, Any]:
        browsers: List[Dict] = []
        seen_pids: set = set()

        for proc in psutil.process_iter(["pid", "name", "exe", "cmdline", "status"]):
            try:
                name_lower = (proc.info.get("name") or "").lower()
                friendly = self._match_browser(proc.info.get("name") or "")
                if not friendly:
                    continue
                if proc.info["pid"] in seen_pids:
                    continue
                seen_pids.add(proc.info["pid"])

                cmdline = proc.info.get("cmdline") or []
                cmdline_str = " ".join(cmdline)
                suspicious_args = [
                    desc for flag, desc in _RISKY_ARGS.items()
                    if flag in cmdline_str
                ]

                browsers.append({
                    "name": friendly,
                    "process_running": True,
                    "pid": proc.info["pid"],
                    "version": self._get_version(proc.info.get("exe")),
                    "suspicious_args": suspicious_args,
                    "risk_level": _score_risk(suspicious_args),
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        high_risk = sum(1 for b in browsers if b["risk_level"] == "high")
        health = "critical" if high_risk > 0 else ("warning" if any(
            b["risk_level"] == "medium" for b in browsers) else "healthy")
        return {"browsers": browsers, "health": health}

    def _match_browser(self, proc_name: str) -> Optional[str]:
        """Return friendly name if proc_name matches a known browser."""
        import platform
        name_map = _BROWSER_PROCESS_NAMES.get(platform.system(), {})
        # Exact match first
        if proc_name in name_map:
            return name_map[proc_name]
        # Case-insensitive
        lower = proc_name.lower()
        for key, friendly in name_map.items():
            if key.lower() in lower:
                return friendly
        return None

    def _get_version(self, exe_path: Optional[str]) -> Optional[str]:
        """Best-effort version string from exe path."""
        if not exe_path:
            return None
        # Windows: extract version from path like .../Chrome/Application/126.0.6478.62/...
        m = re.search(r"(\d+\.\d+\.\d+\.\d+)", exe_path or "")
        if m:
            return m.group(1)
        return None

    def _compute_health(self, data: Dict) -> str:
        return data.get("health", "healthy")


class WindowsBrowserAdapter(_PsutilBrowserAdapter):
    pass

class LinuxBrowserAdapter(_PsutilBrowserAdapter):
    pass

class MacOSBrowserAdapter(_PsutilBrowserAdapter):
    pass


register("browser", "Windows", WindowsBrowserAdapter)
register("browser", "Linux",   LinuxBrowserAdapter)
register("browser", "Darwin",  MacOSBrowserAdapter)
