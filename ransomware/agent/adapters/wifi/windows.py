"""
Windows WiFi Adapter (Adapter Framework Wrapper)
=================================================
Delegates to the existing WindowsWifiAdapter in wifi_scanner/scanner.py,
promoting it into the new adapter framework without duplicating code.
"""
from __future__ import annotations

import logging
import os
import sys
from typing import Any, Dict

from adapters.base import AdapterCapability, CapabilityState
from adapters.wifi.base import WiFiAdapter
from adapters.registry import register

logger = logging.getLogger("agent.adapters.wifi.windows")

# Import the proven scanner implementations
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
try:
    from wifi_scanner.scanner import (
        WindowsWifiAdapter as _WinScanner,
        _detect_evil_twins, _classify_risk,
    )
    _SCANNER_OK = True
except ImportError:
    _SCANNER_OK = False


class WindowsWiFiAdapterV2(WiFiAdapter):

    def check_capability(self) -> AdapterCapability:
        import subprocess
        try:
            r = subprocess.run(
                ["netsh", "wlan", "show", "interfaces"],
                capture_output=True, text=True, timeout=8,
                encoding="utf-8", errors="replace",
            )
            if "WLAN AutoConfig service" in r.stdout or "There is" in r.stdout or "Wi-Fi" in r.stdout or r.returncode == 0:
                return AdapterCapability(
                    module=self.MODULE, supported=True,
                    capability_state=CapabilityState.SUPPORTED,
                    message="netsh wlan available",
                )
        except FileNotFoundError:
            pass
        return AdapterCapability(
            module=self.MODULE, supported=False,
            capability_state=CapabilityState.MISSING_DEPENDENCY,
            dependency="netsh",
            message="netsh not found or WLAN service unavailable",
        )

    def _collect(self) -> Dict[str, Any]:
        if not _SCANNER_OK:
            raise RuntimeError("wifi_scanner module not importable")
        scanner = _WinScanner()
        networks = scanner.scan()
        connected_ssid = scanner.get_connected_ssid()
        networks = _detect_evil_twins(networks)

        for net in networks:
            net["risk_level"] = _classify_risk(net)
            net["is_connected"] = (net["ssid"] == connected_ssid)

        suspicious = sum(1 for n in networks if n["risk_level"] in ("high", "critical"))
        return {
            "networks": networks,
            "total": len(networks),
            "connected_ssid": connected_ssid,
            "suspicious_count": suspicious,
        }

    def _compute_health(self, data: Dict) -> str:
        if data.get("suspicious_count", 0) > 0:
            return "warning"
        return "healthy"


register("wifi", "Windows", WindowsWiFiAdapterV2)
