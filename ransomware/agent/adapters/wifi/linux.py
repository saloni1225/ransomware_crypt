"""
Linux WiFi Adapter (Adapter Framework Wrapper)
===============================================
Delegates to the existing LinuxWifiAdapter in wifi_scanner/scanner.py.
"""
from __future__ import annotations

import logging
import os
import shutil
import sys
from typing import Any, Dict

from adapters.base import AdapterCapability, CapabilityState
from adapters.wifi.base import WiFiAdapter
from adapters.registry import register

logger = logging.getLogger("agent.adapters.wifi.linux")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
try:
    from wifi_scanner.scanner import (
        LinuxWifiAdapter as _LinuxScanner,
        _detect_evil_twins, _classify_risk,
    )
    _SCANNER_OK = True
except ImportError:
    _SCANNER_OK = False


class LinuxWiFiAdapterV2(WiFiAdapter):

    def check_capability(self) -> AdapterCapability:
        if shutil.which("nmcli"):
            return AdapterCapability(
                module=self.MODULE, supported=True,
                capability_state=CapabilityState.SUPPORTED,
                message="nmcli available",
            )
        return AdapterCapability(
            module=self.MODULE, supported=False,
            capability_state=CapabilityState.MISSING_DEPENDENCY,
            dependency="nmcli",
            message="nmcli not found. Install NetworkManager.",
        )

    def _collect(self) -> Dict[str, Any]:
        if not _SCANNER_OK:
            raise RuntimeError("wifi_scanner module not importable")
        scanner = _LinuxScanner()
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


register("wifi", "Linux", LinuxWiFiAdapterV2)
