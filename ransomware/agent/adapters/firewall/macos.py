"""
macOS Firewall Adapter
=======================
Reads the application-level firewall state via defaults/socketfilterfw.
"""
from __future__ import annotations

import logging
import subprocess
from typing import Any, Dict

from adapters.base import AdapterCapability, CapabilityState
from adapters.firewall.base import FirewallAdapter
from adapters.registry import register

logger = logging.getLogger("agent.adapters.firewall.macos")


class MacOSFirewallAdapter(FirewallAdapter):

    _PLIST = "/Library/Preferences/com.apple.alf"

    def check_capability(self) -> AdapterCapability:
        try:
            r = subprocess.run(
                ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"],
                capture_output=True, text=True, timeout=5,
            )
            return AdapterCapability(
                module=self.MODULE, supported=True,
                capability_state=CapabilityState.SUPPORTED,
                message="macOS Application Firewall available",
            )
        except FileNotFoundError:
            # Try defaults read as fallback
            return AdapterCapability(
                module=self.MODULE, supported=True,
                capability_state=CapabilityState.DEGRADED,
                message="socketfilterfw not found — using defaults plist",
            )
        except Exception as exc:
            return AdapterCapability(
                module=self.MODULE, supported=False,
                capability_state=CapabilityState.DEGRADED, message=str(exc),
            )

    def _collect(self) -> Dict[str, Any]:
        enabled = self._check_globalstate()
        stealth = self._check_stealthmode()
        return {
            "profiles": [{
                "name": "application_firewall",
                "enabled": enabled,
                "stealth_mode": stealth,
                "default_inbound": "block" if enabled else "allow",
                "default_outbound": "allow",
            }],
            "health": "healthy" if enabled else "warning",
        }

    def _check_globalstate(self) -> bool:
        try:
            r = subprocess.run(
                ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"],
                capture_output=True, text=True, timeout=5,
            )
            return "enabled" in r.stdout.lower()
        except Exception:
            pass
        # Fallback: read ALF plist
        try:
            r = subprocess.run(
                ["defaults", "read", self._PLIST, "globalstate"],
                capture_output=True, text=True, timeout=5,
            )
            val = r.stdout.strip()
            return val in ("1", "2")
        except Exception:
            return False

    def _check_stealthmode(self) -> bool:
        try:
            r = subprocess.run(
                ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getstealthmode"],
                capture_output=True, text=True, timeout=5,
            )
            return "enabled" in r.stdout.lower()
        except Exception:
            return False

    def _compute_health(self, data: Dict) -> str:
        return data.get("health", "unknown")


register("firewall", "Darwin", MacOSFirewallAdapter)
