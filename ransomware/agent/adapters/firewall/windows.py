"""
Windows Firewall Adapter
=========================
Reads Windows Defender Firewall profile status via netsh advfirewall.
Parses Domain, Private, and Public profiles individually.
"""
from __future__ import annotations

import logging
import re
import subprocess
from typing import Any, Dict, List

from adapters.base import AdapterCapability, CapabilityState
from adapters.firewall.base import FirewallAdapter
from adapters.registry import register

logger = logging.getLogger("agent.adapters.firewall.windows")


class WindowsFirewallAdapter(FirewallAdapter):

    def check_capability(self) -> AdapterCapability:
        try:
            result = subprocess.run(
                ["netsh", "advfirewall", "show", "allprofiles", "state"],
                capture_output=True, text=True, timeout=8,
                encoding="utf-8", errors="replace",
            )
            if result.returncode == 0:
                return AdapterCapability(
                    module=self.MODULE, supported=True,
                    capability_state=CapabilityState.SUPPORTED,
                    message="netsh advfirewall available",
                )
            return AdapterCapability(
                module=self.MODULE, supported=False,
                capability_state=CapabilityState.PERMISSION_DENIED,
                message="netsh advfirewall returned non-zero exit code",
            )
        except FileNotFoundError:
            return AdapterCapability(
                module=self.MODULE, supported=False,
                capability_state=CapabilityState.MISSING_DEPENDENCY,
                dependency="netsh",
                message="netsh not found",
            )
        except Exception as exc:
            return AdapterCapability(
                module=self.MODULE, supported=False,
                capability_state=CapabilityState.DEGRADED, message=str(exc),
            )

    def _collect(self) -> Dict[str, Any]:
        state_output = self._run_netsh("show", "allprofiles", "state")
        policy_output = self._run_netsh("show", "allprofiles", "firewallpolicy")
        profiles = self._parse_profiles(state_output, policy_output)
        all_enabled = all(p["enabled"] for p in profiles)
        health = "healthy" if all_enabled else "critical"
        return {"profiles": profiles, "health": health}

    def _run_netsh(self, *args: str) -> str:
        result = subprocess.run(
            ["netsh", "advfirewall", *args],
            capture_output=True, text=True, timeout=10,
            encoding="utf-8", errors="replace",
        )
        return result.stdout

    def _parse_profiles(self, state_out: str, policy_out: str) -> List[Dict]:
        profiles = []
        profile_order = ["Domain", "Private", "Public"]
        
        # Extract enabled/disabled state per profile
        state_blocks = re.split(r"\n(?=\w+ Profile Settings:)", state_out, flags=re.I)
        # Extract inbound/outbound policy
        policy_blocks = re.split(r"\n(?=\w+ Profile Settings:)", policy_out, flags=re.I)

        state_map: Dict[str, bool] = {}
        for block in state_blocks:
            m_name = re.search(r"^(\w+) Profile", block, re.I)
            m_state = re.search(r"State\s+(\w+)", block, re.I)
            if m_name and m_state:
                name = m_name.group(1).lower()
                state_map[name] = m_state.group(1).upper() == "ON"

        policy_map: Dict[str, Dict] = {}
        for block in policy_blocks:
            m_name = re.search(r"^(\w+) Profile", block, re.I)
            m_in = re.search(r"Firewall Policy\s+(\w+),(\w+)", block, re.I)
            if m_name and m_in:
                name = m_name.group(1).lower()
                policy_map[name] = {
                    "default_inbound": m_in.group(1).lower(),
                    "default_outbound": m_in.group(2).lower(),
                }

        for pname in profile_order:
            key = pname.lower()
            pol = policy_map.get(key, {})
            profiles.append({
                "name": pname.lower(),
                "enabled": state_map.get(key, False),
                "default_inbound": pol.get("default_inbound", "unknown"),
                "default_outbound": pol.get("default_outbound", "unknown"),
            })

        return profiles

    def _compute_health(self, data: Dict) -> str:
        return data.get("health", "unknown")


register("firewall", "Windows", WindowsFirewallAdapter)
