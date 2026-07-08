"""
Linux Firewall Adapter
=======================
Tries ufw first, then iptables for read-only status.
"""
from __future__ import annotations

import logging
import re
import shutil
import subprocess
from typing import Any, Dict, List

from adapters.base import AdapterCapability, CapabilityState
from adapters.firewall.base import FirewallAdapter
from adapters.registry import register

logger = logging.getLogger("agent.adapters.firewall.linux")


class LinuxFirewallAdapter(FirewallAdapter):

    def check_capability(self) -> AdapterCapability:
        if shutil.which("ufw"):
            return AdapterCapability(
                module=self.MODULE, supported=True,
                capability_state=CapabilityState.SUPPORTED,
                message="ufw available",
            )
        if shutil.which("iptables"):
            return AdapterCapability(
                module=self.MODULE, supported=True,
                capability_state=CapabilityState.DEGRADED,
                dependency="ufw",
                message="ufw not found, using iptables (limited info)",
            )
        return AdapterCapability(
            module=self.MODULE, supported=False,
            capability_state=CapabilityState.MISSING_DEPENDENCY,
            dependency="ufw or iptables",
            message="Neither ufw nor iptables found",
        )

    def _collect(self) -> Dict[str, Any]:
        if shutil.which("ufw"):
            return self._collect_ufw()
        return self._collect_iptables()

    def _collect_ufw(self) -> Dict[str, Any]:
        try:
            r = subprocess.run(["ufw", "status", "verbose"],
                               capture_output=True, text=True, timeout=10)
            output = r.stdout
            enabled = "status: active" in output.lower()
            default_in = "deny" if "deny (incoming)" in output.lower() else "allow"
            default_out = "allow" if "allow (outgoing)" in output.lower() else "deny"
            return {
                "profiles": [{"name": "default", "enabled": enabled,
                               "default_inbound": default_in,
                               "default_outbound": default_out}],
                "health": "healthy" if enabled else "critical",
                "tool": "ufw",
            }
        except Exception as exc:
            raise RuntimeError(f"ufw error: {exc}") from exc

    def _collect_iptables(self) -> Dict[str, Any]:
        try:
            r = subprocess.run(["iptables", "-L", "-n", "--line-numbers"],
                               capture_output=True, text=True, timeout=10)
            rule_count = r.stdout.count("Chain")
            return {
                "profiles": [{"name": "default", "enabled": rule_count > 0,
                               "default_inbound": "unknown",
                               "default_outbound": "unknown"}],
                "health": "degraded",
                "tool": "iptables",
                "rule_count": rule_count,
            }
        except PermissionError:
            raise PermissionError("iptables requires root. Run agent as root or with sudo.")

    def _compute_health(self, data: Dict) -> str:
        return data.get("health", "unknown")


register("firewall", "Linux", LinuxFirewallAdapter)
