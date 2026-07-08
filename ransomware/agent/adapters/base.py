"""
Adapter Base Classes
====================
Defines the contract every OS-specific security module adapter must fulfill.
All adapters produce normalized payloads that the backend can ingest cleanly.
"""
from __future__ import annotations

import datetime
import platform
import socket
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


# ── Capability States ─────────────────────────────────────────────────────────

class CapabilityState:
    SUPPORTED          = "supported"
    UNSUPPORTED_OS     = "unsupported_os"
    MISSING_DEPENDENCY = "missing_dependency"
    PERMISSION_DENIED  = "permission_denied"
    DEGRADED           = "degraded"
    DISABLED           = "disabled"


@dataclass
class AdapterCapability:
    """Describes what a module can do on the current host."""
    module: str
    supported: bool
    platform: str = field(default_factory=lambda: platform.system())
    capability_state: str = CapabilityState.SUPPORTED
    dependency: Optional[str] = None
    message: str = ""

    def to_dict(self) -> Dict:
        return asdict(self)


# ── Normalized Payload ────────────────────────────────────────────────────────

@dataclass
class NormalizedPayload:
    """
    Canonical telemetry envelope.  Every adapter emits one of these.
    """
    module: str
    platform: str
    supported: bool
    collected_at: str               # ISO-8601
    host_id: str
    capability: AdapterCapability
    data: Dict[str, Any]            # module-specific findings
    health: str = "unknown"         # healthy | warning | critical | unknown

    def to_dict(self) -> Dict:
        d = asdict(self)
        # capability is already a dict after asdict()
        return d


def _utcnow_iso() -> str:
    return datetime.datetime.utcnow().isoformat() + "Z"


def _host_id() -> str:
    return socket.gethostname()


# ── Base Adapter ──────────────────────────────────────────────────────────────

class BaseAdapter(ABC):
    """
    Every security module adapter must extend this class.

    Subclasses implement:
      - check_capability()  → AdapterCapability
      - _collect()          → Dict  (raw, module-specific data)

    collect() orchestrates the above and wraps the result in a NormalizedPayload.
    """

    MODULE: str = "base"

    def __init__(self) -> None:
        self._platform = platform.system()

    # ── Public API ────────────────────────────────────────────────────────────

    def collect(self) -> NormalizedPayload:
        """
        Run the adapter.  Returns a NormalizedPayload regardless of success/failure.
        Never raises — capability failures are encoded in the payload.
        """
        cap = self.check_capability()
        if not cap.supported:
            return NormalizedPayload(
                module=self.MODULE,
                platform=self._platform,
                supported=False,
                collected_at=_utcnow_iso(),
                host_id=_host_id(),
                capability=cap,
                data={},
                health="unknown",
            )
        try:
            data = self._collect()
            health = self._compute_health(data)
        except PermissionError as exc:
            cap.capability_state = CapabilityState.PERMISSION_DENIED
            cap.message = str(exc)
            cap.supported = False
            data = {}
            health = "unknown"
        except Exception as exc:
            cap.capability_state = CapabilityState.DEGRADED
            cap.message = str(exc)
            data = {"error": str(exc)}
            health = "unknown"

        return NormalizedPayload(
            module=self.MODULE,
            platform=self._platform,
            supported=cap.supported,
            collected_at=_utcnow_iso(),
            host_id=_host_id(),
            capability=cap,
            data=data,
            health=health,
        )

    @abstractmethod
    def check_capability(self) -> AdapterCapability:
        """Probe the host for required tools/permissions without side effects."""

    @abstractmethod
    def _collect(self) -> Dict[str, Any]:
        """Perform the actual collection.  May raise exceptions."""

    def _compute_health(self, data: Dict) -> str:  # noqa: ARG002
        """Override in subclasses for module-specific health logic."""
        return "healthy"


# ── Unsupported Stub ──────────────────────────────────────────────────────────

class UnsupportedAdapter(BaseAdapter):
    """Returned by the registry when no adapter exists for the current OS."""

    def __init__(self, module: str, reason: str = "unsupported_os") -> None:
        super().__init__()
        self.MODULE = module
        self._reason = reason

    def check_capability(self) -> AdapterCapability:
        return AdapterCapability(
            module=self.MODULE,
            supported=False,
            capability_state=self._reason,
            message=f"No adapter available for {self.MODULE} on {self._platform}",
        )

    def _collect(self) -> Dict[str, Any]:
        return {}
