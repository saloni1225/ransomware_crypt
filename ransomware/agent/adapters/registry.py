"""
Adapter Registry
================
Selects the correct OS-specific adapter implementation at runtime.
Each module registers Windows / Linux / macOS classes; the registry
picks the right one based on platform.system().
"""
from __future__ import annotations

import platform
import logging
from typing import Dict, Optional, Type

from adapters.base import BaseAdapter, UnsupportedAdapter

logger = logging.getLogger("agent.adapters.registry")

# ── Module → OS → Adapter class mapping ──────────────────────────────────────

_REGISTRY: Dict[str, Dict[str, Type[BaseAdapter]]] = {}


def register(module: str, os_name: str, adapter_cls: Type[BaseAdapter]) -> None:
    """Register an adapter class for a specific module and OS."""
    if module not in _REGISTRY:
        _REGISTRY[module] = {}
    _REGISTRY[module][os_name] = adapter_cls
    logger.debug("Registered adapter: %s -> %s -> %s", module, os_name, adapter_cls.__name__)


def get_adapter(module: str) -> BaseAdapter:
    """
    Return the appropriate adapter for the current OS and module.
    Falls back to UnsupportedAdapter if no match is found.
    """
    sys_os = platform.system()  # 'Windows', 'Linux', 'Darwin'
    module_adapters = _REGISTRY.get(module, {})

    adapter_cls = module_adapters.get(sys_os)
    if adapter_cls is None:
        logger.warning(
            "No adapter registered for module='%s' os='%s' — using UnsupportedAdapter",
            module, sys_os,
        )
        return UnsupportedAdapter(module=module)

    try:
        return adapter_cls()
    except Exception as exc:
        logger.error("Failed to instantiate adapter %s: %s", adapter_cls.__name__, exc)
        return UnsupportedAdapter(module=module, reason="instantiation_error")


def available_modules() -> list:
    return list(_REGISTRY.keys())


# ── Auto-register all adapters on import ────────────────────────────────────

def _bootstrap() -> None:
    """Import all adapter modules to trigger their register() calls."""
    modules_to_load = [
        "adapters.malware.windows",
        "adapters.malware.linux",
        "adapters.malware.macos",
        "adapters.network.windows",
        "adapters.network.linux",
        "adapters.network.macos",
        "adapters.firewall.windows",
        "adapters.firewall.linux",
        "adapters.firewall.macos",
        "adapters.browser.windows",
        "adapters.browser.linux",
        "adapters.browser.macos",
        "adapters.privacy.windows",
        "adapters.privacy.linux",
        "adapters.privacy.macos",
        "adapters.deception.windows",
        "adapters.deception.linux",
        "adapters.deception.macos",
        "adapters.wifi.windows",
        "adapters.wifi.linux",
        "adapters.wifi.macos",
    ]
    for mod in modules_to_load:
        try:
            __import__(mod)
        except ImportError as exc:
            logger.debug("Could not import adapter module %s: %s", mod, exc)


_bootstrap()
