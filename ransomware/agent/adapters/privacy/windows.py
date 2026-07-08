"""
Cross-Platform Privacy Adapter
================================
Scans only the configured MONITOR_PATHS for:
 1. Plaintext secret / credential patterns
 2. Sensitive file extensions in world-readable paths
 3. Risky executable downloads
 4. Unprotected private key files

IMPORTANT DESIGN CONSTRAINTS:
- Only scans directories in config.MONITOR_PATHS (never arbitrary user files)
- Reads only the first 4096 bytes of each file for pattern matching
- Never includes file content in the payload — only path, type, severity, reason
"""
from __future__ import annotations

import logging
import os
import re
import stat
import sys
from typing import Any, Dict, List, Optional, Tuple

from adapters.base import AdapterCapability, CapabilityState
from adapters.privacy.base import PrivacyAdapter
from adapters.registry import register

logger = logging.getLogger("agent.adapters.privacy")

# ── Secret / Credential Patterns ─────────────────────────────────────────────

_SECRET_PATTERNS: List[Tuple[str, str, str]] = [
    # (type_label, severity, regex)
    ("aws_access_key",       "high",   r"AKIA[0-9A-Z]{16}"),
    ("aws_secret_key",       "high",   r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]"),
    ("private_key_header",   "high",   r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ("password_plaintext",   "medium", r"(?i)password\s*[:=]\s*[^\s]{6,}"),
    ("api_key_pattern",      "medium", r"(?i)(api[_\-]?key|apikey)\s*[:=]\s*['\"][a-zA-Z0-9\-_]{16,}['\"]"),
    ("github_pat",           "high",   r"ghp_[0-9a-zA-Z]{36}"),
    ("stripe_secret",        "high",   r"sk_live_[0-9a-zA-Z]{24,}"),
    ("sendgrid_key",         "high",   r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}"),
    ("connection_string",    "medium", r"(?i)(connectionstring|conn_str)\s*=.*password"),
    ("jwt_token",            "medium", r"eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}"),
]

# Compiled patterns
_COMPILED_PATTERNS = [
    (label, severity, re.compile(pattern))
    for label, severity, pattern in _SECRET_PATTERNS
]

# File extensions that are inherently risky if found in Downloads
_RISKY_DOWNLOAD_EXTS = {".exe", ".bat", ".vbs", ".ps1", ".scr", ".msi", ".dmg", ".sh", ".jar"}

# Extensions that may contain secrets
_SENSITIVE_EXTENSIONS = {".env", ".pem", ".key", ".p12", ".pfx", ".crt", ".cer", ".ovpn"}

# Max file size to scan (bytes)
_MAX_SCAN_BYTES = 4096


def _is_world_readable(path: str) -> bool:
    """Check if file has world-readable permissions (Linux/macOS only)."""
    try:
        mode = os.stat(path).st_mode
        return bool(mode & stat.S_IROTH)
    except Exception:
        return False


def _scan_file_for_secrets(path: str) -> List[Dict]:
    """Read up to _MAX_SCAN_BYTES and check against secret patterns."""
    findings = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read(_MAX_SCAN_BYTES)
        for label, severity, pattern in _COMPILED_PATTERNS:
            if pattern.search(content):
                findings.append({
                    "type": label,
                    "path": path,
                    "severity": severity,
                    "reason": f"Pattern '{label}' detected in file content",
                })
                break  # One finding per file to avoid flooding
    except (OSError, PermissionError):
        pass
    return findings


class _PrivacyScanAdapter(PrivacyAdapter):
    """Shared cross-platform privacy scanner."""

    def check_capability(self) -> AdapterCapability:
        # Import config to get monitor paths
        try:
            sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))
            import config
            paths = config.MONITOR_PATHS
            accessible = [p for p in paths if os.path.isdir(p)]
            if not accessible:
                return AdapterCapability(
                    module=self.MODULE, supported=False,
                    capability_state=CapabilityState.PERMISSION_DENIED,
                    message="No MONITOR_PATHS are accessible",
                )
            return AdapterCapability(
                module=self.MODULE, supported=True,
                capability_state=CapabilityState.SUPPORTED,
                message=f"Scanning {len(accessible)} monitored directories",
            )
        except ImportError:
            return AdapterCapability(
                module=self.MODULE, supported=True,
                capability_state=CapabilityState.DEGRADED,
                message="config.py not found — scanning default user dirs",
            )

    def _collect(self) -> Dict[str, Any]:
        monitor_paths = self._get_monitor_paths()
        findings: List[Dict] = []
        files_scanned = 0

        for base_dir in monitor_paths:
            if not os.path.isdir(base_dir):
                continue
            findings.extend(self._scan_directory(base_dir))
            files_scanned += 1

        # Deduplicate by path
        seen_paths = set()
        unique_findings = []
        for f in findings:
            if f["path"] not in seen_paths:
                seen_paths.add(f["path"])
                unique_findings.append(f)

        high_count = sum(1 for f in unique_findings if f["severity"] == "high")
        health = "critical" if high_count > 0 else (
            "warning" if unique_findings else "healthy"
        )

        return {
            "findings": unique_findings,
            "files_scanned": files_scanned,
            "monitored_paths": monitor_paths,
            "health": health,
        }

    def _get_monitor_paths(self) -> List[str]:
        try:
            sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))
            import config
            return config.MONITOR_PATHS
        except Exception:
            return [
                os.path.expanduser("~/Documents"),
                os.path.expanduser("~/Desktop"),
                os.path.expanduser("~/Downloads"),
            ]

    def _scan_directory(self, base_dir: str) -> List[Dict]:
        findings = []
        is_downloads = "download" in base_dir.lower()

        try:
            for entry in os.scandir(base_dir):
                if not entry.is_file(follow_symlinks=False):
                    continue

                path = entry.path
                ext = os.path.splitext(path)[1].lower()

                # 1. Risky executables in Downloads
                if is_downloads and ext in _RISKY_DOWNLOAD_EXTS:
                    findings.append({
                        "type": "risky_download",
                        "path": path,
                        "severity": "medium",
                        "reason": f"Executable file type '{ext}' found in Downloads folder",
                    })
                    continue

                # 2. Sensitive extension with world-readable permissions
                if ext in _SENSITIVE_EXTENSIONS:
                    if _is_world_readable(path):
                        findings.append({
                            "type": "world_readable_sensitive_file",
                            "path": path,
                            "severity": "high",
                            "reason": f"Sensitive file '{ext}' is world-readable",
                        })
                    else:
                        findings.append({
                            "type": "sensitive_file_present",
                            "path": path,
                            "severity": "low",
                            "reason": f"Sensitive file type '{ext}' found in monitored directory",
                        })
                    continue

                # 3. Scan text-like files for secret patterns
                if ext in (".txt", ".json", ".yaml", ".yml", ".ini", ".cfg",
                           ".conf", ".properties", ".xml", ".env", ""):
                    try:
                        file_size = entry.stat().st_size
                        if 0 < file_size < 512_000:  # skip empty and huge files
                            findings.extend(_scan_file_for_secrets(path))
                    except OSError:
                        pass

        except PermissionError:
            logger.debug("Permission denied scanning: %s", base_dir)

        return findings

    def _compute_health(self, data: Dict) -> str:
        return data.get("health", "unknown")


class WindowsPrivacyAdapter(_PrivacyScanAdapter):
    pass

class LinuxPrivacyAdapter(_PrivacyScanAdapter):
    pass

class MacOSPrivacyAdapter(_PrivacyScanAdapter):
    pass


register("privacy", "Windows", WindowsPrivacyAdapter)
register("privacy", "Linux",   LinuxPrivacyAdapter)
register("privacy", "Darwin",  MacOSPrivacyAdapter)
