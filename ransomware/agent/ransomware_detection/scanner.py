"""
Real Malware / Ransomware File Scanner
======================================
On-demand, fully real file scanner that runs on the endpoint agent.

Unlike a simulation, every verdict here is derived from the actual bytes on
disk:

* Real streamed SHA-256 hash of the file.
* Real Shannon entropy (reuses the file monitor's proven implementation).
* Real file size via os.path.getsize.
* Signature matching against a set of REAL published malware SHA-256 hashes,
  including the industry-standard EICAR anti-malware test file — so detection
  is genuinely verifiable on any machine.
* Behavioural / heuristic rules (packed high-entropy executables, executables
  dropped in temp/appdata/downloads, known ransomware file extensions).

The scanner never raises on a single bad file — unreadable files are reported
as ``error`` and the walk continues.
"""
from __future__ import annotations

import hashlib
import logging
import os
import sys
from typing import Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import config

# Reuse the real entropy + known-ransomware-extension logic instead of
# duplicating it.
from ransomware_detection.detector import (
    KNOWN_RANSOM_EXTS,
    _file_entropy,
)

logger = logging.getLogger("agent.ransomware_detection.scanner")


# ── Real malware signatures (SHA-256) ─────────────────────────────────────────
# Keyed by the *real* SHA-256 of the file's contents.  The EICAR test file is a
# harmless 68-byte string that every AV product is required to detect, which
# makes end-to-end detection reproducible without shipping actual malware.
REAL_MALWARE_SHA256: Dict[str, str] = {
    # EICAR standard anti-malware test file (the canonical benign detection test)
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f":
        "EICAR-Test-File",
    # EICAR wrapped in a zip is a different hash; included for completeness of
    # the well-known EICAR variants.
    "2546dcffc5ad854d4ddc64fbf056871cd5a00f2471cb7a5bfd4ac23b6e9eedad":
        "EICAR-Test-File (zip)",
}

# Executable / script extensions that are inherently higher risk.
SUSPICIOUS_EXEC_EXTS = {
    ".exe", ".dll", ".vbs", ".ps1", ".bat", ".scr", ".com", ".pif", ".wsf",
    ".js", ".jse", ".hta", ".cmd", ".msi",
}

# Directory fragments where a dropped executable is especially suspicious.
SUSPICIOUS_DIR_FRAGMENTS = (
    os.sep + "temp" + os.sep,
    os.sep + "tmp" + os.sep,
    os.sep + "appdata" + os.sep + "roaming" + os.sep,
    os.sep + "appdata" + os.sep + "local" + os.sep + "temp" + os.sep,
    os.sep + "downloads" + os.sep,
)

# Threat family label per executable extension (used for heuristic verdicts).
_EXT_THREAT_LABEL = {
    ".vbs": "Script.Dropper",
    ".js": "Script.Dropper",
    ".jse": "Script.Dropper",
    ".ps1": "PowerShell.Suspicious",
    ".hta": "HTA.Suspicious",
    ".exe": "Executable.Suspicious",
    ".dll": "Library.Suspicious",
    ".scr": "Screensaver.Suspicious",
    ".bat": "Batch.Suspicious",
    ".cmd": "Batch.Suspicious",
}

# Skip directories that are noisy, huge, or not user data.
_SKIP_DIR_NAMES = {"System Volume Information", "$RECYCLE.BIN", "node_modules", ".git"}

# Don't hash absurdly large files — hash a bounded amount is not meaningful for
# signature matching, so we skip the signature check but still record metadata.
_MAX_HASH_BYTES = 256 * 1024 * 1024  # 256 MB


def sha256_file(path: str) -> Optional[str]:
    """Return the real SHA-256 hex digest of a file, or None if unreadable."""
    h = hashlib.sha256()
    try:
        size = os.path.getsize(path)
        if size > _MAX_HASH_BYTES:
            return None
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None


def scan_file(path: str) -> Dict:
    """
    Scan a single real file and return a verdict dict.

    Keys: file_path, file_hash, file_size, status, threat_name, entropy,
          detection_method.
    status ∈ {clean, suspicious, infected, error}
    """
    ext = os.path.splitext(path)[1].lower()

    try:
        file_size = os.path.getsize(path)
    except (OSError, PermissionError) as exc:
        return {
            "file_path": path,
            "file_hash": None,
            "file_size": None,
            "status": "error",
            "threat_name": None,
            "entropy": None,
            "detection_method": "unreadable",
            "error": str(exc)[:120],
        }

    file_hash = sha256_file(path)
    entropy = _file_entropy(path)
    path_lower = path.lower()

    base: Dict = {
        "file_path": path,
        "file_hash": file_hash,
        "file_size": file_size,
        "entropy": round(entropy, 3) if entropy is not None else None,
    }

    # If the file exists but neither its hash nor its entropy could be read, the
    # contents are inaccessible (locked by AV, permission denied, in use). We
    # cannot clear it — report as unreadable rather than a false "clean". Note a
    # very large file (> hash cap) still yields entropy, so it is not affected.
    if file_hash is None and entropy is None:
        return {
            **base,
            "status": "error",
            "threat_name": None,
            "detection_method": "unreadable",
            "error": "file contents could not be read (locked, in use, or access denied)",
        }

    # 1. Exact signature match (highest confidence) — real SHA-256 lookup.
    if file_hash and file_hash in REAL_MALWARE_SHA256:
        return {
            **base,
            "status": "infected",
            "threat_name": REAL_MALWARE_SHA256[file_hash],
            "detection_method": "signature_match",
        }

    # 2. Known ransomware output extension (e.g. .locked, .encrypted).
    if ext in KNOWN_RANSOM_EXTS:
        return {
            **base,
            "status": "suspicious",
            "threat_name": f"Ransomware.EncryptedArtifact.{ext.lstrip('.')}",
            "detection_method": "ransomware_extension",
        }

    # 3. High-entropy executable → likely packed/encrypted payload.
    if (
        entropy is not None
        and entropy > config.ENTROPY_THRESHOLD
        and ext in SUSPICIOUS_EXEC_EXTS
    ):
        label = _EXT_THREAT_LABEL.get(ext, "Packed.Unknown")
        return {
            **base,
            "status": "suspicious",
            "threat_name": f"Heuristic.HighEntropy.{label}",
            "detection_method": "heuristic_entropy",
        }

    # 4. Executable dropped in a suspicious location.
    if ext in SUSPICIOUS_EXEC_EXTS and any(
        frag in path_lower for frag in SUSPICIOUS_DIR_FRAGMENTS
    ):
        label = _EXT_THREAT_LABEL.get(ext, "Executable.Suspicious")
        return {
            **base,
            "status": "suspicious",
            "threat_name": f"Behavioral.SuspiciousLocation.{label}",
            "detection_method": "behavioral_path",
        }

    # Otherwise clean.
    return {
        **base,
        "status": "clean",
        "threat_name": None,
        "detection_method": "full_scan",
    }


def run_scan(
    paths: Optional[List[str]] = None,
    max_files: int = 5000,
) -> List[Dict]:
    """
    Walk real directories and scan every file, returning a list of verdicts.

    * ``paths`` — explicit list of files or directories to scan.  When None,
      the agent's configured MONITOR_PATHS (Documents/Desktop/Downloads) are
      used.
    * ``max_files`` — hard cap so a huge tree can't hang the agent.

    Only files with a non-``clean`` verdict plus a bounded sample of clean
    files are returned, to keep the report lean while still proving coverage.
    """
    targets = paths if paths else list(config.MONITOR_PATHS)
    results: List[Dict] = []
    scanned = 0
    clean_reported = 0
    _MAX_CLEAN_IN_REPORT = 200

    def _record(verdict: Dict) -> None:
        nonlocal clean_reported
        if verdict["status"] == "clean":
            if clean_reported < _MAX_CLEAN_IN_REPORT:
                results.append(verdict)
                clean_reported += 1
        else:
            results.append(verdict)

    for target in targets:
        if scanned >= max_files:
            break

        # A single file target.
        if os.path.isfile(target):
            _record(scan_file(target))
            scanned += 1
            continue

        if not os.path.isdir(target):
            logger.debug("Scan target does not exist, skipping: %s", target)
            continue

        for root, dirs, files in os.walk(target):
            if scanned >= max_files:
                break
            # Prune noisy/system/hidden directories in-place.
            dirs[:] = [
                d for d in dirs
                if not d.startswith(".") and d not in _SKIP_DIR_NAMES
            ]
            for filename in files:
                if scanned >= max_files:
                    break
                full = os.path.join(root, filename)
                _record(scan_file(full))
                scanned += 1

    threats = sum(1 for r in results if r["status"] in ("infected", "suspicious"))
    logger.info(
        "Real file scan complete — scanned=%d reported=%d threats=%d",
        scanned, len(results), threats,
    )
    return results
