"""
Deception Engine — File Placer & Monitor
=========================================
On startup:
1. Creates decoy (honeypot) files in the configured DECOY_DIR.
2. Attaches a dedicated watchdog observer just to those files.
3. Any read or write access immediately triggers a high-severity alert.

The decoy files contain realistic-looking but entirely fake content so that
a real attacker cannot distinguish them from genuine sensitive documents.
"""

import logging
import os
import sys
import threading

try:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer
except ImportError:
    raise SystemExit("watchdog is required: pip install watchdog")

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import config
from sender import sender

logger = logging.getLogger("agent.deception_engine")


# ─────────────────────────────────────────────────────────────────────────────
# Fake content templates
# ─────────────────────────────────────────────────────────────────────────────

_DECOY_CONTENT = {
    "salary.xlsx": (
        "CONFIDENTIAL - SALARY DATA\n"
        "Employee,Department,Base Salary,Bonus\n"
        "John Smith,Engineering,95000,12000\n"
        "Jane Doe,Marketing,78000,9500\n"
        "Robert Lee,HR,65000,7000\n"
        "Sarah Connor,Finance,88000,11000\n"
    ),
    "employee_data.xlsx": (
        "CONFIDENTIAL - EMPLOYEE RECORDS\n"
        "Name,SSN,DOB,Address,Emergency Contact\n"
        "John Smith,XXX-XX-1234,1985-03-12,123 Main St,Mary Smith 555-0101\n"
        "Jane Doe,XXX-XX-5678,1990-07-22,456 Oak Ave,Bob Doe 555-0202\n"
    ),
    "passwords.txt": (
        "== SYSTEM CREDENTIALS (INTERNAL) ==\n"
        "Admin Portal: admin / P@ssw0rd2024!\n"
        "Database: dbadmin / Db$ecure99\n"
        "VPN: vpnuser / Vpn!nfra2024\n"
        "Backup FTP: backup_admin / Bk$3cure!\n"
    ),
    "bank_details.docx": (
        "CORPORATE BANKING INFORMATION\n"
        "Bank: First National Bank\n"
        "Account Number: 1234567890\n"
        "Routing: 021000021\n"
        "SWIFT: FNBKUS33\n"
        "Balance: $2,450,000.00\n"
    ),
    "api_keys.txt": (
        "== API KEYS (INTERNAL USE ONLY) ==\n"
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        "STRIPE_SECRET=sk_live_XXXXXXXXXXXXXXXXXXXX\n"
        "SENDGRID_API_KEY=SG.XXXXXXXXXXXXXXXXXXX\n"
        "GITHUB_TOKEN=ghp_XXXXXXXXXXXXXXXXXXXX\n"
    ),
}


# ─────────────────────────────────────────────────────────────────────────────
# Decoy file creation
# ─────────────────────────────────────────────────────────────────────────────

def _create_decoy_files(decoy_dir: str) -> list:
    """Create decoy files and return list of paths that were created."""
    os.makedirs(decoy_dir, exist_ok=True)
    created = []

    for filename in config.DECOY_FILES:
        path = os.path.join(decoy_dir, filename)
        if not os.path.exists(path):
            content = _DECOY_CONTENT.get(filename, f"CONFIDENTIAL: {filename}\n")
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(content)
                logger.info("Decoy file created: %s", path)
                created.append(path)
            except OSError as exc:
                logger.error("Failed to create decoy file %s: %s", path, exc)
        else:
            created.append(path)  # already exists — still monitor it

    return created


# ─────────────────────────────────────────────────────────────────────────────
# Watchdog handler for decoy files
# ─────────────────────────────────────────────────────────────────────────────

class DecoyFileHandler(FileSystemEventHandler):
    """Fires an immediate high-severity alert whenever a decoy file is touched."""

    def __init__(self, decoy_names: set):
        super().__init__()
        self._decoy_names = {d.lower() for d in decoy_names}

    def _is_decoy(self, path: str) -> bool:
        return os.path.basename(path).lower() in self._decoy_names

    def on_modified(self, event):
        if not event.is_directory and self._is_decoy(event.src_path):
            self._alert(event.src_path, "modified/accessed")

    def on_created(self, event):
        if not event.is_directory and self._is_decoy(event.src_path):
            self._alert(event.src_path, "created")

    def on_deleted(self, event):
        if not event.is_directory and self._is_decoy(event.src_path):
            self._alert(event.src_path, "deleted")

    def on_moved(self, event):
        if not event.is_directory and self._is_decoy(event.src_path):
            self._alert(event.src_path, "moved/renamed")

    def _alert(self, path: str, access_type: str) -> None:
        logger.critical("🚨 HONEYPOT TRIGGERED: %s (%s)", path, access_type)
        sender.enqueue("file", "accessed", {
            "path": path,
            "filename": os.path.basename(path),
            "decoy": True,
            "access_type": access_type,
            "alert": "Honeypot/Decoy file accessed — possible attacker activity",
            "severity": "critical",
        })


# ─────────────────────────────────────────────────────────────────────────────
# Public function
# ─────────────────────────────────────────────────────────────────────────────

def start_deception_engine() -> Observer:
    """Create decoy files and start monitoring them. Returns the Observer."""
    decoy_dir = config.DECOY_DIR
    _create_decoy_files(decoy_dir)

    handler = DecoyFileHandler(decoy_names=set(config.DECOY_FILES))
    observer = Observer()
    observer.schedule(handler, decoy_dir, recursive=False)
    observer.start()

    logger.info("Deception engine started — monitoring %d decoy files in %s",
                len(config.DECOY_FILES), decoy_dir)
    return observer
