#!/usr/bin/env python3
"""
SentinelCrypt EDR — Endpoint Agent
==========================================
Entry point.  Run with:

    python agent/main.py

All monitoring threads are started as daemons.  The main thread blocks on
KeyboardInterrupt / SIGTERM and then performs a graceful shutdown.

Environment overrides (see config.py):
    RDS_BACKEND_URL   — FastAPI backend URL (default: http://localhost:8000/api)
    RDS_DEVICE_ID     — override auto-detected hostname
    RDS_HEARTBEAT_SEC — heartbeat interval in seconds (default: 30)
"""

import logging
import os
import signal
import sys
import time

# ── Logging setup ────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(
            os.path.join(os.path.dirname(__file__), "agent.log"),
            encoding="utf-8",
        ),
    ],
)
logger = logging.getLogger("agent.main")

# ── Internal modules ─────────────────────────────────────────────────────────
# Insert the agent dir into sys.path so sub-modules can import config/sender.
sys.path.insert(0, os.path.dirname(__file__))

import config  # noqa: E402  (after path setup)
from sender import sender  # noqa: E402

# Sub-module watchers
from file_monitor.watcher import start_file_monitor
from process_monitor.watcher import start_process_monitor
from usb_monitor.watcher import start_usb_monitor
from network_monitor.collector import start_network_collector
from wifi_scanner.scanner import start_wifi_scanner
from deception_engine.file_placer import start_deception_engine
from ransomware_detection.detector import start_ransomware_detector
from command_processor import start_command_processor

# ── New real-telemetry module collectors ──────────────────────────────────────
from module_collectors.malware_collector import start_malware_collector
from module_collectors.firewall_collector import start_firewall_collector
from module_collectors.browser_collector import start_browser_collector
from module_collectors.privacy_collector import start_privacy_collector


# ─────────────────────────────────────────────────────────────────────────────
# Shutdown handling
# ─────────────────────────────────────────────────────────────────────────────

_shutdown_requested = False

def _handle_signal(signum, frame):
    global _shutdown_requested
    logger.info("Shutdown signal received (%d) — stopping agent …", signum)
    _shutdown_requested = True


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    logger.info("=" * 60)
    logger.info("  SentinelCrypt EDR — Endpoint Agent")
    logger.info("  Device ID : %s", config.DEVICE_ID)
    logger.info("  Backend   : %s", config.BACKEND_URL)
    logger.info("=" * 60)

    # Register SIGINT / SIGTERM handlers
    signal.signal(signal.SIGINT, _handle_signal)
    try:
        signal.signal(signal.SIGTERM, _handle_signal)
    except AttributeError:
        pass  # SIGTERM not available on Windows — that's fine

    # ── Start sender first (registers device, starts heartbeat) ──────────────
    logger.info("Starting AgentSender …")
    sender.start()

    # ── Start all watchers ───────────────────────────────────────────────────
    components = []

    try:
        logger.info("Starting File Monitor …")
        file_observer = start_file_monitor()
        components.append(("FileMonitor", file_observer))
    except Exception as exc:
        logger.error("File monitor failed to start: %s", exc)

    try:
        logger.info("Starting Deception Engine …")
        decoy_observer = start_deception_engine()
        components.append(("DeceptionEngine", decoy_observer))
    except Exception as exc:
        logger.error("Deception engine failed to start: %s", exc)

    try:
        logger.info("Starting Process Monitor …")
        proc_monitor = start_process_monitor()
        components.append(("ProcessMonitor", proc_monitor))
    except Exception as exc:
        logger.error("Process monitor failed to start: %s", exc)

    try:
        logger.info("Starting USB Monitor …")
        usb_stop = start_usb_monitor()
        components.append(("USBMonitor", usb_stop))
    except Exception as exc:
        logger.error("USB monitor failed to start: %s", exc)

    try:
        logger.info("Starting Network Collector …")
        net_collector = start_network_collector()
        components.append(("NetworkCollector", net_collector))
    except Exception as exc:
        logger.error("Network collector failed to start: %s", exc)

    try:
        logger.info("Starting Wi-Fi Scanner …")
        wifi_scanner = start_wifi_scanner()
        components.append(("WiFiScanner", wifi_scanner))
    except Exception as exc:
        logger.error("Wi-Fi scanner failed to start: %s", exc)

    try:
        logger.info("Starting Ransomware Background Scan …")
        ransom_detector = start_ransomware_detector()
        components.append(("RansomwareDetector", ransom_detector))
    except Exception as exc:
        logger.error("Ransomware detector failed to start: %s", exc)

    try:
        logger.info("Starting Remote Command Processor …")
        cmd_thread, cmd_stop_event = start_command_processor()
        components.append(("CommandProcessor", cmd_stop_event))
    except Exception as exc:
        logger.error("Command processor failed to start: %s", exc)

    # ── Adapter-based module collectors ──────────────────────────────────────
    try:
        logger.info("Starting Malware Collector (Adapter) …")
        _, malware_stop = start_malware_collector()
        components.append(("MalwareCollector", malware_stop))
    except Exception as exc:
        logger.error("Malware collector failed to start: %s", exc)

    try:
        logger.info("Starting Firewall Collector (Adapter) …")
        _, firewall_stop = start_firewall_collector()
        components.append(("FirewallCollector", firewall_stop))
    except Exception as exc:
        logger.error("Firewall collector failed to start: %s", exc)

    try:
        logger.info("Starting Browser Collector (Adapter) …")
        _, browser_stop = start_browser_collector()
        components.append(("BrowserCollector", browser_stop))
    except Exception as exc:
        logger.error("Browser collector failed to start: %s", exc)

    try:
        logger.info("Starting Privacy Collector (Adapter) …")
        _, privacy_stop = start_privacy_collector()
        components.append(("PrivacyCollector", privacy_stop))
    except Exception as exc:
        logger.error("Privacy collector failed to start: %s", exc)

    logger.info("All agent modules started.  Press Ctrl+C to stop.")

    # ── Main loop — keep alive until shutdown ─────────────────────────────────
    try:
        while not _shutdown_requested:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt received")

    # ── Graceful shutdown ────────────────────────────────────────────────────
    logger.info("Shutting down agent …")

    # Stop sender (flushes remaining events)
    sender.stop()

    # Stop each component
    for name, component in components:
        try:
            if hasattr(component, "stop"):
                component.stop()
            elif hasattr(component, "set"):
                component.set()  # threading.Event
            logger.info("%s stopped", name)
        except Exception as exc:
            logger.warning("Error stopping %s: %s", name, exc)

    logger.info("Agent stopped cleanly.")


if __name__ == "__main__":
    main()
