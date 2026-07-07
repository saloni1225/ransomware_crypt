"""
Wi-Fi Scanner Adapter & Scanner
================================
Supports cross-platform scanning:
- Windows: netsh wlan show networks mode=bssid
- Linux: nmcli dev wifi list
- macOS: airport -s

Abstracted behind a clean adapter interface.
Normalization details: ssid, bssid, signal_strength, channel, security_type, frequency.
"""

import logging
import os
import platform
import re
import subprocess
import sys
import threading
import time
from typing import Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import config
from sender import sender

logger = logging.getLogger("agent.wifi_scanner")

# ── Base Adapter ─────────────────────────────────────────────────────────────

class WifiAdapter:
    def scan(self) -> List[Dict]:
        """Return list of parsed visible Wi-Fi networks."""
        raise NotImplementedError("Adapters must implement scan()")

    def get_connected_ssid(self) -> Optional[str]:
        """Return SSID of the currently connected network."""
        raise NotImplementedError("Adapters must implement get_connected_ssid()")

# ── Windows Adapter ──────────────────────────────────────────────────────────

class WindowsWifiAdapter(WifiAdapter):
    def scan(self) -> List[Dict]:
        try:
            result = subprocess.run(
                ["netsh", "wlan", "show", "networks", "mode=bssid"],
                capture_output=True,
                text=True,
                timeout=15,
                encoding="utf-8",
                errors="replace",
            )
            return self._parse_netsh_output(result.stdout)
        except Exception as exc:
            logger.debug("Windows netsh scan failed: %s", exc)
            return []

    def get_connected_ssid(self) -> Optional[str]:
        try:
            result = subprocess.run(
                ["netsh", "wlan", "show", "interfaces"],
                capture_output=True, text=True, timeout=10,
                encoding="utf-8", errors="replace",
            )
            m = re.search(r"\bSSID\s*:\s*(.+)", result.stdout)
            if m:
                return m.group(1).strip()
        except Exception:
            pass
        return None

    def _parse_netsh_output(self, output: str) -> List[Dict]:
        networks: List[Dict] = []
        current: Optional[Dict] = None

        for line in output.splitlines():
            line = line.strip()
            m = re.match(r"^SSID\s+\d+\s*:\s*(.*)", line)
            if m:
                if current:
                    networks.append(current)
                current = {
                    "ssid": m.group(1).strip(),
                    "bssid": "",
                    "security_type": "Unknown",
                    "signal_strength": -100,
                    "channel": None,
                    "frequency": None,
                    "is_connected": False,
                    "is_evil_twin": False,
                }
                continue

            if current is None:
                continue

            m_bssid = re.match(r"^BSSID\s+\d+\s*:\s*([\w:]+)", line)
            if m_bssid:
                current["bssid"] = m_bssid.group(1)
                continue

            m_signal = re.match(r"^Signal\s*:\s*(\d+)%", line)
            if m_signal:
                pct = int(m_signal.group(1))
                current["signal_strength"] = int((pct / 2) - 100)
                continue

            m_auth = re.match(r"^Authentication\s*:\s*(.*)", line)
            if m_auth:
                auth = m_auth.group(1).strip()
                mapping = {
                    "WPA2-Personal": "WPA2",
                    "WPA2-Enterprise": "WPA2",
                    "WPA3-Personal": "WPA3",
                    "WPA-Personal": "WPA",
                    "Open": "Open",
                    "WEP": "WEP",
                }
                current["security_type"] = mapping.get(auth, auth)
                continue

            m_channel = re.match(r"^Channel\s*:\s*(\d+)", line)
            if m_channel:
                channel = int(m_channel.group(1))
                current["channel"] = channel
                # Deduce frequency
                current["frequency"] = 2.4 if channel <= 14 else 5.0
                continue

        if current:
            networks.append(current)

        return networks

# ── Linux Adapter ────────────────────────────────────────────────────────────

class LinuxWifiAdapter(WifiAdapter):
    def scan(self) -> List[Dict]:
        try:
            res = subprocess.run(
                ["nmcli", "-t", "-f", "SSID,BSSID,SIGNAL,CHAN,SECURITY,FREQ", "dev", "wifi", "list"],
                capture_output=True, text=True, timeout=10, encoding="utf-8", errors="replace"
            )
            return self._parse_nmcli_output(res.stdout)
        except Exception as exc:
            logger.debug("Linux nmcli scan failed: %s", exc)
            return []

    def get_connected_ssid(self) -> Optional[str]:
        try:
            res = subprocess.run(
                ["nmcli", "-t", "-f", "ACTIVE,SSID", "dev", "wifi", "list"],
                capture_output=True, text=True, timeout=5, encoding="utf-8", errors="replace"
            )
            for line in res.stdout.splitlines():
                if line.strip().startswith("yes:"):
                    return line.split(":", 1)[1].strip()
        except Exception:
            pass
        return None

    def _parse_nmcli_output(self, output: str) -> List[Dict]:
        networks = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            # Replace escaped colons (MAC address colons like \: inside BSSID)
            line_clean = line.replace(r"\:", "-")
            parts = line_clean.split(":")
            if len(parts) >= 5:
                ssid = parts[0]
                bssid = parts[1].replace("-", ":")
                try:
                    signal_pct = int(parts[2])
                    signal_dbm = int((signal_pct / 2) - 100)
                except ValueError:
                    signal_dbm = -100
                try:
                    channel = int(parts[3])
                except ValueError:
                    channel = None
                security = parts[4]
                freq_str = parts[5] if len(parts) > 5 else ""
                
                freq_val = None
                if freq_str:
                    m = re.search(r"(\d+(?:\.\d+)?)", freq_str)
                    if m:
                        freq_val = float(m.group(1)) / 1000.0 if "MHz" in freq_str else float(m.group(1))
                
                networks.append({
                    "ssid": ssid,
                    "bssid": bssid,
                    "security_type": security or "Open",
                    "signal_strength": signal_dbm,
                    "channel": channel,
                    "frequency": freq_val,
                    "is_connected": False,
                    "is_evil_twin": False,
                })
        return networks

# ── macOS Adapter ────────────────────────────────────────────────────────────

class MacWifiAdapter(WifiAdapter):
    AIRPORT_PATH = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"

    def scan(self) -> List[Dict]:
        try:
            res = subprocess.run(
                [self.AIRPORT_PATH, "-s"],
                capture_output=True, text=True, timeout=15, encoding="utf-8", errors="replace"
            )
            return self._parse_airport_output(res.stdout)
        except Exception as exc:
            logger.debug("macOS airport scan failed: %s", exc)
            return []

    def get_connected_ssid(self) -> Optional[str]:
        try:
            res = subprocess.run([self.AIRPORT_PATH, "-I"], capture_output=True, text=True, timeout=5)
            m = re.search(r"\bSSID:\s*(.*)", res.stdout)
            if m:
                return m.group(1).strip()
        except Exception:
            pass
        return None

    def _parse_airport_output(self, output: str) -> List[Dict]:
        networks = []
        lines = output.splitlines()
        if not lines:
            return []
        
        # Header: SSID BSSID RSSI CHANNEL HT CC SECURITY (XOIP)
        for line in lines[1:]:
            line = line.strip()
            if not line:
                continue
            m = re.search(r"^(.*?)\s+([0-9a-fA-F:]{17})\s+(-?\d+)\s+(\d+)\s+(?:[+-]\d+\s+)?(?:[Y|N]\s+)?(?:\w+\s+)?(.*)$", line)
            if m:
                ssid = m.group(1).strip()
                bssid = m.group(2).strip()
                rssi = int(m.group(3))
                channel = int(m.group(4))
                security = m.group(5).strip()
                
                networks.append({
                    "ssid": ssid,
                    "bssid": bssid,
                    "security_type": security or "Open",
                    "signal_strength": rssi,
                    "channel": channel,
                    "frequency": 2.4 if channel <= 14 else 5.0,
                    "is_connected": False,
                    "is_evil_twin": False,
                })
        return networks

# ── Generic/Mock Fallback Adapter ────────────────────────────────────────────

class FallbackWifiAdapter(WifiAdapter):
    def scan(self) -> List[Dict]:
        logger.debug("Wi-Fi scanner running in fallback mode (empty scan)")
        return []

    def get_connected_ssid(self) -> Optional[str]:
        return None

# ── Scanner Manager ──────────────────────────────────────────────────────────

def _detect_evil_twins(networks: List[Dict]) -> List[Dict]:
    ssid_groups: Dict[str, List[Dict]] = {}
    for net in networks:
        ssid = net["ssid"]
        if ssid:
            if ssid not in ssid_groups:
                ssid_groups[ssid] = []
            ssid_groups[ssid].append(net)

    for ssid, group in ssid_groups.items():
        if len(group) > 1:
            # Duplicate SSID check
            # Look for duplicate SSIDs that have different BSSIDs on the same channel
            # Or flag all duplicates as potential twins for visual security warning
            for net in group:
                net["is_evil_twin"] = True
                logger.warning("Possible Evil Twin detected: SSID='%s' BSSID=%s", ssid, net["bssid"])

    return networks

def _classify_risk(net: Dict) -> str:
    if net.get("is_evil_twin"):
        return "critical"
    sec = net.get("security_type", "").upper()
    if sec in ("OPEN", "", "NONE"):
        return "high"
    if "WEP" in sec:
        return "high"
    if "WPA" in sec and "WPA2" not in sec and "WPA3" not in sec:
        return "medium"
    return "low"

class WiFiScanner:
    def __init__(self):
        self._stop_event = threading.Event()
        self._adapter = self._select_adapter()

    def _select_adapter(self) -> WifiAdapter:
        sys_os = platform.system()
        if sys_os == "Windows":
            logger.info("Initializing Windows Wi-Fi adapter (netsh)")
            return WindowsWifiAdapter()
        elif sys_os == "Linux":
            # Check if nmcli exists
            try:
                subprocess.run(["which", "nmcli"], capture_output=True, check=True)
                logger.info("Initializing Linux Wi-Fi adapter (nmcli)")
                return LinuxWifiAdapter()
            except Exception:
                logger.warning("Linux OS detected but 'nmcli' tool is missing. Falling back.")
                return FallbackWifiAdapter()
        elif sys_os == "Darwin": # macOS
            logger.info("Initializing macOS Wi-Fi adapter (airport)")
            return MacWifiAdapter()
        else:
            logger.warning("Unsupported platform for Wi-Fi scanner: %s. Using fallback.", sys_os)
            return FallbackWifiAdapter()

    def start(self) -> None:
        threading.Thread(target=self._scan_loop, daemon=True,
                         name="agent-wifi-scanner").start()
        logger.info("Wi-Fi scanner started (interval=%ds)", config.WIFI_SCAN_INTERVAL_SEC)

    def stop(self) -> None:
        self._stop_event.set()

    def _scan_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._scan_once()
            except Exception as exc:
                logger.error("Wi-Fi scan execution error: %s", exc)
            self._stop_event.wait(config.WIFI_SCAN_INTERVAL_SEC)

    def _scan_once(self) -> None:
        networks = self._adapter.scan()
        if not networks:
            return

        connected_ssid = self._adapter.get_connected_ssid()
        networks = _detect_evil_twins(networks)

        for net in networks:
            net["risk_level"] = _classify_risk(net)
            net["is_connected"] = (net["ssid"] == connected_ssid)

            # Normalize to the common schema
            net["security"] = net.get("security_type") or "Open"
            net["duplicate_ssid_flag"] = net.get("is_evil_twin", False)
            net["suspicious_flag"] = net["risk_level"] in ("high", "critical")
            net["timestamp"] = time.time()

            sender.enqueue("wifi", "scan_result", net)
            logger.debug(
                "Wi-Fi Telemetry: ssid=%s security=%s risk=%s evil_twin=%s connected=%s",
                net["ssid"], net["security"], net["risk_level"], net["duplicate_ssid_flag"], net["is_connected"]
            )

def start_wifi_scanner() -> WiFiScanner:
    scanner = WiFiScanner()
    scanner.start()
    return scanner
