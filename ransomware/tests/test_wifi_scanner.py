import os
import sys
from unittest.mock import patch, MagicMock

# Ensure agent directory is on path
AGENT_DIR = os.path.join(os.path.dirname(__file__), "..", "agent")
if AGENT_DIR not in sys.path:
    sys.path.insert(0, AGENT_DIR)

from wifi_scanner.scanner import (
    WindowsWifiAdapter,
    LinuxWifiAdapter,
    MacWifiAdapter,
    WiFiScanner,
    _detect_evil_twins,
    _classify_risk
)

# Mock outputs
NETSH_OUTPUT = """
Interface name : Wi-Fi 
There are 2 networks currently visible. 

SSID 1 : TargetNetwork
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : 00:11:22:33:44:55
        Signal              : 90%
        Radio type          : 802.11ax
        Channel             : 6

SSID 2 : GuestNetwork
    Network type            : Infrastructure
    Authentication          : Open
    Encryption              : None
    BSSID 1                 : 66:77:88:99:aa:bb
        Signal              : 50%
        Radio type          : 802.11n
        Channel             : 149
"""

NMCLI_OUTPUT = """
TargetNetwork:00\\:11\\:22\\:33\\:44\\:55:90:6:WPA2Personal:2437 MHz
GuestNetwork:66\\:77\\:88\\:99\\:aa\\:bb:50:149:Open:5180 MHz
"""

AIRPORT_OUTPUT = """
                 SSID BSSID             RSSI CHANNEL HT CC SECURITY (2.4Ghz/5Ghz)
        TargetNetwork 00:11:22:33:44:55 -50  6       Y  US WPA2(PSK/AES/AES) 
         GuestNetwork 66:77:88:99:aa:bb -75  149     Y  US NONE
"""

def test_windows_wifi_adapter_parsing():
    adapter = WindowsWifiAdapter()
    networks = adapter._parse_netsh_output(NETSH_OUTPUT)
    assert len(networks) == 2
    
    n1 = networks[0]
    assert n1["ssid"] == "TargetNetwork"
    assert n1["bssid"] == "00:11:22:33:44:55"
    assert n1["signal_strength"] == -55  # (90/2) - 100 = -55
    assert n1["channel"] == 6
    assert n1["security_type"] == "WPA2"
    assert n1["frequency"] == 2.4

    n2 = networks[1]
    assert n2["ssid"] == "GuestNetwork"
    assert n2["bssid"] == "66:77:88:99:aa:bb"
    assert n2["signal_strength"] == -75  # (50/2) - 100 = -75
    assert n2["channel"] == 149
    assert n2["security_type"] == "Open"
    assert n2["frequency"] == 5.0

def test_linux_wifi_adapter_parsing():
    adapter = LinuxWifiAdapter()
    networks = adapter._parse_nmcli_output(NMCLI_OUTPUT)
    assert len(networks) == 2
    
    n1 = networks[0]
    assert n1["ssid"] == "TargetNetwork"
    assert n1["bssid"] == "00:11:22:33:44:55"
    assert n1["signal_strength"] == -55  # (90/2) - 100
    assert n1["channel"] == 6
    assert n1["security_type"] == "WPA2Personal"
    assert n1["frequency"] == 2.437

    n2 = networks[1]
    assert n2["ssid"] == "GuestNetwork"
    assert n2["bssid"] == "66:77:88:99:aa:bb"
    assert n2["signal_strength"] == -75  # (50/2) - 100
    assert n2["channel"] == 149
    assert n2["security_type"] == "Open"
    assert n2["frequency"] == 5.18

def test_mac_wifi_adapter_parsing():
    adapter = MacWifiAdapter()
    networks = adapter._parse_airport_output(AIRPORT_OUTPUT)
    assert len(networks) == 2
    
    n1 = networks[0]
    assert n1["ssid"] == "TargetNetwork"
    assert n1["bssid"] == "00:11:22:33:44:55"
    assert n1["signal_strength"] == -50
    assert n1["channel"] == 6
    assert "WPA2" in n1["security_type"]
    assert n1["frequency"] == 2.4

    n2 = networks[1]
    assert n2["ssid"] == "GuestNetwork"
    assert n2["bssid"] == "66:77:88:99:aa:bb"
    assert n2["signal_strength"] == -75
    assert n2["channel"] == 149
    assert n2["security_type"] == "NONE"
    assert n2["frequency"] == 5.0

def test_evil_twin_detection():
    nets = [
        {"ssid": "TargetNetwork", "bssid": "00:11:22:33:44:55", "is_evil_twin": False},
        {"ssid": "TargetNetwork", "bssid": "00:11:22:33:44:aa", "is_evil_twin": False},
    ]
    detected = _detect_evil_twins(nets)
    assert len(detected) == 2
    assert detected[0]["is_evil_twin"] is True
    assert detected[1]["is_evil_twin"] is True

def test_classify_risk():
    assert _classify_risk({"is_evil_twin": True}) == "critical"
    assert _classify_risk({"security_type": "Open"}) == "high"
    assert _classify_risk({"security_type": "WEP"}) == "high"
    assert _classify_risk({"security_type": "WPA"}) == "medium"
    assert _classify_risk({"security_type": "WPA2"}) == "low"

@patch("wifi_scanner.scanner.sender")
def test_wifi_scanner_normalization_flow(mock_sender):
    mock_adapter = MagicMock()
    mock_adapter.scan.return_value = [
        {
            "ssid": "TargetNetwork",
            "bssid": "00:11:22:33:44:55",
            "signal_strength": -55,
            "channel": 6,
            "security_type": "WPA2",
            "frequency": 2.4,
            "is_connected": False,
            "is_evil_twin": False
        },
        {
            "ssid": "PublicGuest",
            "bssid": "66:77:88:99:aa:bb",
            "signal_strength": -75,
            "channel": 11,
            "security_type": "Open",
            "frequency": 2.4,
            "is_connected": False,
            "is_evil_twin": False
        }
    ]
    mock_adapter.get_connected_ssid.return_value = "TargetNetwork"

    scanner = WiFiScanner()
    scanner._adapter = mock_adapter

    scanner._scan_once()

    assert mock_sender.enqueue.call_count == 2
    calls = mock_sender.enqueue.call_args_list

    category_1, type_1, net_1 = calls[0][0]
    assert category_1 == "wifi"
    assert type_1 == "scan_result"
    assert net_1["ssid"] == "TargetNetwork"
    assert net_1["security"] == "WPA2"
    assert net_1["duplicate_ssid_flag"] is False
    assert net_1["suspicious_flag"] is False
    assert "timestamp" in net_1
    assert isinstance(net_1["timestamp"], float)

    category_2, type_2, net_2 = calls[1][0]
    assert category_2 == "wifi"
    assert type_2 == "scan_result"
    assert net_2["ssid"] == "PublicGuest"
    assert net_2["security"] == "Open"
    assert net_2["duplicate_ssid_flag"] is False
    assert net_2["suspicious_flag"] is True
    assert "timestamp" in net_2
    assert isinstance(net_2["timestamp"], float)
