"""
Wi-Fi Scanner Router — /api/wifi
Phase 2: Discovers and risk-scores nearby Wi-Fi networks.
"""
import random
import datetime
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import WiFiNetwork, Device
from app.services.auth_service import get_current_user

router = APIRouter(prefix="/wifi", tags=["WiFi"])

# Simulated Wi-Fi environment
SIMULATED_NETWORKS = [
    {"ssid": "HomeNetwork_5G", "bssid": "AA:BB:CC:DD:EE:01", "signal_strength": -45, "channel": 36, "security_type": "WPA3", "frequency": 5.0, "risk_level": "low", "is_evil_twin": False},
    {"ssid": "TP-Link_Guest_2.4G", "bssid": "AA:BB:CC:DD:EE:02", "signal_strength": -62, "channel": 6, "security_type": "WPA2", "frequency": 2.4, "risk_level": "low", "is_evil_twin": False},
    {"ssid": "FREE_WIFI_AIRPORT", "bssid": "AA:BB:CC:DD:EE:03", "signal_strength": -70, "channel": 1, "security_type": "Open", "frequency": 2.4, "risk_level": "high", "is_evil_twin": False},
    {"ssid": "CorporateWifi", "bssid": "AA:BB:CC:DD:EE:04", "signal_strength": -55, "channel": 11, "security_type": "WPA2-Enterprise", "frequency": 2.4, "risk_level": "low", "is_evil_twin": False},
    {"ssid": "HomeNetwork_5G", "bssid": "FF:EE:DD:CC:BB:05", "signal_strength": -58, "channel": 36, "security_type": "WPA2", "frequency": 5.0, "risk_level": "critical", "is_evil_twin": True},
    {"ssid": "Starbucks_WiFi", "bssid": "AA:BB:CC:DD:EE:06", "signal_strength": -75, "channel": 6, "security_type": "Open", "frequency": 2.4, "risk_level": "high", "is_evil_twin": False},
    {"ssid": "Netgear_FiOS-5G", "bssid": "AA:BB:CC:DD:EE:07", "signal_strength": -48, "channel": 100, "security_type": "WPA3", "frequency": 5.0, "risk_level": "low", "is_evil_twin": False},
    {"ssid": "D-Link_OLD", "bssid": "AA:BB:CC:DD:EE:08", "signal_strength": -82, "channel": 11, "security_type": "WEP", "frequency": 2.4, "risk_level": "high", "is_evil_twin": False},
    {"ssid": "XFINITY_GUEST", "bssid": "AA:BB:CC:DD:EE:09", "signal_strength": -68, "channel": 6, "security_type": "WPA", "frequency": 2.4, "risk_level": "medium", "is_evil_twin": False},
    {"ssid": "AndroidHotspot_EvilAP", "bssid": "00:11:22:33:44:05", "signal_strength": -40, "channel": 6, "security_type": "WPA2", "frequency": 2.4, "risk_level": "critical", "is_evil_twin": True},
    {"ssid": "Linksys_2GEXT", "bssid": "AA:BB:CC:DD:EE:11", "signal_strength": -72, "channel": 1, "security_type": "WPA2", "frequency": 2.4, "risk_level": "low", "is_evil_twin": False},
    {"ssid": "ATT_5GHz_7823", "bssid": "AA:BB:CC:DD:EE:12", "signal_strength": -60, "channel": 149, "security_type": "WPA2", "frequency": 5.0, "risk_level": "low", "is_evil_twin": False},
]

def assess_wifi_risk(network: dict) -> str:
    """Derive risk level from security type and evil-twin flag."""
    if network.get("is_evil_twin"):
        return "critical"
    sec = network.get("security_type", "Open")
    if sec == "Open":
        return "high"
    if sec in ["WEP", "WPA"]:
        return "high"
    if sec == "WPA2":
        return "low"
    if sec in ["WPA3", "WPA2-Enterprise"]:
        return "low"
    return "medium"

@router.post("/scan")
def trigger_wifi_scan(
    device_id: str,
    db: Session = Depends(get_db)
):
    """Ingest a Wi-Fi scan result for a device (agent-called)."""
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        device = Device(id=device_id, hostname=device_id, status="online", last_seen=datetime.datetime.utcnow())
        db.add(device)
        db.commit()

    # Simulate a random selection of visible networks
    num = random.randint(5, 12)
    visible = random.sample(SIMULATED_NETWORKS, min(num, len(SIMULATED_NETWORKS)))

    # Mark one as connected
    if visible:
        visible[0]["is_connected"] = True

    added = []
    for net in visible:
        db_net = WiFiNetwork(
            device_id=device_id,
            ssid=net["ssid"],
            bssid=net["bssid"],
            signal_strength=net["signal_strength"],
            channel=net["channel"],
            security_type=net["security_type"],
            frequency=net["frequency"],
            risk_level=assess_wifi_risk(net),
            is_connected=net.get("is_connected", False),
            is_evil_twin=net["is_evil_twin"],
        )
        db.add(db_net)
        added.append(net["ssid"])

    db.commit()
    evil_count = sum(1 for n in visible if n["is_evil_twin"])
    open_count = sum(1 for n in visible if n["security_type"] == "Open")
    return {"device_id": device_id, "networks_found": len(added), "evil_twin_detected": evil_count, "open_networks": open_count}

@router.get("/networks")
def list_wifi_networks(
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """List all scanned Wi-Fi networks."""
    nets = db.query(WiFiNetwork).order_by(WiFiNetwork.timestamp.desc()).limit(limit).all()
    return [
        {
            "id": n.id,
            "device_id": n.device_id,
            "ssid": n.ssid,
            "bssid": n.bssid,
            "signal_strength": n.signal_strength,
            "channel": n.channel,
            "security_type": n.security_type,
            "frequency": n.frequency,
            "risk_level": n.risk_level,
            "is_connected": n.is_connected,
            "is_evil_twin": n.is_evil_twin,
            "timestamp": n.timestamp.isoformat() if n.timestamp else None,
        }
        for n in nets
    ]

@router.get("/stats")
def wifi_stats(
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Summarize Wi-Fi network risk distribution."""
    total = db.query(WiFiNetwork).count()
    open_nets = db.query(WiFiNetwork).filter(WiFiNetwork.security_type == "Open").count()
    wpa2 = db.query(WiFiNetwork).filter(WiFiNetwork.security_type == "WPA2").count()
    wpa3 = db.query(WiFiNetwork).filter(WiFiNetwork.security_type == "WPA3").count()
    evil_twin = db.query(WiFiNetwork).filter(WiFiNetwork.is_evil_twin == True).count()
    high_risk = db.query(WiFiNetwork).filter(WiFiNetwork.risk_level.in_(["high", "critical"])).count()
    return {
        "total": total,
        "open": open_nets,
        "wpa2": wpa2,
        "wpa3": wpa3,
        "evil_twin": evil_twin,
        "high_risk": high_risk,
        "safe": total - high_risk,
    }
