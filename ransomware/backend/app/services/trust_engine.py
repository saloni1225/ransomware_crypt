"""
Trust Score Engine — 7-component weighted scoring for Device Trust.
"""
from sqlalchemy.orm import Session
from app.models import Device, ThreatEvent, MalwareScan, WiFiNetwork, ThreatLog, BrowserEvent
import datetime

def compute_trust_score(db: Session, device_id: str) -> dict:
    """
    Computes a 7-component trust score for a device.
    Returns dict with component scores, total, and label.
    """
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        return {"overall_score": 0, "max": 100, "label": "Unknown", "breakdown": {}}

    breakdown = {}
    now = datetime.datetime.utcnow()
    seven_days_ago = now - datetime.timedelta(days=7)

    # 1. OS Updates (max 20)
    # Default to up_to_date if not set
    patch_status = device.patch_status or "up_to_date"
    if patch_status == "up_to_date":
        os_score = 20
        os_detail = "OS is fully up to date"
        os_status = "pass"
    elif patch_status == "needs_reboot":
        os_score = 12
        os_detail = "Pending reboot for updates"
        os_status = "warn"
    else:  # critical_missing
        os_score = 0
        os_detail = "Critical security updates missing"
        os_status = "fail"

    breakdown["os_updates"] = {
        "score": os_score,
        "max": 20,
        "label": f"OS Updates Status ({patch_status.replace('_', ' ').title()})",
        "status": os_status,
        "detail": os_detail
    }

    # 2. Firewall Status (max 15)
    firewall_status = device.firewall_status or "disabled"
    if firewall_status == "enabled":
        firewall_score = 15
        firewall_detail = "Host firewall is active"
        firewall_status_lbl = "pass"
    else:
        firewall_score = 0
        firewall_detail = "Firewall is disabled or unknown"
        firewall_status_lbl = "fail"

    breakdown["firewall_status"] = {
        "score": firewall_score,
        "max": 15,
        "label": f"Firewall status ({device.firewall_status})",
        "status": firewall_status_lbl,
        "detail": firewall_detail
    }

    # 3. Wi-Fi Security (max 10)
    evil_twin = db.query(WiFiNetwork).filter(
        WiFiNetwork.device_id == device_id,
        WiFiNetwork.is_evil_twin == True,
        WiFiNetwork.is_connected == True
    ).count()

    risky_wifi = db.query(WiFiNetwork).filter(
        WiFiNetwork.device_id == device_id,
        WiFiNetwork.risk_level.in_(["high", "critical"]),
        WiFiNetwork.is_connected == True
    ).count()

    if evil_twin > 0:
        wifi_score = 0
        wifi_detail = "Connected to an Evil Twin access point"
        wifi_status = "fail"
    elif risky_wifi > 0:
        wifi_score = 3
        wifi_detail = f"Connected to {risky_wifi} risky network(s)"
        wifi_status = "warn"
    else:
        wifi_score = 10
        wifi_detail = "Connected to secure Wi-Fi (WPA3/WPA2)"
        wifi_status = "pass"

    breakdown["wifi_security"] = {
        "score": wifi_score,
        "max": 10,
        "label": "Wi-Fi Security status",
        "status": wifi_status,
        "detail": wifi_detail
    }

    # 4. USB Removable Control (max 10)
    active_usb_threats = db.query(ThreatEvent).filter(
        ThreatEvent.device_id == device_id,
        ThreatEvent.category == "usb",
        ThreatEvent.status == "active"
    ).count()

    unauthorized_usb_logs = db.query(ThreatLog).filter(
        ThreatLog.device_id == device_id,
        ThreatLog.type == "usb",
        ThreatLog.action == "mounted",
        ThreatLog.timestamp >= seven_days_ago
    ).all()

    unauth_usb_count = 0
    for log in unauthorized_usb_logs:
        details = log.details or {}
        if not details.get("authorized", True) or "unauthorized" in details.get("status", "").lower():
            unauth_usb_count += 1

    if active_usb_threats > 0:
        usb_score = 0
        usb_detail = "Active unauthorized USB block event present"
        usb_status = "fail"
    elif unauth_usb_count > 0:
        usb_score = 3
        usb_detail = f"{unauth_usb_count} unauthorized USB mount attempt(s) in last 7 days"
        usb_status = "warn"
    else:
        usb_score = 10
        usb_detail = "No unauthorized USB mount attempts"
        usb_status = "pass"

    breakdown["usb_risk"] = {
        "score": usb_score,
        "max": 10,
        "label": "USB Removable Control",
        "status": usb_status,
        "detail": usb_detail
    }

    # 5. Malware & Ransomware logs (max 20)
    active_malware_threats = db.query(ThreatEvent).filter(
        ThreatEvent.device_id == device_id,
        ThreatEvent.category.in_(["ransomware", "malware"]),
        ThreatEvent.status == "active"
    ).count()

    infected_scans = db.query(MalwareScan).filter(
        MalwareScan.device_id == device_id,
        MalwareScan.status.in_(["infected", "suspicious"])
    ).count()

    if active_malware_threats > 0:
        malware_score = 0
        malware_detail = f"{active_malware_threats} active ransomware/malware incident(s)!"
        malware_status = "fail"
    elif infected_scans > 0:
        malware_score = 5
        malware_detail = f"{infected_scans} infected/suspicious files currently in quarantine"
        malware_status = "warn"
    else:
        malware_score = 20
        malware_detail = "No active malware threats detected"
        malware_status = "pass"

    breakdown["malware_events"] = {
        "score": malware_score,
        "max": 20,
        "label": "Malware & Ransomware logs",
        "status": malware_status,
        "detail": malware_detail
    }

    # 6. Identity & Credential safety (max 15)
    active_identity_threats = db.query(ThreatEvent).filter(
        ThreatEvent.device_id == device_id,
        ThreatEvent.category.in_(["identity", "deception"]),
        ThreatEvent.status == "active"
    ).count()

    if active_identity_threats > 0:
        identity_score = max(0, 15 - (active_identity_threats * 5))
        identity_detail = f"{active_identity_threats} active identity abuse/decoy access alert(s)"
        identity_status = "fail" if identity_score == 0 else "warn"
    else:
        identity_score = 15
        identity_detail = "No suspicious credential dumps or honey file access"
        identity_status = "pass"

    breakdown["identity_risk"] = {
        "score": identity_score,
        "max": 15,
        "label": "Identity & Credential safety",
        "status": identity_status,
        "detail": identity_detail
    }

    # 7. Safe Browsing (max 10)
    unblocked_phishing = db.query(BrowserEvent).filter(
        BrowserEvent.device_id == device_id,
        BrowserEvent.is_blocked == False,
        BrowserEvent.risk_score >= 70,
        BrowserEvent.timestamp >= seven_days_ago
    ).count()

    blocked_phishing = db.query(BrowserEvent).filter(
        BrowserEvent.device_id == device_id,
        BrowserEvent.is_blocked == True,
        BrowserEvent.timestamp >= seven_days_ago
    ).count()

    if unblocked_phishing > 0:
        browser_score = 0
        browser_detail = f"{unblocked_phishing} unblocked high-risk browser event(s)!"
        browser_status = "fail"
    elif blocked_phishing > 0:
        browser_score = 5
        browser_detail = f"{blocked_phishing} malicious browser threat(s) blocked recently"
        browser_status = "warn"
    else:
        browser_score = 10
        browser_detail = "No unsafe browsing activity in last 7 days"
        browser_status = "pass"

    breakdown["browser_risk"] = {
        "score": browser_score,
        "max": 10,
        "label": "Safe Browsing",
        "status": browser_status,
        "detail": browser_detail
    }

    total = os_score + firewall_score + wifi_score + usb_score + malware_score + identity_score + browser_score

    # Save to database
    device.trust_score = total
    db.commit()

    if total >= 85:
        label = "Trusted"
    elif total >= 60:
        label = "Moderate Risk"
    elif total >= 40:
        label = "At Risk"
    else:
        label = "Untrusted"

    return {
        "device_id": device_id,
        "overall_score": total,
        "max": 100,
        "label": label,
        "breakdown": breakdown,
    }
