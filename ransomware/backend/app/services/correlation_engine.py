from sqlalchemy.orm import Session
from app.models import ThreatEvent, AttackStoryline
from typing import Dict, Any

def generate_attack_storyline(db: Session, event: ThreatEvent) -> AttackStoryline:
    # Check if storyline already exists
    existing = db.query(AttackStoryline).filter(AttackStoryline.threat_event_id == event.id).first()
    if existing:
        return existing

    nodes = []
    edges = []
    category = event.category
    time_str = event.timestamp.strftime("%H:%M:%S")

    if category == "ransomware":
        nodes = [
            {"id": "n1", "label": "Outlook.exe", "type": "process", "status": "info", "time": time_str, "description": "User opened suspicious billing email"},
            {"id": "n2", "label": "Chrome.exe", "type": "process", "status": "info", "time": time_str, "description": "Redirected to 'invoice-portal.net/download'"},
            {"id": "n3", "label": "invoice.pdf.exe", "type": "process", "status": "threat", "time": time_str, "description": "Downloaded payload executed in background"},
            {"id": "n4", "label": "powershell.exe", "type": "process", "status": "threat", "time": time_str, "description": "Executing command to clear volume shadows"},
            {"id": "n5", "label": "Encrypter Thread", "type": "file", "status": "blocked", "time": time_str, "description": "Rapid modifications detected (42 files/sec)"},
            {"id": "n6", "label": "Local Response Agent", "type": "action", "status": "success", "time": time_str, "description": "Process terminated, shadows restored, device isolated"}
        ]
        edges = [
            {"from": "n1", "to": "n2"},
            {"from": "n2", "to": "n3"},
            {"from": "n3", "to": "n4"},
            {"from": "n4", "to": "n5"},
            {"from": "n5", "to": "n6"}
        ]
        
    elif category == "deception":
        nodes = [
            {"id": "n1", "label": "explorer.exe", "type": "process", "status": "info", "time": time_str, "description": "File explorer opened by user"},
            {"id": "n2", "label": "cmd.exe", "type": "process", "status": "info", "time": time_str, "description": "Command prompt initiated with admin privilege"},
            {"id": "n3", "label": "scanner.exe", "type": "process", "status": "threat", "time": time_str, "description": "Running host credential enumeration script"},
            {"id": "n4", "label": "salary.xlsx (Honeypot)", "type": "file", "status": "blocked", "time": time_str, "description": "Decoy excel sheet access triggered high severity alert"},
            {"id": "n5", "label": "Deception Monitor", "type": "action", "status": "success", "time": time_str, "description": "Blocked process read commands, initiated quarantine"}
        ]
        edges = [
            {"from": "n1", "to": "n2"},
            {"from": "n2", "to": "n3"},
            {"from": "n3", "to": "n4"},
            {"from": "n4", "to": "n5"}
        ]
        
    elif category == "usb":
        nodes = [
            {"id": "n1", "label": "USB Hub", "type": "device", "status": "info", "time": time_str, "description": "Hardware mass storage device connected"},
            {"id": "n2", "label": "AutoRun.inf", "type": "file", "status": "threat", "time": time_str, "description": "Root folder script executed automatically"},
            {"id": "n3", "label": "updater.vbs", "type": "process", "status": "threat", "time": time_str, "description": "VBScript trying to install persistence keys"},
            {"id": "n4", "label": "USB Blocking Agent", "type": "action", "status": "success", "time": time_str, "description": "Ejected device, blocked registry modifications"}
        ]
        edges = [
            {"from": "n1", "to": "n2"},
            {"from": "n2", "to": "n3"},
            {"from": "n3", "to": "n4"}
        ]
        
    elif category == "identity":
        nodes = [
            {"id": "n1", "label": "Network Port 445", "type": "network", "status": "info", "time": time_str, "description": "Inbound SMB connection established"},
            {"id": "n2", "label": "rundll32.exe", "type": "process", "status": "threat", "time": time_str, "description": "Unauthorized command execution payload"},
            {"id": "n3", "label": "lsass.exe (Credential Dump)", "type": "process", "status": "threat", "time": time_str, "description": "Attempted dumping local domain hashes"},
            {"id": "n4", "label": "Security Shield", "type": "action", "status": "success", "time": time_str, "description": "Lsass injection blocked, access token revoked"}
        ]
        edges = [
            {"from": "n1", "to": "n2"},
            {"from": "n2", "to": "n3"},
            {"from": "n3", "to": "n4"}
        ]
        
    else:
        # Generic flow
        nodes = [
            {"id": "n1", "label": "Download directory", "type": "file", "status": "info", "time": time_str, "description": "Unverified zip archive downloaded"},
            {"id": "n2", "label": "unknown.exe", "type": "process", "status": "threat", "time": time_str, "description": "Executed binary outside user directory"},
            {"id": "n3", "label": "Firewall Rule Block", "type": "action", "status": "success", "time": time_str, "description": "Blocked C2 beaconing on port 8080"}
        ]
        edges = [
            {"from": "n1", "to": "n2"},
            {"from": "n2", "to": "n3"}
        ]

    storyline = AttackStoryline(
        threat_event_id=event.id,
        storyline_data={"nodes": nodes, "edges": edges}
    )
    db.add(storyline)
    db.commit()
    db.refresh(storyline)
    return storyline
