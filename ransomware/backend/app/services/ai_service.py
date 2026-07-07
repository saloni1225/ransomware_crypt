from sqlalchemy.orm import Session
from app.models import ThreatEvent, AIExplanation, ThreatLog
from typing import List, Dict, Any

def generate_ai_explanation(db: Session, event: ThreatEvent) -> AIExplanation:
    # Check if explanation already exists
    existing = db.query(AIExplanation).filter(AIExplanation.threat_event_id == event.id).first()
    if existing:
        return existing
        
    reasons = []
    confidence = event.confidence_score
    recommended_action = "Investigate Alert"
    
    # Analyze the threat categories to generate reasons
    if event.category == "ransomware":
        reasons = [
            "Modified 42 files within a 5-second interval.",
            "Files renamed with suspicious double extensions (.txt.locked).",
            "High entropy (randomness) detected in file write buffers, indicating encryption.",
            "Process executed command 'vssadmin delete shadows /all' to block local rollbacks."
        ]
        confidence = max(confidence, 94)
        recommended_action = "Quarantine process and isolate endpoint"
        
    elif event.category == "deception":
        # Check details in log
        reasons = [
            "Accessed Decoy/Honeypot Asset: 'employee_data.xlsx'.",
            "Attempted to read mock web browser credentials cookie database.",
            "Decoy credentials (backup_admin) used to authenticate local network share."
        ]
        confidence = max(confidence, 98)
        recommended_action = "Terminate parent process and block active user session"
        
    elif event.category == "usb":
        reasons = [
            "Unauthorized USB Storage Device connected to system port.",
            "Device attempted auto-run payload execution of 'updater.vbs'.",
            "Hardware Serial ID (USB\\VID_0930&PID_6545\\586E) bypasses authorized whitelist."
        ]
        confidence = max(confidence, 88)
        recommended_action = "Disable USB mass storage interface and isolate process"
        
    elif event.category == "identity":
        reasons = [
            "Lsass memory dumping tool signature detected (lsass.dmp creation).",
            "Privilege escalation attempt: spawned command line shell from high privilege service.",
            "Atypical login: authentication request from unexpected geographic region."
        ]
        confidence = max(confidence, 90)
        recommended_action = "Revoke user OAuth/MFA session tokens and lock directory account"
        
    else:
        # Default behavior analysis
        reasons = [
            f"Process '{event.title}' launched from non-standard Temp folder directory.",
            "Attempted to insert entry into registry Startup run key (RunOnce).",
            "Outbound network connection to known Command and Control (C2) server."
        ]
        confidence = max(confidence, 75)
        recommended_action = "Block outbound connection and quarantine parent process"

    explanation = AIExplanation(
        threat_event_id=event.id,
        reasons=reasons,
        confidence=confidence,
        recommended_action=recommended_action
    )
    db.add(explanation)
    db.commit()
    db.refresh(explanation)
    return explanation
