from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Optional
import datetime

from app.database import get_db
from app.models import ThreatLog, ThreatEvent, Device, WiFiNetwork, NetworkConnection, MalwareScan
from app.schemas import ThreatLogCreate, ThreatLogBatch, ThreatLogResponse, ThreatEventResponse, ThreatEventCreate
from app.services.auth_service import get_current_user
from app.services.ai_service import generate_ai_explanation
from app.services.correlation_engine import generate_attack_storyline

router = APIRouter(prefix="/threats", tags=["Threats"])

# Helper to analyze log and auto-create threat events
def analyze_logs_and_trigger_events(db: Session, log: ThreatLog):
    device = db.query(Device).filter(Device.id == log.device_id).first()
    if not device:
        return
        
    triggered_event = None
    
    # 1. Ransomware Detection Rule
    if log.type == "file" and log.action == "modified":
        details = log.details or {}
        modified_count = details.get("modified_count", 0)
        entropy = details.get("entropy", 0)
        if modified_count >= 30 or entropy > 7.5 or "locked" in details.get("extension", ""):
            triggered_event = ThreatEvent(
                device_id=log.device_id,
                title="Ransomware Behavior Detected",
                description=f"Rapid modification of {modified_count} files. Detected high entropy write buffers.",
                category="ransomware",
                severity="critical",
                confidence_score=94,
                timestamp=datetime.datetime.utcnow()
            )
            
    # 2. Deception Engine Rule
    elif log.type == "file" and log.action == "accessed":
        details = log.details or {}
        file_path = details.get("path", "").lower()
        if "salary" in file_path or "employee_data" in file_path or "passwords" in file_path or "decoy" in file_path:
            triggered_event = ThreatEvent(
                device_id=log.device_id,
                title="Decoy Honey File Access",
                description=f"Decoy sensitive asset accessed: {details.get('path')}",
                category="deception",
                severity="high",
                confidence_score=98,
                timestamp=datetime.datetime.utcnow()
            )
            
    # 3. USB Control Rule
    elif log.type == "usb" and log.action == "mounted":
        details = log.details or {}
        is_authorized = details.get("authorized", True)
        if not is_authorized or "unauthorized" in details.get("status", "").lower():
            triggered_event = ThreatEvent(
                device_id=log.device_id,
                title="Unauthorized USB Connected",
                description=f"Blocked connection of unauthorized mass storage: {details.get('label', 'Unknown USB')}",
                category="usb",
                severity="medium",
                confidence_score=85,
                timestamp=datetime.datetime.utcnow()
            )
            
    # 4. Identity Abuse Rule
    elif log.type == "process" and log.action == "started":
        details = log.details or {}
        process_name = details.get("name", "").lower()
        command = details.get("command", "").lower()
        if "lsass" in process_name or "dump" in command or "vssadmin delete shadows" in command:
            triggered_event = ThreatEvent(
                device_id=log.device_id,
                title="Privilege Escalation / Credential Dumping Attempt",
                description=f"Suspicious security command/process started: {process_name}",
                category="identity",
                severity="high",
                confidence_score=90,
                timestamp=datetime.datetime.utcnow()
            )

    if triggered_event:
        db.add(triggered_event)
        db.commit()
        db.refresh(triggered_event)
        
        # Automatically generate AI Explanation and Attack Storyline for this new event
        generate_ai_explanation(db, triggered_event)
        generate_attack_storyline(db, triggered_event)
        
        # Deduct trust score immediately
        device.trust_score = max(0, device.trust_score - 20)
        db.commit()

        # Send Webhook Notification
        try:
            from app.services.notification_service import send_threat_notification
            send_threat_notification(triggered_event)
        except Exception as e:
            print(f"Error calling notification service: {e}")

@router.post("/logs", response_model=ThreatLogResponse)
def ingest_log(log_in: ThreatLogCreate, db: Session = Depends(get_db)):
    # Verify device exists (register it automatically if not seen before)
    device = db.query(Device).filter(Device.id == log_in.device_id).first()
    if not device:
        device = Device(
            id=log_in.device_id,
            hostname=log_in.device_id,
            status="online",
            trust_score=100,
            last_seen=datetime.datetime.utcnow()
        )
        db.add(device)
        db.commit()
        db.refresh(device)

    # Handle special types that go to dedicated tables rather than threat_logs
    _handle_specialised_event(db, log_in, device)

    db_log = ThreatLog(
        device_id=log_in.device_id,
        type=log_in.type,
        action=log_in.action,
        details=log_in.details,
        timestamp=datetime.datetime.utcnow()
    )
    db.add(db_log)
    db.commit()
    db.refresh(db_log)

    # Process rules and trigger threat events if matching patterns are found
    analyze_logs_and_trigger_events(db, db_log)

    return db_log


@router.post("/logs/batch")
def ingest_log_batch(batch: ThreatLogBatch, db: Session = Depends(get_db)):
    """
    Batch event ingestion endpoint for the real agent.
    Accepts up to 100 events per request and processes them sequentially.
    Returns a summary dict rather than full log objects to keep the response lean.
    """
    results = {"accepted": 0, "rejected": 0, "errors": []}

    for event in batch.events[:100]:  # hard cap at 100 per batch
        try:
            # Ensure device exists
            device = db.query(Device).filter(Device.id == event.device_id).first()
            if not device:
                device = Device(
                    id=event.device_id,
                    hostname=event.device_id,
                    status="online",
                    trust_score=100,
                    last_seen=datetime.datetime.utcnow()
                )
                db.add(device)
                db.commit()
                db.refresh(device)
            else:
                # Update last_seen on each batch
                device.last_seen = datetime.datetime.utcnow()
                db.commit()

            # Handle specialised event routing (WiFi, Network, etc.)
            _handle_specialised_event(db, event, device)

            db_log = ThreatLog(
                device_id=event.device_id,
                type=event.type,
                action=event.action,
                details=event.details,
                timestamp=datetime.datetime.utcnow()
            )
            db.add(db_log)
            db.commit()
            db.refresh(db_log)

            analyze_logs_and_trigger_events(db, db_log)
            results["accepted"] += 1

        except Exception as exc:
            results["rejected"] += 1
            results["errors"].append(str(exc)[:120])

    return results


def _handle_specialised_event(
    db: Session,
    log_in: ThreatLogCreate,
    device: Device,
) -> None:
    """
    Routes certain event types into their dedicated tables
    (WiFiNetwork, NetworkConnection, MalwareScan) so the corresponding
    frontend modules display live data from the agent.
    """
    details = log_in.details or {}
    event_type = log_in.type
    action = log_in.action

    # ── WiFi scan results ─────────────────────────────────────────────────
    if event_type == "wifi" and action == "scan_result":
        existing = db.query(WiFiNetwork).filter(
            WiFiNetwork.device_id == device.id,
            WiFiNetwork.ssid == details.get("ssid", ""),
            WiFiNetwork.bssid == details.get("bssid", ""),
        ).first()
        if not existing:
            wifi = WiFiNetwork(
                device_id=device.id,
                ssid=details.get("ssid", "Unknown"),
                bssid=details.get("bssid", ""),
                signal_strength=details.get("signal_strength", -70),
                channel=details.get("channel"),
                security_type=details.get("security_type", "Unknown"),
                risk_level=details.get("risk_level", "low"),
                is_connected=details.get("is_connected", False),
                is_evil_twin=details.get("is_evil_twin", False),
            )
            db.add(wifi)
            db.commit()

    # ── Network connections ───────────────────────────────────────────────
    elif event_type == "network" and action in ("new_connection", "suspicious_connection"):
        conn = NetworkConnection(
            device_id=device.id,
            remote_ip=details.get("remote_ip", "0.0.0.0"),
            remote_port=details.get("remote_port"),
            local_port=details.get("local_port"),
            protocol=details.get("protocol", "TCP"),
            process_name=details.get("process_name", "unknown"),
            status=details.get("status", "normal"),
        )
        db.add(conn)
        db.commit()


@router.get("/events", response_model=List[ThreatEventResponse])
def list_threat_events(db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    return db.query(ThreatEvent).order_by(ThreatEvent.id.desc()).all()

@router.get("/events/{event_id}", response_model=ThreatEventResponse)
def get_threat_event(event_id: int, db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    event = db.query(ThreatEvent).filter(ThreatEvent.id == event_id).first()
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Threat event not found"
        )
    return event

@router.put("/events/{event_id}/status", response_model=ThreatEventResponse)
def update_threat_status(
    event_id: int, 
    status_update: str, # active, quarantined, ignored, resolved
    db: Session = Depends(get_db), 
    current_user = Depends(get_current_user)
):
    event = db.query(ThreatEvent).filter(ThreatEvent.id == event_id).first()
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Threat event not found"
        )
    
    if status_update not in ["active", "quarantined", "ignored", "resolved"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid status"
        )
        
    event.status = status_update
    
    # If a threat is resolved or ignored, we might recover trust score
    if status_update in ["resolved", "ignored"]:
        device = db.query(Device).filter(Device.id == event.device_id).first()
        if device:
            device.trust_score = min(100, device.trust_score + 15)
            
    db.commit()
    db.refresh(event)
    return event

@router.get("/events/{event_id}/explanation")
def get_event_explanation(event_id: int, db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    event = db.query(ThreatEvent).filter(ThreatEvent.id == event_id).first()
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Threat event not found"
        )
        
    explanation = generate_ai_explanation(db, event)
    return {
        "id": explanation.id,
        "threat_event_id": explanation.threat_event_id,
        "reasons": explanation.reasons,
        "confidence": explanation.confidence,
        "recommended_action": explanation.recommended_action
    }

@router.get("/events/{event_id}/storyline")
def get_event_storyline(event_id: int, db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    event = db.query(ThreatEvent).filter(ThreatEvent.id == event_id).first()
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Threat event not found"
        )
        
    storyline = generate_attack_storyline(db, event)
    return storyline.storyline_data

@router.get("/")
def get_threats(db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    return list_threat_events(db, current_user)

@router.post("/")
def create_threat(threat_in: ThreatEventCreate, db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    device = db.query(Device).filter(Device.id == threat_in.device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    new_event = ThreatEvent(
        device_id=threat_in.device_id,
        title=threat_in.title,
        description=threat_in.description,
        category=threat_in.category,
        severity=threat_in.severity,
        confidence_score=threat_in.confidence_score,
        timestamp=datetime.datetime.utcnow()
    )
    db.add(new_event)
    db.commit()
    db.refresh(new_event)
    return new_event

@router.get("/{id}")
def get_threat(id: int, db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    return get_threat_event(id, db, current_user)

@router.get("/incidents/all")
def get_incidents(db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    return list_threat_events(db, current_user)

@router.get("/storyline/{id}")
def get_storyline_by_id(id: int, db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    return get_event_storyline(id, db, current_user)
