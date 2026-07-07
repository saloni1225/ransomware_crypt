import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Header
from sqlalchemy.orm import Session
from typing import List
from app.database import get_db
from app.models import Device, ThreatEvent, AgentCommand, MalwareScan, RecoveryAction
from app.schemas import (
    DeviceCreate, DeviceHeartbeat, DeviceResponse,
    AgentCommandCreate, AgentCommandStatusUpdate, AgentCommandResponse
)
from app.services.auth_service import get_current_user
from app.config import settings

router = APIRouter(prefix="/devices", tags=["Devices"])

@router.get("/", response_model=List[DeviceResponse])
def list_devices(db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    return db.query(Device).all()

@router.post("/register", response_model=DeviceResponse)
def register_device(device_in: DeviceCreate, db: Session = Depends(get_db)):
    # Check if device exists
    device = db.query(Device).filter(Device.id == device_in.id).first()
    if device:
        # Update details
        device.hostname = device_in.hostname
        device.ip_address = device_in.ip_address
        device.mac_address = device_in.mac_address
        device.os_type = device_in.os_type
        device.firewall_status = device_in.firewall_status
        device.status = "online"
        device.last_seen = datetime.datetime.utcnow()
    else:
        # Create device
        device = Device(
            id=device_in.id,
            hostname=device_in.hostname,
            ip_address=device_in.ip_address,
            mac_address=device_in.mac_address,
            os_type=device_in.os_type,
            firewall_status=device_in.firewall_status,
            status="online",
            trust_score=100,
            last_seen=datetime.datetime.utcnow()
        )
        db.add(device)
    
    db.commit()
    db.refresh(device)
    return device

@router.post("/{device_id}/heartbeat", response_model=DeviceResponse)
def device_heartbeat(device_id: str, heartbeat: DeviceHeartbeat, db: Session = Depends(get_db)):
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found"
        )
    
    device.status = heartbeat.status
    device.firewall_status = heartbeat.firewall_status
    device.last_seen = datetime.datetime.utcnow()
    
    # Recalculate trust score based on status and active alerts
    # Weight factors:
    # OS Updates: 20%, Firewall: 15%, Wi-Fi: 10%, USB: 10%, Malware Events: 20%, Identity Risk: 15%, Browser: 10%
    base_score = 100
    
    # 1. Firewall deduction
    if heartbeat.firewall_status == "disabled":
        base_score -= 15
        
    # 2. Count active malware/ransomware events on this device
    active_threats_count = (
        db.query(ThreatEvent)
        .filter(
            ThreatEvent.device_id == device_id,
            ThreatEvent.status == "active"
        )
        .count()
    )
    
    # Deduct 15 points per active threat, max 40 points deduction for threats
    base_score -= min(active_threats_count * 15, 40)
    
    if heartbeat.trust_score is not None:
        # Override if agent computed score is sent, but cap it
        device.trust_score = heartbeat.trust_score
    else:
        device.trust_score = max(base_score, 0)
        
    db.commit()
    db.refresh(device)
    return device

@router.get("/{device_id}/trust-breakdown")
def get_trust_breakdown(device_id: str, db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    from app.services.trust_engine import compute_trust_score
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found"
        )
        
    return compute_trust_score(db, device_id)

@router.get("/{device_id}/trust-score")
def get_trust_score_v2(device_id: str, db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    """Phase 3: 6-component weighted trust scoring using the trust engine."""
    from app.services.trust_engine import compute_trust_score
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    return compute_trust_score(db, device_id)

@router.delete("/{device_id}")
def delete_device(device_id: str, db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized")
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    db.delete(device)
    db.commit()
    return {"detail": "Device deleted successfully"}


# ── Agent Command APIs ───────────────────────────────────────────────────────

def verify_agent_secret(x_agent_secret: str = Header(None)):
    expected = settings.AGENT_SHARED_SECRET
    if not x_agent_secret or not expected or x_agent_secret != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing agent secret header"
        )

@router.post("/{device_id}/commands", response_model=AgentCommandResponse)
def queue_agent_command(
    device_id: str,
    command_in: AgentCommandCreate,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Queue a new control/remediation command for an agent."""
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
        
    cmd = AgentCommand(
        device_id=device_id,
        command_type=command_in.command_type,
        payload=command_in.payload,
        status="queued"
    )
    db.add(cmd)
    db.commit()
    db.refresh(cmd)
    return cmd

@router.get("/{device_id}/commands", response_model=List[AgentCommandResponse])
def list_agent_commands(
    device_id: str,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Retrieve full history of commands dispatched to a device."""
    return db.query(AgentCommand).filter(AgentCommand.device_id == device_id).order_by(AgentCommand.created_at.desc()).all()

@router.get("/{device_id}/commands/pending", response_model=List[AgentCommandResponse])
def get_pending_agent_commands(
    device_id: str,
    db: Session = Depends(get_db),
    _agent_secret = Depends(verify_agent_secret)
):
    """Polled by the local agent to fetch commands waiting for execution."""
    cmds = (
        db.query(AgentCommand)
        .filter(
            AgentCommand.device_id == device_id,
            AgentCommand.status.in_(["queued", "sent"])
        )
        .order_by(AgentCommand.created_at.asc())
        .all()
    )
    # Mark queued as sent when fetched by the agent
    for cmd in cmds:
        if cmd.status == "queued":
            cmd.status = "sent"
    db.commit()
    return cmds

@router.put("/{device_id}/commands/{command_id}/status", response_model=AgentCommandResponse)
def update_agent_command_status(
    device_id: str,
    command_id: int,
    status_update: AgentCommandStatusUpdate,
    db: Session = Depends(get_db),
    _agent_secret = Depends(verify_agent_secret)
):
    """Updated by the agent to report progress, completion, or failures."""
    cmd = db.query(AgentCommand).filter(
        AgentCommand.id == command_id,
        AgentCommand.device_id == device_id
    ).first()
    if not cmd:
        raise HTTPException(status_code=404, detail="Command not found")
        
    cmd.status = status_update.status
    if status_update.execution_result is not None:
        cmd.execution_result = status_update.execution_result
    if status_update.error_message is not None:
        cmd.error_message = status_update.error_message
        
    # Wire command completion back to MalwareScan and RecoveryAction
    if status_update.status == "completed":
        if cmd.command_type == "restore_file" and cmd.payload:
            scan_id = cmd.payload.get("scan_id")
            if scan_id:
                scan = db.query(MalwareScan).filter(MalwareScan.id == scan_id).first()
                if scan:
                    scan.status = "restored"
                action = db.query(RecoveryAction).filter(RecoveryAction.scan_id == scan_id, RecoveryAction.action_type == "restore").first()
                if action:
                    action.status = "success"
                    
        elif cmd.command_type == "quarantine_file" and cmd.payload:
            scan_id = cmd.payload.get("scan_id")
            if scan_id:
                scan = db.query(MalwareScan).filter(MalwareScan.id == scan_id).first()
                if scan:
                    scan.status = "quarantined"
                action = db.query(RecoveryAction).filter(RecoveryAction.scan_id == scan_id, RecoveryAction.action_type == "quarantine_confirm").first()
                if action:
                    action.status = "success"
                    
        elif (cmd.command_type == "rollback" or cmd.command_type == "acknowledge_alert" or cmd.command_type == "terminate_process") and cmd.payload:
            event_id = cmd.payload.get("threat_event_id")
            if event_id:
                event = db.query(ThreatEvent).filter(ThreatEvent.id == event_id).first()
                if event:
                    event.status = "resolved"
                action = db.query(RecoveryAction).filter(RecoveryAction.threat_event_id == event_id, RecoveryAction.action_type == "rollback").first()
                if action:
                    action.status = "success"
                    
    elif status_update.status == "failed":
        if cmd.command_type == "restore_file" and cmd.payload:
            scan_id = cmd.payload.get("scan_id")
            if scan_id:
                scan = db.query(MalwareScan).filter(MalwareScan.id == scan_id).first()
                if scan:
                    scan.status = "quarantined"
                action = db.query(RecoveryAction).filter(RecoveryAction.scan_id == scan_id, RecoveryAction.action_type == "restore").first()
                if action:
                    action.status = "failed"
                    action.notes = f"Agent execution failed: {status_update.error_message}"
        elif cmd.command_type == "quarantine_file" and cmd.payload:
            scan_id = cmd.payload.get("scan_id")
            if scan_id:
                scan = db.query(MalwareScan).filter(MalwareScan.id == scan_id).first()
                if scan:
                    scan.status = "infected"
                action = db.query(RecoveryAction).filter(RecoveryAction.scan_id == scan_id, RecoveryAction.action_type == "quarantine_confirm").first()
                if action:
                    action.status = "failed"
                    action.notes = f"Agent execution failed: {status_update.error_message}"
                    
    db.commit()
    db.refresh(cmd)
    return cmd

