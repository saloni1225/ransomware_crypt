import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.database import Base, engine, SessionLocal
from app.models import Device, MalwareScan, RecoveryAction, ThreatEvent, AgentCommand, User
from app.services.auth_service import hash_password
import datetime

# Ensure tables exist
Base.metadata.create_all(bind=engine)

@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c

@pytest.fixture
def auth_header(client):
    db = SessionLocal()
    try:
        test_email = "admin@defense.com"
        user = db.query(User).filter(User.email == test_email).first()
        if not user:
            user = User(
                email=test_email,
                hashed_password=hash_password("password123"),
                role="admin",
                totp_enabled=False
            )
            db.add(user)
            db.commit()
            db.refresh(user)
    finally:
        db.close()
        
    response = client.post("/api/auth/login", json={"email": test_email, "password": "password123"})
    assert response.status_code == 200
    res_data = response.json()
    token = res_data["access_token"]
    return {"Authorization": f"Bearer {token}"}

@pytest.fixture(autouse=True)
def clean_db():
    db = SessionLocal()
    try:
        # Clean up database entities
        db.query(AgentCommand).filter(AgentCommand.device_id == "test-device-cmd").delete()
        db.query(RecoveryAction).filter(RecoveryAction.device_id == "test-device-cmd").delete()
        db.query(MalwareScan).filter(MalwareScan.device_id == "test-device-cmd").delete()
        db.query(ThreatEvent).filter(ThreatEvent.device_id == "test-device-cmd").delete()
        db.query(Device).filter(Device.id == "test-device-cmd").delete()
        db.commit()
    finally:
        db.close()

def test_command_lifecycle_success(client, auth_header):
    db = SessionLocal()
    try:
        # 1. Register device
        device = Device(
            id="test-device-cmd",
            hostname="test-device-cmd",
            ip_address="192.168.1.100",
            mac_address="00:aa:bb:cc:dd:ee",
            os_type="Windows",
            firewall_status="enabled",
            status="online",
            trust_score=100,
            last_seen=datetime.datetime.utcnow()
        )
        db.add(device)
        
        # 2. Seed a quarantined malware scan
        scan = MalwareScan(
            device_id="test-device-cmd",
            file_path="C:\\test_file.txt",
            file_hash="abc123hash",
            file_size=1024,
            threat_name="Ransomware.Test",
            scan_engine="ClamAV",
            scan_time=datetime.datetime.utcnow(),
            status="quarantined"
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        scan_id = scan.id
    finally:
        db.close()

    # 3. Call restore endpoint
    restore_res = client.post(f"/api/recovery/restore/{scan_id}", headers=auth_header)
    assert restore_res.status_code == 200
    action_id = restore_res.json()["id"]

    # Verify status in database is now 'restore_pending'
    db = SessionLocal()
    try:
        updated_scan = db.query(MalwareScan).filter(MalwareScan.id == scan_id).first()
        assert updated_scan.status == "restore_pending"
        
        recovery_action = db.query(RecoveryAction).filter(RecoveryAction.id == action_id).first()
        assert recovery_action.status == "pending"
        
        # Verify AgentCommand is queued
        cmd = db.query(AgentCommand).filter(
            AgentCommand.device_id == "test-device-cmd",
            AgentCommand.command_type == "restore_file"
        ).first()
        assert cmd is not None
        assert cmd.status == "queued"
        command_id = cmd.id
    finally:
        db.close()

    # 4. Fetch pending commands simulating the agent
    agent_headers = {"X-Agent-Secret": "test-agent-secret-for-ci"}
    pending_res = client.get("/api/devices/test-device-cmd/commands/pending", headers=agent_headers)
    assert pending_res.status_code == 200
    pending_cmds = pending_res.json()
    assert len(pending_cmds) == 1
    assert pending_cmds[0]["id"] == command_id
    assert pending_cmds[0]["status"] == "sent"

    # 5. Update command status to received
    update_res = client.put(
        f"/api/devices/test-device-cmd/commands/{command_id}/status",
        headers=agent_headers,
        json={"status": "received"}
    )
    assert update_res.status_code == 200
    assert update_res.json()["status"] == "received"

    # 6. Update command status to started
    update_res = client.put(
        f"/api/devices/test-device-cmd/commands/{command_id}/status",
        headers=agent_headers,
        json={"status": "started"}
    )
    assert update_res.status_code == 200
    assert update_res.json()["status"] == "started"

    # 7. Update command status to completed
    update_res = client.put(
        f"/api/devices/test-device-cmd/commands/{command_id}/status",
        headers=agent_headers,
        json={"status": "completed", "execution_result": {"restored": True}}
    )
    assert update_res.status_code == 200
    assert update_res.json()["status"] == "completed"

    # Verify updates propagate back to DB models
    db = SessionLocal()
    try:
        final_scan = db.query(MalwareScan).filter(MalwareScan.id == scan_id).first()
        assert final_scan.status == "restored"

        final_action = db.query(RecoveryAction).filter(RecoveryAction.id == action_id).first()
        assert final_action.status == "success"
    finally:
        db.close()

def test_command_lifecycle_failure(client, auth_header):
    db = SessionLocal()
    try:
        # 1. Register device
        device = Device(
            id="test-device-cmd",
            hostname="test-device-cmd",
            ip_address="192.168.1.100",
            mac_address="00:aa:bb:cc:dd:ee",
            os_type="Windows",
            firewall_status="enabled",
            status="online",
            trust_score=100,
            last_seen=datetime.datetime.utcnow()
        )
        db.add(device)
        
        # 2. Seed a quarantined malware scan
        scan = MalwareScan(
            device_id="test-device-cmd",
            file_path="C:\\test_file.txt",
            file_hash="abc123hash",
            file_size=1024,
            threat_name="Ransomware.Test",
            scan_engine="ClamAV",
            scan_time=datetime.datetime.utcnow(),
            status="quarantined"
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        scan_id = scan.id
    finally:
        db.close()

    # 3. Call restore endpoint
    restore_res = client.post(f"/api/recovery/restore/{scan_id}", headers=auth_header)
    assert restore_res.status_code == 200
    action_id = restore_res.json()["id"]

    db = SessionLocal()
    try:
        cmd = db.query(AgentCommand).filter(
            AgentCommand.device_id == "test-device-cmd",
            AgentCommand.command_type == "restore_file"
        ).first()
        command_id = cmd.id
    finally:
        db.close()

    # 4. Update command status to failed
    agent_headers = {"X-Agent-Secret": "test-agent-secret-for-ci"}
    update_res = client.put(
        f"/api/devices/test-device-cmd/commands/{command_id}/status",
        headers=agent_headers,
        json={"status": "failed", "error_message": "Access Denied"}
    )
    assert update_res.status_code == 200
    assert update_res.json()["status"] == "failed"

    # Verify updates revert scan status back to quarantined for retries, and set action status to failed
    db = SessionLocal()
    try:
        final_scan = db.query(MalwareScan).filter(MalwareScan.id == scan_id).first()
        assert final_scan.status == "quarantined"

        final_action = db.query(RecoveryAction).filter(RecoveryAction.id == action_id).first()
        assert final_action.status == "failed"
        assert "Access Denied" in final_action.notes
    finally:
        db.close()
