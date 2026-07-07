import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.database import Base, engine, SessionLocal
from app.models import Device, ThreatEvent, ThreatLog, AIExplanation, AttackStoryline

# Setup Test Database
Base.metadata.create_all(bind=engine)

@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c

@pytest.fixture(autouse=True)
def clean_db():
    db = SessionLocal()
    try:
        # Clean up database test entities
        event_ids = [e.id for e in db.query(ThreatEvent).filter(ThreatEvent.device_id == "test-device-y").all()]
        if event_ids:
            db.query(AIExplanation).filter(AIExplanation.threat_event_id.in_(event_ids)).delete()
            db.query(AttackStoryline).filter(AttackStoryline.threat_event_id.in_(event_ids)).delete()
            
        db.query(ThreatLog).filter(ThreatLog.device_id == "test-device-y").delete()
        db.query(ThreatEvent).filter(ThreatEvent.device_id == "test-device-y").delete()
        db.query(Device).filter(Device.id == "test-device-y").delete()
        db.commit()
    finally:
        db.close()

def test_device_lifecycle_and_threat_ingestion(client):
    # 1. Register Device
    reg_res = client.post("/api/devices/register", json={
        "id": "test-device-y",
        "hostname": "test-device-y",
        "ip_address": "192.168.1.50",
        "mac_address": "00:11:22:33:44:55",
        "os_type": "Windows",
        "firewall_status": "enabled"
    })
    assert reg_res.status_code == 200
    assert reg_res.json()["hostname"] == "test-device-y"
    assert reg_res.json()["trust_score"] == 100
    
    # 2. Ingest low-severity benign log (no alert should trigger)
    log_res = client.post("/api/threats/logs", json={
        "device_id": "test-device-y",
        "type": "file",
        "action": "modified",
        "details": {"path": "C:\\safe_file.txt", "modified_count": 1}
    })
    assert log_res.status_code == 200
    
    # Verify no threat event triggered
    db = SessionLocal()
    events_count = db.query(ThreatEvent).filter(ThreatEvent.device_id == "test-device-y").count()
    assert events_count == 0
    db.close()
    
    # 3. Ingest malicious log: Deception Decoy File Access
    log_res_deception = client.post("/api/threats/logs", json={
        "device_id": "test-device-y",
        "type": "file",
        "action": "accessed",
        "details": {"path": "C:\\Users\\User\\Documents\\salary.xlsx"}
    })
    assert log_res_deception.status_code == 200
    
    # Verify a high-severity deception threat event triggered automatically!
    db = SessionLocal()
    triggered_event = db.query(ThreatEvent).filter(
        ThreatEvent.device_id == "test-device-y",
        ThreatEvent.category == "deception"
    ).first()
    assert triggered_event is not None
    assert triggered_event.severity == "high"
    assert triggered_event.confidence_score == 98
    
    # 4. Verify that the AI Explanation was generated automatically
    explanation = db.query(AIExplanation).filter(AIExplanation.threat_event_id == triggered_event.id).first()
    assert explanation is not None
    assert explanation.confidence == 98
    assert "employee_data.xlsx" in explanation.reasons[0] or "salary.xlsx" in explanation.reasons[0]
    
    # 5. Verify that the Attack Storyline was generated automatically
    storyline = db.query(AttackStoryline).filter(AttackStoryline.threat_event_id == triggered_event.id).first()
    assert storyline is not None
    assert "nodes" in storyline.storyline_data
    assert len(storyline.storyline_data["nodes"]) > 0
    
    # 6. Verify Device Trust score dropped
    device = db.query(Device).filter(Device.id == "test-device-y").first()
    assert device.trust_score < 100
    
    db.close()
