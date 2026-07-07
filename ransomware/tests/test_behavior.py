import pytest
from fastapi.testclient import TestClient
import pyotp
# pyrefly: ignore [missing-import]
from app.main import app
from app.database import Base, engine, SessionLocal
from app.models import Device, BehaviorProfile, AnomalyEvent, ThreatEvent, User, AIExplanation, AttackStoryline
from app.services.auth_service import hash_password, generate_totp_secret

# Setup Test Database
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
        # Clean up database test entities
        db.query(AnomalyEvent).filter(AnomalyEvent.device_id == "behavior-test-device").delete(synchronize_session=False)
        db.query(BehaviorProfile).filter(BehaviorProfile.device_id == "behavior-test-device").delete(synchronize_session=False)
        
        # Clean up escalations to ThreatEvent
        test_events = db.query(ThreatEvent).filter(ThreatEvent.device_id == "behavior-test-device").all()
        event_ids = [e.id for e in test_events]
        if event_ids:
            db.query(AIExplanation).filter(AIExplanation.threat_event_id.in_(event_ids)).delete(synchronize_session=False)
            db.query(AttackStoryline).filter(AttackStoryline.threat_event_id.in_(event_ids)).delete(synchronize_session=False)
        
        db.query(ThreatEvent).filter(ThreatEvent.device_id == "behavior-test-device").delete(synchronize_session=False)
        db.query(Device).filter(Device.id == "behavior-test-device").delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()

def test_behavior_baseline_and_anomaly_detection(client, auth_header):
    # 1. Post 4 data points (no anomaly should trigger since we need min 5 datapoints)
    for i in range(4):
        response = client.post("/api/behavior/update", json={
            "device_id": "behavior-test-device",
            "metric_name": "cpu_usage",
            "value": 10.0
        })
        assert response.status_code == 200
        res_data = response.json()
        assert res_data["status"] == "success"
        assert res_data["anomaly_detected"] is False

    # Check baseline was created and updated
    db = SessionLocal()
    profile = db.query(BehaviorProfile).filter(
        BehaviorProfile.device_id == "behavior-test-device",
        BehaviorProfile.metric_name == "cpu_usage"
    ).first()
    assert profile is not None
    assert profile.datapoint_count == 4
    # Mean should be around 10.0
    assert abs(profile.baseline_mean - 10.0) < 1.0
    db.close()

    # 2. Post 5th data point (now we have min datapoints required)
    response = client.post("/api/behavior/update", json={
        "device_id": "behavior-test-device",
        "metric_name": "cpu_usage",
        "value": 11.0
    })
    assert response.status_code == 200
    assert response.json()["anomaly_detected"] is False

    # 3. Post a massive anomalous value
    response = client.post("/api/behavior/update", json={
        "device_id": "behavior-test-device",
        "metric_name": "cpu_usage",
        "value": 90.0
    })
    assert response.status_code == 200
    res_data = response.json()
    assert res_data["anomaly_detected"] is True
    assert res_data["anomaly"]["z_score"] >= 3.0

    # Verify AnomalyEvent was stored in DB
    db = SessionLocal()
    anomaly = db.query(AnomalyEvent).filter(AnomalyEvent.device_id == "behavior-test-device").first()
    assert anomaly is not None
    assert anomaly.observed_value == 90.0
    assert anomaly.z_score >= 3.0

    # Since Z-score is very high, it should have escalated to a ThreatEvent and dropped trust score
    threat = db.query(ThreatEvent).filter(ThreatEvent.device_id == "behavior-test-device").first()
    assert threat is not None
    assert "Behavior Baseline Alert" in threat.title
    
    device = db.query(Device).filter(Device.id == "behavior-test-device").first()
    assert device.trust_score < 100
    db.close()

    # 4. Fetch device profiles
    profile_response = client.get("/api/behavior/profile/behavior-test-device", headers=auth_header)
    assert profile_response.status_code == 200
    profiles = profile_response.json()
    assert len(profiles) == 1
    assert profiles[0]["metric_name"] == "cpu_usage"

    # 5. Fetch all anomalies
    anom_response = client.get("/api/behavior/anomalies", headers=auth_header)
    assert anom_response.status_code == 200
    anomalies_list = anom_response.json()
    device_anoms = [a for a in anomalies_list if a["device_id"] == "behavior-test-device"]
    assert len(device_anoms) == 1

    # 6. Fetch stats
    stats_response = client.get("/api/behavior/stats", headers=auth_header)
    assert stats_response.status_code == 200
    stats = stats_response.json()
    assert stats["total_profiles"] >= 1
    assert stats["total_anomalies"] >= 1
