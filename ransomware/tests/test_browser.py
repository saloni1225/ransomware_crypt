import pytest
from fastapi.testclient import TestClient
import pyotp
from app.main import app
from app.database import Base, engine, SessionLocal
from app.models import Device, BrowserEvent, ThreatEvent, User, AIExplanation, AttackStoryline
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
        db.query(BrowserEvent).filter(BrowserEvent.device_id == "browser-test-device").delete(synchronize_session=False)
        
        # Deleting dependent tables to avoid PostgreSQL FK violations
        test_events = db.query(ThreatEvent).filter(ThreatEvent.device_id == "browser-test-device").all()
        event_ids = [e.id for e in test_events]
        if event_ids:
            db.query(AIExplanation).filter(AIExplanation.threat_event_id.in_(event_ids)).delete(synchronize_session=False)
            db.query(AttackStoryline).filter(AttackStoryline.threat_event_id.in_(event_ids)).delete(synchronize_session=False)
        
        db.query(ThreatEvent).filter(ThreatEvent.device_id == "browser-test-device").delete(synchronize_session=False)
        db.query(Device).filter(Device.id == "browser-test-device").delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()

def test_check_url_safety(client, auth_header):
    # Test clean URL
    response = client.post("/api/browser/check-url", json={"url": "https://google.com"}, headers=auth_header)
    assert response.status_code == 200
    res_data = response.json()
    assert res_data["risk_score"] == 0
    assert res_data["is_blocked"] is False
    assert res_data["category"] == "clean"

    # Test phishing URL (keyword)
    response = client.post("/api/browser/check-url", json={"url": "http://login-secure-paypal.com/signin"}, headers=auth_header)
    assert response.status_code == 200
    res_data = response.json()
    assert res_data["risk_score"] > 0
    assert res_data["is_blocked"] is True
    assert "phishing" in res_data["category"]

    # Test IP address URL
    response = client.post("/api/browser/check-url", json={"url": "http://192.168.1.1:8080/payload"}, headers=auth_header)
    assert response.status_code == 200
    res_data = response.json()
    assert res_data["risk_score"] >= 60  # IP address + unusual port
    assert res_data["is_blocked"] is True

def test_report_and_retrieve_browser_event(client, auth_header):
    # 1. Report benign event
    report_res = client.post("/api/browser/report-event", json={
        "device_id": "browser-test-device",
        "event_type": "suspicious_domain",
        "url": "http://example.com",
        "risk_score": 10,
        "is_blocked": False,
        "details": {"referrer": "direct"}
    })
    assert report_res.status_code == 200
    assert report_res.json()["status"] == "success"

    # Verify event stored in DB
    db = SessionLocal()
    event = db.query(BrowserEvent).filter(BrowserEvent.device_id == "browser-test-device").first()
    assert event is not None
    assert event.risk_score == 10
    assert event.is_blocked is False

    # Verify device was auto-registered with 100 trust score (since risk was low)
    device = db.query(Device).filter(Device.id == "browser-test-device").first()
    assert device is not None
    assert device.trust_score == 100
    db.close()

    # 2. Report malicious blocked event
    report_res2 = client.post("/api/browser/report-event", json={
        "device_id": "browser-test-device",
        "event_type": "phishing",
        "url": "http://login-secure-paypal.com/verify",
        "risk_score": 80,
        "is_blocked": True,
        "details": {"input_field": "username"}
    })
    assert report_res2.status_code == 200

    # Verify device trust score drops
    db = SessionLocal()
    device = db.query(Device).filter(Device.id == "browser-test-device").first()
    assert device.trust_score < 100

    # Verify a ThreatEvent was created automatically
    threat = db.query(ThreatEvent).filter(
        ThreatEvent.device_id == "browser-test-device"
    ).first()
    assert threat is not None
    assert threat.severity == "high"
    assert threat.status == "resolved"  # since it was blocked
    db.close()

    # 3. Retrieve events list
    events_res = client.get("/api/browser/events", headers=auth_header)
    assert events_res.status_code == 200
    events_list = events_res.json()
    assert len(events_list) >= 2
    # Check if the test device is present
    device_events = [e for e in events_list if e["device_id"] == "browser-test-device"]
    assert len(device_events) == 2

    # 4. Retrieve stats
    stats_res = client.get("/api/browser/stats", headers=auth_header)
    assert stats_res.status_code == 200
    stats = stats_res.json()
    assert stats["total_events"] >= 2
    assert stats["blocked_count"] >= 1
