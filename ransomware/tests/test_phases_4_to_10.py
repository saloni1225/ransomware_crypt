import pytest
from fastapi.testclient import TestClient
import pyotp
import datetime
from app.main import app
from app.database import Base, engine, SessionLocal
from app.models import User, Device, ThreatEvent, LoginRiskEvent, BrowserEvent
from app.services.trust_engine import compute_trust_score

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
        db.query(LoginRiskEvent).delete()
        db.query(Device).filter(Device.id == "test-device-p10").delete()
        db.query(User).filter(User.email == "test_p10@defense.com").delete()
        db.commit()
    finally:
        db.close()

def test_pdf_report_export(client):
    from app.services.auth_service import hash_password
    db = SessionLocal()
    try:
        admin = db.query(User).filter(User.email == "admin@defense.com").first()
        if not admin:
            admin = User(
                email="admin@defense.com",
                hashed_password=hash_password("password123"),
                role="admin",
                totp_enabled=False
            )
            db.add(admin)
        else:
            admin.hashed_password = hash_password("password123")
            admin.totp_enabled = False
        db.commit()
    finally:
        db.close()
        
    login_res = client.post("/api/auth/login", json={
        "email": "admin@defense.com",
        "password": "password123"
    })
    token = login_res.json()["access_token"]

    response = client.get(f"/api/reports/export-pdf?token={token}")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert b"%PDF" in response.content

def test_trust_score_7_components():
    db = SessionLocal()
    try:
        # Create mock device with custom patch status and firewall
        device = Device(
            id="test-device-p10",
            hostname="test-device-p10",
            ip_address="127.0.0.1",
            status="online",
            firewall_status="enabled",
            patch_status="needs_reboot",
            trust_score=100,
            last_seen=datetime.datetime.utcnow()
        )
        db.add(device)
        db.commit()

        # Compute trust score
        score_res = compute_trust_score(db, "test-device-p10")
        assert score_res["overall_score"] == 92  # 12 (needs_reboot) + 15 (firewall) + 10 (wifi) + 10 (usb) + 20 (malware) + 15 (identity) + 10 (browser) = 92
        assert score_res["breakdown"]["os_updates"]["score"] == 12
        assert score_res["breakdown"]["firewall_status"]["score"] == 15
    finally:
        db.close()

def test_risk_based_login(client):
    email = "test_p10@defense.com"
    password = "SecretPassword123"
    
    # 1. Register User
    reg_response = client.post("/api/auth/register", json={
        "email": email,
        "password": password
    })
    assert reg_response.status_code == 201

    # Enable TOTP in database for this user
    db = SessionLocal()
    user = db.query(User).filter(User.email == email).first()
    user.totp_enabled = True
    secret = user.totp_secret
    db.commit()
    db.close()
    
    # 2. Login User
    login_response = client.post("/api/auth/login", json={
        "email": email,
        "password": password
    })
    assert login_response.status_code == 200
    secret = login_response.json()["totp_secret"] if "totp_secret" in login_response.json() else secret
    
    # 3. Verify TOTP Code (which triggers risk calculations)
    totp = pyotp.TOTP(secret)
    verify_response = client.post("/api/auth/verify-otp", json={
        "email": email,
        "otp_code": totp.now()
    })
    assert verify_response.status_code == 200

    # Verify that a LoginRiskEvent was logged in database
    db = SessionLocal()
    try:
        event = db.query(LoginRiskEvent).filter(LoginRiskEvent.user_email == email).first()
        assert event is not None
        assert event.risk_score == 0  # Initial login has no history, so risk is 0
        assert event.status == "allowed"
    finally:
        db.close()
