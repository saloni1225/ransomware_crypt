import pytest
from fastapi.testclient import TestClient
import pyotp
import time
import datetime
from app.main import app
from app.database import Base, engine, SessionLocal
from app.models import User

# Setup Test Database
Base.metadata.create_all(bind=engine)

@pytest.fixture
def client():
    # Use standard test client
    with TestClient(app) as c:
        yield c

@pytest.fixture(autouse=True)
def clean_db():
    db = SessionLocal()
    try:
        db.query(User).filter(User.email == "test@defense.com").delete()
        db.commit()
    finally:
        db.close()

def test_auth_full_flow(client):
    email = "test@defense.com"
    password = "SecretPassword123"
    
    # 1. Register User (MFA starts disabled)
    reg_response = client.post("/api/auth/register", json={
        "email": email,
        "password": password
    })
    assert reg_response.status_code == 201
    reg_data = reg_response.json()
    assert reg_data["email"] == email
    
    # 2. Login User (MFA is disabled initially, should require enrollment)
    login_response = client.post("/api/auth/login", json={
        "email": email,
        "password": password
    })
    assert login_response.status_code == 200
    login_data = login_response.json()
    assert login_data["detail"] == "MFA enrollment required"
    assert login_data["totp_enabled"] is False
    assert "qr_code" in login_data
    assert "totp_secret" in login_data
    
    secret = login_data["totp_secret"]
    
    # 3. Generate Valid TOTP Code and Verify Setup via public verify-otp route
    totp = pyotp.TOTP(secret)
    valid_code = totp.now()
    
    verify_otp_response = client.post("/api/auth/verify-otp", json={
        "email": email,
        "otp_code": valid_code
    })
    assert verify_otp_response.status_code == 200
    token = verify_otp_response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    # 4. Request MFA Setup again (Authenticated) - should fail now since already enabled
    setup_response = client.post("/api/auth/mfa/setup", headers=headers)
    assert setup_response.status_code == 400
    
    # 5. Retrieve Profile to verify totp_enabled is True
    me_response = client.get("/api/auth/me", headers=headers)
    assert me_response.status_code == 200
    me_data = me_response.json()
    
    # 6. Login again (MFA is now enabled, should require MFA)
    login_mfa_response = client.post("/api/auth/login", json={
        "email": email,
        "password": password
    })
    assert login_mfa_response.status_code == 200
    login_mfa_data = login_mfa_response.json()
    assert login_mfa_data["detail"] == "MFA required"
    assert login_mfa_data["totp_enabled"] is True
    
    # 7. Complete Login via verify-otp (use code from next window to bypass anti-replay)
    valid_code_2 = totp.at(datetime.datetime.now() + datetime.timedelta(seconds=30))
    verify_otp_response = client.post("/api/auth/verify-otp", json={
        "email": email,
        "otp_code": valid_code_2
    })
    assert verify_otp_response.status_code == 200
    verify_otp_data = verify_otp_response.json()
    assert "access_token" in verify_otp_data
