from fastapi import APIRouter, Depends, HTTPException, status, Request
from app.config import settings
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import User
from app.schemas import (
    UserCreate, UserLogin, UserResponse, OTPVerify, Token, ForgotPassword, 
    ResetPassword, UserRoleUpdate, MFASetupResponse, MFADisable, MFAVerifyPayload
)
from app.services.auth_service import (
    hash_password, verify_password, generate_totp_secret,
    get_totp_uri, generate_qr_code_base64, verify_totp,
    create_access_token, get_current_user, oauth2_scheme
)

router = APIRouter(prefix="/auth", tags=["Authentication"])

@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(user_in: UserCreate, db: Session = Depends(get_db)):
    # Check if user email already exists
    existing_user = db.query(User).filter(User.email == user_in.email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Create new user with a unique TOTP secret
    db_user = User(
        email=user_in.email,
        hashed_password=hash_password(user_in.password),
        role="admin",
        totp_secret=generate_totp_secret(),
        totp_enabled=False
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@router.post("/login")
def login(credentials: UserLogin, db: Session = Depends(get_db)):
    # Retrieve user
    user = db.query(User).filter(User.email == credentials.email).first()
    if not user or not verify_password(credentials.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect email or password"
        )
    
    # Lazy initialize TOTP secret if not present
    if not user.totp_secret:
        user.totp_secret = generate_totp_secret()
        db.commit()
        db.refresh(user)

    # Enforce TOTP if enabled
    if user.totp_enabled:
        return {
            "detail": "MFA required",
            "totp_enabled": True,
            "email": user.email
        }
    
    # Otherwise bypass TOTP and issue JWT token directly for Break-glass admin only
    if user.email == "admin@defense.com":
        access_token = create_access_token(data={"sub": user.email, "role": user.role})
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "email": user.email,
            "role": user.role,
            "totp_enabled": False
        }
        
    # Enforce mandatory MFA enrollment for all normal users
    uri = get_totp_uri(user.totp_secret, user.email)
    qr_code = generate_qr_code_base64(uri)
    return {
        "detail": "MFA enrollment required",
        "totp_enabled": False,
        "email": user.email,
        "qr_code": qr_code,
        "totp_secret": user.totp_secret
    }

@router.post("/mfa/setup", response_model=MFASetupResponse)
def mfa_setup(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if current_user.totp_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA is already enabled"
        )
    if not current_user.totp_secret:
        current_user.totp_secret = generate_totp_secret()
        db.commit()
        db.refresh(current_user)
        
    uri = get_totp_uri(current_user.totp_secret, current_user.email)
    qr_code = generate_qr_code_base64(uri)
    
    return {
        "qr_code": qr_code,
        "totp_secret": current_user.totp_secret,
        "totp_enabled": current_user.totp_enabled
    }

@router.post("/mfa/verify")
def mfa_verify(
    payload: MFAVerifyPayload,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if current_user.totp_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA is already enabled"
        )
    
    is_valid = verify_totp(current_user.totp_secret, payload.otp_code, current_user.email)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired authentication code"
        )
        
    current_user.totp_enabled = True
    db.commit()
    return {"detail": "Multi-Factor Authentication enabled successfully"}

@router.post("/mfa/disable")
def mfa_disable(
    payload: MFADisable,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if not current_user.totp_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA is not enabled"
        )
    
    if not verify_password(payload.password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect password"
        )
        
    current_user.totp_enabled = False
    current_user.totp_secret = generate_totp_secret() # rotate secret key
    db.commit()
    return {"detail": "Multi-Factor Authentication disabled successfully"}

@router.post("/verify-otp", response_model=Token)
def verify_otp_endpoint(payload: OTPVerify, request: Request, db: Session = Depends(get_db)):
    # Validate user exists
    user = db.query(User).filter(User.email == payload.email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User not found"
        )
    
    # Verify TOTP code
    is_valid = verify_totp(user.totp_secret, payload.otp_code, user.email)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired MFA code"
        )
    
    # Activate TOTP
    if not user.totp_enabled:
        user.totp_enabled = True
        db.commit()
    
    # Risk-based login check
    from app.models import LoginRiskEvent
    import datetime

    client_ip = request.client.host
    now = datetime.datetime.utcnow()
    current_hour = now.hour

    history = (
        db.query(LoginRiskEvent)
        .filter(LoginRiskEvent.user_email == user.email, LoginRiskEvent.status == "allowed")
        .order_by(LoginRiskEvent.timestamp.desc())
        .limit(15)
        .all()
    )

    risk_score = 0
    risk_factors = []

    if len(history) >= 3:
        # Check IP Anomaly
        ip_set = {h.ip_address for h in history}
        if client_ip not in ip_set:
            risk_score += 50
            risk_factors.append("unusual_ip")

        # Check Time Anomaly (circular distance)
        hours = [h.timestamp.hour for h in history]
        mean_hour = sum(hours) / len(hours)
        dist = min(abs(current_hour - mean_hour), 24 - abs(current_hour - mean_hour))
        if dist > 4.0:
            risk_score += 30
            risk_factors.append("unusual_time")
    
    login_status = "allowed"
    if risk_score >= 80:
        login_status = "blocked"
    elif risk_score >= 50:
        login_status = "flagged"

    risk_event = LoginRiskEvent(
        user_email=user.email,
        ip_address=client_ip,
        risk_score=risk_score,
        risk_factors=risk_factors,
        status=login_status,
        timestamp=now
    )
    db.add(risk_event)
    db.commit()

    if login_status == "blocked":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Security access blocked: high-risk login detected. Factors: {', '.join(risk_factors)}"
        )

    # Generate JWT Token
    access_token = create_access_token(data={"sub": user.email, "role": user.role})
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "email": user.email,
        "role": user.role
    }

@router.get("/me", response_model=UserResponse)
def get_me(current_user: User = Depends(get_current_user)):
    current_user.break_glass_admin = (current_user.email == "admin@defense.com")
    current_user.mfa_enrolled = current_user.totp_enabled
    
    if current_user.email == "admin@defense.com":
        current_user.mfa_required = False
    else:
        current_user.mfa_required = not current_user.totp_enabled
        
    current_user.mfa_reset_required = (not current_user.totp_enabled and current_user.totp_secret is not None)
    
    return current_user

@router.post("/logout")
def logout_endpoint(token: str = Depends(oauth2_scheme)):
    from app.services.auth_service import decode_access_token
    from app.redis_client import redis_client
    import time
    
    payload = decode_access_token(token)
    if payload:
        exp = payload.get("exp")
        if exp:
            now = int(time.time())
            ttl = int(exp - now)
            if ttl > 0:
                redis_client.blacklist_token(token, ttl)
                
    return {"detail": "Successfully logged out"}

@router.get("/debug-totp")
def get_debug_totp(email: str, db: Session = Depends(get_db)):
    if settings.ENVIRONMENT != "development":
        raise HTTPException(status_code=403, detail="Forbidden in non-dev environments")
    user = db.query(User).filter(User.email == email).first()
    if not user or not user.totp_secret:
        raise HTTPException(status_code=404, detail="User or TOTP secret not found")
    import pyotp
    totp = pyotp.TOTP(user.totp_secret)
    return {"code": totp.now()}

@router.post("/forgot-password")
def forgot_password(payload: ForgotPassword, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == payload.email).first()
    if not user:
        return {"detail": "If the email is registered, a password reset link has been sent."}
    
    token = create_access_token(data={"sub": user.email, "type": "reset"})
    return {"detail": "If the email is registered, a password reset link has been sent.", "mock_token": token}

@router.post("/reset-password")
def reset_password(payload: ResetPassword, db: Session = Depends(get_db)):
    try:
        from jose import jwt
        from app.config import settings
        payload_data = jwt.decode(payload.token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        email = payload_data.get("sub")
        if email != payload.email:
            raise HTTPException(status_code=400, detail="Invalid token")
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid or expired token")
        
    user = db.query(User).filter(User.email == payload.email).first()
    if not user:
        raise HTTPException(status_code=400, detail="User not found")
        
    user.hashed_password = hash_password(payload.new_password)
    db.commit()
    return {"detail": "Password successfully reset"}

@router.put("/users/{user_id}/role")
def update_user_role(user_id: int, payload: UserRoleUpdate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Not authorized to change roles")
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    user.role = payload.role
    db.commit()
    return {"detail": f"Role updated to {payload.role}"}

@router.get("/users")
def get_all_users(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Not authorized")
    users = db.query(User).all()
    return [{"id": u.id, "email": u.email, "role": u.role, "is_active": u.is_active} for u in users]
