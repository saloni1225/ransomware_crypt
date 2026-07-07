from pydantic import BaseModel, EmailStr
from typing import List, Optional, Any
from datetime import datetime

# Token Schemas
class Token(BaseModel):
    access_token: str
    token_type: str
    email: str
    role: str

class TokenData(BaseModel):
    email: Optional[str] = None

# User Schemas
class UserBase(BaseModel):
    email: EmailStr

class UserCreate(UserBase):
    password: str

class UserLogin(UserBase):
    password: str

class UserResponse(UserBase):
    id: int
    role: str
    is_active: bool
    created_at: datetime
    totp_enabled: bool
    break_glass_admin: bool = False
    mfa_required: bool = False
    mfa_enrolled: bool = False
    mfa_reset_required: bool = False

    class Config:
        from_attributes = True

# OTP Schemas
class OTPVerify(BaseModel):
    email: EmailStr
    otp_code: str

# Device Schemas
class DeviceBase(BaseModel):
    id: str
    hostname: str
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    os_type: Optional[str] = None
    firewall_status: Optional[str] = "enabled"

class DeviceCreate(DeviceBase):
    pass

class DeviceHeartbeat(BaseModel):
    status: str
    firewall_status: Optional[str] = "enabled"
    trust_score: Optional[int] = None

class DeviceResponse(DeviceBase):
    status: str
    trust_score: int
    last_seen: datetime

    class Config:
        from_attributes = True

# Threat Log Schemas
class ThreatLogCreate(BaseModel):
    device_id: str
    type: str  # file, process, usb, network
    action: str  # e.g., modified, started, blocked
    details: Optional[dict] = None

class ThreatLogBatch(BaseModel):
    """Batch of log events from the real agent — processed in one request."""
    events: List[ThreatLogCreate]

class ThreatLogResponse(BaseModel):
    id: int
    device_id: str
    timestamp: datetime
    type: str
    action: str
    details: Optional[dict] = None

    class Config:
        from_attributes = True

# Threat Event Schemas
class ThreatEventCreate(BaseModel):
    device_id: str
    title: str
    description: Optional[str] = None
    category: str
    severity: str
    confidence_score: int

class ThreatEventResponse(BaseModel):
    id: int
    device_id: str
    title: str
    description: Optional[str] = None
    category: str
    severity: str
    status: str
    confidence_score: int
    timestamp: datetime

    class Config:
        from_attributes = True

# AI Explanation Schemas
class AIExplanationResponse(BaseModel):
    id: int
    threat_event_id: int
    reasons: List[str]
    confidence: int
    recommended_action: str

    class Config:
        from_attributes = True

# Attack Storyline Schemas
class AttackStorylineResponse(BaseModel):
    id: int
    threat_event_id: int
    storyline_data: Any

    class Config:
        from_attributes = True

# Dashboard Summary Schema
class DashboardSummary(BaseModel):
    total_devices: int
    active_devices: int
    critical_threats: int
    total_threats: int
    overall_trust_score: int
    recent_events: List[ThreatEventResponse]

# Auth Schemas
class ForgotPassword(BaseModel):
    email: EmailStr

class ResetPassword(BaseModel):
    email: EmailStr
    token: str
    new_password: str

class UserRoleUpdate(BaseModel):
    role: str

class MFASetupResponse(BaseModel):
    qr_code: str
    totp_secret: str
    totp_enabled: bool

class MFADisable(BaseModel):
    password: str

class MFAVerifyPayload(BaseModel):
    otp_code: str


# Agent Command Schemas
class AgentCommandCreate(BaseModel):
    command_type: str
    payload: Optional[dict] = None

class AgentCommandStatusUpdate(BaseModel):
    status: str  # 'received', 'started', 'completed', 'failed'
    execution_result: Optional[dict] = None
    error_message: Optional[str] = None

class AgentCommandResponse(BaseModel):
    id: int
    device_id: str
    command_type: str
    payload: Optional[dict] = None
    status: str
    execution_result: Optional[dict] = None
    error_message: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


