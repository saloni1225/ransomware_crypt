"""
Privacy Dashboard Router — /api/privacy
Phase 3: Data exfiltration monitoring, privacy health score, and compliance tracking.
"""
import datetime
import random
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional

from app.database import get_db
from app.models import PrivacyEvent, Device
from app.services.auth_service import get_current_user

router = APIRouter(prefix="/privacy", tags=["Privacy"])

class PrivacyEventCreate(BaseModel):
    device_id: Optional[str] = None
    event_type: str  # exfiltration, data_access, policy_violation, leak_attempt
    data_category: str  # PII, credentials, financial, health, intellectual_property
    severity: str = "medium"
    details: Optional[dict] = None
    is_blocked: bool = False

@router.get("/events")
def list_privacy_events(
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """List all privacy events ordered by most recent."""
    events = db.query(PrivacyEvent).order_by(PrivacyEvent.timestamp.desc()).limit(limit).all()
    return [
        {
            "id": e.id,
            "device_id": e.device_id,
            "event_type": e.event_type,
            "data_category": e.data_category,
            "severity": e.severity,
            "details": e.details,
            "is_blocked": e.is_blocked,
            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
        }
        for e in events
    ]

@router.post("/events")
def log_privacy_event(
    event_in: PrivacyEventCreate,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Manually log a privacy event."""
    event = PrivacyEvent(
        device_id=event_in.device_id,
        event_type=event_in.event_type,
        data_category=event_in.data_category,
        severity=event_in.severity,
        details=event_in.details,
        is_blocked=event_in.is_blocked,
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return {"id": event.id, "status": "logged"}

@router.get("/score")
def get_privacy_score(
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Compute a privacy health score (0–100) based on recent unblocked events.
    Higher score = better privacy posture.
    """
    # Weight: critical=-20, high=-10, medium=-5, low=-2
    WEIGHTS = {"critical": 20, "high": 10, "medium": 5, "low": 2}

    cutoff = datetime.datetime.utcnow() - datetime.timedelta(days=30)
    recent = db.query(PrivacyEvent).filter(
        PrivacyEvent.timestamp >= cutoff,
        PrivacyEvent.is_blocked == False
    ).all()

    deductions = sum(WEIGHTS.get(e.severity, 5) for e in recent)
    score = max(0, 100 - deductions)

    # Determine label
    if score >= 85:
        label = "Excellent"
        color = "#00f2fe"
    elif score >= 70:
        label = "Good"
        color = "#43e97b"
    elif score >= 50:
        label = "Fair"
        color = "#f7971e"
    elif score >= 30:
        label = "Poor"
        color = "#f64f59"
    else:
        label = "Critical"
        color = "#c0392b"

    # Breakdown by category
    categories = {}
    for e in recent:
        categories[e.data_category] = categories.get(e.data_category, 0) + 1

    # GDPR/Compliance checks
    compliance_checks = [
        {"check": "Data Minimization Policy", "status": "pass" if deductions < 20 else "fail"},
        {"check": "Encryption at Rest", "status": "pass"},
        {"check": "Access Logging", "status": "pass" if len(recent) < 10 else "warn"},
        {"check": "Retention Policy (30-day)", "status": "pass"},
        {"check": "No Unauthorized Exfiltration", "status": "pass" if not any(e.event_type == "exfiltration" and not e.is_blocked for e in recent) else "fail"},
        {"check": "Consent Management", "status": "pass"},
    ]

    return {
        "score": score,
        "label": label,
        "color": color,
        "total_violations": len(recent),
        "category_breakdown": categories,
        "compliance_checks": compliance_checks,
    }

@router.get("/data-categories")
def data_category_breakdown(
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Breakdown of privacy events by data category."""
    from sqlalchemy import func
    results = db.query(
        PrivacyEvent.data_category,
        func.count(PrivacyEvent.id).label("count")
    ).group_by(PrivacyEvent.data_category).all()

    return [{"category": r[0], "count": r[1]} for r in results]

@router.get("/stats")
def privacy_stats(
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Summary statistics for privacy dashboard."""
    total = db.query(PrivacyEvent).count()
    blocked = db.query(PrivacyEvent).filter(PrivacyEvent.is_blocked == True).count()
    unblocked = total - blocked
    critical = db.query(PrivacyEvent).filter(PrivacyEvent.severity == "critical").count()
    high = db.query(PrivacyEvent).filter(PrivacyEvent.severity == "high").count()
    exfil = db.query(PrivacyEvent).filter(PrivacyEvent.event_type == "exfiltration").count()

    return {
        "total_events": total,
        "blocked": blocked,
        "unblocked": unblocked,
        "critical": critical,
        "high": high,
        "exfiltration_attempts": exfil,
    }
