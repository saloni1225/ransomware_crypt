"""
Behavior Baseline Engine Router — /api/behavior
Phase 4: Behavioral anomaly detection, baselines, and profiling.
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional, List
import datetime

from app.database import get_db
from app.models import BehaviorProfile, AnomalyEvent, Device
from app.services.auth_service import get_current_user
from app.services.behavior_engine import check_anomaly, update_baseline

router = APIRouter(prefix="/behavior", tags=["Behavior Baseline"])

class BehaviorMetricUpdate(BaseModel):
    device_id: str
    metric_name: str
    value: float

class BaselineProfileResponse(BaseModel):
    id: int
    device_id: str
    metric_name: str
    baseline_mean: float
    baseline_std: float
    datapoint_count: int
    last_updated: datetime.datetime

    class Config:
        from_attributes = True

class AnomalyEventResponse(BaseModel):
    id: int
    device_id: str
    metric_name: str
    observed_value: float
    expected_mean: float
    z_score: float
    severity: str
    is_false_positive: bool
    timestamp: datetime.datetime

    class Config:
        from_attributes = True

@router.post("/update")
def report_behavior_metric(payload: BehaviorMetricUpdate, db: Session = Depends(get_db)):
    """
    Ingest a new behavioral metric.
    Checks for anomalies against the current baseline before updating the baseline profile.
    """
    # 1. Ensure device exists
    device = db.query(Device).filter(Device.id == payload.device_id).first()
    if not device:
        device = Device(
            id=payload.device_id,
            hostname=payload.device_id,
            status="online",
            trust_score=100,
            last_seen=datetime.datetime.utcnow()
        )
        db.add(device)
        db.commit()
        db.refresh(device)
    else:
        device.last_seen = datetime.datetime.utcnow()
        db.commit()

    # 2. Check for anomaly first using pre-existing baseline
    anomaly = check_anomaly(db, payload.device_id, payload.metric_name, payload.value)

    # 3. Update the baseline model profile
    update_baseline(db, payload.device_id, payload.metric_name, payload.value)

    return {
        "status": "success",
        "anomaly_detected": anomaly is not None,
        "anomaly": {
            "id": anomaly.id,
            "z_score": anomaly.z_score,
            "severity": anomaly.severity
        } if anomaly else None
    }

@router.get("/profile/{device_id}", response_model=List[BaselineProfileResponse])
def get_device_profiles(
    device_id: str,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Fetch all baseline profiles for a specific device."""
    profiles = db.query(BehaviorProfile).filter(BehaviorProfile.device_id == device_id).all()
    return profiles

@router.get("/anomalies", response_model=List[AnomalyEventResponse])
def list_anomalies(
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Retrieve list of anomalous behavior events, sorted by recent."""
    anomalies = db.query(AnomalyEvent).order_by(AnomalyEvent.timestamp.desc()).limit(limit).all()
    return anomalies

@router.get("/stats")
def get_behavior_stats(
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Gather basic statistical counts for the Behavior dashboard."""
    from sqlalchemy import func

    total_profiles = db.query(BehaviorProfile).count()
    total_anomalies = db.query(AnomalyEvent).count()
    critical_anomalies = db.query(AnomalyEvent).filter(AnomalyEvent.severity == "critical").count()
    high_anomalies = db.query(AnomalyEvent).filter(AnomalyEvent.severity == "high").count()

    avg_z = db.query(func.avg(AnomalyEvent.z_score)).scalar()
    avg_z = round(avg_z, 2) if avg_z is not None else 0.0

    return {
        "total_profiles": total_profiles,
        "total_anomalies": total_anomalies,
        "critical_anomalies": critical_anomalies,
        "high_anomalies": high_anomalies,
        "average_z_score": avg_z
    }
