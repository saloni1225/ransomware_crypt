"""
Behavior Baseline Engine Service — Phase 4
Implements incremental baseline tracking and Z-score deviation anomaly detection.
"""
import datetime
import math
from sqlalchemy.orm import Session
from typing import Optional

from app.models import BehaviorProfile, AnomalyEvent, Device, ThreatEvent

MIN_DATAPOINTS_FOR_ANOMALY = 5
DEFAULT_STD_DEV = 1.0
MIN_STD_DEV = 0.1

def update_baseline(db: Session, device_id: str, metric_name: str, value: float) -> BehaviorProfile:
    """
    Updates the running baseline mean and standard deviation for a device metric.
    Uses an exponential moving average (EMA) approach to allow baselines to evolve.
    """
    profile = db.query(BehaviorProfile).filter(
        BehaviorProfile.device_id == device_id,
        BehaviorProfile.metric_name == metric_name
    ).first()

    if not profile:
        profile = BehaviorProfile(
            device_id=device_id,
            metric_name=metric_name,
            baseline_mean=value,
            baseline_std=DEFAULT_STD_DEV,
            datapoint_count=1,
            last_updated=datetime.datetime.utcnow()
        )
        db.add(profile)
        db.commit()
        db.refresh(profile)
        return profile

    # Update logic using adaptive alpha
    count = profile.datapoint_count
    mean_old = profile.baseline_mean
    std_old = profile.baseline_std

    # Alpha decreases as we gather more data, smoothing the baseline, but caps at 0.05
    alpha = max(0.05, 2.0 / (count + 1.0))

    mean_new = (1 - alpha) * mean_old + alpha * value
    
    # Running standard deviation approximation (mean absolute deviation scaled)
    delta = abs(value - mean_old)
    std_new = (1 - alpha) * std_old + alpha * delta
    std_new = max(MIN_STD_DEV, std_new)

    profile.baseline_mean = mean_new
    profile.baseline_std = std_new
    profile.datapoint_count = count + 1
    profile.last_updated = datetime.datetime.utcnow()

    db.commit()
    db.refresh(profile)
    return profile

def check_anomaly(db: Session, device_id: str, metric_name: str, value: float) -> Optional[AnomalyEvent]:
    """
    Checks if a given value is anomalous compared to the baseline using Z-score.
    If Z-score >= 3.0, records an AnomalyEvent.
    If Z-score >= 4.5, escalates to a ThreatEvent and drops device trust score.
    """
    profile = db.query(BehaviorProfile).filter(
        BehaviorProfile.device_id == device_id,
        BehaviorProfile.metric_name == metric_name
    ).first()

    # Do not detect anomalies until we establish a minimum baseline threshold
    if not profile or profile.datapoint_count < MIN_DATAPOINTS_FOR_ANOMALY:
        return None

    mean = profile.baseline_mean
    std = profile.baseline_std

    # Calculate absolute Z-score
    z_score = abs(value - mean) / std

    if z_score < 3.0:
        return None

    # Determine severity
    if z_score >= 6.0:
        severity = "critical"
    elif z_score >= 4.5:
        severity = "high"
    else:
        severity = "medium"

    anomaly = AnomalyEvent(
        device_id=device_id,
        metric_name=metric_name,
        observed_value=value,
        expected_mean=mean,
        z_score=round(z_score, 2),
        severity=severity,
        is_false_positive=False,
        timestamp=datetime.datetime.utcnow()
    )
    db.add(anomaly)
    db.commit()
    db.refresh(anomaly)

    # Escalation to ThreatEvent for serious deviations (Z-score >= 4.5)
    if z_score >= 4.5:
        device = db.query(Device).filter(Device.id == device_id).first()
        if device:
            # Deduct trust score
            deduction = min(20, int(z_score * 3))
            device.trust_score = max(0, device.trust_score - deduction)
            db.commit()

        # Route Category based on metric type
        category = "identity"
        if "network" in metric_name or "connection" in metric_name:
            category = "network"
        elif "file" in metric_name or "entropy" in metric_name or "process" in metric_name:
            category = "ransomware"

        threat = ThreatEvent(
            device_id=device_id,
            title=f"Behavior Baseline Alert: {metric_name.replace('_', ' ').title()}",
            description=(
                f"Suspicious behavioral deviation detected. Observed value '{value}' for metric '{metric_name}' "
                f"deviates from the expected baseline mean of {mean:.2f} (Z-score: {z_score:.2f})."
            ),
            category=category,
            severity=severity,
            status="active",
            confidence_score=min(100, int(z_score * 15)),
            timestamp=datetime.datetime.utcnow()
        )
        db.add(threat)
        db.commit()
        db.refresh(threat)

        # Trigger AI analysis & storyline correlation
        try:
            from app.services.ai_service import generate_ai_explanation
            from app.services.correlation_engine import generate_attack_storyline
            generate_ai_explanation(db, threat)
            generate_attack_storyline(db, threat)
        except Exception as e:
            print(f"Error executing correlation engines for behavioral alert: {e}")

    return anomaly
