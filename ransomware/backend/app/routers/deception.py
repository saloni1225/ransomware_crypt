"""
Deception Engine Router — /api/deception
Phase 3: Honeypot asset management and trigger analytics.
"""
import datetime
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional

from app.database import get_db
from app.models import DeceptionAsset, ThreatEvent
from app.services.auth_service import get_current_user
from app.services.ai_service import generate_ai_explanation
from app.services.correlation_engine import generate_attack_storyline

router = APIRouter(prefix="/deception", tags=["Deception"])

class DeceptionAssetCreate(BaseModel):
    asset_name: str
    asset_type: str = "file"  # file, credential, registry, network_share
    path: Optional[str] = None
    description: Optional[str] = None

class TriggerRequest(BaseModel):
    asset_id: int
    device_id: str
    triggered_by: Optional[str] = "unknown_process"

@router.get("/assets")
def list_assets(
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """List all deception assets with trigger history."""
    assets = db.query(DeceptionAsset).order_by(DeceptionAsset.created_at.desc()).all()
    return [
        {
            "id": a.id,
            "asset_name": a.asset_name,
            "asset_type": a.asset_type,
            "path": a.path,
            "description": a.description,
            "is_active": a.is_active,
            "is_triggered": a.is_triggered,
            "trigger_count": a.trigger_count,
            "last_triggered": a.last_triggered.isoformat() if a.last_triggered else None,
            "created_at": a.created_at.isoformat() if a.created_at else None,
        }
        for a in assets
    ]

@router.post("/assets")
def create_asset(
    asset_in: DeceptionAssetCreate,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Deploy a new deception / honeypot asset."""
    asset = DeceptionAsset(
        asset_name=asset_in.asset_name,
        asset_type=asset_in.asset_type,
        path=asset_in.path,
        description=asset_in.description,
        is_active=True,
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return {"id": asset.id, "asset_name": asset.asset_name, "status": "deployed"}

@router.put("/assets/{asset_id}/toggle")
def toggle_asset(
    asset_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Enable or disable a deception asset."""
    asset = db.query(DeceptionAsset).filter(DeceptionAsset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    asset.is_active = not asset.is_active
    db.commit()
    return {"id": asset_id, "is_active": asset.is_active}

@router.delete("/assets/{asset_id}")
def delete_asset(
    asset_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Remove a deception asset."""
    asset = db.query(DeceptionAsset).filter(DeceptionAsset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    db.delete(asset)
    db.commit()
    return {"id": asset_id, "status": "removed"}

@router.post("/trigger")
def trigger_asset(
    trigger: TriggerRequest,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Simulate a decoy asset being accessed.
    Creates a ThreatEvent and auto-generates AI explanation + storyline.
    """
    asset = db.query(DeceptionAsset).filter(DeceptionAsset.id == trigger.asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    # Update trigger state
    asset.is_triggered = True
    asset.trigger_count += 1
    asset.last_triggered = datetime.datetime.utcnow()
    db.commit()

    # Generate a threat event
    threat = ThreatEvent(
        device_id=trigger.device_id,
        title=f"Honeypot Triggered: {asset.asset_name}",
        description=f"Deception asset '{asset.asset_name}' ({asset.asset_type}) was accessed by process: {trigger.triggered_by}. Immediate investigation required.",
        category="deception",
        severity="high",
        confidence_score=99,
        timestamp=datetime.datetime.utcnow(),
    )
    db.add(threat)
    db.commit()
    db.refresh(threat)

    # Auto-generate AI explanation and storyline
    explanation = generate_ai_explanation(db, threat)
    generate_attack_storyline(db, threat)

    return {
        "asset_id": asset.id,
        "asset_name": asset.asset_name,
        "threat_event_id": threat.id,
        "trigger_count": asset.trigger_count,
        "ai_action": explanation.recommended_action,
    }

@router.get("/stats")
def deception_stats(
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Deception engine summary statistics."""
    total = db.query(DeceptionAsset).count()
    active = db.query(DeceptionAsset).filter(DeceptionAsset.is_active == True).count()
    triggered = db.query(DeceptionAsset).filter(DeceptionAsset.is_triggered == True).count()

    from sqlalchemy import func
    total_triggers = db.query(func.sum(DeceptionAsset.trigger_count)).scalar() or 0

    # Asset type breakdown
    types = {}
    for t in ["file", "credential", "registry", "network_share"]:
        types[t] = db.query(DeceptionAsset).filter(DeceptionAsset.asset_type == t).count()

    return {
        "total_assets": total,
        "active_assets": active,
        "triggered_assets": triggered,
        "total_trigger_events": total_triggers,
        "type_breakdown": types,
    }
