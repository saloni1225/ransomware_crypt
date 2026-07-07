"""
Firewall Module Router — /api/firewall
Phase 2: CRUD for firewall rules with toggle and stats.
"""
import datetime
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional

from app.database import get_db
from app.models import FirewallRule
from app.services.auth_service import get_current_user

router = APIRouter(prefix="/firewall", tags=["Firewall"])

class FirewallRuleCreate(BaseModel):
    rule_name: str
    direction: str = "inbound"  # inbound, outbound, both
    action: str = "block"       # allow, block
    protocol: str = "TCP"       # TCP, UDP, ICMP, Any
    port: Optional[str] = "any"
    remote_ip: Optional[str] = "any"
    device_id: Optional[str] = None
    priority: int = 100

@router.get("/rules")
def list_rules(
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """List all firewall rules ordered by priority."""
    rules = db.query(FirewallRule).order_by(FirewallRule.priority.asc()).all()
    return [
        {
            "id": r.id,
            "device_id": r.device_id,
            "rule_name": r.rule_name,
            "direction": r.direction,
            "action": r.action,
            "protocol": r.protocol,
            "port": r.port,
            "remote_ip": r.remote_ip,
            "is_active": r.is_active,
            "priority": r.priority,
            "hit_count": r.hit_count,
            "last_triggered": r.last_triggered.isoformat() if r.last_triggered else None,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rules
    ]

@router.post("/rules")
def create_rule(
    rule_in: FirewallRuleCreate,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Create a new firewall rule."""
    rule = FirewallRule(
        device_id=rule_in.device_id,
        rule_name=rule_in.rule_name,
        direction=rule_in.direction,
        action=rule_in.action,
        protocol=rule_in.protocol,
        port=rule_in.port,
        remote_ip=rule_in.remote_ip,
        priority=rule_in.priority,
        is_active=True,
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return {"id": rule.id, "rule_name": rule.rule_name, "status": "created"}

@router.put("/rules/{rule_id}/toggle")
def toggle_rule(
    rule_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Toggle a firewall rule on or off."""
    rule = db.query(FirewallRule).filter(FirewallRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    rule.is_active = not rule.is_active
    db.commit()
    return {"id": rule_id, "rule_name": rule.rule_name, "is_active": rule.is_active}

@router.put("/rules/{rule_id}")
def update_rule(
    rule_id: int,
    rule_in: FirewallRuleCreate,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Update an existing firewall rule."""
    rule = db.query(FirewallRule).filter(FirewallRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    rule.rule_name = rule_in.rule_name
    rule.direction = rule_in.direction
    rule.action = rule_in.action
    rule.protocol = rule_in.protocol
    rule.port = rule_in.port
    rule.remote_ip = rule_in.remote_ip
    rule.priority = rule_in.priority
    db.commit()
    return {"id": rule_id, "status": "updated"}

@router.delete("/rules/{rule_id}")
def delete_rule(
    rule_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Delete a firewall rule."""
    rule = db.query(FirewallRule).filter(FirewallRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    db.delete(rule)
    db.commit()
    return {"id": rule_id, "status": "deleted"}

@router.post("/rules/{rule_id}/trigger")
def simulate_trigger(
    rule_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Simulate a firewall rule being triggered (increment hit counter)."""
    rule = db.query(FirewallRule).filter(FirewallRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    rule.hit_count += 1
    rule.last_triggered = datetime.datetime.utcnow()
    db.commit()
    return {"id": rule_id, "hit_count": rule.hit_count}

@router.get("/stats")
def firewall_stats(
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Firewall rule statistics."""
    total = db.query(FirewallRule).count()
    active = db.query(FirewallRule).filter(FirewallRule.is_active == True).count()
    inactive = db.query(FirewallRule).filter(FirewallRule.is_active == False).count()
    block_rules = db.query(FirewallRule).filter(FirewallRule.action == "block").count()
    allow_rules = db.query(FirewallRule).filter(FirewallRule.action == "allow").count()
    inbound = db.query(FirewallRule).filter(FirewallRule.direction == "inbound").count()
    outbound = db.query(FirewallRule).filter(FirewallRule.direction == "outbound").count()

    from sqlalchemy import func
    total_hits = db.query(func.sum(FirewallRule.hit_count)).scalar() or 0

    return {
        "total": total,
        "active": active,
        "inactive": inactive,
        "block_rules": block_rules,
        "allow_rules": allow_rules,
        "inbound": inbound,
        "outbound": outbound,
        "total_hits": total_hits,
    }
