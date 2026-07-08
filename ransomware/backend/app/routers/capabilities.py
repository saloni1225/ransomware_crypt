"""
Capabilities Router — /api/capabilities
=========================================
Returns the capability state for all agent modules on a given device.
The agent posts module snapshots to ThreatLog; this endpoint aggregates them.
"""
from __future__ import annotations

import datetime
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import Dict, Any, List, Optional

from app.database import get_db
from app.models import ThreatLog, Device
from app.services.auth_service import get_current_user

router = APIRouter(prefix="/capabilities", tags=["Capabilities"])

_ALL_MODULES = ["malware", "network", "firewall", "browser", "privacy", "wifi", "deception"]


@router.get("/{device_id}")
def get_device_capabilities(
    device_id: str,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user),
):
    """
    Return the latest capability snapshot for each module from a specific device.
    Falls back to 'unknown' if no telemetry has arrived yet.
    """
    capabilities: Dict[str, Any] = {}

    for module in _ALL_MODULES:
        # Get the most recent telemetry_snapshot for this device + module
        log = (
            db.query(ThreatLog)
            .filter(
                ThreatLog.device_id == device_id,
                ThreatLog.type == module,
                ThreatLog.action == "telemetry_snapshot",
            )
            .order_by(ThreatLog.timestamp.desc())
            .first()
        )

        if log and log.details:
            details = log.details
            capabilities[module] = {
                "module": module,
                "supported": details.get("supported", True),
                "health": details.get("health", "unknown"),
                "platform": details.get("platform", ""),
                "capability_state": (
                    details.get("capability_state") or
                    ("supported" if details.get("supported", True) else "unsupported_os")
                ),
                "last_seen": log.timestamp.isoformat() if log.timestamp else None,
                "message": details.get("message", ""),
            }
        else:
            capabilities[module] = {
                "module": module,
                "supported": None,
                "health": "unknown",
                "platform": "",
                "capability_state": "no_data",
                "last_seen": None,
                "message": "No telemetry received yet from agent",
            }

    return {
        "device_id": device_id,
        "capabilities": capabilities,
        "modules": _ALL_MODULES,
        "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
    }


@router.get("/")
def list_all_capabilities(
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user),
):
    """
    Return a summary of capability states across all known devices.
    """
    devices = db.query(Device).all()
    result = []
    for device in devices:
        device_caps = {"device_id": device.id, "hostname": device.hostname, "modules": {}}
        for module in _ALL_MODULES:
            log = (
                db.query(ThreatLog)
                .filter(
                    ThreatLog.device_id == device.id,
                    ThreatLog.type == module,
                    ThreatLog.action == "telemetry_snapshot",
                )
                .order_by(ThreatLog.timestamp.desc())
                .first()
            )
            if log and log.details:
                device_caps["modules"][module] = {
                    "health": log.details.get("health", "unknown"),
                    "supported": log.details.get("supported", True),
                }
            else:
                device_caps["modules"][module] = {"health": "unknown", "supported": None}
        result.append(device_caps)
    return result
