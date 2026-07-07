"""
Network Monitor Router — /api/network
Phase 2: Live connection ingestion and threat analysis.
"""
import random
import datetime
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import List

from app.database import get_db
from app.models import NetworkConnection, Device
from app.services.auth_service import get_current_user
from app.services.network_service import ingest_connections, get_network_stats, classify_connection

router = APIRouter(prefix="/network", tags=["Network"])

# Simulation data for auto-generating network connections
SIMULATION_CONNECTIONS = [
    {"remote_ip": "8.8.8.8", "remote_port": 53, "protocol": "UDP", "process_name": "chrome.exe", "bytes_sent": 256, "bytes_recv": 512},
    {"remote_ip": "185.220.101.45", "remote_port": 443, "protocol": "TCP", "process_name": "svchost.exe", "bytes_sent": 45230, "bytes_recv": 12800},
    {"remote_ip": "142.250.185.78", "remote_port": 443, "protocol": "TCP", "process_name": "chrome.exe", "bytes_sent": 15200, "bytes_recv": 98400},
    {"remote_ip": "91.92.128.77", "remote_port": 4444, "protocol": "TCP", "process_name": "powershell.exe", "bytes_sent": 8920, "bytes_recv": 34500},
    {"remote_ip": "1.1.1.1", "remote_port": 53, "protocol": "UDP", "process_name": "system", "bytes_sent": 128, "bytes_recv": 256},
    {"remote_ip": "193.32.162.100", "remote_port": 8080, "protocol": "TCP", "process_name": "invoice_dropper.exe", "bytes_sent": 2048, "bytes_recv": 81920},
    {"remote_ip": "13.107.42.14", "remote_port": 443, "protocol": "TCP", "process_name": "teams.exe", "bytes_sent": 420000, "bytes_recv": 1200000},
    {"remote_ip": "198.54.117.88", "remote_port": 9050, "protocol": "TCP", "process_name": "tor.exe", "bytes_sent": 55000, "bytes_recv": 120000},
    {"remote_ip": "172.217.14.196", "remote_port": 443, "protocol": "TCP", "process_name": "chrome.exe", "bytes_sent": 5120, "bytes_recv": 204800},
    {"remote_ip": "45.33.32.156", "remote_port": 6667, "protocol": "TCP", "process_name": "backdoor.exe", "bytes_sent": 890, "bytes_recv": 4500},
]

@router.post("/connections")
def ingest_connection_snapshot(
    device_id: str,
    db: Session = Depends(get_db)
):
    """Ingest a batch network connection snapshot from an endpoint agent."""
    # Auto-register device if not known
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        device = Device(id=device_id, hostname=device_id, status="online", last_seen=datetime.datetime.utcnow())
        db.add(device)
        db.commit()

    # Select random subset for simulation
    num = random.randint(5, 10)
    connections = random.sample(SIMULATION_CONNECTIONS, min(num, len(SIMULATION_CONNECTIONS)))
    results = ingest_connections(db, device_id, connections)
    return {"device_id": device_id, "connections_ingested": len(results), "threats_detected": sum(1 for r in results if r["status"] in ["suspicious", "c2"])}

@router.get("/connections")
def list_connections(
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """List recent network connections ordered by timestamp desc."""
    conns = db.query(NetworkConnection).order_by(NetworkConnection.timestamp.desc()).limit(limit).all()
    return [
        {
            "id": c.id,
            "device_id": c.device_id,
            "remote_ip": c.remote_ip,
            "remote_port": c.remote_port,
            "local_port": c.local_port,
            "protocol": c.protocol,
            "process_name": c.process_name,
            "bytes_sent": c.bytes_sent,
            "bytes_recv": c.bytes_recv,
            "status": c.status,
            "country": c.country,
            "timestamp": c.timestamp.isoformat() if c.timestamp else None,
        }
        for c in conns
    ]

@router.get("/connections/{device_id}")
def list_device_connections(
    device_id: str,
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """List connections for a specific device."""
    conns = db.query(NetworkConnection).filter(
        NetworkConnection.device_id == device_id
    ).order_by(NetworkConnection.timestamp.desc()).limit(limit).all()
    return [
        {
            "id": c.id,
            "remote_ip": c.remote_ip,
            "remote_port": c.remote_port,
            "protocol": c.protocol,
            "process_name": c.process_name,
            "bytes_sent": c.bytes_sent,
            "bytes_recv": c.bytes_recv,
            "status": c.status,
            "country": c.country,
            "timestamp": c.timestamp.isoformat() if c.timestamp else None,
        }
        for c in conns
    ]

@router.post("/simulate")
def simulate_connections(
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Generate a fresh batch of simulated connections for all known devices."""
    devices = db.query(Device).all()
    total = 0
    for device in devices:
        num = random.randint(3, 7)
        conns = random.sample(SIMULATION_CONNECTIONS, min(num, len(SIMULATION_CONNECTIONS)))
        ingest_connections(db, device.id, conns)
        total += num
    return {"simulated_connections": total, "devices_updated": len(devices)}

@router.get("/stats")
def network_stats(
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Aggregate network monitoring statistics."""
    return get_network_stats(db)
