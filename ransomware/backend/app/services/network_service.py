"""
Network Monitor Service — Real-time connection analysis with C2 IP blocklist.
"""
import random
import ipaddress
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from app.models import NetworkConnection

# Known malicious IP ranges (C2 servers, botnets)
MALICIOUS_IPS = {
    "185.220.101.0/24": "Tor Exit Node",
    "193.32.162.0/24": "Botnet C2 — Emotet",
    "91.92.128.0/24": "Ransomware C2 — REvil",
    "45.33.32.0/24": "Cobalt Strike Beacon",
    "176.97.72.0/24": "Dark Web Exit Node",
    "5.188.206.0/24": "DDoS Botnet Reflector",
    "194.165.16.0/24": "Phishing Infrastructure",
    "198.54.117.0/24": "Cryptominer Pool",
}

MALICIOUS_IP_LIST = [
    "185.220.101.45", "193.32.162.100", "91.92.128.77",
    "45.33.32.156", "176.97.72.8", "5.188.206.34",
    "194.165.16.201", "198.54.117.88", "10.0.0.254",
]

# Port risk scoring
PORT_RISK = {
    80: ("HTTP", "low"), 443: ("HTTPS", "low"), 53: ("DNS", "low"),
    22: ("SSH", "medium"), 3389: ("RDP", "high"), 445: ("SMB", "high"),
    139: ("NetBIOS", "high"), 4444: ("Meterpreter", "critical"),
    8080: ("HTTP-Alt", "medium"), 1433: ("MSSQL", "medium"),
    3306: ("MySQL", "medium"), 6667: ("IRC Botnet", "critical"),
    9001: ("Tor", "high"), 9050: ("Tor SOCKS", "high"),
    31337: ("Back Orifice", "critical"),
}

# Country geo-simulation
COUNTRY_MAP = {
    "1.": "China", "5.": "Russia", "45.": "Netherlands", "91.": "Ukraine",
    "176.": "Russia", "185.": "Germany", "193.": "Russia", "194.": "Lithuania",
    "198.": "United States", "8.8": "United States", "1.1": "Australia",
}

def classify_connection(remote_ip: str, remote_port: int) -> tuple[str, str]:
    """Returns (status, country) for a given connection."""
    # Check against known malicious IPs
    if remote_ip in MALICIOUS_IP_LIST:
        return "c2", "Unknown"

    try:
        ip = ipaddress.ip_address(remote_ip)
        for cidr, _ in MALICIOUS_IPS.items():
            if ip in ipaddress.ip_network(cidr, strict=False):
                return "c2", "Unknown"
    except ValueError:
        pass

    # Check port risk
    port_info = PORT_RISK.get(remote_port, ("Unknown", "low"))
    if port_info[1] == "critical":
        return "suspicious", _guess_country(remote_ip)
    if port_info[1] == "high":
        return "suspicious", _guess_country(remote_ip)

    return "normal", _guess_country(remote_ip)

def _guess_country(ip: str) -> str:
    for prefix, country in COUNTRY_MAP.items():
        if ip.startswith(prefix):
            return country
    return "United States"

def ingest_connections(db: Session, device_id: str, connections: list[dict]) -> list[dict]:
    """Persist a batch of network connections from an agent snapshot."""
    results = []
    for conn in connections:
        remote_ip = conn.get("remote_ip", "0.0.0.0")
        remote_port = conn.get("remote_port", 0)
        status, country = classify_connection(remote_ip, remote_port)

        db_conn = NetworkConnection(
            device_id=device_id,
            remote_ip=remote_ip,
            remote_port=remote_port,
            local_port=conn.get("local_port", random.randint(49152, 65535)),
            protocol=conn.get("protocol", "TCP"),
            process_name=conn.get("process_name", "unknown"),
            bytes_sent=conn.get("bytes_sent", random.randint(0, 500000)),
            bytes_recv=conn.get("bytes_recv", random.randint(0, 5000000)),
            status=status,
            country=country,
        )
        db.add(db_conn)
        results.append({
            "remote_ip": remote_ip, "remote_port": remote_port,
            "status": status, "country": country,
            "process_name": conn.get("process_name", "unknown"),
        })

    db.commit()
    return results

def get_network_stats(db: Session) -> dict:
    """Return aggregate stats for network connections dashboard."""
    total = db.query(NetworkConnection).count()
    suspicious = db.query(NetworkConnection).filter(NetworkConnection.status == "suspicious").count()
    c2 = db.query(NetworkConnection).filter(NetworkConnection.status == "c2").count()
    blocked = db.query(NetworkConnection).filter(NetworkConnection.status == "blocked").count()
    normal = db.query(NetworkConnection).filter(NetworkConnection.status == "normal").count()

    # Aggregate bytes
    from sqlalchemy import func
    row = db.query(
        func.sum(NetworkConnection.bytes_sent),
        func.sum(NetworkConnection.bytes_recv)
    ).first()
    total_sent = row[0] or 0
    total_recv = row[1] or 0

    return {
        "total_connections": total,
        "normal": normal,
        "suspicious": suspicious,
        "c2_detected": c2,
        "blocked": blocked,
        "total_bytes_sent": total_sent,
        "total_bytes_recv": total_recv,
        "threat_connections": suspicious + c2,
    }
