"""
Browser Protection Router — /api/browser
Phase 3: Web threat protection, malicious download blocking, fake login detection, and URL safety verification.
"""
import datetime
import re
from urllib.parse import urlparse
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional, List

from app.database import get_db
from app.models import BrowserEvent, Device, ThreatEvent
from app.services.auth_service import get_current_user

router = APIRouter(prefix="/browser", tags=["Browser Protection"])

class CheckURLRequest(BaseModel):
    url: str

class BrowserEventReport(BaseModel):
    device_id: str
    event_type: str  # phishing, fake_login, malicious_download, suspicious_domain
    url: str
    domain: Optional[str] = None
    risk_score: int
    is_blocked: bool = False
    details: Optional[dict] = None

def analyze_url_safety(url: str):
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path
    if ":" in domain:
        domain = domain.split(":")[0]

    # Heuristics
    risk_score = 0
    reasons = []
    category = "clean"

    # 1. Suspicious keywords in the domain or path
    suspicious_keywords = {
        "phishing": ["login-secure", "verify-bank", "signin-session", "credential-update", "paypaI", "netflix-update", "securesignin", "accounts-verify"],
        "malware": ["get-rich", "free-bitcoin", "malicious-payload", "update-flash-player", "ransomware-decrypter", "crack-exe", "keygen-patch"],
        "suspicious_domain": ["attacker", "evil-site", "bypass-security", "hacker-space", "c2-server"]
    }

    lowercased_url = url.lower()
    for cat, keywords in suspicious_keywords.items():
        for kw in keywords:
            if kw in lowercased_url:
                risk_score += 60
                reasons.append(f"Contains suspicious keyword: '{kw}' ({cat})")
                if category == "clean" or category == "suspicious_domain":
                    category = cat

    # 2. IP address in the domain
    ip_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    if re.match(ip_pattern, domain):
        risk_score += 40
        reasons.append("Host uses raw IP address instead of a domain name")
        if category == "clean":
            category = "suspicious_domain"

    # 3. Port check
    if parsed.port and parsed.port not in [80, 443]:
        risk_score += 20
        reasons.append(f"Uses unusual non-standard web port: {parsed.port}")
        if category == "clean":
            category = "suspicious_domain"

    # 4. Too many hyphens in domain (typosquatting)
    if domain.count("-") >= 3:
        risk_score += 15
        reasons.append("Domain contains excessive hyphens (potential typosquatting)")
        if category == "clean":
            category = "suspicious_domain"

    # Cap risk score at 100
    risk_score = min(100, risk_score)

    if risk_score >= 50:
        is_blocked = True
        if category == "clean":
            category = "suspicious_domain"
    else:
        is_blocked = False

    return {
        "url": url,
        "domain": domain,
        "risk_score": risk_score,
        "is_blocked": is_blocked,
        "category": category,
        "reasons": reasons
    }

@router.post("/check-url")
def check_url_safety(req: CheckURLRequest, current_user = Depends(get_current_user)):
    """Analyze a URL manually and return a safety classification."""
    if not req.url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")
    return analyze_url_safety(req.url)

@router.post("/report-event")
def report_browser_event(event_in: BrowserEventReport, db: Session = Depends(get_db)):
    """Ingest a browser event reported by the Endpoint Agent."""
    # Find or register device
    device = db.query(Device).filter(Device.id == event_in.device_id).first()
    if not device:
        device = Device(
            id=event_in.device_id,
            hostname=event_in.device_id,
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

    # Domain extraction fallback
    domain = event_in.domain
    if not domain and event_in.url:
        try:
            parsed = urlparse(event_in.url)
            domain = parsed.netloc or parsed.path
            if ":" in domain:
                domain = domain.split(":")[0]
        except:
            domain = "unknown"

    db_event = BrowserEvent(
        device_id=event_in.device_id,
        event_type=event_in.event_type,
        url=event_in.url,
        domain=domain,
        risk_score=event_in.risk_score,
        is_blocked=event_in.is_blocked,
        details=event_in.details or {}
    )
    db.add(db_event)
    db.commit()
    db.refresh(db_event)

    # Correlate critical events
    if event_in.risk_score >= 50:
        # Deduct trust score
        deduction = min(25, int(event_in.risk_score / 4))
        device.trust_score = max(0, device.trust_score - deduction)
        db.commit()

        # Create ThreatEvent in Threat Center
        title = "Browser Protection: Malicious URL Blocked" if event_in.is_blocked else "Browser Protection: Malicious URL Accessed"
        severity = "medium"
        if event_in.risk_score >= 80:
            severity = "high"
        if event_in.risk_score >= 95:
            severity = "critical"

        threat = ThreatEvent(
            device_id=device.id,
            title=title,
            description=f"Device visited malicious/suspicious website: {event_in.url}. Category: {event_in.event_type}.",
            category="malware" if event_in.event_type == "malicious_download" else "network",
            severity=severity,
            status="resolved" if event_in.is_blocked else "active",
            confidence_score=event_in.risk_score,
            timestamp=datetime.datetime.utcnow()
        )
        db.add(threat)
        db.commit()
        db.refresh(threat)

        # Generate explanations & storylines
        try:
            from app.services.ai_service import generate_ai_explanation
            from app.services.correlation_engine import generate_attack_storyline
            generate_ai_explanation(db, threat)
            generate_attack_storyline(db, threat)
        except Exception as e:
            # Tolerant to failure in AI gen (mocking or database constraints)
            print(f"Error generating AI explanations: {e}")

    return {"status": "success", "event_id": db_event.id}

@router.get("/events")
def list_browser_events(
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """List all browser protection events, sorted by recent."""
    events = db.query(BrowserEvent).order_by(BrowserEvent.timestamp.desc()).limit(limit).all()
    return [
        {
            "id": e.id,
            "device_id": e.device_id,
            "event_type": e.event_type,
            "url": e.url,
            "domain": e.domain,
            "risk_score": e.risk_score,
            "is_blocked": e.is_blocked,
            "details": e.details,
            "timestamp": e.timestamp.isoformat() if e.timestamp else None
        }
        for e in events
    ]

@router.get("/stats")
def get_browser_stats(
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get summarized statistics for browser protection."""
    from sqlalchemy import func

    total = db.query(BrowserEvent).count()
    blocked = db.query(BrowserEvent).filter(BrowserEvent.is_blocked == True).count()
    
    phishing = db.query(BrowserEvent).filter(
        BrowserEvent.event_type.in_(["phishing", "fake_login"])
    ).count()
    
    downloads = db.query(BrowserEvent).filter(
        BrowserEvent.event_type == "malicious_download"
    ).count()
    
    suspicious_domains = db.query(BrowserEvent).filter(
        BrowserEvent.event_type == "suspicious_domain"
    ).count()

    avg_score = db.query(func.avg(BrowserEvent.risk_score)).scalar()
    avg_score = round(avg_score, 1) if avg_score is not None else 0.0

    return {
        "total_events": total,
        "blocked_count": blocked,
        "phishing_count": phishing,
        "malicious_download_count": downloads,
        "suspicious_domain_count": suspicious_domains,
        "average_risk_score": avg_score
    }
