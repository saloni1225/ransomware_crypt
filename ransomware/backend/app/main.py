from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.database import engine, Base, SessionLocal
from app.routers import auth, devices, threats, reports, malware, network, wifi, firewall, deception, privacy, recovery, browser, behavior, capabilities
from app.config import settings

# Create database tables automatically (including new Phase 2 & 3 tables)
Base.metadata.create_all(bind=engine)


def ensure_default_admin():
    from app.models import User
    from app.services.auth_service import hash_password, generate_totp_secret

    db = SessionLocal()
    try:
        if not db.query(User).filter(User.email == "admin@defense.com").first():
            db.add(User(
                email="admin@defense.com",
                hashed_password=hash_password("password123"),
                role="admin",
                totp_secret=generate_totp_secret(),
                totp_enabled=False,
            ))
            db.commit()
    finally:
        db.close()


ensure_default_admin()

app = FastAPI(
    title="SentinelCrypt EDR API",
    description="Backend services for real-time endpoint threat monitoring, deception engines, and threat correlation.",
    version="2.0.0"
)

# Configure CORS for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins for dev ease
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register Rate Limiting Middleware
from app.middleware.rate_limiter import RateLimitingMiddleware
app.add_middleware(RateLimitingMiddleware)

# Phase 1 Routers
app.include_router(auth.router, prefix="/api")
app.include_router(devices.router, prefix="/api")
app.include_router(threats.router, prefix="/api")
app.include_router(reports.router, prefix="/api")

# Phase 2 Routers
app.include_router(malware.router, prefix="/api")
app.include_router(network.router, prefix="/api")
app.include_router(wifi.router, prefix="/api")
app.include_router(firewall.router, prefix="/api")

# Phase 3 Routers
app.include_router(deception.router, prefix="/api")
app.include_router(privacy.router, prefix="/api")
app.include_router(browser.router, prefix="/api")

# Phase 4 Router
app.include_router(behavior.router, prefix="/api")

# Recovery & Rollback
app.include_router(recovery.router, prefix="/api")

# Phase 3 (Real Adapters) — Capability discovery
app.include_router(capabilities.router, prefix="/api")

@app.get("/")
def read_root():
    return {
        "status": "online",
        "system": "SentinelCrypt EDR API",
        "version": "2.0.0",
        "phases": ["Phase 1: Core", "Phase 2: Network & Malware", "Phase 3: Deception & Privacy"],
        "documentation": "/docs"
    }
