import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, JSON, Float, BigInteger
from sqlalchemy.orm import relationship
from app.database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="admin")
    is_active = Column(Boolean, default=True)
    totp_secret = Column(String, nullable=True)
    totp_enabled = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

class Device(Base):
    __tablename__ = "devices"

    id = Column(String, primary_key=True, index=True) # Usually hostname or mac_address
    hostname = Column(String, nullable=False)
    ip_address = Column(String, nullable=True)
    mac_address = Column(String, nullable=True)
    os_type = Column(String, nullable=True) # Windows, Linux, macOS
    status = Column(String, default="online") # online, offline
    trust_score = Column(Integer, default=100)
    firewall_status = Column(String, default="enabled") # enabled, disabled, unknown
    patch_status = Column(String, default="up_to_date") # up_to_date, needs_reboot, critical_missing
    last_seen = Column(DateTime, default=datetime.datetime.utcnow)

    logs = relationship("ThreatLog", back_populates="device", cascade="all, delete-orphan")
    threat_events = relationship("ThreatEvent", back_populates="device", cascade="all, delete-orphan")

class ThreatLog(Base):
    __tablename__ = "threat_logs"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(String, ForeignKey("devices.id"), nullable=False)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    type = Column(String, nullable=False) # file, process, usb, network
    action = Column(String, nullable=False) # e.g. modified, started, mounted, blocked
    details = Column(JSON, nullable=True) # Store specific activity details

    device = relationship("Device", back_populates="logs")

class ThreatEvent(Base):
    __tablename__ = "threat_events"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(String, ForeignKey("devices.id"), nullable=False)
    title = Column(String, nullable=False)
    description = Column(String, nullable=True)
    category = Column(String, nullable=False) # ransomware, malware, usb, deception, identity
    text_content = Column(String, nullable=True) # Backwards compatibility/detail
    severity = Column(String, nullable=False) # low, medium, high, critical
    status = Column(String, default="active") # active, quarantined, ignored, resolved
    confidence_score = Column(Integer, default=50)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)

    device = relationship("Device", back_populates="threat_events")
    explanations = relationship("AIExplanation", back_populates="threat_event", cascade="all, delete-orphan")
    storylines = relationship("AttackStoryline", back_populates="threat_event", cascade="all, delete-orphan")

class AIExplanation(Base):
    __tablename__ = "ai_explanations"

    id = Column(Integer, primary_key=True, index=True)
    threat_event_id = Column(Integer, ForeignKey("threat_events.id"), nullable=False)
    reasons = Column(JSON, nullable=False) # JSON array of strings
    confidence = Column(Integer, nullable=False)
    recommended_action = Column(String, nullable=False)

    threat_event = relationship("ThreatEvent", back_populates="explanations")

class AttackStoryline(Base):
    __tablename__ = "attack_storylines"

    id = Column(Integer, primary_key=True, index=True)
    threat_event_id = Column(Integer, ForeignKey("threat_events.id"), nullable=False)
    storyline_data = Column(JSON, nullable=False) # JSON structured representation of process/attack chain

    threat_event = relationship("ThreatEvent", back_populates="storylines")

# ─── Phase 2 Models ─────────────────────────────────────────────────────────

class MalwareScan(Base):
    __tablename__ = "malware_scans"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(String, ForeignKey("devices.id"), nullable=False)
    file_path = Column(String, nullable=False)
    file_hash = Column(String, nullable=True)
    file_size = Column(BigInteger, nullable=True)
    status = Column(String, default="clean")  # clean, infected, quarantined, suspicious
    threat_name = Column(String, nullable=True)
    scan_engine = Column(String, default="SentinelCrypt Scan Engine v2.1")
    scan_time = Column(DateTime, default=datetime.datetime.utcnow)

    device = relationship("Device", foreign_keys=[device_id])

class NetworkConnection(Base):
    __tablename__ = "network_connections"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(String, ForeignKey("devices.id"), nullable=False)
    remote_ip = Column(String, nullable=False)
    remote_port = Column(Integer, nullable=True)
    local_port = Column(Integer, nullable=True)
    protocol = Column(String, default="TCP")  # TCP, UDP, ICMP
    process_name = Column(String, nullable=True)
    bytes_sent = Column(BigInteger, default=0)
    bytes_recv = Column(BigInteger, default=0)
    status = Column(String, default="normal")  # normal, suspicious, blocked, c2
    country = Column(String, nullable=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)

    device = relationship("Device", foreign_keys=[device_id])

class WiFiNetwork(Base):
    __tablename__ = "wifi_networks"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(String, ForeignKey("devices.id"), nullable=False)
    ssid = Column(String, nullable=False)
    bssid = Column(String, nullable=True)
    signal_strength = Column(Integer, default=-70)  # dBm
    channel = Column(Integer, nullable=True)
    security_type = Column(String, default="WPA2")  # Open, WEP, WPA, WPA2, WPA3
    frequency = Column(Float, nullable=True)  # GHz
    risk_level = Column(String, default="low")  # low, medium, high, critical
    is_connected = Column(Boolean, default=False)
    is_evil_twin = Column(Boolean, default=False)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)

    device = relationship("Device", foreign_keys=[device_id])

class FirewallRule(Base):
    __tablename__ = "firewall_rules"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(String, nullable=True)  # null = global rule
    rule_name = Column(String, nullable=False)
    direction = Column(String, default="inbound")  # inbound, outbound, both
    action = Column(String, default="block")  # allow, block
    protocol = Column(String, default="TCP")  # TCP, UDP, ICMP, Any
    port = Column(String, nullable=True)  # e.g. "80", "443", "1-1024", "any"
    remote_ip = Column(String, nullable=True)  # IP or CIDR or "any"
    is_active = Column(Boolean, default=True)
    priority = Column(Integer, default=100)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    last_triggered = Column(DateTime, nullable=True)
    hit_count = Column(Integer, default=0)

# ─── Phase 3 Models ─────────────────────────────────────────────────────────

class DeceptionAsset(Base):
    __tablename__ = "deception_assets"

    id = Column(Integer, primary_key=True, index=True)
    asset_name = Column(String, nullable=False)
    asset_type = Column(String, default="file")  # file, credential, registry, network_share
    path = Column(String, nullable=True)
    description = Column(String, nullable=True)
    is_active = Column(Boolean, default=True)
    is_triggered = Column(Boolean, default=False)
    trigger_count = Column(Integer, default=0)
    last_triggered = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

class PrivacyEvent(Base):
    __tablename__ = "privacy_events"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(String, ForeignKey("devices.id"), nullable=True)
    event_type = Column(String, nullable=False)  # exfiltration, data_access, policy_violation, leak_attempt
    data_category = Column(String, nullable=False)  # PII, credentials, financial, health, intellectual_property
    severity = Column(String, default="medium")  # low, medium, high, critical
    details = Column(JSON, nullable=True)
    is_blocked = Column(Boolean, default=False)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)

    device = relationship("Device", foreign_keys=[device_id])

class BrowserEvent(Base):
    __tablename__ = "browser_events"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(String, ForeignKey("devices.id"), nullable=False)
    event_type = Column(String, nullable=False)  # phishing, fake_login, malicious_download, suspicious_domain
    url = Column(String, nullable=False)
    domain = Column(String, nullable=True)
    risk_score = Column(Integer, default=0)
    is_blocked = Column(Boolean, default=False)
    details = Column(JSON, nullable=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)

    device = relationship("Device", foreign_keys=[device_id])

class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    report_type = Column(String, nullable=False) # e.g. weekly, incident, threat
    generated_by = Column(String, nullable=True) # User email or "system"
    file_path = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_email = Column(String, nullable=True)
    action = Column(String, nullable=False) # e.g. login, export_report, delete_device
    details = Column(String, nullable=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)

class Notification(Base):
    __tablename__ = "notifications"

    id = Column(Integer, primary_key=True, index=True)
    user_email = Column(String, nullable=True)
    title = Column(String, nullable=False)
    message = Column(String, nullable=True)
    is_read = Column(Boolean, default=False)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)

class TrustScoreHistory(Base):
    __tablename__ = "trust_score_history"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(String, ForeignKey("devices.id"), nullable=False)
    score = Column(Integer, nullable=False)
    factors = Column(JSON, nullable=True) # E.g. what caused the score to change
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)

    device = relationship("Device", foreign_keys=[device_id])


# ─── Recovery & Rollback Models ──────────────────────────────────────────────

class RecoveryAction(Base):
    __tablename__ = "recovery_actions"

    id = Column(Integer, primary_key=True, index=True)
    # Optional link to the malware scan whose quarantined file is being restored
    scan_id = Column(Integer, ForeignKey("malware_scans.id"), nullable=True)
    # Optional link to the threat event that triggered the action
    threat_event_id = Column(Integer, ForeignKey("threat_events.id"), nullable=True)
    device_id = Column(String, ForeignKey("devices.id"), nullable=True)
    # 'restore', 'rollback', 'quarantine_confirm', 'delete_permanent'
    action_type = Column(String, nullable=False, default="restore")
    # The full path of the file involved
    file_path = Column(String, nullable=True)
    # Who performed the action (user email or "system")
    performed_by = Column(String, nullable=True)
    # 'success', 'failed', 'pending', 'reversed'
    status = Column(String, default="pending")
    notes = Column(String, nullable=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)

    scan = relationship("MalwareScan", foreign_keys=[scan_id])
    threat_event = relationship("ThreatEvent", foreign_keys=[threat_event_id])
    device = relationship("Device", foreign_keys=[device_id])

# ─── Behavior Baseline Engine Models ──────────────────────────────────────────

class BehaviorProfile(Base):
    __tablename__ = "behavior_profiles"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(String, ForeignKey("devices.id"), nullable=False)
    metric_name = Column(String, nullable=False) # e.g. login_hour, process_count, network_volume_mb
    baseline_mean = Column(Float, default=0.0)
    baseline_std = Column(Float, default=1.0)
    datapoint_count = Column(Integer, default=0)
    last_updated = Column(DateTime, default=datetime.datetime.utcnow)

    device = relationship("Device", foreign_keys=[device_id])

class AnomalyEvent(Base):
    __tablename__ = "anomaly_events"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(String, ForeignKey("devices.id"), nullable=False)
    metric_name = Column(String, nullable=False)
    observed_value = Column(Float, nullable=False)
    expected_mean = Column(Float, nullable=False)
    z_score = Column(Float, nullable=False)
    severity = Column(String, default="low") # low, medium, high, critical
    is_false_positive = Column(Boolean, default=False)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)

    device = relationship("Device", foreign_keys=[device_id])

class LoginRiskEvent(Base):
    __tablename__ = "login_risk_events"

    id = Column(Integer, primary_key=True, index=True)
    user_email = Column(String, nullable=False)
    ip_address = Column(String, nullable=False)
    risk_score = Column(Integer, default=0)
    risk_factors = Column(JSON, nullable=True) # JSON list of strings e.g. ["unusual_ip", "unusual_time"]
    status = Column(String, default="allowed") # allowed, flagged, blocked
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)


class AgentCommand(Base):
    __tablename__ = "agent_commands"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(String, ForeignKey("devices.id"), nullable=False)
    command_type = Column(String, nullable=False)  # 'terminate_process', 'quarantine_file', 'restore_file', 'acknowledge_alert', 'sync_policy'
    payload = Column(JSON, nullable=True)
    status = Column(String, default="queued")  # 'queued', 'sent', 'running', 'success', 'failed'
    execution_result = Column(JSON, nullable=True)
    error_message = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    device = relationship("Device", foreign_keys=[device_id])
