import datetime
from app.database import engine, SessionLocal, Base
from app.models import (
    User, Device, ThreatLog, ThreatEvent, AIExplanation, AttackStoryline,
    MalwareScan, NetworkConnection, WiFiNetwork, FirewallRule,
    DeceptionAsset, PrivacyEvent, BrowserEvent, BehaviorProfile, AnomalyEvent
)
from app.services.auth_service import hash_password
from app.services.ai_service import generate_ai_explanation
from app.services.correlation_engine import generate_attack_storyline

def seed_db():
    # Recreate tables
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    
    db = SessionLocal()
    
    try:
        print("Seeding database...")
        
        # 1. Create Default Admin User
        admin = User(
            email="admin@defense.com",
            hashed_password=hash_password("password123"),
            role="admin",
            totp_secret="JBSWY3DPEHPK3PXP",
            totp_enabled=False
        )
        db.add(admin)
        db.commit()
        print("Created default user: admin@defense.com / password123")
        
        # 2. Create Mock Devices
        dev1 = Device(
            id="win10-office-pc",
            hostname="win10-office-pc",
            ip_address="192.168.1.45",
            mac_address="00:1A:2B:3C:4D:5E",
            os_type="Windows",
            status="online",
            trust_score=75,
            firewall_status="enabled",
            last_seen=datetime.datetime.utcnow()
        )
        dev2 = Device(
            id="macbook-m2-dev",
            hostname="macbook-m2-dev",
            ip_address="192.168.1.112",
            mac_address="F0:18:98:C3:A2:10",
            os_type="macOS",
            status="online",
            trust_score=100,
            firewall_status="enabled",
            last_seen=datetime.datetime.utcnow()
        )
        dev3 = Device(
            id="linux-prod-db",
            hostname="linux-prod-db",
            ip_address="10.0.4.12",
            mac_address="52:54:00:12:34:56",
            os_type="Linux",
            status="offline",
            trust_score=85,
            firewall_status="disabled",
            last_seen=datetime.datetime.utcnow() - datetime.timedelta(hours=2)
        )
        
        db.add_all([dev1, dev2, dev3])
        db.commit()
        print("Created mock devices.")
        
        # 3. Create Threat logs
        log1 = ThreatLog(
            device_id="win10-office-pc",
            type="process",
            action="started",
            details={"name": "outlook.exe", "pid": 4200, "command": "outlook.exe"},
            timestamp=datetime.datetime.utcnow() - datetime.timedelta(minutes=10)
        )
        log2 = ThreatLog(
            device_id="win10-office-pc",
            type="file",
            action="modified",
            details={"path": "C:\\Users\\User\\Downloads\\invoice.pdf.exe", "size": 154000},
            timestamp=datetime.datetime.utcnow() - datetime.timedelta(minutes=8)
        )
        log3 = ThreatLog(
            device_id="win10-office-pc",
            type="file",
            action="modified",
            details={"modified_count": 42, "entropy": 7.8, "extension": ".locked"},
            timestamp=datetime.datetime.utcnow() - datetime.timedelta(minutes=5)
        )
        log4 = ThreatLog(
            device_id="macbook-m2-dev",
            type="file",
            action="accessed",
            details={"path": "/Users/dev/Documents/salary.xlsx", "process": "scanner.exe"},
            timestamp=datetime.datetime.utcnow() - datetime.timedelta(minutes=15)
        )
        log5 = ThreatLog(
            device_id="win10-office-pc",
            type="usb",
            action="mounted",
            details={"label": "RecoveryKey", "serial": "USB1238912", "authorized": False},
            timestamp=datetime.datetime.utcnow() - datetime.timedelta(minutes=2)
        )
        
        db.add_all([log1, log2, log3, log4, log5])
        db.commit()
        print("Created threat logs.")
        
        # 4. Create Threat Events
        # Ransomware Event
        event1 = ThreatEvent(
            device_id="win10-office-pc",
            title="Ransomware Behavior Detected",
            description="Rapid modification of 42 files. Detected high entropy write buffers.",
            category="ransomware",
            severity="critical",
            status="active",
            confidence_score=94,
            timestamp=datetime.datetime.utcnow() - datetime.timedelta(minutes=5)
        )
        
        # Deception Honey File Event
        event2 = ThreatEvent(
            device_id="macbook-m2-dev",
            title="Decoy Honey File Access",
            description="Decoy sensitive asset accessed: /Users/dev/Documents/salary.xlsx",
            category="deception",
            severity="high",
            status="quarantined",
            confidence_score=98,
            timestamp=datetime.datetime.utcnow() - datetime.timedelta(minutes=15)
        )
        
        # Unauthorized USB Event
        event3 = ThreatEvent(
            device_id="win10-office-pc",
            title="Unauthorized USB Connected",
            description="Blocked connection of unauthorized mass storage: RecoveryKey",
            category="usb",
            severity="medium",
            status="resolved",
            confidence_score=85,
            timestamp=datetime.datetime.utcnow() - datetime.timedelta(minutes=2)
        )
        
        db.add_all([event1, event2, event3])
        db.commit()
        print("Created threat events.")
        
        # 5. Generate AI Explanations and Attack Storylines
        for ev in [event1, event2, event3]:
            generate_ai_explanation(db, ev)
            generate_attack_storyline(db, ev)
            
        print("Generated AI Explanations & Attack Storylines successfully.")

        # 6. Seed Firewall Rules
        fw_rules = [
            FirewallRule(rule_name="Block Meterpreter (4444)", direction="inbound", action="block", protocol="TCP", port="4444", remote_ip="any", is_active=True, priority=10, hit_count=17),
            FirewallRule(rule_name="Block IRC Botnet (6667)", direction="both", action="block", protocol="TCP", port="6667", remote_ip="any", is_active=True, priority=11, hit_count=5),
            FirewallRule(rule_name="Block Tor (9001/9050)", direction="outbound", action="block", protocol="TCP", port="9001", remote_ip="any", is_active=True, priority=12, hit_count=3),
            FirewallRule(rule_name="Block SMB Lateral Movement", direction="inbound", action="block", protocol="TCP", port="445", remote_ip="any", is_active=True, priority=20, hit_count=42),
            FirewallRule(rule_name="Allow HTTPS Outbound", direction="outbound", action="allow", protocol="TCP", port="443", remote_ip="any", is_active=True, priority=50, hit_count=2048),
            FirewallRule(rule_name="Allow DNS", direction="outbound", action="allow", protocol="UDP", port="53", remote_ip="8.8.8.8", is_active=True, priority=51, hit_count=5820),
            FirewallRule(rule_name="Block RDP External", direction="inbound", action="block", protocol="TCP", port="3389", remote_ip="any", is_active=True, priority=15, hit_count=128),
            FirewallRule(rule_name="Block C2 Range 185.220.101.0/24", direction="both", action="block", protocol="Any", port="any", remote_ip="185.220.101.0/24", is_active=True, priority=5, hit_count=8),
            FirewallRule(rule_name="Allow HTTP (Legacy Apps)", direction="outbound", action="allow", protocol="TCP", port="80", remote_ip="any", is_active=False, priority=60, hit_count=0),
            FirewallRule(rule_name="Block Back Orifice (31337)", direction="inbound", action="block", protocol="TCP", port="31337", remote_ip="any", is_active=True, priority=8, hit_count=1),
        ]
        for rule in fw_rules:
            rule.last_triggered = datetime.datetime.utcnow() - datetime.timedelta(hours=rule.hit_count % 48) if rule.hit_count > 0 else None
        db.add_all(fw_rules)
        db.commit()
        print("Seeded firewall rules.")

        # 7. Seed Deception Assets
        decoys = [
            DeceptionAsset(asset_name="salary_Q4_2024.xlsx", asset_type="file", path="C:\\Users\\Admin\\Documents\\salary_Q4_2024.xlsx", description="Decoy salary spreadsheet", is_active=True, is_triggered=True, trigger_count=3, last_triggered=datetime.datetime.utcnow() - datetime.timedelta(hours=2)),
            DeceptionAsset(asset_name="employee_passwords.txt", asset_type="file", path="C:\\Users\\Admin\\Desktop\\employee_passwords.txt", description="Decoy credential file", is_active=True, is_triggered=False, trigger_count=0),
            DeceptionAsset(asset_name="backup_admin", asset_type="credential", path="Active Directory > backup_admin", description="Honeypot AD account", is_active=True, is_triggered=True, trigger_count=1, last_triggered=datetime.datetime.utcnow() - datetime.timedelta(days=1)),
            DeceptionAsset(asset_name="HKLM\\Software\\Vault\\MasterKey", asset_type="registry", path="HKLM\\Software\\Vault\\MasterKey", description="Fake registry credential store", is_active=True, is_triggered=False, trigger_count=0),
            DeceptionAsset(asset_name="\\\\FILESERVER\\HR_Private", asset_type="network_share", path="\\\\FILESERVER\\HR_Private", description="Decoy HR network share", is_active=True, is_triggered=False, trigger_count=0),
            DeceptionAsset(asset_name="aws_keys_backup.env", asset_type="file", path="C:\\Users\\Admin\\Documents\\aws_keys_backup.env", description="Fake AWS credential file", is_active=True, is_triggered=False, trigger_count=0),
        ]
        db.add_all(decoys)
        db.commit()
        print("Seeded deception assets.")

        # 8. Seed Privacy Events
        privacy_evs = [
            PrivacyEvent(device_id="win10-office-pc", event_type="exfiltration", data_category="credentials", severity="critical", is_blocked=True, details={"destination": "185.220.101.45", "bytes": 4096, "process": "powershell.exe"}, timestamp=datetime.datetime.utcnow() - datetime.timedelta(hours=1)),
            PrivacyEvent(device_id="macbook-m2-dev", event_type="data_access", data_category="PII", severity="high", is_blocked=False, details={"file": "customer_records.xlsx", "user": "dev_user"}, timestamp=datetime.datetime.utcnow() - datetime.timedelta(hours=3)),
            PrivacyEvent(device_id="win10-office-pc", event_type="policy_violation", data_category="financial", severity="medium", is_blocked=True, details={"policy": "No external USB export", "action": "blocked"}, timestamp=datetime.datetime.utcnow() - datetime.timedelta(hours=5)),
            PrivacyEvent(device_id="linux-prod-db", event_type="leak_attempt", data_category="health", severity="high", is_blocked=False, details={"table": "patient_records", "query_count": 15000}, timestamp=datetime.datetime.utcnow() - datetime.timedelta(days=1)),
            PrivacyEvent(device_id="win10-office-pc", event_type="data_access", data_category="intellectual_property", severity="medium", is_blocked=True, details={"file": "source_code_backup.zip", "action": "attempted_copy"}, timestamp=datetime.datetime.utcnow() - datetime.timedelta(days=2)),
            PrivacyEvent(device_id="macbook-m2-dev", event_type="exfiltration", data_category="credentials", severity="critical", is_blocked=False, details={"method": "email_attachment", "recipient": "external@suspicious.ru"}, timestamp=datetime.datetime.utcnow() - datetime.timedelta(hours=6)),
        ]
        db.add_all(privacy_evs)
        db.commit()
        print("Seeded privacy events.")

        # 8b. Seed Browser Events
        browser_evs = [
            BrowserEvent(device_id="win10-office-pc", event_type="phishing", url="http://login-secure-paypal.com/verify", domain="login-secure-paypal.com", risk_score=85, is_blocked=True, details={"user_agent": "Chrome", "ip": "185.220.101.45"}, timestamp=datetime.datetime.utcnow() - datetime.timedelta(hours=1)),
            BrowserEvent(device_id="win10-office-pc", event_type="malicious_download", url="https://crack-exe-site.org/patch.exe", domain="crack-exe-site.org", risk_score=95, is_blocked=True, details={"filename": "patch.exe", "size": 1048576}, timestamp=datetime.datetime.utcnow() - datetime.timedelta(hours=2)),
            BrowserEvent(device_id="macbook-m2-dev", event_type="fake_login", url="http://netflix-update-billing.secure-signin.info/login", domain="netflix-update-billing.secure-signin.info", risk_score=75, is_blocked=False, details={"method": "POST"}, timestamp=datetime.datetime.utcnow() - datetime.timedelta(hours=4)),
            BrowserEvent(device_id="linux-prod-db", event_type="suspicious_domain", url="http://198.54.117.88:8080/shell", domain="198.54.117.88", risk_score=90, is_blocked=True, details={"port": 8080}, timestamp=datetime.datetime.utcnow() - datetime.timedelta(days=1)),
        ]
        db.add_all(browser_evs)
        db.commit()
        print("Seeded browser events.")

        # 9. Seed Malware Scans
        mal_scans = [
            MalwareScan(device_id="win10-office-pc", file_path="C:\\Users\\Admin\\Downloads\\invoice_2024.pdf.exe", file_hash="44d88612fea8a8f36de82e1278abb02f", file_size=45230, status="infected", threat_name="EICAR-Test-File"),
            MalwareScan(device_id="win10-office-pc", file_path="C:\\Windows\\Temp\\updater.vbs", file_hash="eccbc87e4b5ce2fe28308fd9f2a7baf3", file_size=8192, status="infected", threat_name="Worm.Emotet.B"),
            MalwareScan(device_id="win10-office-pc", file_path="C:\\Program Files\\Office\\Word.exe", file_hash="abc123clean", file_size=14000000, status="clean", threat_name=None),
            MalwareScan(device_id="win10-office-pc", file_path="C:\\Windows\\System32\\svchost.exe", file_hash="def456clean", file_size=98304, status="clean", threat_name=None),
            MalwareScan(device_id="macbook-m2-dev", file_path="/Users/dev/Downloads/crack_v3.exe", file_hash="c4ca4238a0b923820dcc509a6f75849b", file_size=2456780, status="quarantined", threat_name="Backdoor.Cobalt.Strike"),
            MalwareScan(device_id="macbook-m2-dev", file_path="/Applications/Chrome.app", file_hash="aaa111clean", file_size=220000000, status="clean", threat_name=None),
            MalwareScan(device_id="linux-prod-db", file_path="/tmp/miner_worker", file_hash="6512bd43d9caa6e02c990b0a82652dca", file_size=789456, status="infected", threat_name="Miner.XMRig.Cryptojack"),
            MalwareScan(device_id="linux-prod-db", file_path="/usr/bin/bash", file_hash="bbb222clean", file_size=1232896, status="clean", threat_name=None),
            MalwareScan(device_id="win10-office-pc", file_path="C:\\Users\\Admin\\AppData\\Roaming\\startup.vbs", file_hash="ccc333susp", file_size=4096, status="suspicious", threat_name="Heuristic.HighEntropy.Script-based Dropper"),
        ]
        db.add_all(mal_scans)
        db.commit()
        print("Seeded malware scans.")

        # 10. Seed Network Connections
        net_conns = [
            NetworkConnection(device_id="win10-office-pc", remote_ip="185.220.101.45", remote_port=443, protocol="TCP", process_name="svchost.exe", bytes_sent=45230, bytes_recv=12800, status="c2", country="Germany"),
            NetworkConnection(device_id="win10-office-pc", remote_ip="8.8.8.8", remote_port=53, protocol="UDP", process_name="chrome.exe", bytes_sent=256, bytes_recv=512, status="normal", country="United States"),
            NetworkConnection(device_id="win10-office-pc", remote_ip="91.92.128.77", remote_port=4444, protocol="TCP", process_name="powershell.exe", bytes_sent=8920, bytes_recv=34500, status="suspicious", country="Ukraine"),
            NetworkConnection(device_id="macbook-m2-dev", remote_ip="142.250.185.78", remote_port=443, protocol="TCP", process_name="chrome", bytes_sent=15200, bytes_recv=98400, status="normal", country="United States"),
            NetworkConnection(device_id="macbook-m2-dev", remote_ip="45.33.32.156", remote_port=6667, protocol="TCP", process_name="backdoor.exe", bytes_sent=890, bytes_recv=4500, status="c2", country="Netherlands"),
            NetworkConnection(device_id="linux-prod-db", remote_ip="198.54.117.88", remote_port=9050, protocol="TCP", process_name="tor", bytes_sent=55000, bytes_recv=120000, status="suspicious", country="United States"),
            NetworkConnection(device_id="linux-prod-db", remote_ip="1.1.1.1", remote_port=53, protocol="UDP", process_name="systemd-resolved", bytes_sent=128, bytes_recv=256, status="normal", country="Australia"),
        ]
        db.add_all(net_conns)
        db.commit()
        print("Seeded network connections.")

        # 11. Seed Wi-Fi Networks
        wifi_nets = [
            WiFiNetwork(device_id="win10-office-pc", ssid="CorporateWifi", bssid="AA:BB:CC:DD:EE:04", signal_strength=-55, channel=11, security_type="WPA2-Enterprise", frequency=2.4, risk_level="low", is_connected=True, is_evil_twin=False),
            WiFiNetwork(device_id="win10-office-pc", ssid="FREE_WIFI_AIRPORT", bssid="AA:BB:CC:DD:EE:03", signal_strength=-70, channel=1, security_type="Open", frequency=2.4, risk_level="high", is_connected=False, is_evil_twin=False),
            WiFiNetwork(device_id="win10-office-pc", ssid="HomeNetwork_5G", bssid="FF:EE:DD:CC:BB:05", signal_strength=-58, channel=36, security_type="WPA2", frequency=5.0, risk_level="critical", is_connected=False, is_evil_twin=True),
            WiFiNetwork(device_id="macbook-m2-dev", ssid="HomeNetwork_5G", bssid="AA:BB:CC:DD:EE:01", signal_strength=-45, channel=36, security_type="WPA3", frequency=5.0, risk_level="low", is_connected=True, is_evil_twin=False),
            WiFiNetwork(device_id="macbook-m2-dev", ssid="D-Link_OLD", bssid="AA:BB:CC:DD:EE:08", signal_strength=-82, channel=11, security_type="WEP", frequency=2.4, risk_level="high", is_connected=False, is_evil_twin=False),
            WiFiNetwork(device_id="linux-prod-db", ssid="ServerRoom_5G", bssid="CC:DD:EE:FF:00:11", signal_strength=-35, channel=100, security_type="WPA3", frequency=5.0, risk_level="low", is_connected=True, is_evil_twin=False),
        ]
        db.add_all(wifi_nets)
        db.commit()
        print("Seeded Wi-Fi networks.")

        # 12. Seed Behavior Profiles
        profiles = [
            BehaviorProfile(device_id="win10-office-pc", metric_name="cpu_usage", baseline_mean=14.5, baseline_std=3.2, datapoint_count=45),
            BehaviorProfile(device_id="win10-office-pc", metric_name="network_sent_mb", baseline_mean=120.4, baseline_std=15.1, datapoint_count=32),
            BehaviorProfile(device_id="macbook-m2-dev", metric_name="process_count", baseline_mean=180.0, baseline_std=10.0, datapoint_count=60),
            BehaviorProfile(device_id="macbook-m2-dev", metric_name="login_hour", baseline_mean=9.2, baseline_std=0.8, datapoint_count=20),
            BehaviorProfile(device_id="linux-prod-db", metric_name="active_connections", baseline_mean=42.0, baseline_std=2.5, datapoint_count=100),
        ]
        db.add_all(profiles)
        db.commit()
        print("Seeded behavior profiles.")

        # 13. Seed Anomaly Events
        anomalies = [
            AnomalyEvent(device_id="win10-office-pc", metric_name="network_sent_mb", observed_value=450.2, expected_mean=120.4, z_score=21.84, severity="critical", is_false_positive=False, timestamp=datetime.datetime.utcnow() - datetime.timedelta(hours=2)),
            AnomalyEvent(device_id="macbook-m2-dev", metric_name="login_hour", observed_value=3.5, expected_mean=9.2, z_score=7.12, severity="high", is_false_positive=False, timestamp=datetime.datetime.utcnow() - datetime.timedelta(hours=5)),
            AnomalyEvent(device_id="linux-prod-db", metric_name="active_connections", observed_value=51.0, expected_mean=42.0, z_score=3.6, severity="medium", is_false_positive=False, timestamp=datetime.datetime.utcnow() - datetime.timedelta(days=1)),
        ]
        db.add_all(anomalies)
        db.commit()
        print("Seeded anomaly events.")

        print("\n[OK] Database seeding completed (Phase 1 + Phase 2 + Phase 3 + Phase 4).")
        
    except Exception as e:
        db.rollback()
        print(f"Error seeding database: {e}")
        raise e
    finally:
        db.close()

if __name__ == "__main__":
    seed_db()
