"""
Agent Configuration
===================
Centralised settings for the SentinelCrypt EDR endpoint agent.
Override any value via environment variables (e.g. RDS_BACKEND_URL).
"""
import os
import socket
import uuid

# ── Backend connectivity ─────────────────────────────────────────────────────
BACKEND_URL: str = os.getenv("RDS_BACKEND_URL", "http://localhost:8000/api")

# ── Device identity ──────────────────────────────────────────────────────────
# Uses the machine hostname as the stable device ID.  Override with env var if needed.
DEVICE_ID: str = os.getenv("RDS_DEVICE_ID", socket.gethostname())
HOSTNAME: str = socket.gethostname()

# ── Heartbeat ────────────────────────────────────────────────────────────────
HEARTBEAT_INTERVAL_SEC: int = int(os.getenv("RDS_HEARTBEAT_SEC", "30"))

# ── Event batching ───────────────────────────────────────────────────────────
BATCH_SIZE: int = int(os.getenv("RDS_BATCH_SIZE", "20"))          # max events per POST
BATCH_INTERVAL_SEC: float = float(os.getenv("RDS_BATCH_SEC", "3")) # flush every N seconds

# ── Retry / offline buffer ───────────────────────────────────────────────────
MAX_RETRY_ATTEMPTS: int = int(os.getenv("RDS_MAX_RETRIES", "5"))
RETRY_BASE_DELAY_SEC: float = 1.0   # exponential backoff base
OFFLINE_BUFFER_PATH: str = os.path.join(
    os.path.dirname(__file__), "offline_buffer.jsonl"
)

# ── File monitoring ──────────────────────────────────────────────────────────
# Directories that the file-monitor watchdog will observe recursively.
MONITOR_PATHS: list = [
    os.path.expanduser("~/Documents"),
    os.path.expanduser("~/Desktop"),
    os.path.expanduser("~/Downloads"),
]

# Rapid-modification threshold for ransomware detection
RAPID_MOD_THRESHOLD: int = int(os.getenv("RDS_RAPID_MOD", "30"))   # files in window
RAPID_MOD_WINDOW_SEC: int = int(os.getenv("RDS_RAPID_WINDOW", "10")) # seconds

# Entropy threshold — above this value file writes look encrypted
ENTROPY_THRESHOLD: float = float(os.getenv("RDS_ENTROPY", "7.2"))

# ── Decoy / honeypot files ───────────────────────────────────────────────────
DECOY_DIR: str = os.path.expanduser("~/Documents")
DECOY_FILES: list = [
    "salary.xlsx",
    "employee_data.xlsx",
    "passwords.txt",
    "bank_details.docx",
    "api_keys.txt",
]

# ── Process monitoring ───────────────────────────────────────────────────────
PROCESS_POLL_INTERVAL_SEC: float = float(os.getenv("RDS_PROC_POLL", "2"))

# Suspicious process name patterns (case-insensitive substring match)
SUSPICIOUS_PROC_NAMES: list = [
    "mimikatz", "procdump", "wce.exe", "fgdump",
    "pwdump", "cachedump", "gsecdump",
]

# Suspicious command-line fragments
SUSPICIOUS_CMDLINE_FRAGMENTS: list = [
    "vssadmin delete shadows",
    "bcdedit /set recoveryenabled no",
    "wbadmin delete catalog",
    "lsass.dmp",
    "comsvcs.dll, MiniDump",
    "sekurlsa::logonpasswords",
    "-encodedcommand",       # base64 PowerShell
    "invoke-mimikatz",
    "invoke-webrequest",
]

# ── Network monitoring ───────────────────────────────────────────────────────
NETWORK_POLL_INTERVAL_SEC: float = float(os.getenv("RDS_NET_POLL", "5"))

# Known-bad / C2 ports to flag immediately
SUSPICIOUS_PORTS: set = {4444, 4445, 8080, 1337, 31337, 6666, 9001}

# ── Wi-Fi scanning ───────────────────────────────────────────────────────────
WIFI_SCAN_INTERVAL_SEC: int = int(os.getenv("RDS_WIFI_SEC", "60"))
