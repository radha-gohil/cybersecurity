from pathlib import Path


# ============================================================
# PROJECT PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

DATA_DIR = BASE_DIR / "data"
ENDPOINT_DATA_DIR = DATA_DIR / "endpoint"

DATABASE_DIR = DATA_DIR / "database"
LOG_DIR = DATA_DIR / "logs"
QUARANTINE_DIR = DATA_DIR / "quarantine"


# ============================================================
# DATABASE
# ============================================================

ENDPOINT_DATABASE_PATH = (
    DATABASE_DIR / "sentinel_endpoint.db"
)


# ============================================================
# LOGGING
# ============================================================

EVENT_LOG_PATH = (
    LOG_DIR / "sentinel_events.log"
)


# ============================================================
# DEVICE
# ============================================================

DEVICE_NAME = "local-device"


# ============================================================
# AUTONOMY
# ============================================================

# 0 = Monitor only
# 1 = Explain threats
# 2 = Recommend response
# 3 = Execute approved low-risk actions
# 4 = Automatic containment using policies

DEFAULT_AUTONOMY_LEVEL = 2


# ============================================================
# SEVERITY
# ============================================================

SUPPORTED_SEVERITIES = [
    "INFO",
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
]


# ============================================================
# THREAT TYPES
# ============================================================

SUPPORTED_THREAT_TYPES = [
    "BENIGN",
    "SUSPICIOUS",
    "MALWARE",
    "RANSOMWARE",
    "PHISHING",
    "NETWORK_ATTACK",
    "PERSISTENCE",
    "CREDENTIAL_ATTACK",
    "PRIVILEGE_ESCALATION",
    "COMMAND_AND_CONTROL",
    "DATA_EXFILTRATION",
    "UNKNOWN",
]


# ============================================================
# REQUIRED DIRECTORIES
# ============================================================

REQUIRED_DIRECTORIES = [
    DATA_DIR,
    ENDPOINT_DATA_DIR,
    DATABASE_DIR,
    LOG_DIR,
    QUARANTINE_DIR,
]

# ============================================================
# FILE MONITOR SETTINGS
# ============================================================

FILE_MONITOR_PATH = (
    Path.home()
    / "Downloads"
    / "sentinel_test"
)

FILE_MONITOR_PATH.mkdir(
    parents=True,
    exist_ok=True,
)

for directory in REQUIRED_DIRECTORIES:
    directory.mkdir(
        parents=True,
        exist_ok=True,
    )


DEBUG = True
