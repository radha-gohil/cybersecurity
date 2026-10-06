import os
from pathlib import Path


# ============================================================
# PROJECT PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

DATA_DIR = BASE_DIR / "data"

ENDPOINT_DATA_DIR = (
    DATA_DIR / "endpoint"
)

DATABASE_DIR = (
    DATA_DIR / "database"
)

LOG_DIR = (
    DATA_DIR / "logs"
)

QUARANTINE_DIR = (
    DATA_DIR / "quarantine"
)


# ============================================================
# SENTINEL-X RUNTIME MODE
#
# VALIDATION
#     Real telemetry is used only for Live Monitor.
#     Persisted SOC workflow uses synthetic validation data.
#
# LIVE
#     Normal production-style SENTINEL-X operation.
# ============================================================

SUPPORTED_RUNTIME_MODES = {
    "VALIDATION",
    "LIVE",
}


SENTINEL_RUNTIME_MODE = (
    os.getenv(
        "SENTINEL_RUNTIME_MODE",
        "VALIDATION",
    )
    .strip()
    .upper()
)


if (
    SENTINEL_RUNTIME_MODE
    not in SUPPORTED_RUNTIME_MODES
):

    raise RuntimeError(
        "Invalid SENTINEL_RUNTIME_MODE: "
        f"{SENTINEL_RUNTIME_MODE}. "
        "Expected VALIDATION or LIVE."
    )


IS_VALIDATION_MODE = (
    SENTINEL_RUNTIME_MODE
    == "VALIDATION"
)


IS_LIVE_MODE = (
    SENTINEL_RUNTIME_MODE
    == "LIVE"
)


# ============================================================
# DATABASES
# ============================================================

# Existing real / historical endpoint database.
LIVE_ENDPOINT_DATABASE_PATH = (
    DATABASE_DIR
    / "sentinel_endpoint.db"
)


# Controlled synthetic validation database.
VALIDATION_DATABASE_PATH = (
    DATABASE_DIR
    / "sentinel_validation.db"
)


# ============================================================
# ACTIVE SOC DATABASE
#
# During VALIDATION:
#
#       synthetic telemetry
#       detections
#       incidents
#       SOC cases
#       tickets
#       actions
#       evidence
#
# all go here:
#
#       sentinel_validation.db
#
# During LIVE:
#
#       sentinel_endpoint.db
# ============================================================

ACTIVE_SOC_DATABASE_PATH = (

    VALIDATION_DATABASE_PATH

    if IS_VALIDATION_MODE

    else LIVE_ENDPOINT_DATABASE_PATH
)


# ============================================================
# BACKWARD COMPATIBILITY
#
# Existing modules currently import ENDPOINT_DATABASE_PATH.
# Keep that name while routing it to the correct database.
# ============================================================

ENDPOINT_DATABASE_PATH = (
    ACTIVE_SOC_DATABASE_PATH
)


# ============================================================
# DATA SOURCE LABELS
# ============================================================

DATA_SOURCE_LIVE = (
    "LIVE_ENDPOINT"
)

DATA_SOURCE_VALIDATION = (
    "SYNTHETIC_VALIDATION"
)


# ============================================================
# LOGGING
# ============================================================

EVENT_LOG_PATH = (
    LOG_DIR
    / "sentinel_events.log"
)


# ============================================================
# DEVICE
# ============================================================

DEVICE_NAME = (
    "local-device"
)


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