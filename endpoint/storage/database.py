import json
import sqlite3
from contextlib import closing

from config import ENDPOINT_DATABASE_PATH

from endpoint.models.security_event import SecurityEvent
from endpoint.utils.logger import get_logger


logger = get_logger(__name__)


# ============================================================
# TABLE: EVENTS
# ============================================================

CREATE_EVENTS_TABLE = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    event_id TEXT UNIQUE NOT NULL,
    timestamp TEXT NOT NULL,
    device_id TEXT NOT NULL,

    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    source TEXT NOT NULL,

    process_data TEXT,
    file_data TEXT,
    network_data TEXT,
    registry_data TEXT,
    metadata TEXT,

    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)
"""


# ============================================================
# TABLE: DETECTIONS
# ============================================================

CREATE_DETECTIONS_TABLE = """
CREATE TABLE IF NOT EXISTS detections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    event_id TEXT,

    engine TEXT NOT NULL,

    detected INTEGER NOT NULL,

    threat_type TEXT,

    confidence REAL,

    risk_score REAL,

    severity TEXT,

    reason TEXT,

    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)
"""


# ============================================================
# TABLE: ACTIONS
# ============================================================

CREATE_ACTIONS_TABLE = """
CREATE TABLE IF NOT EXISTS actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    event_id TEXT,

    action_type TEXT NOT NULL,

    action_status TEXT NOT NULL,

    actor TEXT,

    details TEXT,

    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)
"""


# ============================================================
# TABLE: QUARANTINE
# ============================================================

CREATE_QUARANTINE_TABLE = """
CREATE TABLE IF NOT EXISTS quarantine (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    original_path TEXT NOT NULL,

    quarantine_path TEXT NOT NULL,

    sha256 TEXT,

    threat_type TEXT,

    risk_score REAL,

    status TEXT DEFAULT 'QUARANTINED',

    quarantined_at DATETIME DEFAULT CURRENT_TIMESTAMP
)
"""


# ============================================================
# TABLE: SETTINGS
# ============================================================

CREATE_SETTINGS_TABLE = """
CREATE TABLE IF NOT EXISTS settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    key TEXT UNIQUE NOT NULL,

    value TEXT,

    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
)
"""


# ============================================================
# DATABASE CONNECTION
# ============================================================

def get_connection():
    return sqlite3.connect(
        ENDPOINT_DATABASE_PATH
    )


# ============================================================
# INITIALIZE DATABASE
# ============================================================

def initialize_database():

    with closing(get_connection()) as connection:

        cursor = connection.cursor()

        cursor.execute(
            CREATE_EVENTS_TABLE
        )

        cursor.execute(
            CREATE_DETECTIONS_TABLE
        )

        cursor.execute(
            CREATE_ACTIONS_TABLE
        )

        cursor.execute(
            CREATE_QUARANTINE_TABLE
        )

        cursor.execute(
            CREATE_SETTINGS_TABLE
        )

        connection.commit()

    logger.info(
        "Endpoint database initialized at %s",
        ENDPOINT_DATABASE_PATH,
    )


# ============================================================
# SAVE SECURITY EVENT
# ============================================================

def save_event(
    event: SecurityEvent,
):

    data = event.to_dict()

    query = """
    INSERT INTO events (
        event_id,
        timestamp,
        device_id,
        event_type,
        severity,
        source,
        process_data,
        file_data,
        network_data,
        registry_data,
        metadata
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """

    values = (
        data["event_id"],
        data["timestamp"],
        data["device_id"],
        data["event_type"],
        data["severity"],
        data["source"],

        json.dumps(
            data["process"]
        )
        if data["process"]
        else None,

        json.dumps(
            data["file"]
        )
        if data["file"]
        else None,

        json.dumps(
            data["network"]
        )
        if data["network"]
        else None,

        json.dumps(
            data["registry"]
        )
        if data["registry"]
        else None,

        json.dumps(
            data["metadata"]
        ),
    )

    with closing(get_connection()) as connection:

        cursor = connection.cursor()

        cursor.execute(
            query,
            values,
        )

        connection.commit()

    logger.info(
        "Saved event: %s | %s",
        data["event_id"],
        data["event_type"],
    )


# ============================================================
# SAVE DETECTION
# ============================================================

def save_detection(
    event_id: str,
    detection: dict,
):

    query = """
    INSERT INTO detections (
        event_id,
        engine,
        detected,
        threat_type,
        confidence,
        risk_score,
        severity,
        reason
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """

    values = (
        event_id,

        detection.get(
            "engine"
        ),

        int(
            detection.get(
                "detected",
                False,
            )
        ),

        detection.get(
            "threat_type"
        ),

        detection.get(
            "confidence"
        ),

        detection.get(
            "risk_score"
        ),

        detection.get(
            "severity"
        ),

        json.dumps(
            detection.get(
                "reason",
                [],
            )
        ),
    )

    with closing(get_connection()) as connection:

        cursor = connection.cursor()

        cursor.execute(
            query,
            values,
        )

        connection.commit()

    logger.info(
        "Detection saved | Event=%s | Engine=%s | Risk=%s | Severity=%s",
        event_id,
        detection.get("engine"),
        detection.get("risk_score"),
        detection.get("severity"),
    )