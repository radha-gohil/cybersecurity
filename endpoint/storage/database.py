import json
import sqlite3

from collections import Counter
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

    connection = sqlite3.connect(
        ENDPOINT_DATABASE_PATH
    )

    connection.row_factory = sqlite3.Row

    return connection


# ============================================================
# JSON HELPERS
# ============================================================

def safe_json_dumps(
    value,
):

    if value is None:
        return None

    try:

        return json.dumps(
            value
        )

    except (
        TypeError,
        ValueError,
    ):

        return json.dumps(
            str(value)
        )


def safe_json_loads(
    value,
    default=None,
):

    if value is None:
        return default

    if not isinstance(
        value,
        str,
    ):
        return value

    try:

        return json.loads(
            value
        )

    except (
        json.JSONDecodeError,
        TypeError,
    ):

        return value


# ============================================================
# EVENT CATEGORY
# ============================================================

def infer_event_category(
    event_type: str,
    metadata=None,
):

    metadata = (
        metadata
        if isinstance(
            metadata,
            dict,
        )
        else {}
    )


    category = metadata.get(
        "event_category"
    )


    if category:

        return str(
            category
        ).upper()


    value = str(
        event_type
        or ""
    ).lower()


    if value.startswith(
        "process"
    ):
        return "PROCESS"


    if value.startswith(
        "file"
    ):
        return "FILE"


    if value.startswith(
        "network"
    ):
        return "NETWORK"


    if value.startswith(
        "registry"
    ):
        return "REGISTRY"


    if value.startswith(
        "startup"
    ):
        return "STARTUP"


    if value.startswith(
        "security"
    ):
        return "SECURITY"


    if value.startswith(
        "response"
    ):
        return "RESPONSE"


    return "SYSTEM"


# ============================================================
# INITIALIZE DATABASE
# ============================================================

def initialize_database():

    with closing(
        get_connection()
    ) as connection:

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


        safe_json_dumps(
            data.get("process")
        )
        if data.get("process")
        else None,


        safe_json_dumps(
            data.get("file")
        )
        if data.get("file")
        else None,


        safe_json_dumps(
            data.get("network")
        )
        if data.get("network")
        else None,


        safe_json_dumps(
            data.get("registry")
        )
        if data.get("registry")
        else None,


        safe_json_dumps(
            data.get(
                "metadata",
                {},
            )
        ),
    )


    with closing(
        get_connection()
    ) as connection:

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
# NORMALIZE DETECTOR OUTPUT
# ============================================================

def normalize_detection(
    detection: dict,
):

    detection = (
        detection
        if isinstance(
            detection,
            dict,
        )
        else {}
    )


    # --------------------------------------------------------
    # ENGINE
    # --------------------------------------------------------

    engine = (

        detection.get(
            "engine"
        )

        or detection.get(
            "detector"
        )

        or detection.get(
            "detection_engine"
        )

        or "unknown"
    )


    # --------------------------------------------------------
    # DETECTION TYPE
    #
    # Different detector modules use slightly different names.
    # Normalize them before storing.
    # --------------------------------------------------------

    threat_type = (

        detection.get(
            "threat_type"
        )

        or detection.get(
            "detection_type"
        )

        or detection.get(
            "type"
        )

        or detection.get(
            "prediction"
        )

        or "UNKNOWN"
    )


    # --------------------------------------------------------
    # RISK
    # --------------------------------------------------------

    risk_score = detection.get(
        "risk_score"
    )


    if risk_score is None:

        risk_score = detection.get(
            "risk"
        )


    # --------------------------------------------------------
    # CONFIDENCE
    # --------------------------------------------------------

    confidence = detection.get(
        "confidence"
    )


    if confidence is None:

        confidence = detection.get(
            "ml_confidence"
        )


    # --------------------------------------------------------
    # DETECTED
    #
    # save_detection() is called after a detector generated a
    # detection. Older detector payloads often did not explicitly
    # contain detected=True.
    # --------------------------------------------------------

    if "detected" in detection:

        detected = bool(
            detection.get(
                "detected"
            )
        )

    else:

        detected = True


    # --------------------------------------------------------
    # REASON
    # --------------------------------------------------------

    reason = detection.get(
        "reason"
    )


    if reason is None:

        reason = detection.get(
            "reasons",
            [],
        )


    return {

        "engine":
            str(engine),

        "detected":
            detected,

        "threat_type":
            threat_type,

        "confidence":
            confidence,

        "risk_score":
            risk_score,

        "severity":
            detection.get(
                "severity",
                "INFO",
            ),

        "reason":
            reason,
    }


# ============================================================
# SAVE DETECTION
# ============================================================

def save_detection(
    event_id: str,
    detection: dict,
):

    normalized = (
        normalize_detection(
            detection
        )
    )


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

        normalized[
            "engine"
        ],

        int(
            normalized[
                "detected"
            ]
        ),

        normalized[
            "threat_type"
        ],

        normalized[
            "confidence"
        ],

        normalized[
            "risk_score"
        ],

        normalized[
            "severity"
        ],

        safe_json_dumps(
            normalized[
                "reason"
            ]
        ),
    )


    with closing(
        get_connection()
    ) as connection:

        cursor = connection.cursor()

        cursor.execute(
            query,
            values,
        )

        connection.commit()


    logger.info(
        "Detection saved | "
        "Event=%s | "
        "Engine=%s | "
        "Type=%s | "
        "Risk=%s | "
        "Severity=%s",

        event_id,

        normalized[
            "engine"
        ],

        normalized[
            "threat_type"
        ],

        normalized[
            "risk_score"
        ],

        normalized[
            "severity"
        ],
    )


# ============================================================
# EVENT COUNT
# ============================================================

def get_event_count():

    query = """
    SELECT COUNT(*) AS count
    FROM events
    """


    with closing(
        get_connection()
    ) as connection:

        row = connection.execute(
            query
        ).fetchone()


    return int(
        row["count"]
        if row
        else 0
    )


# ============================================================
# DETECTION COUNT
# ============================================================

def get_detection_count():

    query = """
    SELECT COUNT(*) AS count
    FROM detections
    """


    with closing(
        get_connection()
    ) as connection:

        row = connection.execute(
            query
        ).fetchone()


    return int(
        row["count"]
        if row
        else 0
    )


# ============================================================
# RECENT EVENTS
# ============================================================

def get_recent_events(
    limit: int = 100,
):

    limit = max(
        1,
        min(
            int(limit),
            1000,
        ),
    )


    query = """
    SELECT
        id,
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
        metadata,
        created_at

    FROM events

    ORDER BY id DESC

    LIMIT ?
    """


    with closing(
        get_connection()
    ) as connection:

        rows = connection.execute(
            query,
            (
                limit,
            ),
        ).fetchall()


    events = []


    for row in rows:

        metadata = safe_json_loads(
            row[
                "metadata"
            ],
            {},
        )


        if not isinstance(
            metadata,
            dict,
        ):

            metadata = {}


        event = {

            "database_id":
                row["id"],

            "event_id":
                row["event_id"],

            "timestamp":
                row["timestamp"],

            "device_id":
                row["device_id"],

            "event_type":
                row["event_type"],

            "event_category":
                infer_event_category(
                    row[
                        "event_type"
                    ],
                    metadata,
                ),

            "severity":
                row["severity"],

            "source":
                row["source"],

            "process":
                safe_json_loads(
                    row[
                        "process_data"
                    ],
                    {},
                ),

            "file":
                safe_json_loads(
                    row[
                        "file_data"
                    ],
                    {},
                ),

            "network":
                safe_json_loads(
                    row[
                        "network_data"
                    ],
                    {},
                ),

            "registry":
                safe_json_loads(
                    row[
                        "registry_data"
                    ],
                    {},
                ),

            "metadata":
                metadata,

            "created_at":
                row["created_at"],
        }


        events.append(
            event
        )


    return events


# ============================================================
# RECENT DETECTIONS
# ============================================================

def get_recent_detections(
    limit: int = 100,
):

    limit = max(
        1,
        min(
            int(limit),
            1000,
        ),
    )


    query = """
    SELECT

        d.id AS detection_id,
        d.event_id,
        d.engine,
        d.detected,
        d.threat_type,
        d.confidence,
        d.risk_score,
        d.severity,
        d.reason,
        d.created_at,

        e.timestamp AS event_timestamp,
        e.event_type AS event_type,
        e.source AS event_source,
        e.device_id AS device_id,

        e.process_data AS process_data,
        e.file_data AS file_data,
        e.network_data AS network_data,
        e.registry_data AS registry_data,
        e.metadata AS event_metadata

    FROM detections d

    LEFT JOIN events e
        ON e.event_id = d.event_id

    ORDER BY d.id DESC

    LIMIT ?
    """


    with closing(
        get_connection()
    ) as connection:

        rows = connection.execute(
            query,
            (
                limit,
            ),
        ).fetchall()


    detections = []


    for row in rows:

        event_metadata = safe_json_loads(
            row[
                "event_metadata"
            ],
            {},
        )


        if not isinstance(
            event_metadata,
            dict,
        ):

            event_metadata = {}


        threat_type = (
            row[
                "threat_type"
            ]
            or "UNKNOWN"
        )


        detection = {

            "detection_id":
                row[
                    "detection_id"
                ],

            "event_id":
                row[
                    "event_id"
                ],

            "engine":
                row[
                    "engine"
                ],

            "detected":
                bool(
                    row[
                        "detected"
                    ]
                ),

            "stored_detection_record":
                True,

            "threat_type":
                threat_type,

            "detection_type":
                threat_type,

            "confidence":
                row[
                    "confidence"
                ],

            "risk_score":
                row[
                    "risk_score"
                ],

            "severity":
                row[
                    "severity"
                ]
                or "INFO",

            "reason":
                safe_json_loads(
                    row[
                        "reason"
                    ],
                    [],
                ),

            "created_at":
                row[
                    "created_at"
                ],

            "event_timestamp":
                row[
                    "event_timestamp"
                ],

            "event_type":
                row[
                    "event_type"
                ],

            "event_source":
                row[
                    "event_source"
                ],

            "device_id":
                row[
                    "device_id"
                ],

            "event_category":
                infer_event_category(
                    row[
                        "event_type"
                    ],
                    event_metadata,
                ),

            "process":
                safe_json_loads(
                    row[
                        "process_data"
                    ],
                    {},
                ),

            "file":
                safe_json_loads(
                    row[
                        "file_data"
                    ],
                    {},
                ),

            "network":
                safe_json_loads(
                    row[
                        "network_data"
                    ],
                    {},
                ),

            "registry":
                safe_json_loads(
                    row[
                        "registry_data"
                    ],
                    {},
                ),

            "metadata":
                event_metadata,
        }


        detections.append(
            detection
        )


    return detections


# ============================================================
# EVENT SEVERITY COUNTS
# ============================================================

def get_event_severity_counts():

    query = """
    SELECT
        UPPER(
            COALESCE(
                severity,
                'UNKNOWN'
            )
        ) AS severity,

        COUNT(*) AS count

    FROM events

    GROUP BY
        UPPER(
            COALESCE(
                severity,
                'UNKNOWN'
            )
        )
    """


    result = {

        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
        "UNKNOWN": 0,
    }


    with closing(
        get_connection()
    ) as connection:

        rows = connection.execute(
            query
        ).fetchall()


    for row in rows:

        severity = (
            row[
                "severity"
            ]
            or "UNKNOWN"
        )


        result[
            severity
        ] = int(
            row[
                "count"
            ]
        )


    return result


# ============================================================
# DETECTION SEVERITY COUNTS
# ============================================================

def get_detection_severity_counts():

    query = """
    SELECT
        UPPER(
            COALESCE(
                severity,
                'UNKNOWN'
            )
        ) AS severity,

        COUNT(*) AS count

    FROM detections

    GROUP BY
        UPPER(
            COALESCE(
                severity,
                'UNKNOWN'
            )
        )
    """


    result = {

        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
        "UNKNOWN": 0,
    }


    with closing(
        get_connection()
    ) as connection:

        rows = connection.execute(
            query
        ).fetchall()


    for row in rows:

        severity = (
            row[
                "severity"
            ]
            or "UNKNOWN"
        )


        result[
            severity
        ] = int(
            row[
                "count"
            ]
        )


    return result


# ============================================================
# DETECTION ENGINE COUNTS
# ============================================================

def get_detection_engine_counts():

    query = """
    SELECT

        COALESCE(
            engine,
            'unknown'
        ) AS engine,

        COUNT(*) AS count

    FROM detections

    GROUP BY engine

    ORDER BY count DESC
    """


    result = {}


    with closing(
        get_connection()
    ) as connection:

        rows = connection.execute(
            query
        ).fetchall()


    for row in rows:

        result[
            row[
                "engine"
            ]
        ] = int(
            row[
                "count"
            ]
        )


    return result


# ============================================================
# DETECTION TYPE COUNTS
# ============================================================

def get_detection_type_counts():

    query = """
    SELECT

        COALESCE(
            threat_type,
            'UNKNOWN'
        ) AS threat_type,

        COUNT(*) AS count

    FROM detections

    GROUP BY threat_type

    ORDER BY count DESC
    """


    result = {}


    with closing(
        get_connection()
    ) as connection:

        rows = connection.execute(
            query
        ).fetchall()


    for row in rows:

        result[
            row[
                "threat_type"
            ]
        ] = int(
            row[
                "count"
            ]
        )


    return result


# ============================================================
# EVENT CATEGORY COUNTS
# ============================================================

def get_event_category_counts():

    query = """
    SELECT
        event_type,
        metadata
    FROM events
    """


    counts = Counter()


    with closing(
        get_connection()
    ) as connection:

        rows = connection.execute(
            query
        ).fetchall()


    for row in rows:

        metadata = safe_json_loads(
            row[
                "metadata"
            ],
            {},
        )


        if not isinstance(
            metadata,
            dict,
        ):

            metadata = {}


        category = infer_event_category(
            row[
                "event_type"
            ],
            metadata,
        )


        counts[
            category
        ] += 1


    return dict(
        counts
    )


# ============================================================
# COMPLETE ENDPOINT DATABASE SUMMARY
# ============================================================

def get_endpoint_database_summary(
    recent_limit: int = 50,
):

    recent_limit = max(
        1,
        min(
            int(
                recent_limit
            ),
            200,
        ),
    )


    return {

        "event_count":
            get_event_count(),

        "detection_count":
            get_detection_count(),

        "event_category_counts":
            get_event_category_counts(),

        "event_severity_counts":
            get_event_severity_counts(),

        "detection_severity_counts":
            get_detection_severity_counts(),

        "detection_engine_counts":
            get_detection_engine_counts(),

        "detection_type_counts":
            get_detection_type_counts(),

        "events":
            get_recent_events(
                limit=
                    recent_limit
            ),

        "detections":
            get_recent_detections(
                limit=
                    recent_limit
            ),
    }