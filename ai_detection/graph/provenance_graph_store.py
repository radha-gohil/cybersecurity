from __future__ import annotations

import json
import sqlite3
import hashlib

from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


# ================================================================
# PROJECT PATH
# ================================================================

PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[2]
)


DEFAULT_DATABASE_PATH = (
    PROJECT_ROOT
    / "data"
    / "database"
    / "sentinel_endpoint.db"
)


# ================================================================
# PROVENANCE GRAPH STORE
#
# Persistent SQLite storage for:
#
#   Events
#   Process nodes
#   File nodes
#   Network endpoint nodes
#   Registry nodes
#
# and relationships such as:
#
#   OBSERVED_PROCESS
#   SPAWNED
#   OBSERVED_FILE
#   TOUCHED_FILE
#   OBSERVED_NETWORK
#   CONNECTED_TO
#   OBSERVED_REGISTRY
#   MODIFIED_REGISTRY
#
# ================================================================


class ProvenanceGraphStore:

    def __init__(
        self,
        database_path=None,
    ):

        if database_path is None:

            database_path = (
                DEFAULT_DATABASE_PATH
            )


        self.database_path = Path(
            database_path
        )


        self.database_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )


        self.initialize_tables()


    # ============================================================
    # CURRENT UTC TIME
    # ============================================================

    def now_iso(
        self,
    ) -> str:

        return (
            datetime.now(
                timezone.utc
            ).isoformat()
        )


    # ============================================================
    # CONNECTION
    #
    # IMPORTANT:
    #
    # Do not store a long-lived SQLite connection on self.
    #
    # Every database operation opens and closes its own connection.
    #
    # This is especially important on Windows because an open
    # connection prevents TemporaryDirectory from deleting the DB.
    # ============================================================

    def get_connection(
        self,
    ) -> sqlite3.Connection:

        connection = sqlite3.connect(
            str(
                self.database_path
            ),
            timeout=15,
        )


        connection.row_factory = (
            sqlite3.Row
        )


        connection.execute(
            "PRAGMA foreign_keys = ON"
        )


        connection.execute(
            "PRAGMA busy_timeout = 15000"
        )


        return connection


    # ============================================================
    # JSON SERIALIZATION
    # ============================================================

    def serialize(
        self,
        value,
    ) -> str:

        return json.dumps(
            value,
            ensure_ascii=False,
            default=str,
            sort_keys=True,
        )


    # ============================================================
    # JSON DESERIALIZATION
    # ============================================================

    def deserialize(
        self,
        value,
        default,
    ):

        if value in {
            None,
            "",
        }:

            return default


        try:

            return json.loads(
                value
            )


        except (
            json.JSONDecodeError,
            TypeError,
            ValueError,
        ):

            return default


    # ============================================================
    # INITIALIZE TABLES
    # ============================================================

    def initialize_tables(
        self,
    ) -> None:

        with closing(
            self.get_connection()
        ) as connection:

            cursor = (
                connection.cursor()
            )


            # ====================================================
            # EVENT TRACKING
            # ====================================================

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS provenance_events (

                    event_id TEXT PRIMARY KEY,

                    event_type TEXT,

                    event_category TEXT,

                    source TEXT,

                    severity TEXT,

                    device_id TEXT,

                    timestamp TEXT,

                    created_at TEXT NOT NULL
                )
                """
            )


            # ====================================================
            # NODES
            # ====================================================

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS provenance_nodes (

                    node_id TEXT PRIMARY KEY,

                    node_type TEXT NOT NULL,

                    label TEXT,

                    properties TEXT,

                    first_seen TEXT NOT NULL,

                    last_seen TEXT NOT NULL
                )
                """
            )


            # ====================================================
            # EDGES
            # ====================================================

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS provenance_edges (

                    edge_id TEXT PRIMARY KEY,

                    source_node_id TEXT NOT NULL,

                    target_node_id TEXT NOT NULL,

                    edge_type TEXT NOT NULL,

                    event_id TEXT,

                    properties TEXT,

                    created_at TEXT NOT NULL,

                    FOREIGN KEY (
                        source_node_id
                    )
                    REFERENCES provenance_nodes (
                        node_id
                    ),

                    FOREIGN KEY (
                        target_node_id
                    )
                    REFERENCES provenance_nodes (
                        node_id
                    )
                )
                """
            )


            # ====================================================
            # INDEXES
            # ====================================================

            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_provenance_nodes_type
                ON provenance_nodes (
                    node_type
                )
                """
            )


            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_provenance_edges_source
                ON provenance_edges (
                    source_node_id
                )
                """
            )


            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_provenance_edges_target
                ON provenance_edges (
                    target_node_id
                )
                """
            )


            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_provenance_edges_type
                ON provenance_edges (
                    edge_type
                )
                """
            )


            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_provenance_edges_event
                ON provenance_edges (
                    event_id
                )
                """
            )


            connection.commit()


    # ============================================================
    # EVENT EXISTS
    # ============================================================

    def event_exists(
        self,
        event_id: str,
    ) -> bool:

        with closing(
            self.get_connection()
        ) as connection:

            row = connection.execute(
                """
                SELECT 1
                FROM provenance_events
                WHERE event_id = ?
                LIMIT 1
                """,
                (
                    str(
                        event_id
                    ),
                ),
            ).fetchone()


        return (
            row is not None
        )


    # ============================================================
    # SAVE EVENT
    # ============================================================

    def save_event(
        self,
        event: Dict[str, Any],
    ) -> None:

        event_id = str(
            event.get(
                "event_id"
            )
            or ""
        ).strip()


        if not event_id:

            raise ValueError(
                "Provenance event requires event_id."
            )


        metadata = (
            event.get(
                "metadata"
            )

            if isinstance(
                event.get(
                    "metadata"
                ),
                dict,
            )

            else {}
        )


        event_category = (
            event.get(
                "event_category"
            )
            or
            metadata.get(
                "event_category"
            )
        )


        device_id = (
            event.get(
                "device_id"
            )
            or
            metadata.get(
                "device_id"
            )
        )


        timestamp = (
            event.get(
                "timestamp"
            )
            or
            metadata.get(
                "timestamp"
            )
            or
            self.now_iso()
        )


        created_at = (
            self.now_iso()
        )


        with closing(
            self.get_connection()
        ) as connection:

            connection.execute(
                """
                INSERT INTO provenance_events (

                    event_id,
                    event_type,
                    event_category,
                    source,
                    severity,
                    device_id,
                    timestamp,
                    created_at

                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)

                ON CONFLICT(event_id)
                DO UPDATE SET

                    event_type =
                        excluded.event_type,

                    event_category =
                        excluded.event_category,

                    source =
                        excluded.source,

                    severity =
                        excluded.severity,

                    device_id =
                        excluded.device_id,

                    timestamp =
                        excluded.timestamp
                """,
                (
                    event_id,

                    event.get(
                        "event_type"
                    ),

                    event_category,

                    event.get(
                        "source"
                    ),

                    event.get(
                        "severity"
                    ),

                    device_id,

                    timestamp,

                    created_at,
                ),
            )


            connection.commit()


    # ============================================================
    # UPSERT NODE
    # ============================================================

    def upsert_node(
        self,
        *,
        node_id: str,
        node_type: str,
        label: Optional[str] = None,
        properties: Optional[
            Dict[str, Any]
        ] = None,
    ) -> None:

        timestamp = (
            self.now_iso()
        )


        properties = (
            properties
            if isinstance(
                properties,
                dict,
            )
            else {}
        )


        with closing(
            self.get_connection()
        ) as connection:

            existing = (
                connection.execute(
                    """
                    SELECT properties
                    FROM provenance_nodes
                    WHERE node_id = ?
                    """,
                    (
                        node_id,
                    ),
                )
                .fetchone()
            )


            existing_properties = {}


            if existing is not None:

                existing_properties = (
                    self.deserialize(
                        existing[
                            "properties"
                        ],
                        {},
                    )
                )


            merged_properties = dict(
                existing_properties
            )


            merged_properties.update(
                properties
            )


            connection.execute(
                """
                INSERT INTO provenance_nodes (

                    node_id,
                    node_type,
                    label,
                    properties,
                    first_seen,
                    last_seen

                )
                VALUES (?, ?, ?, ?, ?, ?)

                ON CONFLICT(node_id)
                DO UPDATE SET

                    node_type =
                        excluded.node_type,

                    label =
                        COALESCE(
                            excluded.label,
                            provenance_nodes.label
                        ),

                    properties =
                        excluded.properties,

                    last_seen =
                        excluded.last_seen
                """,
                (
                    node_id,

                    node_type,

                    label,

                    self.serialize(
                        merged_properties
                    ),

                    timestamp,

                    timestamp,
                ),
            )


            connection.commit()


    # ============================================================
    # EDGE ID
    # ============================================================

    def build_edge_id(
        self,
        *,
        source_node_id: str,
        target_node_id: str,
        edge_type: str,
        event_id: Optional[str],
    ) -> str:

        raw = (
            f"{source_node_id}|"
            f"{target_node_id}|"
            f"{edge_type}|"
            f"{event_id or ''}"
        )


        digest = (
            hashlib.sha256(
                raw.encode(
                    "utf-8",
                    errors="ignore",
                )
            )
            .hexdigest()
            [:24]
        )


        return (
            f"EDGE:{digest}"
        )


    # ============================================================
    # SAVE EDGE
    # ============================================================

    def save_edge(
        self,
        *,
        source_node_id: str,
        target_node_id: str,
        edge_type: str,
        event_id: Optional[str] = None,
        properties: Optional[
            Dict[str, Any]
        ] = None,
    ) -> str:

        edge_id = (
            self.build_edge_id(

                source_node_id=
                    source_node_id,

                target_node_id=
                    target_node_id,

                edge_type=
                    edge_type,

                event_id=
                    event_id,
            )
        )


        properties = (
            properties
            if isinstance(
                properties,
                dict,
            )
            else {}
        )


        with closing(
            self.get_connection()
        ) as connection:

            connection.execute(
                """
                INSERT INTO provenance_edges (

                    edge_id,
                    source_node_id,
                    target_node_id,
                    edge_type,
                    event_id,
                    properties,
                    created_at

                )
                VALUES (?, ?, ?, ?, ?, ?, ?)

                ON CONFLICT(edge_id)
                DO UPDATE SET

                    properties =
                        excluded.properties
                """,
                (
                    edge_id,

                    source_node_id,

                    target_node_id,

                    edge_type,

                    event_id,

                    self.serialize(
                        properties
                    ),

                    self.now_iso(),
                ),
            )


            connection.commit()


        return edge_id


    # ============================================================
    # GET NODE
    # ============================================================

    def get_node(
        self,
        node_id: str,
    ) -> Optional[
        Dict[str, Any]
    ]:

        with closing(
            self.get_connection()
        ) as connection:

            row = (
                connection.execute(
                    """
                    SELECT *
                    FROM provenance_nodes
                    WHERE node_id = ?
                    """,
                    (
                        node_id,
                    ),
                )
                .fetchone()
            )


        if row is None:

            return None


        return {
            "node_id":
                row[
                    "node_id"
                ],

            "node_type":
                row[
                    "node_type"
                ],

            "label":
                row[
                    "label"
                ],

            "properties":
                self.deserialize(
                    row[
                        "properties"
                    ],
                    {},
                ),

            "first_seen":
                row[
                    "first_seen"
                ],

            "last_seen":
                row[
                    "last_seen"
                ],
        }


    # ============================================================
    # GET ALL NODES
    # ============================================================

    def get_nodes(
        self,
        limit: int = 1000,
    ) -> List[
        Dict[str, Any]
    ]:

        with closing(
            self.get_connection()
        ) as connection:

            rows = (
                connection.execute(
                    """
                    SELECT *
                    FROM provenance_nodes
                    ORDER BY last_seen DESC
                    LIMIT ?
                    """,
                    (
                        int(
                            limit
                        ),
                    ),
                )
                .fetchall()
            )


        return [

            {
                "node_id":
                    row[
                        "node_id"
                    ],

                "node_type":
                    row[
                        "node_type"
                    ],

                "label":
                    row[
                        "label"
                    ],

                "properties":
                    self.deserialize(
                        row[
                            "properties"
                        ],
                        {},
                    ),

                "first_seen":
                    row[
                        "first_seen"
                    ],

                "last_seen":
                    row[
                        "last_seen"
                    ],
            }

            for row in rows
        ]


    # ============================================================
    # GET EDGES
    # ============================================================

    def get_edges(
        self,
        limit: int = 2000,
    ) -> List[
        Dict[str, Any]
    ]:

        with closing(
            self.get_connection()
        ) as connection:

            rows = (
                connection.execute(
                    """
                    SELECT *
                    FROM provenance_edges
                    ORDER BY created_at DESC
                    LIMIT ?
                    """,
                    (
                        int(
                            limit
                        ),
                    ),
                )
                .fetchall()
            )


        return [

            {
                "edge_id":
                    row[
                        "edge_id"
                    ],

                "source_node_id":
                    row[
                        "source_node_id"
                    ],

                "target_node_id":
                    row[
                        "target_node_id"
                    ],

                "edge_type":
                    row[
                        "edge_type"
                    ],

                "event_id":
                    row[
                        "event_id"
                    ],

                "properties":
                    self.deserialize(
                        row[
                            "properties"
                        ],
                        {},
                    ),

                "created_at":
                    row[
                        "created_at"
                    ],
            }

            for row in rows
        ]


    # ============================================================
    # COUNT EVENTS
    # ============================================================

    def count_events(
        self,
    ) -> int:

        with closing(
            self.get_connection()
        ) as connection:

            row = (
                connection.execute(
                    """
                    SELECT COUNT(*) AS total
                    FROM provenance_events
                    """
                )
                .fetchone()
            )


        return int(
            row[
                "total"
            ]
        )


    # ============================================================
    # COUNT NODES
    # ============================================================

    def count_nodes(
        self,
    ) -> int:

        with closing(
            self.get_connection()
        ) as connection:

            row = (
                connection.execute(
                    """
                    SELECT COUNT(*) AS total
                    FROM provenance_nodes
                    """
                )
                .fetchone()
            )


        return int(
            row[
                "total"
            ]
        )


    # ============================================================
    # COUNT EDGES
    # ============================================================

    def count_edges(
        self,
    ) -> int:

        with closing(
            self.get_connection()
        ) as connection:

            row = (
                connection.execute(
                    """
                    SELECT COUNT(*) AS total
                    FROM provenance_edges
                    """
                )
                .fetchone()
            )


        return int(
            row[
                "total"
            ]
        )


    # ============================================================
    # NODE TYPE COUNTS
    # ============================================================

    def get_node_type_counts(
        self,
    ) -> Dict[str, int]:

        with closing(
            self.get_connection()
        ) as connection:

            rows = (
                connection.execute(
                    """
                    SELECT
                        node_type,
                        COUNT(*) AS total
                    FROM provenance_nodes
                    GROUP BY node_type
                    ORDER BY node_type
                    """
                )
                .fetchall()
            )


        return {

            row[
                "node_type"
            ]:
                int(
                    row[
                        "total"
                    ]
                )

            for row in rows
        }


    # ============================================================
    # EDGE TYPE COUNTS
    # ============================================================

    def get_edge_type_counts(
        self,
    ) -> Dict[str, int]:

        with closing(
            self.get_connection()
        ) as connection:

            rows = (
                connection.execute(
                    """
                    SELECT
                        edge_type,
                        COUNT(*) AS total
                    FROM provenance_edges
                    GROUP BY edge_type
                    ORDER BY edge_type
                    """
                )
                .fetchall()
            )


        return {

            row[
                "edge_type"
            ]:
                int(
                    row[
                        "total"
                    ]
                )

            for row in rows
        }


    # ============================================================
    # FIND PROCESS NODE
    # ============================================================

    def find_process_node(
        self,
        *,
        pid=None,
        device_id=None,
    ) -> Optional[
        Dict[str, Any]
    ]:

        nodes = (
            self.get_nodes(
                limit=10000
            )
        )


        for node in nodes:

            if (
                node.get(
                    "node_type"
                )
                != "PROCESS"
            ):

                continue


            properties = (
                node.get(
                    "properties"
                )

                or {}
            )


            if (
                pid is not None

                and

                str(
                    properties.get(
                        "pid"
                    )
                )
                != str(
                    pid
                )
            ):

                continue


            if (
                device_id is not None

                and

                properties.get(
                    "device_id"
                )

                and

                str(
                    properties.get(
                        "device_id"
                    )
                )
                != str(
                    device_id
                )
            ):

                continue


            return node


        return None


    # ============================================================
    # GRAPH SUMMARY
    # ============================================================

    def get_summary(
        self,
    ) -> Dict[str, Any]:

        return {
            "event_count":
                self.count_events(),

            "node_count":
                self.count_nodes(),

            "edge_count":
                self.count_edges(),

            "node_types":
                self.get_node_type_counts(),

            "edge_types":
                self.get_edge_type_counts(),
        }


    # ============================================================
    # CLOSE
    #
    # There is intentionally no persistent connection.
    #
    # Method retained so callers/tests may safely call close().
    # ============================================================

    def close(
        self,
    ) -> None:

        return None