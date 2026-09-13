import json
import sqlite3
from pathlib import Path
from datetime import datetime, timezone


# ============================================================
# PROJECT / DATABASE PATH
# ============================================================

PROJECT_ROOT = Path(
    __file__
).resolve().parents[2]

DATABASE_PATH = (
    PROJECT_ROOT
    / "data"
    / "database"
    / "sentinel_endpoint.db"
)


class IncidentStore:

    def __init__(
        self,
        database_path=None,
    ):

        if database_path is None:

            database_path = (
                DATABASE_PATH
            )

        self.database_path = Path(
            database_path
        )

        self.database_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.initialize_table()


    # ============================================================
    # DATABASE CONNECTION
    # ============================================================

    def get_connection(
        self,
    ):

        connection = sqlite3.connect(
            self.database_path
        )

        connection.row_factory = (
            sqlite3.Row
        )

        return connection


    # ============================================================
    # CURRENT UTC TIME
    # ============================================================

    def current_timestamp(
        self,
    ) -> str:

        return (
            datetime.now(
                timezone.utc
            ).isoformat()
        )


    # ============================================================
    # CREATE INCIDENT TABLE
    # ============================================================

    def initialize_table(
        self,
    ):

        connection = (
            self.get_connection()
        )

        try:

            cursor = (
                connection.cursor()
            )

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS incidents (

                    incident_id TEXT PRIMARY KEY,

                    title TEXT NOT NULL,

                    status TEXT NOT NULL,

                    correlation_score INTEGER NOT NULL,

                    severity TEXT NOT NULL,

                    categories TEXT,

                    event_ids TEXT,

                    event_count INTEGER,

                    timeline TEXT,

                    source TEXT,

                    requires_investigation INTEGER,

                    created_at TEXT,

                    updated_at TEXT
                )
                """
            )

            connection.commit()

        finally:

            connection.close()


    # ============================================================
    # SERIALIZE JSON DATA
    # ============================================================

    def serialize(
        self,
        value,
    ) -> str:

        return json.dumps(
            value,
            ensure_ascii=False,
        )


    # ============================================================
    # DESERIALIZE JSON DATA
    # ============================================================

    def deserialize(
        self,
        value,
        default,
    ):

        if not value:

            return default

        try:

            return json.loads(
                value
            )

        except (
            json.JSONDecodeError,
            TypeError,
        ):

            return default


    # ============================================================
    # SAVE / UPDATE INCIDENT
    # ============================================================

    def save_incident(
        self,
        incident: dict,
    ):

        incident_id = (
            incident.get(
                "incident_id"
            )
        )

        if not incident_id:

            raise ValueError(
                "Incident does not contain incident_id."
            )


        updated_at = (
            incident.get(
                "updated_at"
            )
            or self.current_timestamp()
        )


        connection = (
            self.get_connection()
        )


        try:

            cursor = (
                connection.cursor()
            )


            cursor.execute(
                """
                INSERT INTO incidents (

                    incident_id,
                    title,
                    status,
                    correlation_score,
                    severity,
                    categories,
                    event_ids,
                    event_count,
                    timeline,
                    source,
                    requires_investigation,
                    created_at,
                    updated_at

                )

                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)

                ON CONFLICT(incident_id)

                DO UPDATE SET

                    title =
                        excluded.title,

                    status =
                        excluded.status,

                    correlation_score =
                        excluded.correlation_score,

                    severity =
                        excluded.severity,

                    categories =
                        excluded.categories,

                    event_ids =
                        excluded.event_ids,

                    event_count =
                        excluded.event_count,

                    timeline =
                        excluded.timeline,

                    source =
                        excluded.source,

                    requires_investigation =
                        excluded.requires_investigation,

                    updated_at =
                        excluded.updated_at
                """,

                (
                    incident_id,

                    incident.get(
                        "title",
                        "Security Incident",
                    ),

                    incident.get(
                        "status",
                        "NEW",
                    ),

                    incident.get(
                        "correlation_score",
                        0,
                    ),

                    incident.get(
                        "severity",
                        "INFO",
                    ),

                    self.serialize(
                        incident.get(
                            "categories",
                            [],
                        )
                    ),

                    self.serialize(
                        incident.get(
                            "event_ids",
                            [],
                        )
                    ),

                    incident.get(
                        "event_count",
                        0,
                    ),

                    self.serialize(
                        incident.get(
                            "timeline",
                            [],
                        )
                    ),

                    incident.get(
                        "source",
                        "CorrelationManager",
                    ),

                    1
                    if incident.get(
                        "requires_investigation",
                        False,
                    )
                    else 0,

                    incident.get(
                        "created_at"
                    )
                    or self.current_timestamp(),

                    updated_at,
                ),
            )


            connection.commit()


        finally:

            connection.close()


    # ============================================================
    # GET INCIDENT BY ID
    # ============================================================

    def get_incident(
        self,
        incident_id: str,
    ):

        connection = (
            self.get_connection()
        )

        try:

            cursor = (
                connection.cursor()
            )


            cursor.execute(
                """
                SELECT *
                FROM incidents
                WHERE incident_id = ?
                """,
                (
                    incident_id,
                ),
            )


            row = (
                cursor.fetchone()
            )


            if row is None:

                return None


            return (
                self.row_to_incident(
                    row
                )
            )


        finally:

            connection.close()


    # ============================================================
    # GET ALL INCIDENTS
    # ============================================================

    def get_incidents(
        self,
    ) -> list:

        connection = (
            self.get_connection()
        )

        try:

            cursor = (
                connection.cursor()
            )


            cursor.execute(
                """
                SELECT *
                FROM incidents
                ORDER BY updated_at DESC
                """
            )


            rows = (
                cursor.fetchall()
            )


            return [
                self.row_to_incident(
                    row
                )
                for row in rows
            ]


        finally:

            connection.close()


    # ============================================================
    # DATABASE ROW -> INCIDENT
    # ============================================================

    def row_to_incident(
        self,
        row,
    ) -> dict:

        return {

            "incident_id":
                row["incident_id"],

            "title":
                row["title"],

            "status":
                row["status"],

            "correlation_score":
                row["correlation_score"],

            "severity":
                row["severity"],

            "categories":
                self.deserialize(
                    row["categories"],
                    [],
                ),

            "event_ids":
                self.deserialize(
                    row["event_ids"],
                    [],
                ),

            "event_count":
                row["event_count"],

            "timeline":
                self.deserialize(
                    row["timeline"],
                    [],
                ),

            "source":
                row["source"],

            "requires_investigation":
                bool(
                    row[
                        "requires_investigation"
                    ]
                ),

            "created_at":
                row["created_at"],

            "updated_at":
                row["updated_at"],
        }


    # ============================================================
    # COUNT INCIDENTS
    # ============================================================

    def count_incidents(
        self,
    ) -> int:

        connection = (
            self.get_connection()
        )

        try:

            cursor = (
                connection.cursor()
            )


            cursor.execute(
                """
                SELECT COUNT(*)
                FROM incidents
                """
            )


            result = (
                cursor.fetchone()
            )


            return int(
                result[0]
            )


        finally:

            connection.close()