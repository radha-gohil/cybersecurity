import json
import sqlite3
from pathlib import Path
from datetime import datetime, timezone


class IncidentEvidenceStore:

    def __init__(
        self,
        database_path=None,
    ):

        if database_path is None:

            database_path = (
                Path(__file__)
                .resolve()
                .parents[1]
                / "data"
                / "database"
                / "sentinel_endpoint.db"
            )

        self.database_path = Path(
            database_path
        )

        self.database_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.initialize()


    # ============================================================
    # TIME
    # ============================================================

    def now_iso(self):

        return datetime.now(
            timezone.utc
        ).isoformat()


    # ============================================================
    # CONNECTION
    # ============================================================

    def get_connection(self):

        connection = sqlite3.connect(
            self.database_path
        )

        connection.row_factory = (
            sqlite3.Row
        )

        return connection


    # ============================================================
    # INITIALIZE TABLES
    # ============================================================

    def initialize(self):

        with self.get_connection() as conn:

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS incident_evidence (

                    evidence_id INTEGER PRIMARY KEY AUTOINCREMENT,

                    incident_id TEXT NOT NULL,

                    evidence_type TEXT NOT NULL,

                    entity_key TEXT,

                    evidence_json TEXT NOT NULL,

                    created_at TEXT NOT NULL
                )
                """
            )


            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_incident_evidence_incident
                ON incident_evidence(incident_id)
                """
            )


            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_incident_evidence_type
                ON incident_evidence(evidence_type)
                """
            )


            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS incident_timeline (

                    timeline_id INTEGER PRIMARY KEY AUTOINCREMENT,

                    incident_id TEXT NOT NULL,

                    sequence_no INTEGER NOT NULL,

                    event_type TEXT NOT NULL,

                    event_time TEXT,

                    description TEXT,

                    event_json TEXT NOT NULL,

                    created_at TEXT NOT NULL
                )
                """
            )


            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_incident_timeline_incident
                ON incident_timeline(incident_id)
                """
            )


            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_incident_timeline_sequence
                ON incident_timeline(
                    incident_id,
                    sequence_no
                )
                """
            )


            conn.commit()


    # ============================================================
    # JSON HELPERS
    # ============================================================

    def encode_json(
        self,
        value,
    ):

        return json.dumps(
            value,
            default=str,
            ensure_ascii=False,
        )


    def decode_json(
        self,
        value,
        default=None,
    ):

        if not value:

            return (
                default
                if default is not None
                else {}
            )


        try:

            return json.loads(
                value
            )

        except (
            TypeError,
            json.JSONDecodeError,
        ):

            return (
                default
                if default is not None
                else {}
            )


    # ============================================================
    # ENTITY KEY
    # ============================================================

    def build_entity_key(
        self,
        evidence_type,
        evidence,
    ):

        evidence_type = str(
            evidence_type
        ).upper()


        if not isinstance(
            evidence,
            dict,
        ):

            return None


        if evidence_type == "PROCESS":

            pid = evidence.get(
                "pid"
            )

            exe = (
                evidence.get(
                    "exe"
                )
                or evidence.get(
                    "path"
                )
                or evidence.get(
                    "name"
                )
            )

            return (
                f"{pid}|{exe}"
            )


        if evidence_type == "FILE":

            sha256 = evidence.get(
                "sha256"
            )

            path = evidence.get(
                "path"
            )

            return (
                sha256
                or path
            )


        if evidence_type == "NETWORK":

            return (
                f"{evidence.get('pid')}|"
                f"{evidence.get('remote_ip')}|"
                f"{evidence.get('remote_port')}"
            )


        if evidence_type == "REGISTRY":

            return (
                f"{evidence.get('key')}|"
                f"{evidence.get('value_name')}"
            )


        return None


    # ============================================================
    # CLEAR INCIDENT
    # ============================================================

    def clear_incident(
        self,
        incident_id,
    ):

        with self.get_connection() as conn:

            conn.execute(
                """
                DELETE FROM incident_evidence
                WHERE incident_id = ?
                """,
                (
                    incident_id,
                ),
            )


            conn.execute(
                """
                DELETE FROM incident_timeline
                WHERE incident_id = ?
                """,
                (
                    incident_id,
                ),
            )


            conn.commit()


    # ============================================================
    # SAVE ONE EVIDENCE ITEM
    # ============================================================

    def save_evidence(
        self,
        incident_id,
        evidence_type,
        evidence,
    ):

        if not incident_id:

            raise ValueError(
                "incident_id is required."
            )


        if not isinstance(
            evidence,
            dict,
        ):

            raise TypeError(
                "evidence must be a dictionary."
            )


        evidence_type = str(
            evidence_type
        ).upper()


        entity_key = (
            self.build_entity_key(
                evidence_type,
                evidence,
            )
        )


        with self.get_connection() as conn:

            cursor = conn.execute(
                """
                INSERT INTO incident_evidence (

                    incident_id,
                    evidence_type,
                    entity_key,
                    evidence_json,
                    created_at

                ) VALUES (?, ?, ?, ?, ?)
                """,

                (
                    incident_id,
                    evidence_type,
                    entity_key,
                    self.encode_json(
                        evidence
                    ),
                    self.now_iso(),
                ),
            )


            conn.commit()


        return cursor.lastrowid


    # ============================================================
    # SAVE EVIDENCE COLLECTIONS
    # ============================================================

    def save_evidence_bundle(
        self,
        incident_id,
        evidence,
        replace_existing=True,
    ):

        if not isinstance(
            evidence,
            dict,
        ):

            evidence = {}


        if replace_existing:

            self.clear_incident(
                incident_id
            )


        mapping = {

            "processes":
                "PROCESS",

            "files":
                "FILE",

            "network_connections":
                "NETWORK",

            "registry_artifacts":
                "REGISTRY",
        }


        saved = {

            "PROCESS":
                0,

            "FILE":
                0,

            "NETWORK":
                0,

            "REGISTRY":
                0,
        }


        for source_key, evidence_type in (
            mapping.items()
        ):

            items = (
                evidence.get(
                    source_key,
                    []
                )
            )


            if not isinstance(
                items,
                list,
            ):

                continue


            for item in items:

                if not isinstance(
                    item,
                    dict,
                ):

                    continue


                self.save_evidence(
                    incident_id=
                        incident_id,

                    evidence_type=
                        evidence_type,

                    evidence=
                        item,
                )


                saved[
                    evidence_type
                ] += 1


        return {

            "incident_id":
                incident_id,

            "saved":
                saved,

            "total":
                sum(
                    saved.values()
                ),
        }


    # ============================================================
    # GET EVIDENCE
    # ============================================================

    def get_evidence(
        self,
        incident_id,
        evidence_type=None,
    ):

        query = """
            SELECT *
            FROM incident_evidence
            WHERE incident_id = ?
        """

        params = [
            incident_id
        ]


        if evidence_type:

            query += """
                AND evidence_type = ?
            """

            params.append(
                str(
                    evidence_type
                ).upper()
            )


        query += """
            ORDER BY evidence_id ASC
        """


        with self.get_connection() as conn:

            rows = conn.execute(
                query,
                tuple(
                    params
                ),
            ).fetchall()


        results = []


        for row in rows:

            data = dict(
                row
            )


            results.append(
                {

                    "evidence_id":
                        data[
                            "evidence_id"
                        ],

                    "incident_id":
                        data[
                            "incident_id"
                        ],

                    "evidence_type":
                        data[
                            "evidence_type"
                        ],

                    "entity_key":
                        data[
                            "entity_key"
                        ],

                    "evidence":
                        self.decode_json(
                            data[
                                "evidence_json"
                            ],
                            {},
                        ),

                    "created_at":
                        data[
                            "created_at"
                        ],
                }
            )


        return results


    # ============================================================
    # GET EVIDENCE BUNDLE
    # ============================================================

    def get_evidence_bundle(
        self,
        incident_id,
    ):

        rows = (
            self.get_evidence(
                incident_id
            )
        )


        bundle = {

            "processes":
                [],

            "files":
                [],

            "network_connections":
                [],

            "registry_artifacts":
                [],
        }


        reverse_mapping = {

            "PROCESS":
                "processes",

            "FILE":
                "files",

            "NETWORK":
                "network_connections",

            "REGISTRY":
                "registry_artifacts",
        }


        for row in rows:

            target_key = (
                reverse_mapping.get(
                    row[
                        "evidence_type"
                    ]
                )
            )


            if target_key:

                bundle[
                    target_key
                ].append(
                    row[
                        "evidence"
                    ]
                )


        return bundle


    # ============================================================
    # SAVE TIMELINE
    # ============================================================

    def save_timeline(
        self,
        incident_id,
        timeline,
        replace_existing=True,
    ):

        if not isinstance(
            timeline,
            list,
        ):

            timeline = []


        if replace_existing:

            with self.get_connection() as conn:

                conn.execute(
                    """
                    DELETE FROM incident_timeline
                    WHERE incident_id = ?
                    """,
                    (
                        incident_id,
                    ),
                )

                conn.commit()


        saved = 0


        for index, event in enumerate(
            timeline,
            start=1,
        ):

            if not isinstance(
                event,
                dict,
            ):

                continue


            event_type = (
                event.get(
                    "event_type"
                )
                or event.get(
                    "type"
                )
                or event.get(
                    "category"
                )
                or "UNKNOWN"
            )


            event_time = (
                event.get(
                    "timestamp"
                )
                or event.get(
                    "time"
                )
                or event.get(
                    "event_time"
                )
            )


            description = (
                event.get(
                    "description"
                )
                or event.get(
                    "summary"
                )
                or ""
            )


            with self.get_connection() as conn:

                conn.execute(
                    """
                    INSERT INTO incident_timeline (

                        incident_id,
                        sequence_no,
                        event_type,
                        event_time,
                        description,
                        event_json,
                        created_at

                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,

                    (
                        incident_id,
                        index,
                        str(
                            event_type
                        ),
                        event_time,
                        str(
                            description
                        ),
                        self.encode_json(
                            event
                        ),
                        self.now_iso(),
                    ),
                )


                conn.commit()


            saved += 1


        return {

            "incident_id":
                incident_id,

            "saved_timeline_events":
                saved,
        }


    # ============================================================
    # GET TIMELINE
    # ============================================================

    def get_timeline(
        self,
        incident_id,
    ):

        with self.get_connection() as conn:

            rows = conn.execute(
                """
                SELECT *
                FROM incident_timeline

                WHERE incident_id = ?

                ORDER BY sequence_no ASC
                """,
                (
                    incident_id,
                ),
            ).fetchall()


        results = []


        for row in rows:

            data = dict(
                row
            )


            results.append(
                {

                    "timeline_id":
                        data[
                            "timeline_id"
                        ],

                    "sequence_no":
                        data[
                            "sequence_no"
                        ],

                    "event_type":
                        data[
                            "event_type"
                        ],

                    "event_time":
                        data[
                            "event_time"
                        ],

                    "description":
                        data[
                            "description"
                        ],

                    "event":
                        self.decode_json(
                            data[
                                "event_json"
                            ],
                            {},
                        ),

                    "created_at":
                        data[
                            "created_at"
                        ],
                }
            )


        return results


    # ============================================================
    # COUNT
    # ============================================================

    def count_evidence(
        self,
        incident_id=None,
    ):

        with self.get_connection() as conn:

            if incident_id:

                row = conn.execute(
                    """
                    SELECT COUNT(*) AS total
                    FROM incident_evidence
                    WHERE incident_id = ?
                    """,
                    (
                        incident_id,
                    ),
                ).fetchone()

            else:

                row = conn.execute(
                    """
                    SELECT COUNT(*) AS total
                    FROM incident_evidence
                    """
                ).fetchone()


        return int(
            row[
                "total"
            ]
        )


    def count_timeline(
        self,
        incident_id=None,
    ):

        with self.get_connection() as conn:

            if incident_id:

                row = conn.execute(
                    """
                    SELECT COUNT(*) AS total
                    FROM incident_timeline
                    WHERE incident_id = ?
                    """,
                    (
                        incident_id,
                    ),
                ).fetchone()

            else:

                row = conn.execute(
                    """
                    SELECT COUNT(*) AS total
                    FROM incident_timeline
                    """
                ).fetchone()


        return int(
            row[
                "total"
            ]
        )