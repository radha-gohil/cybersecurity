from __future__ import annotations

import json
import sqlite3

from datetime import (
    datetime,
    timezone,
)

from pathlib import Path

from typing import (
    Any,
    Dict,
    List,
    Optional,
)


from ai_detection.behavior.process_feature_schema import (
    PROCESS_FEATURE_NAMES,
    ProcessFeatureRecord,
)


# ================================================================
# PROJECT PATHS
# ================================================================

PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[2]
)


DATABASE_PATH = (
    PROJECT_ROOT
    / "data"
    / "database"
    / "sentinel_endpoint.db"
)


# ================================================================
# TIME HELPER
# ================================================================

def now_iso() -> str:

    return (
        datetime
        .now(
            timezone.utc
        )
        .isoformat()
    )


# ================================================================
# DATABASE CONNECTION
# ================================================================

def get_connection() -> sqlite3.Connection:

    DATABASE_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )


    connection = sqlite3.connect(

        str(
            DATABASE_PATH
        ),

        timeout=10,
    )


    connection.row_factory = (
        sqlite3.Row
    )


    return connection


# ================================================================
# BEHAVIOR FEATURE STORE
# ================================================================

class BehaviorFeatureStore:

    def __init__(
        self,
    ):

        self.initialize()


    # ============================================================
    # INITIALIZE DATABASE TABLE
    # ============================================================

    def initialize(
        self,
    ) -> None:

        with get_connection() as connection:

            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS process_behavior_features (

                    id INTEGER PRIMARY KEY AUTOINCREMENT,

                    schema_version TEXT NOT NULL,

                    extracted_at TEXT NOT NULL,

                    pid INTEGER,

                    process_name TEXT,

                    parent_process_name TEXT,

                    executable_path TEXT,

                    feature_json TEXT NOT NULL,

                    feature_vector_json TEXT NOT NULL,

                    anomaly_score REAL,

                    anomaly_prediction TEXT,

                    model_name TEXT,

                    model_version TEXT,

                    created_at TEXT NOT NULL

                )
                """
            )


            # ----------------------------------------------------
            # INDEXES
            # ----------------------------------------------------

            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_process_behavior_pid

                ON process_behavior_features (
                    pid
                )
                """
            )


            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_process_behavior_name

                ON process_behavior_features (
                    process_name
                )
                """
            )


            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_process_behavior_extracted_at

                ON process_behavior_features (
                    extracted_at
                )
                """
            )


            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_process_behavior_prediction

                ON process_behavior_features (
                    anomaly_prediction
                )
                """
            )


            connection.commit()


    # ============================================================
    # SAVE PROCESS FEATURE RECORD
    # ============================================================

    def save_process_features(

        self,

        record: ProcessFeatureRecord,

        anomaly_score: Optional[
            float
        ] = None,

        anomaly_prediction: Optional[
            str
        ] = None,

        model_name: Optional[
            str
        ] = None,

        model_version: Optional[
            str
        ] = None,

    ) -> int:


        feature_dict = (
            record.features.to_dict()
        )


        feature_vector = (
            record.features.to_vector()
        )


        # --------------------------------------------------------
        # VALIDATE VECTOR SIZE
        # --------------------------------------------------------

        if len(
            feature_vector
        ) != len(
            PROCESS_FEATURE_NAMES
        ):

            raise ValueError(

                "Process feature vector length does not "
                "match PROCESS_FEATURE_NAMES."
            )


        with get_connection() as connection:

            cursor = connection.execute(

                """
                INSERT INTO process_behavior_features (

                    schema_version,

                    extracted_at,

                    pid,

                    process_name,

                    parent_process_name,

                    executable_path,

                    feature_json,

                    feature_vector_json,

                    anomaly_score,

                    anomaly_prediction,

                    model_name,

                    model_version,

                    created_at

                )

                VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
                """,

                (

                    record.schema_version,

                    record.extracted_at,

                    record.pid,

                    record.process_name,

                    record.parent_process_name,

                    record.executable_path,

                    json.dumps(
                        feature_dict
                    ),

                    json.dumps(
                        feature_vector
                    ),

                    anomaly_score,

                    anomaly_prediction,

                    model_name,

                    model_version,

                    now_iso(),
                ),
            )


            connection.commit()


            return int(
                cursor.lastrowid
            )


    # ============================================================
    # UPDATE AI RESULT
    #
    # We will use this after Isolation Forest is added.
    # ============================================================

    def update_ai_result(

        self,

        record_id: int,

        anomaly_score: float,

        anomaly_prediction: str,

        model_name: str,

        model_version: str,

    ) -> None:


        with get_connection() as connection:

            connection.execute(

                """
                UPDATE process_behavior_features

                SET

                    anomaly_score = ?,

                    anomaly_prediction = ?,

                    model_name = ?,

                    model_version = ?

                WHERE id = ?
                """,

                (

                    float(
                        anomaly_score
                    ),

                    str(
                        anomaly_prediction
                    ),

                    str(
                        model_name
                    ),

                    str(
                        model_version
                    ),

                    int(
                        record_id
                    ),
                ),
            )


            connection.commit()


    # ============================================================
    # GET FEATURE RECORD
    # ============================================================

    def get_record(

        self,

        record_id: int,

    ) -> Optional[
        Dict[
            str,
            Any,
        ]
    ]:


        with get_connection() as connection:

            row = connection.execute(

                """
                SELECT *

                FROM process_behavior_features

                WHERE id = ?
                """,

                (
                    int(
                        record_id
                    ),
                ),

            ).fetchone()


        if row is None:

            return None


        return self._row_to_dict(
            row
        )


    # ============================================================
    # GET RECENT FEATURE RECORDS
    # ============================================================

    def get_recent(

        self,

        limit: int = 100,

    ) -> List[
        Dict[
            str,
            Any,
        ]
    ]:


        safe_limit = max(
            1,
            min(
                int(
                    limit
                ),
                5000,
            ),
        )


        with get_connection() as connection:

            rows = connection.execute(

                """
                SELECT *

                FROM process_behavior_features

                ORDER BY id DESC

                LIMIT ?
                """,

                (
                    safe_limit,
                ),

            ).fetchall()


        return [

            self._row_to_dict(
                row
            )

            for row
            in rows
        ]


    # ============================================================
    # GET TRAINING VECTORS
    #
    # This is what Isolation Forest will train on.
    # ============================================================

    def get_training_vectors(

        self,

        limit: Optional[
            int
        ] = None,

    ) -> List[
        List[
            float
        ]
    ]:


        query = """
            SELECT feature_vector_json

            FROM process_behavior_features

            ORDER BY id ASC
        """


        parameters = ()


        if limit is not None:

            safe_limit = max(
                1,
                int(
                    limit
                ),
            )


            query += """
                LIMIT ?
            """


            parameters = (
                safe_limit,
            )


        with get_connection() as connection:

            rows = connection.execute(

                query,

                parameters,

            ).fetchall()


        vectors = []


        for row in rows:

            try:

                vector = json.loads(
                    row[
                        "feature_vector_json"
                    ]
                )


                if not isinstance(
                    vector,
                    list,
                ):

                    continue


                if len(
                    vector
                ) != len(
                    PROCESS_FEATURE_NAMES
                ):

                    continue


                vectors.append(

                    [
                        float(
                            value
                        )

                        for value
                        in vector
                    ]
                )


            except (
                json.JSONDecodeError,
                TypeError,
                ValueError,
            ):

                continue


        return vectors


    # ============================================================
    # GET COUNT
    # ============================================================

    def count(
        self,
    ) -> int:


        with get_connection() as connection:

            row = connection.execute(
                """
                SELECT COUNT(*) AS total

                FROM process_behavior_features
                """
            ).fetchone()


        if row is None:

            return 0


        return int(
            row[
                "total"
            ]
        )


    # ============================================================
    # GET ANOMALOUS RECORDS
    # ============================================================

    def get_anomalies(

        self,

        limit: int = 100,

    ) -> List[
        Dict[
            str,
            Any,
        ]
    ]:


        safe_limit = max(
            1,
            min(
                int(
                    limit
                ),
                1000,
            ),
        )


        with get_connection() as connection:

            rows = connection.execute(

                """
                SELECT *

                FROM process_behavior_features

                WHERE anomaly_prediction = 'ANOMALOUS'

                ORDER BY id DESC

                LIMIT ?
                """,

                (
                    safe_limit,
                ),

            ).fetchall()


        return [

            self._row_to_dict(
                row
            )

            for row
            in rows
        ]


    # ============================================================
    # DATABASE ROW → DICTIONARY
    # ============================================================

    def _row_to_dict(

        self,

        row: sqlite3.Row,

    ) -> Dict[
        str,
        Any,
    ]:


        try:

            feature_dict = json.loads(
                row[
                    "feature_json"
                ]
            )

        except Exception:

            feature_dict = {}


        try:

            feature_vector = json.loads(
                row[
                    "feature_vector_json"
                ]
            )

        except Exception:

            feature_vector = []


        return {

            "id":
                row[
                    "id"
                ],

            "schema_version":
                row[
                    "schema_version"
                ],

            "extracted_at":
                row[
                    "extracted_at"
                ],

            "pid":
                row[
                    "pid"
                ],

            "process_name":
                row[
                    "process_name"
                ],

            "parent_process_name":
                row[
                    "parent_process_name"
                ],

            "executable_path":
                row[
                    "executable_path"
                ],

            "features":
                feature_dict,

            "feature_vector":
                feature_vector,

            "anomaly_score":
                row[
                    "anomaly_score"
                ],

            "anomaly_prediction":
                row[
                    "anomaly_prediction"
                ],

            "model_name":
                row[
                    "model_name"
                ],

            "model_version":
                row[
                    "model_version"
                ],

            "created_at":
                row[
                    "created_at"
                ],
        }


# ================================================================
# SHARED STORE
# ================================================================

shared_behavior_feature_store = (
    BehaviorFeatureStore()
)


# ================================================================
# MANUAL TEST
# ================================================================

if __name__ == "__main__":

    store = (
        BehaviorFeatureStore()
    )


    print(
        "Behavior feature store ready."
    )


    print(
        "Stored process behavior records:",
        store.count(),
    )