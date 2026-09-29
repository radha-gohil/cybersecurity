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


# ================================================================
# SENTINEL-X TEMPORAL RESULT STORE V1
#
# Stores every successful Temporal Transformer inference.
#
# One row represents:
#
#       one 8-step process sequence
#               ↓
#       Temporal Transformer
#               ↓
#       temporal anomaly result
#
#
# Stored:
#
#       process identity
#       feature record IDs
#       sequence timing
#       raw reconstruction error
#       anomaly score
#       anomaly label
#       severity
#       alert state
#       most unusual timestep
#       per-timestep errors
#       64D temporal embedding
#       full predictor result
#
# ================================================================


# ================================================================
# PATHS
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
# IDENTITY
# ================================================================

STORE_NAME = (
    "sentinelx_process_temporal_result_store"
)


STORE_VERSION = "v1"


# ================================================================
# HELPERS
# ================================================================

def now_iso() -> str:

    return (
        datetime
        .now(
            timezone.utc
        )
        .isoformat()
    )


def json_text(
    value: Any,
) -> str:

    return json.dumps(

        value,

        separators=(
            ",",
            ":",
        ),

        ensure_ascii=False,
    )


# ================================================================
# STORE
# ================================================================

class ProcessTemporalResultStore:

    def __init__(
        self,
        database_path: Optional[
            str | Path
        ] = None,
    ):

        self.database_path = Path(

            database_path

            if database_path is not None

            else DEFAULT_DATABASE_PATH
        )


        self.database_path.parent.mkdir(

            parents=True,

            exist_ok=True,
        )


        self.ensure_table()


    # ============================================================
    # CONNECTION
    # ============================================================

    def get_connection(
        self,
    ):

        connection = sqlite3.connect(

            self.database_path,

            timeout=30.0,
        )


        connection.row_factory = (
            sqlite3.Row
        )


        return connection


    # ============================================================
    # TABLE
    # ============================================================

    def ensure_table(
        self,
    ) -> None:

        connection = (
            self.get_connection()
        )


        try:

            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS process_temporal_results (

                    id INTEGER PRIMARY KEY AUTOINCREMENT,

                    feature_record_id INTEGER NOT NULL,

                    pid INTEGER NOT NULL,

                    process_name TEXT NOT NULL,

                    process_create_time REAL NOT NULL,

                    sequence_generation INTEGER NOT NULL DEFAULT 0,

                    sequence_start_timestamp REAL,

                    sequence_end_timestamp REAL,

                    sequence_feature_record_ids_json TEXT NOT NULL,

                    model_name TEXT NOT NULL,

                    model_version TEXT NOT NULL,

                    predictor_version TEXT,

                    calibration_version TEXT,

                    raw_reconstruction_error REAL NOT NULL,

                    anomaly_score REAL NOT NULL,

                    anomaly_label TEXT NOT NULL,

                    severity TEXT NOT NULL,

                    is_active INTEGER NOT NULL DEFAULT 0,

                    is_strong INTEGER NOT NULL DEFAULT 0,

                    should_alert INTEGER NOT NULL DEFAULT 0,

                    most_unusual_timestep INTEGER,

                    maximum_timestep_error REAL,

                    per_timestep_errors_json TEXT,

                    temporal_embedding_json TEXT,

                    temporal_embedding_dimension INTEGER,

                    result_json TEXT NOT NULL,

                    created_at TEXT NOT NULL,

                    updated_at TEXT NOT NULL,

                    UNIQUE(
                        feature_record_id,
                        model_name,
                        model_version,
                        calibration_version
                    )
                )
                """
            )


            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS
                    idx_temporal_results_feature_record

                ON process_temporal_results(
                    feature_record_id
                )
                """
            )


            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS
                    idx_temporal_results_pid

                ON process_temporal_results(
                    pid
                )
                """
            )


            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS
                    idx_temporal_results_score

                ON process_temporal_results(
                    anomaly_score DESC
                )
                """
            )


            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS
                    idx_temporal_results_label

                ON process_temporal_results(
                    anomaly_label
                )
                """
            )


            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS
                    idx_temporal_results_created

                ON process_temporal_results(
                    created_at DESC
                )
                """
            )


            connection.commit()


        finally:

            connection.close()


    # ============================================================
    # SAVE
    # ============================================================

    def save_result(
        self,
        *,
        feature_record_id: int,
        pid: int,
        process_name: str,
        process_create_time: float,
        sequence_generation: int,
        sequence_feature_record_ids: List[
            Optional[int]
        ],
        sequence_start_timestamp: Optional[float],
        sequence_end_timestamp: Optional[float],
        temporal_result: Dict[str, Any],
    ) -> int:

        if not temporal_result.get(
            "available",
            False,
        ):

            raise ValueError(

                "Cannot persist unavailable "
                "Temporal Transformer result."
            )


        model_name = str(

            temporal_result.get(
                "model_name"
            )

            or "sentinelx_process_temporal_transformer"
        )


        model_version = str(

            temporal_result.get(
                "model_version"
            )

            or "unknown"
        )


        predictor_version = str(

            temporal_result.get(
                "predictor_version"
            )

            or ""
        )


        calibration_version = str(

            temporal_result.get(
                "calibration_version"
            )

            or ""
        )


        raw_error = float(

            temporal_result[
                "raw_temporal_reconstruction_error"
            ]
        )


        anomaly_score = float(

            temporal_result[
                "anomaly_score"
            ]
        )


        anomaly_label = str(

            temporal_result[
                "anomaly_label"
            ]
        )


        severity = str(

            temporal_result[
                "severity"
            ]
        )


        is_active = int(
            bool(
                temporal_result.get(
                    "is_active",
                    False,
                )
            )
        )


        is_strong = int(
            bool(
                temporal_result.get(
                    "is_strong",
                    False,
                )
            )
        )


        should_alert = int(
            bool(
                temporal_result.get(
                    "should_alert",
                    False,
                )
            )
        )


        most_unusual_timestep = (
            temporal_result.get(
                "most_unusual_timestep"
            )
        )


        maximum_timestep_error = (
            temporal_result.get(
                "maximum_timestep_error"
            )
        )


        per_timestep_errors = (
            temporal_result.get(
                "per_timestep_errors"
            )

            or []
        )


        temporal_embedding = (
            temporal_result.get(
                "temporal_embedding"
            )

            or []
        )


        temporal_embedding_dimension = int(

            temporal_result.get(
                "temporal_embedding_dimension"
            )

            or len(
                temporal_embedding
            )
        )


        created_at = (
            now_iso()
        )


        connection = (
            self.get_connection()
        )


        try:

            connection.execute(
                """
                INSERT INTO process_temporal_results (

                    feature_record_id,

                    pid,

                    process_name,

                    process_create_time,

                    sequence_generation,

                    sequence_start_timestamp,

                    sequence_end_timestamp,

                    sequence_feature_record_ids_json,

                    model_name,

                    model_version,

                    predictor_version,

                    calibration_version,

                    raw_reconstruction_error,

                    anomaly_score,

                    anomaly_label,

                    severity,

                    is_active,

                    is_strong,

                    should_alert,

                    most_unusual_timestep,

                    maximum_timestep_error,

                    per_timestep_errors_json,

                    temporal_embedding_json,

                    temporal_embedding_dimension,

                    result_json,

                    created_at,

                    updated_at
                )

                VALUES (

                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )

                ON CONFLICT(
                    feature_record_id,
                    model_name,
                    model_version,
                    calibration_version
                )

                DO UPDATE SET

                    pid =
                        excluded.pid,

                    process_name =
                        excluded.process_name,

                    process_create_time =
                        excluded.process_create_time,

                    sequence_generation =
                        excluded.sequence_generation,

                    sequence_start_timestamp =
                        excluded.sequence_start_timestamp,

                    sequence_end_timestamp =
                        excluded.sequence_end_timestamp,

                    sequence_feature_record_ids_json =
                        excluded.sequence_feature_record_ids_json,

                    raw_reconstruction_error =
                        excluded.raw_reconstruction_error,

                    anomaly_score =
                        excluded.anomaly_score,

                    anomaly_label =
                        excluded.anomaly_label,

                    severity =
                        excluded.severity,

                    is_active =
                        excluded.is_active,

                    is_strong =
                        excluded.is_strong,

                    should_alert =
                        excluded.should_alert,

                    most_unusual_timestep =
                        excluded.most_unusual_timestep,

                    maximum_timestep_error =
                        excluded.maximum_timestep_error,

                    per_timestep_errors_json =
                        excluded.per_timestep_errors_json,

                    temporal_embedding_json =
                        excluded.temporal_embedding_json,

                    temporal_embedding_dimension =
                        excluded.temporal_embedding_dimension,

                    result_json =
                        excluded.result_json,

                    updated_at =
                        excluded.updated_at
                """,

                (
                    int(
                        feature_record_id
                    ),

                    int(
                        pid
                    ),

                    str(
                        process_name
                    ),

                    float(
                        process_create_time
                    ),

                    int(
                        sequence_generation
                    ),

                    (
                        float(
                            sequence_start_timestamp
                        )

                        if sequence_start_timestamp
                        is not None

                        else None
                    ),

                    (
                        float(
                            sequence_end_timestamp
                        )

                        if sequence_end_timestamp
                        is not None

                        else None
                    ),

                    json_text(
                        sequence_feature_record_ids
                    ),

                    model_name,

                    model_version,

                    predictor_version,

                    calibration_version,

                    raw_error,

                    anomaly_score,

                    anomaly_label,

                    severity,

                    is_active,

                    is_strong,

                    should_alert,

                    (
                        int(
                            most_unusual_timestep
                        )

                        if most_unusual_timestep
                        is not None

                        else None
                    ),

                    (
                        float(
                            maximum_timestep_error
                        )

                        if maximum_timestep_error
                        is not None

                        else None
                    ),

                    json_text(
                        per_timestep_errors
                    ),

                    json_text(
                        temporal_embedding
                    ),

                    temporal_embedding_dimension,

                    json_text(
                        temporal_result
                    ),

                    created_at,

                    created_at,
                ),
            )


            connection.commit()


            row = (
                connection.execute(
                    """
                    SELECT id

                    FROM process_temporal_results

                    WHERE
                        feature_record_id = ?

                        AND model_name = ?

                        AND model_version = ?

                        AND calibration_version = ?
                    """,

                    (
                        int(
                            feature_record_id
                        ),

                        model_name,

                        model_version,

                        calibration_version,
                    ),
                )
                .fetchone()
            )


            if row is None:

                raise RuntimeError(

                    "Temporal result was written but "
                    "could not be reloaded."
                )


            return int(
                row[
                    "id"
                ]
            )


        finally:

            connection.close()


    # ============================================================
    # PARSE ROW
    # ============================================================

    def parse_row(
        self,
        row,
    ) -> Dict[str, Any]:

        result = dict(
            row
        )


        for key in [

            "sequence_feature_record_ids_json",

            "per_timestep_errors_json",

            "temporal_embedding_json",

            "result_json",

        ]:

            raw = (
                result.get(
                    key
                )
            )


            if raw is None:

                parsed = None

            else:

                try:

                    parsed = json.loads(
                        raw
                    )

                except json.JSONDecodeError:

                    parsed = None


            result[
                key.replace(
                    "_json",
                    ""
                )
            ] = parsed


        result[
            "is_active"
        ] = bool(
            result.get(
                "is_active"
            )
        )


        result[
            "is_strong"
        ] = bool(
            result.get(
                "is_strong"
            )
        )


        result[
            "should_alert"
        ] = bool(
            result.get(
                "should_alert"
            )
        )


        return result


    # ============================================================
    # GET BY ID
    # ============================================================

    def get_by_id(
        self,
        result_id: int,
    ) -> Optional[
        Dict[str, Any]
    ]:

        connection = (
            self.get_connection()
        )


        try:

            row = (
                connection.execute(
                    """
                    SELECT *

                    FROM process_temporal_results

                    WHERE id = ?
                    """,

                    (
                        int(
                            result_id
                        ),
                    ),
                )
                .fetchone()
            )


            if row is None:

                return None


            return self.parse_row(
                row
            )


        finally:

            connection.close()


    # ============================================================
    # RECENT
    # ============================================================

    def get_recent(
        self,
        limit: int = 100,
    ) -> List[
        Dict[str, Any]
    ]:

        connection = (
            self.get_connection()
        )


        try:

            rows = (
                connection.execute(
                    """
                    SELECT *

                    FROM process_temporal_results

                    ORDER BY id DESC

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

                self.parse_row(
                    row
                )

                for row in rows
            ]


        finally:

            connection.close()


    # ============================================================
    # RECENT FOR PID
    # ============================================================

    def get_recent_for_pid(
        self,
        pid: int,
        limit: int = 50,
    ) -> List[
        Dict[str, Any]
    ]:

        connection = (
            self.get_connection()
        )


        try:

            rows = (
                connection.execute(
                    """
                    SELECT *

                    FROM process_temporal_results

                    WHERE pid = ?

                    ORDER BY id DESC

                    LIMIT ?
                    """,

                    (
                        int(
                            pid
                        ),

                        int(
                            limit
                        ),
                    ),
                )
                .fetchall()
            )


            return [

                self.parse_row(
                    row
                )

                for row in rows
            ]


        finally:

            connection.close()


    # ============================================================
    # COUNT
    # ============================================================

    def count(
        self,
    ) -> int:

        connection = (
            self.get_connection()
        )


        try:

            return int(

                connection.execute(
                    """
                    SELECT COUNT(*)

                    FROM process_temporal_results
                    """
                )
                .fetchone()[0]
            )


        finally:

            connection.close()


    # ============================================================
    # COUNT ALERT CANDIDATES
    # ============================================================

    def count_alert_candidates(
        self,
    ) -> int:

        connection = (
            self.get_connection()
        )


        try:

            return int(

                connection.execute(
                    """
                    SELECT COUNT(*)

                    FROM process_temporal_results

                    WHERE should_alert = 1
                    """
                )
                .fetchone()[0]
            )


        finally:

            connection.close()


# ================================================================
# SHARED STORE
# ================================================================

shared_process_temporal_result_store = (
    ProcessTemporalResultStore()
)