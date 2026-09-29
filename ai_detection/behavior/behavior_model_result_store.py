from __future__ import annotations

import json

from datetime import (
    datetime,
    timezone,
)

from typing import (
    Any,
    Dict,
    List,
    Optional,
)


from ai_detection.behavior.behavior_feature_store import (
    get_connection,
)


# ================================================================
# SENTINEL-X MULTI-MODEL BEHAVIOR RESULT STORE
#
# One process feature record may now have multiple AI results:
#
# process_behavior_features
#          │
#          ├── Isolation Forest result
#          ├── Autoencoder result
#          └── future models
#
# The original feature table remains unchanged.
# ================================================================


def now_iso() -> str:

    return (
        datetime
        .now(
            timezone.utc
        )
        .isoformat()
    )


class BehaviorModelResultStore:

    def __init__(
        self,
    ):

        self.initialize()


    # ============================================================
    # DATABASE INITIALIZATION
    # ============================================================

    def initialize(
        self,
    ) -> None:

        connection = (
            get_connection()
        )

        try:

            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS behavior_model_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,

                    feature_record_id INTEGER NOT NULL,

                    model_family TEXT NOT NULL,

                    model_name TEXT NOT NULL,

                    model_version TEXT NOT NULL,

                    anomaly_score REAL,

                    anomaly_label TEXT,

                    severity TEXT,

                    is_alert_candidate INTEGER NOT NULL DEFAULT 0,

                    raw_metric_name TEXT,

                    raw_metric_value REAL,

                    embedding_json TEXT,

                    result_json TEXT NOT NULL,

                    created_at TEXT NOT NULL,

                    updated_at TEXT NOT NULL,

                    UNIQUE (
                        feature_record_id,
                        model_family,
                        model_name,
                        model_version
                    )
                )
                """
            )


            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_behavior_model_results_feature_record
                ON behavior_model_results (
                    feature_record_id
                )
                """
            )


            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_behavior_model_results_family
                ON behavior_model_results (
                    model_family
                )
                """
            )


            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_behavior_model_results_score
                ON behavior_model_results (
                    anomaly_score
                )
                """
            )


            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_behavior_model_results_created
                ON behavior_model_results (
                    created_at
                )
                """
            )


            connection.commit()

        finally:

            connection.close()


    # ============================================================
    # SAVE / UPDATE MODEL RESULT
    # ============================================================

    def save_result(

        self,

        feature_record_id: int,

        model_family: str,

        result: Dict[
            str,
            Any,
        ],

        raw_metric_name: Optional[str] = None,

        raw_metric_value: Optional[float] = None,

    ) -> int:


        if feature_record_id is None:

            raise ValueError(
                "feature_record_id is required."
            )


        model_name = (

            str(

                result.get(
                    "model_name"
                )

                or "UNKNOWN"
            )
        )


        model_version = (

            str(

                result.get(
                    "model_version"
                )

                or "UNKNOWN"
            )
        )


        anomaly_score = (
            result.get(
                "anomaly_confidence"
            )
        )


        anomaly_label = (
            result.get(
                "anomaly_label"
            )
        )


        severity = (
            result.get(
                "severity"
            )
        )


        # --------------------------------------------------------
        # Candidate alert fields differ slightly by model.
        # --------------------------------------------------------

        alert_candidate = bool(

            result.get(
                "should_alert",
                False,
            )

            or

            result.get(
                "candidate_alert",
                False,
            )
        )


        embedding = (
            result.get(
                "behavior_embedding"
            )
        )


        embedding_json = None


        if embedding is not None:

            embedding_json = (
                json.dumps(
                    embedding,
                    default=str,
                )
            )


        result_json = (
            json.dumps(

                result,

                default=str,

                sort_keys=False,
            )
        )


        timestamp = (
            now_iso()
        )


        connection = (
            get_connection()
        )


        try:

            connection.execute(
                """
                INSERT INTO behavior_model_results (
                    feature_record_id,
                    model_family,
                    model_name,
                    model_version,
                    anomaly_score,
                    anomaly_label,
                    severity,
                    is_alert_candidate,
                    raw_metric_name,
                    raw_metric_value,
                    embedding_json,
                    result_json,
                    created_at,
                    updated_at
                )
                VALUES (
                    ?,
                    ?,
                    ?,
                    ?,
                    ?,
                    ?,
                    ?,
                    ?,
                    ?,
                    ?,
                    ?,
                    ?,
                    ?,
                    ?
                )
                ON CONFLICT (
                    feature_record_id,
                    model_family,
                    model_name,
                    model_version
                )
                DO UPDATE SET
                    anomaly_score = excluded.anomaly_score,
                    anomaly_label = excluded.anomaly_label,
                    severity = excluded.severity,
                    is_alert_candidate = excluded.is_alert_candidate,
                    raw_metric_name = excluded.raw_metric_name,
                    raw_metric_value = excluded.raw_metric_value,
                    embedding_json = excluded.embedding_json,
                    result_json = excluded.result_json,
                    updated_at = excluded.updated_at
                """,
                (
                    int(
                        feature_record_id
                    ),

                    str(
                        model_family
                    ),

                    model_name,

                    model_version,

                    (
                        float(
                            anomaly_score
                        )

                        if anomaly_score is not None

                        else None
                    ),

                    (
                        str(
                            anomaly_label
                        )

                        if anomaly_label is not None

                        else None
                    ),

                    (
                        str(
                            severity
                        )

                        if severity is not None

                        else None
                    ),

                    1
                    if alert_candidate
                    else 0,

                    raw_metric_name,

                    (
                        float(
                            raw_metric_value
                        )

                        if raw_metric_value is not None

                        else None
                    ),

                    embedding_json,

                    result_json,

                    timestamp,

                    timestamp,
                ),
            )


            connection.commit()


            row = connection.execute(
                """
                SELECT id
                FROM behavior_model_results
                WHERE feature_record_id = ?
                  AND model_family = ?
                  AND model_name = ?
                  AND model_version = ?
                """,
                (
                    int(
                        feature_record_id
                    ),

                    str(
                        model_family
                    ),

                    model_name,

                    model_version,
                ),
            ).fetchone()


            if row is None:

                raise RuntimeError(

                    "Unable to retrieve stored "
                    "behavior-model result."
                )


            return int(
                row[
                    "id"
                ]
            )


        finally:

            connection.close()


    # ============================================================
    # RESULT PARSING
    # ============================================================

    def _row_to_dict(
        self,
        row,
    ) -> Dict[
        str,
        Any,
    ]:

        if row is None:

            return {}


        result = dict(
            row
        )


        raw_result = (
            result.get(
                "result_json"
            )
        )


        try:

            result[
                "result"
            ] = (

                json.loads(
                    raw_result
                )

                if raw_result

                else {}
            )

        except (
            TypeError,
            json.JSONDecodeError,
        ):

            result[
                "result"
            ] = {}


        raw_embedding = (
            result.get(
                "embedding_json"
            )
        )


        try:

            result[
                "embedding"
            ] = (

                json.loads(
                    raw_embedding
                )

                if raw_embedding

                else None
            )

        except (
            TypeError,
            json.JSONDecodeError,
        ):

            result[
                "embedding"
            ] = None


        result[
            "is_alert_candidate"
        ] = bool(

            result.get(
                "is_alert_candidate",
                0,
            )
        )


        return result


    # ============================================================
    # RESULTS FOR ONE FEATURE RECORD
    # ============================================================

    def get_results_for_feature_record(

        self,

        feature_record_id: int,

    ) -> List[
        Dict[
            str,
            Any,
        ]
    ]:

        connection = (
            get_connection()
        )


        try:

            rows = (
                connection.execute(
                    """
                    SELECT *
                    FROM behavior_model_results
                    WHERE feature_record_id = ?
                    ORDER BY id ASC
                    """,
                    (
                        int(
                            feature_record_id
                        ),
                    ),
                )
                .fetchall()
            )


            return [

                self._row_to_dict(
                    row
                )

                for row
                in rows
            ]


        finally:

            connection.close()


    # ============================================================
    # RECENT MODEL RESULTS
    # ============================================================

    def get_recent(

        self,

        limit: int = 100,

        model_family: Optional[str] = None,

    ) -> List[
        Dict[
            str,
            Any,
        ]
    ]:


        limit = max(
            1,
            min(
                int(
                    limit
                ),
                5000,
            ),
        )


        connection = (
            get_connection()
        )


        try:

            if model_family:

                rows = (
                    connection.execute(
                        """
                        SELECT *
                        FROM behavior_model_results
                        WHERE model_family = ?
                        ORDER BY id DESC
                        LIMIT ?
                        """,
                        (
                            model_family,
                            limit,
                        ),
                    )
                    .fetchall()
                )

            else:

                rows = (
                    connection.execute(
                        """
                        SELECT *
                        FROM behavior_model_results
                        ORDER BY id DESC
                        LIMIT ?
                        """,
                        (
                            limit,
                        ),
                    )
                    .fetchall()
                )


            return [

                self._row_to_dict(
                    row
                )

                for row
                in rows
            ]


        finally:

            connection.close()


    # ============================================================
    # COUNT
    # ============================================================

    def count(
        self,
        model_family: Optional[str] = None,
    ) -> int:

        connection = (
            get_connection()
        )


        try:

            if model_family:

                row = (
                    connection.execute(
                        """
                        SELECT COUNT(*) AS count_value
                        FROM behavior_model_results
                        WHERE model_family = ?
                        """,
                        (
                            model_family,
                        ),
                    )
                    .fetchone()
                )

            else:

                row = (
                    connection.execute(
                        """
                        SELECT COUNT(*) AS count_value
                        FROM behavior_model_results
                        """
                    )
                    .fetchone()
                )


            return int(
                row[
                    "count_value"
                ]
            )


        finally:

            connection.close()


# ================================================================
# SHARED STORE
# ================================================================

shared_behavior_model_result_store = (
    BehaviorModelResultStore()
)