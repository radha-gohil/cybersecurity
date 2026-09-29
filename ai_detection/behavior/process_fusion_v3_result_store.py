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
# SENTINEL-X FUSION V3 RESULT STORE
#
# Stores one final Fusion-v3 decision per behavioral feature record.
#
# Fusion v3 combines:
#
#   Rules
#   Statistical behavior
#   Behavioral AI consensus (IF + AE)
#   Temporal AI
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


STORE_NAME = (
    "sentinelx_process_fusion_v3_result_store"
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

class ProcessFusionV3ResultStore:

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
                CREATE TABLE IF NOT EXISTS process_fusion_v3_results (

                    id INTEGER PRIMARY KEY AUTOINCREMENT,

                    feature_record_id INTEGER NOT NULL,

                    pid INTEGER NOT NULL,

                    process_name TEXT NOT NULL,

                    process_create_time REAL,

                    fusion_name TEXT NOT NULL,

                    fusion_version TEXT NOT NULL,

                    operating_mode TEXT NOT NULL,

                    fusion_score REAL NOT NULL,

                    severity TEXT NOT NULL,

                    suspicious INTEGER NOT NULL DEFAULT 0,

                    should_alert INTEGER NOT NULL DEFAULT 0,

                    critical_allowed INTEGER NOT NULL DEFAULT 0,

                    evidence_confidence TEXT,

                    available_category_count INTEGER,

                    active_signal_count INTEGER,

                    strong_signal_count INTEGER,

                    rule_score REAL,

                    statistical_score REAL,

                    behavioral_ai_score REAL,

                    temporal_ai_score REAL,

                    temporal_ai_available INTEGER NOT NULL DEFAULT 0,

                    ai_temporal_disagreement INTEGER NOT NULL DEFAULT 0,

                    active_categories_json TEXT,

                    strong_categories_json TEXT,

                    reasons_json TEXT,

                    result_json TEXT NOT NULL,

                    created_at TEXT NOT NULL,

                    updated_at TEXT NOT NULL,

                    UNIQUE(
                        feature_record_id,
                        fusion_version
                    )
                )
                """
            )


            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS
                    idx_fusion_v3_feature_record

                ON process_fusion_v3_results(
                    feature_record_id
                )
                """
            )


            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS
                    idx_fusion_v3_pid

                ON process_fusion_v3_results(
                    pid
                )
                """
            )


            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS
                    idx_fusion_v3_score

                ON process_fusion_v3_results(
                    fusion_score DESC
                )
                """
            )


            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS
                    idx_fusion_v3_alert

                ON process_fusion_v3_results(
                    should_alert
                )
                """
            )


            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS
                    idx_fusion_v3_created

                ON process_fusion_v3_results(
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
        process_create_time: Optional[float],
        fusion_result: Dict[str, Any],
        operating_mode: str = "SHADOW_VALIDATION",
    ) -> int:

        fusion_name = str(

            fusion_result.get(
                "fusion_name"
            )

            or "sentinelx_process_threat_fusion"
        )


        fusion_version = str(

            fusion_result.get(
                "fusion_version"
            )

            or "v3"
        )


        scores = (
            fusion_result.get(
                "scores"
            )

            or {}
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
                INSERT INTO process_fusion_v3_results (

                    feature_record_id,
                    pid,
                    process_name,
                    process_create_time,

                    fusion_name,
                    fusion_version,
                    operating_mode,

                    fusion_score,
                    severity,
                    suspicious,
                    should_alert,
                    critical_allowed,

                    evidence_confidence,

                    available_category_count,
                    active_signal_count,
                    strong_signal_count,

                    rule_score,
                    statistical_score,
                    behavioral_ai_score,
                    temporal_ai_score,

                    temporal_ai_available,
                    ai_temporal_disagreement,

                    active_categories_json,
                    strong_categories_json,
                    reasons_json,

                    result_json,

                    created_at,
                    updated_at
                )

                VALUES (

                    ?, ?, ?, ?,
                    ?, ?, ?,
                    ?, ?, ?, ?, ?,
                    ?,
                    ?, ?, ?,
                    ?, ?, ?, ?,
                    ?, ?,
                    ?, ?, ?,
                    ?,
                    ?, ?
                )

                ON CONFLICT(
                    feature_record_id,
                    fusion_version
                )

                DO UPDATE SET

                    pid =
                        excluded.pid,

                    process_name =
                        excluded.process_name,

                    process_create_time =
                        excluded.process_create_time,

                    operating_mode =
                        excluded.operating_mode,

                    fusion_score =
                        excluded.fusion_score,

                    severity =
                        excluded.severity,

                    suspicious =
                        excluded.suspicious,

                    should_alert =
                        excluded.should_alert,

                    critical_allowed =
                        excluded.critical_allowed,

                    evidence_confidence =
                        excluded.evidence_confidence,

                    available_category_count =
                        excluded.available_category_count,

                    active_signal_count =
                        excluded.active_signal_count,

                    strong_signal_count =
                        excluded.strong_signal_count,

                    rule_score =
                        excluded.rule_score,

                    statistical_score =
                        excluded.statistical_score,

                    behavioral_ai_score =
                        excluded.behavioral_ai_score,

                    temporal_ai_score =
                        excluded.temporal_ai_score,

                    temporal_ai_available =
                        excluded.temporal_ai_available,

                    ai_temporal_disagreement =
                        excluded.ai_temporal_disagreement,

                    active_categories_json =
                        excluded.active_categories_json,

                    strong_categories_json =
                        excluded.strong_categories_json,

                    reasons_json =
                        excluded.reasons_json,

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

                    (
                        float(
                            process_create_time
                        )

                        if process_create_time
                        is not None

                        else None
                    ),

                    fusion_name,

                    fusion_version,

                    str(
                        operating_mode
                    ),

                    float(
                        fusion_result.get(
                            "fusion_score",
                            0.0,
                        )
                    ),

                    str(
                        fusion_result.get(
                            "severity",
                            "INFO",
                        )
                    ),

                    int(
                        bool(
                            fusion_result.get(
                                "suspicious",
                                False,
                            )
                        )
                    ),

                    int(
                        bool(
                            fusion_result.get(
                                "should_alert",
                                False,
                            )
                        )
                    ),

                    int(
                        bool(
                            fusion_result.get(
                                "critical_allowed",
                                False,
                            )
                        )
                    ),

                    str(
                        fusion_result.get(
                            "evidence_confidence",
                            "LOW",
                        )
                    ),

                    int(
                        fusion_result.get(
                            "available_category_count",
                            0,
                        )
                    ),

                    int(
                        fusion_result.get(
                            "active_signal_count",
                            0,
                        )
                    ),

                    int(
                        fusion_result.get(
                            "strong_signal_count",
                            0,
                        )
                    ),

                    float(
                        scores.get(
                            "rules",
                            0.0,
                        )
                    ),

                    float(
                        scores.get(
                            "statistical",
                            0.0,
                        )
                    ),

                    float(
                        scores.get(
                            "behavioral_ai_consensus",
                            0.0,
                        )
                    ),

                    float(
                        scores.get(
                            "temporal_ai",
                            0.0,
                        )
                    ),

                    int(
                        bool(
                            fusion_result.get(
                                "temporal_ai_available",
                                False,
                            )
                        )
                    ),

                    int(
                        bool(
                            fusion_result.get(
                                "ai_temporal_disagreement",
                                False,
                            )
                        )
                    ),

                    json_text(
                        fusion_result.get(
                            "active_categories",
                            [],
                        )
                    ),

                    json_text(
                        fusion_result.get(
                            "strong_categories",
                            [],
                        )
                    ),

                    json_text(
                        fusion_result.get(
                            "reasons",
                            [],
                        )
                    ),

                    json_text(
                        fusion_result
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

                    FROM process_fusion_v3_results

                    WHERE
                        feature_record_id = ?

                        AND fusion_version = ?
                    """,

                    (
                        int(
                            feature_record_id
                        ),

                        fusion_version,
                    ),
                )
                .fetchone()
            )


            if row is None:

                raise RuntimeError(
                    "Fusion v3 result could not be reloaded."
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

            "active_categories_json",

            "strong_categories_json",

            "reasons_json",

            "result_json",

        ]:

            raw = (
                result.get(
                    key
                )
            )


            try:

                parsed = (

                    json.loads(
                        raw
                    )

                    if raw

                    else None
                )


            except json.JSONDecodeError:

                parsed = None


            result[
                key.replace(
                    "_json",
                    ""
                )
            ] = parsed


        for key in [

            "suspicious",

            "should_alert",

            "critical_allowed",

            "temporal_ai_available",

            "ai_temporal_disagreement",

        ]:

            result[
                key
            ] = bool(
                result.get(
                    key
                )
            )


        return result


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

                    FROM process_fusion_v3_results

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
    ) -> int:

        connection = (
            self.get_connection()
        )


        try:

            return int(

                connection.execute(
                    """
                    SELECT COUNT(*)

                    FROM process_fusion_v3_results
                    """
                )
                .fetchone()[0]
            )


        finally:

            connection.close()


    # ============================================================
    # ALERT COUNT
    # ============================================================

    def count_alerts(
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

                    FROM process_fusion_v3_results

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

shared_process_fusion_v3_result_store = (
    ProcessFusionV3ResultStore()
)