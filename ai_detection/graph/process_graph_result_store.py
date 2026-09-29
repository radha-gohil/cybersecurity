from __future__ import annotations

import json
import sqlite3

from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


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


class ProcessGraphResultStore:

    TABLE_NAME = (
        "process_graph_ai_results"
    )


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


        self.initialize_table()


    def now_iso(
        self,
    ) -> str:

        return (
            datetime.now(
                timezone.utc
            ).isoformat()
        )


    def get_connection(
        self,
    ):

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
            "PRAGMA busy_timeout = 15000"
        )


        return connection


    def initialize_table(
        self,
    ):

        with closing(
            self.get_connection()
        ) as connection:

            connection.execute(
                f"""
                CREATE TABLE IF NOT EXISTS
                {self.TABLE_NAME} (

                    result_id INTEGER PRIMARY KEY AUTOINCREMENT,

                    event_id TEXT,

                    pid INTEGER,

                    process_name TEXT,

                    device_id TEXT,

                    predictor_name TEXT,

                    predictor_version TEXT,

                    model_version TEXT,

                    calibration_version TEXT,

                    operating_mode TEXT,

                    state TEXT,

                    graph_node_count INTEGER,

                    graph_edge_count INTEGER,

                    raw_reconstruction_error REAL,

                    center_reconstruction_error REAL,

                    graph_anomaly_score REAL,

                    graph_anomaly_band TEXT,

                    graph_signal_active INTEGER,

                    graph_signal_strong INTEGER,

                    authoritative_alert INTEGER,

                    embedding_dimension INTEGER,

                    embedding_json TEXT,

                    evidence_coverage_json TEXT,

                    node_types_json TEXT,

                    edge_types_json TEXT,

                    calibration_source TEXT,

                    calibration_quality TEXT,

                    created_at TEXT NOT NULL
                )
                """
            )


            connection.execute(
                f"""
                CREATE INDEX IF NOT EXISTS
                idx_{self.TABLE_NAME}_pid

                ON {self.TABLE_NAME} (
                    pid
                )
                """
            )


            connection.execute(
                f"""
                CREATE INDEX IF NOT EXISTS
                idx_{self.TABLE_NAME}_event

                ON {self.TABLE_NAME} (
                    event_id
                )
                """
            )


            connection.execute(
                f"""
                CREATE INDEX IF NOT EXISTS
                idx_{self.TABLE_NAME}_created

                ON {self.TABLE_NAME} (
                    created_at
                )
                """
            )


            connection.commit()


    def save_result(
        self,
        result: Dict[str, Any],
        *,
        event_id: Optional[str] = None,
    ) -> int:

        if not isinstance(
            result,
            dict,
        ):

            raise TypeError(
                "Graph-AI result must be a dictionary."
            )


        with closing(
            self.get_connection()
        ) as connection:

            cursor = connection.execute(
                f"""
                INSERT INTO {self.TABLE_NAME} (

                    event_id,
                    pid,
                    process_name,
                    device_id,

                    predictor_name,
                    predictor_version,
                    model_version,
                    calibration_version,

                    operating_mode,
                    state,

                    graph_node_count,
                    graph_edge_count,

                    raw_reconstruction_error,
                    center_reconstruction_error,

                    graph_anomaly_score,
                    graph_anomaly_band,

                    graph_signal_active,
                    graph_signal_strong,

                    authoritative_alert,

                    embedding_dimension,
                    embedding_json,

                    evidence_coverage_json,
                    node_types_json,
                    edge_types_json,

                    calibration_source,
                    calibration_quality,

                    created_at
                )

                VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
                """,
                (
                    event_id,

                    result.get(
                        "pid"
                    ),

                    result.get(
                        "process_name"
                    ),

                    result.get(
                        "device_id"
                    ),

                    result.get(
                        "predictor_name"
                    ),

                    result.get(
                        "predictor_version"
                    ),

                    result.get(
                        "model_version"
                    ),

                    result.get(
                        "calibration_version"
                    ),

                    result.get(
                        "operating_mode"
                    ),

                    result.get(
                        "state"
                    ),

                    result.get(
                        "graph_node_count"
                    ),

                    result.get(
                        "graph_edge_count"
                    ),

                    result.get(
                        "raw_reconstruction_error"
                    ),

                    result.get(
                        "center_reconstruction_error"
                    ),

                    result.get(
                        "graph_anomaly_score"
                    ),

                    result.get(
                        "graph_anomaly_band"
                    ),

                    int(
                        bool(
                            result.get(
                                "graph_signal_active",
                                False,
                            )
                        )
                    ),

                    int(
                        bool(
                            result.get(
                                "graph_signal_strong",
                                False,
                            )
                        )
                    ),

                    int(
                        bool(
                            result.get(
                                "authoritative_alert",
                                False,
                            )
                        )
                    ),

                    result.get(
                        "embedding_dimension"
                    ),

                    json.dumps(
                        result.get(
                            "embedding"
                        ),
                        default=str,
                    ),

                    json.dumps(
                        result.get(
                            "ai_evidence_coverage"
                        ),
                        default=str,
                    ),

                    json.dumps(
                        result.get(
                            "graph_node_types"
                        ),
                        default=str,
                    ),

                    json.dumps(
                        result.get(
                            "graph_edge_types"
                        ),
                        default=str,
                    ),

                    result.get(
                        "calibration_source"
                    ),

                    result.get(
                        "calibration_quality"
                    ),

                    self.now_iso(),
                ),
            )


            connection.commit()


            return int(
                cursor.lastrowid
            )


    def count(
        self,
    ) -> int:

        with closing(
            self.get_connection()
        ) as connection:

            row = connection.execute(
                f"""
                SELECT COUNT(*) AS total
                FROM {self.TABLE_NAME}
                """
            ).fetchone()


        return int(
            row[
                "total"
            ]
        )


    def count_active(
        self,
    ) -> int:

        with closing(
            self.get_connection()
        ) as connection:

            row = connection.execute(
                f"""
                SELECT COUNT(*) AS total
                FROM {self.TABLE_NAME}

                WHERE graph_signal_active = 1
                """
            ).fetchone()


        return int(
            row[
                "total"
            ]
        )


    def count_strong(
        self,
    ) -> int:

        with closing(
            self.get_connection()
        ) as connection:

            row = connection.execute(
                f"""
                SELECT COUNT(*) AS total
                FROM {self.TABLE_NAME}

                WHERE graph_signal_strong = 1
                """
            ).fetchone()


        return int(
            row[
                "total"
            ]
        )


    def parse_row(
        self,
        row,
    ):

        if row is None:

            return None


        result = dict(
            row
        )


        json_fields = {

            "embedding_json":
                "embedding",

            "evidence_coverage_json":
                "ai_evidence_coverage",

            "node_types_json":
                "graph_node_types",

            "edge_types_json":
                "graph_edge_types",
        }


        for (
            source,
            target,
        ) in json_fields.items():

            value = (
                result.pop(
                    source,
                    None,
                )
            )


            try:

                result[
                    target
                ] = (
                    json.loads(
                        value
                    )

                    if value

                    else None
                )


            except (
                TypeError,
                json.JSONDecodeError,
            ):

                result[
                    target
                ] = None


        result[
            "graph_signal_active"
        ] = bool(
            result.get(
                "graph_signal_active"
            )
        )


        result[
            "graph_signal_strong"
        ] = bool(
            result.get(
                "graph_signal_strong"
            )
        )


        result[
            "authoritative_alert"
        ] = bool(
            result.get(
                "authoritative_alert"
            )
        )


        return result


    def get_recent(
        self,
        limit: int = 100,
    ) -> List[
        Dict[str, Any]
    ]:

        with closing(
            self.get_connection()
        ) as connection:

            rows = connection.execute(
                f"""
                SELECT *
                FROM {self.TABLE_NAME}

                ORDER BY
                    result_id DESC

                LIMIT ?
                """,
                (
                    int(
                        limit
                    ),
                ),
            ).fetchall()


        return [

            self.parse_row(
                row
            )

            for row in rows
        ]


    def get_latest_for_pid(
        self,
        pid,
    ):

        with closing(
            self.get_connection()
        ) as connection:

            row = connection.execute(
                f"""
                SELECT *
                FROM {self.TABLE_NAME}

                WHERE pid = ?

                ORDER BY
                    result_id DESC

                LIMIT 1
                """,
                (
                    pid,
                ),
            ).fetchone()


        return (
            self.parse_row(
                row
            )
        )


    def close(
        self,
    ):

        return None