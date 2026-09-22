import json
import sqlite3

from pathlib import Path
from datetime import datetime, timezone
from contextlib import closing


class SOCCaseStore:

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

    def now_iso(
        self,
    ):

        return datetime.now(
            timezone.utc
        ).isoformat()

    # ============================================================
    # CONNECTION
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
    # INITIALIZE
    # ============================================================

    def initialize(
        self,
    ):

        # --------------------------------------------------------
        # closing() guarantees the SQLite connection is physically
        # closed when the block exits.
        # --------------------------------------------------------

        with closing(
            self.get_connection()
        ) as conn:

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS soc_cases (

                    incident_id TEXT PRIMARY KEY,

                    ticket_id TEXT,

                    case_status TEXT NOT NULL,

                    risk_score INTEGER,

                    risk_level TEXT,

                    selected_plan TEXT,

                    predicted_residual_risk INTEGER,

                    decision_json TEXT,

                    explanation_json TEXT,

                    ticket_json TEXT,

                    mitigation_verification_json TEXT,

                    created_at TEXT NOT NULL,

                    updated_at TEXT NOT NULL
                )
                """
            )

            # ====================================================
            # SCHEMA MIGRATION
            #
            # Existing databases may not yet contain the
            # mitigation verification column.
            # ====================================================

            columns = {

                row[
                    "name"
                ]

                for row in conn.execute(
                    """
                    PRAGMA table_info(soc_cases)
                    """
                ).fetchall()
            }

            if (
                "mitigation_verification_json"
                not in columns
            ):

                conn.execute(
                    """
                    ALTER TABLE soc_cases
                    ADD COLUMN mitigation_verification_json TEXT
                    DEFAULT '{}'
                    """
                )

            # ====================================================
            # INDEXES
            # ====================================================

            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_soc_cases_ticket_id
                ON soc_cases(ticket_id)
                """
            )

            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_soc_cases_status
                ON soc_cases(case_status)
                """
            )

            conn.commit()

    # ============================================================
    # JSON HELPERS
    # ============================================================

    def to_json(
        self,
        value,
    ):

        return json.dumps(
            value,
            default=str,
            ensure_ascii=False,
        )

    def from_json(
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
    # SAVE CASE
    # ============================================================

    def save_case(
        self,
        case: dict,
    ):

        if not isinstance(
            case,
            dict,
        ):

            raise TypeError(
                "case must be a dictionary."
            )

        # ========================================================
        # INCIDENT ID
        # ========================================================

        incident_id = (
            case.get(
                "incident_id"
            )
        )

        if not incident_id:

            raise ValueError(
                "incident_id is required."
            )

        # ========================================================
        # CASE COMPONENTS
        # ========================================================

        decision = (
            case.get(
                "decision",
                {},
            )
            or {}
        )

        explanation = (
            case.get(
                "explanation",
                {},
            )
            or {}
        )

        ticket_data = (
            case.get(
                "ticket_data",
                {},
            )
            or {}
        )

        mitigation_verification = (
            case.get(
                "mitigation_verification",
                {},
            )
            or {}
        )

        best_plan = (
            decision.get(
                "best_plan",
                {},
            )
            or {}
        )

        # ========================================================
        # TIMESTAMPS
        # ========================================================

        now = (
            self.now_iso()
        )

        existing = (
            self.get_case(
                incident_id
            )
        )

        created_at = (

            existing.get(
                "created_at"
            )

            if existing

            else now
        )

        # ========================================================
        # DATABASE WRITE
        # ========================================================

        with closing(
            self.get_connection()
        ) as conn:

            conn.execute(
                """
                INSERT OR REPLACE INTO soc_cases (

                    incident_id,

                    ticket_id,

                    case_status,

                    risk_score,

                    risk_level,

                    selected_plan,

                    predicted_residual_risk,

                    decision_json,

                    explanation_json,

                    ticket_json,

                    mitigation_verification_json,

                    created_at,

                    updated_at

                ) VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
                """,

                (
                    incident_id,

                    ticket_data.get(
                        "ticket_id"
                    ),

                    case.get(
                        "status",
                        "UNKNOWN",
                    ),

                    ticket_data.get(
                        "risk_score",
                        decision.get(
                            "initial_risk_score",
                            0,
                        ),
                    ),

                    ticket_data.get(
                        "risk_level",
                        decision.get(
                            "initial_risk_level",
                            "INFO",
                        ),
                    ),

                    best_plan.get(
                        "plan_name"
                    ),

                    best_plan.get(
                        "predicted_residual_risk"
                    ),

                    self.to_json(
                        decision
                    ),

                    self.to_json(
                        explanation
                    ),

                    self.to_json(
                        ticket_data
                    ),

                    self.to_json(
                        mitigation_verification
                    ),

                    created_at,

                    now,
                ),
            )

            conn.commit()

        return incident_id

    # ============================================================
    # GET CASE
    # ============================================================

    def get_case(
        self,
        incident_id: str,
    ):

        with closing(
            self.get_connection()
        ) as conn:

            row = conn.execute(
                """
                SELECT *
                FROM soc_cases
                WHERE incident_id = ?
                """,
                (
                    incident_id,
                ),
            ).fetchone()

        if row is None:

            return None

        data = dict(
            row
        )

        return {

            "incident_id":
                data[
                    "incident_id"
                ],

            "ticket_id":
                data[
                    "ticket_id"
                ],

            "status":
                data[
                    "case_status"
                ],

            "risk_score":
                data[
                    "risk_score"
                ],

            "risk_level":
                data[
                    "risk_level"
                ],

            "selected_plan":
                data[
                    "selected_plan"
                ],

            "predicted_residual_risk":
                data[
                    "predicted_residual_risk"
                ],

            "decision":
                self.from_json(
                    data[
                        "decision_json"
                    ],
                    {},
                ),

            "explanation":
                self.from_json(
                    data[
                        "explanation_json"
                    ],
                    {},
                ),

            "ticket_data":
                self.from_json(
                    data[
                        "ticket_json"
                    ],
                    {},
                ),

            "mitigation_verification":
                self.from_json(
                    data.get(
                        "mitigation_verification_json"
                    ),
                    {},
                ),

            "created_at":
                data[
                    "created_at"
                ],

            "updated_at":
                data[
                    "updated_at"
                ],
        }

    # ============================================================
    # LIST CASES
    # ============================================================

    def list_cases(
        self,
        limit=100,
    ):

        limit = max(
            1,
            int(
                limit
            ),
        )

        with closing(
            self.get_connection()
        ) as conn:

            rows = conn.execute(
                """
                SELECT

                    incident_id,

                    ticket_id,

                    case_status,

                    risk_score,

                    risk_level,

                    selected_plan,

                    predicted_residual_risk,

                    created_at,

                    updated_at

                FROM soc_cases

                ORDER BY updated_at DESC

                LIMIT ?
                """,
                (
                    limit,
                ),
            ).fetchall()

        return [

            dict(
                row
            )

            for row in rows
        ]

    # ============================================================
    # UPDATE STATUS
    # ============================================================

    def update_status(
        self,
        incident_id: str,
        status: str,
    ):

        with closing(
            self.get_connection()
        ) as conn:

            conn.execute(
                """
                UPDATE soc_cases

                SET

                    case_status = ?,

                    updated_at = ?

                WHERE incident_id = ?
                """,

                (
                    status,

                    self.now_iso(),

                    incident_id,
                ),
            )

            conn.commit()

    # ============================================================
    # COUNT
    # ============================================================

    def count(
        self,
    ):

        with closing(
            self.get_connection()
        ) as conn:

            row = conn.execute(
                """
                SELECT COUNT(*) AS total
                FROM soc_cases
                """
            ).fetchone()

        return int(
            row[
                "total"
            ]
        )