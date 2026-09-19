import json
import sqlite3
from pathlib import Path

from response.response_action import (
    ResponseAction,
)


class ResponseActionStore:

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
    # INITIALIZE DATABASE TABLE
    # ============================================================

    def initialize(self):

        with self.get_connection() as conn:

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS response_actions (

                    action_id TEXT PRIMARY KEY,

                    incident_id TEXT NOT NULL,

                    action_type TEXT NOT NULL,

                    risk_level TEXT,

                    approval_required INTEGER,

                    approval_status TEXT,

                    execution_status TEXT,

                    policy_decision TEXT,

                    requested_by TEXT,

                    reason TEXT,

                    target_json TEXT,

                    audit_history_json TEXT,

                    created_at TEXT,

                    updated_at TEXT
                )
                """
            )


            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_response_actions_incident_id
                ON response_actions(incident_id)
                """
            )


            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_response_actions_approval
                ON response_actions(approval_status)
                """
            )


            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_response_actions_execution
                ON response_actions(execution_status)
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
        default,
    ):

        if not value:

            return default


        try:

            return json.loads(
                value
            )

        except (
            TypeError,
            json.JSONDecodeError,
        ):

            return default


    # ============================================================
    # SAVE RESPONSE ACTION
    # ============================================================

    def save_action(
        self,
        action: ResponseAction,
    ):

        if not isinstance(
            action,
            ResponseAction,
        ):

            raise TypeError(
                "action must be a ResponseAction."
            )


        data = (
            action.to_dict()
        )


        with self.get_connection() as conn:

            conn.execute(
                """
                INSERT INTO response_actions (

                    action_id,
                    incident_id,
                    action_type,
                    risk_level,
                    approval_required,
                    approval_status,
                    execution_status,
                    policy_decision,
                    requested_by,
                    reason,
                    target_json,
                    audit_history_json,
                    created_at,
                    updated_at

                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)

                ON CONFLICT(action_id)
                DO UPDATE SET

                    incident_id =
                        excluded.incident_id,

                    action_type =
                        excluded.action_type,

                    risk_level =
                        excluded.risk_level,

                    approval_required =
                        excluded.approval_required,

                    approval_status =
                        excluded.approval_status,

                    execution_status =
                        excluded.execution_status,

                    policy_decision =
                        excluded.policy_decision,

                    requested_by =
                        excluded.requested_by,

                    reason =
                        excluded.reason,

                    target_json =
                        excluded.target_json,

                    audit_history_json =
                        excluded.audit_history_json,

                    created_at =
                        excluded.created_at,

                    updated_at =
                        excluded.updated_at
                """,

                (
                    data[
                        "action_id"
                    ],

                    data[
                        "incident_id"
                    ],

                    data[
                        "action_type"
                    ],

                    data.get(
                        "risk_level"
                    ),

                    1
                    if data.get(
                        "approval_required"
                    )
                    else 0,

                    data.get(
                        "approval_status"
                    ),

                    data.get(
                        "execution_status"
                    ),

                    data.get(
                        "policy_decision"
                    ),

                    data.get(
                        "requested_by"
                    ),

                    data.get(
                        "reason"
                    ),

                    self.encode_json(
                        data.get(
                            "target",
                            {},
                        )
                    ),

                    self.encode_json(
                        data.get(
                            "audit_history",
                            [],
                        )
                    ),

                    data.get(
                        "created_at"
                    ),

                    data.get(
                        "updated_at"
                    ),
                ),
            )


            conn.commit()


        return action.action_id


    # ============================================================
    # RECONSTRUCT RESPONSE ACTION
    # ============================================================

    def row_to_action(
        self,
        row,
    ):

        if row is None:

            return None


        data = dict(
            row
        )


        target = (
            self.decode_json(
                data.get(
                    "target_json"
                ),
                {},
            )
        )


        stored_audit_history = (
            self.decode_json(
                data.get(
                    "audit_history_json"
                ),
                [],
            )
        )


        # --------------------------------------------------------
        # IMPORTANT:
        #
        # ResponseAction.__post_init__() automatically initializes
        # approval_status depending on approval_required and also
        # creates an ACTION_CREATED audit entry.
        #
        # Therefore we first construct the object normally and then
        # restore persisted mutable state from SQLite.
        # --------------------------------------------------------

        action = ResponseAction(

            incident_id=
                data[
                    "incident_id"
                ],

            action_type=
                data[
                    "action_type"
                ],

            target=
                target,

            reason=
                data.get(
                    "reason"
                )
                or "",

            requested_by=
                data.get(
                    "requested_by"
                )
                or "PersistenceRestore",

            risk_level=
                data.get(
                    "risk_level"
                )
                or "INFO",

            approval_required=
                bool(
                    data.get(
                        "approval_required"
                    )
                ),

            policy_decision=
                data.get(
                    "policy_decision"
                )
                or "RECOMMEND_ONLY",

            action_id=
                data[
                    "action_id"
                ],
        )


        # ========================================================
        # RESTORE DATABASE STATE
        #
        # This MUST happen after construction because __post_init__
        # initializes approval status.
        # ========================================================

        stored_approval_status = (
            data.get(
                "approval_status"
            )
        )


        stored_execution_status = (
            data.get(
                "execution_status"
            )
        )


        if stored_approval_status:

            action.approval_status = (
                stored_approval_status
            )


        if stored_execution_status:

            action.execution_status = (
                stored_execution_status
            )


        # --------------------------------------------------------
        # Restore original timestamps
        # --------------------------------------------------------

        if data.get(
            "created_at"
        ):

            action.created_at = (
                data[
                    "created_at"
                ]
            )


        if data.get(
            "updated_at"
        ):

            action.updated_at = (
                data[
                    "updated_at"
                ]
            )


        # --------------------------------------------------------
        # Replace constructor-generated audit history with the
        # actual history saved in the database.
        # --------------------------------------------------------

        action.audit_history = (
            stored_audit_history
            if isinstance(
                stored_audit_history,
                list,
            )
            else []
        )


        # ========================================================
        # STATE CONSISTENCY VALIDATION
        # ========================================================

        self.validate_restored_state(
            action
        )


        return action


    # ============================================================
    # VALIDATE RESTORED STATE
    # ============================================================

    def validate_restored_state(
        self,
        action: ResponseAction,
    ):

        valid_approval_states = {

            "NOT_REQUIRED",
            "PENDING",
            "APPROVED",
            "REJECTED",
        }


        valid_execution_states = {

            "NOT_EXECUTED",
            "READY",
            "EXECUTING",
            "SUCCESS",
            "FAILED",
            "CANCELLED",
        }


        if (
            action.approval_status
            not in valid_approval_states
        ):

            raise ValueError(
                (
                    "Invalid persisted approval status: "
                    f"{action.approval_status}"
                )
            )


        if (
            action.execution_status
            not in valid_execution_states
        ):

            raise ValueError(
                (
                    "Invalid persisted execution status: "
                    f"{action.execution_status}"
                )
            )


        # --------------------------------------------------------
        # Safety invariant:
        #
        # An approval-required action must never be READY,
        # EXECUTING or SUCCESS while approval is incomplete.
        # --------------------------------------------------------

        protected_execution_states = {

            "READY",
            "EXECUTING",
            "SUCCESS",
        }


        if (

            action.approval_required

            and

            action.execution_status
            in protected_execution_states

            and

            action.approval_status
            != "APPROVED"
        ):

            raise ValueError(
                (
                    "Invalid persisted ResponseAction state: "
                    f"approval_status="
                    f"{action.approval_status}, "
                    f"execution_status="
                    f"{action.execution_status}. "
                    "An approval-required action cannot be "
                    "READY, EXECUTING or SUCCESS without "
                    "APPROVED status."
                )
            )


        # --------------------------------------------------------
        # Rejected actions must remain cancelled.
        # --------------------------------------------------------

        if (

            action.approval_status
            == "REJECTED"

            and

            action.execution_status
            != "CANCELLED"
        ):

            raise ValueError(
                (
                    "Invalid persisted ResponseAction state: "
                    "REJECTED actions must have "
                    "execution_status=CANCELLED."
                )
            )


        return True


    # ============================================================
    # GET RESPONSE ACTION
    # ============================================================

    def get_action(
        self,
        action_id: str,
    ):

        with self.get_connection() as conn:

            row = conn.execute(
                """
                SELECT *
                FROM response_actions

                WHERE action_id = ?
                """,

                (
                    action_id,
                ),
            ).fetchone()


        return self.row_to_action(
            row
        )


    # ============================================================
    # GET ACTIONS BY INCIDENT
    # ============================================================

    def get_by_incident(
        self,
        incident_id: str,
    ):

        with self.get_connection() as conn:

            rows = conn.execute(
                """
                SELECT *
                FROM response_actions

                WHERE incident_id = ?

                ORDER BY created_at ASC
                """,

                (
                    incident_id,
                ),
            ).fetchall()


        return [

            self.row_to_action(
                row
            )

            for row
            in rows
        ]


    # ============================================================
    # LIST RESPONSE ACTIONS
    # ============================================================

    def list_actions(
        self,
        limit=100,
    ):

        limit = max(
            1,
            min(
                int(
                    limit
                ),
                1000,
            ),
        )


        with self.get_connection() as conn:

            rows = conn.execute(
                """
                SELECT *
                FROM response_actions

                ORDER BY created_at DESC

                LIMIT ?
                """,

                (
                    limit,
                ),
            ).fetchall()


        return [

            self.row_to_action(
                row
            )

            for row
            in rows
        ]


    # ============================================================
    # DELETE ACTION
    # ============================================================

    def delete_action(
        self,
        action_id: str,
    ):

        with self.get_connection() as conn:

            cursor = conn.execute(
                """
                DELETE FROM response_actions

                WHERE action_id = ?
                """,

                (
                    action_id,
                ),
            )


            conn.commit()


        return (
            cursor.rowcount
            > 0
        )


    # ============================================================
    # COUNT
    # ============================================================

    def count(self):

        with self.get_connection() as conn:

            row = conn.execute(
                """
                SELECT COUNT(*) AS total
                FROM response_actions
                """
            ).fetchone()


        return int(
            row[
                "total"
            ]
        )