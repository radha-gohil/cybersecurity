import sqlite3
from pathlib import Path

from response.soc_ticket import SOCTicket


class SOCTicketStore:

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
    # INITIALIZE TABLE
    # ============================================================

    def initialize(self):

        with self.get_connection() as conn:

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS soc_tickets (

                    ticket_id TEXT PRIMARY KEY,

                    incident_id TEXT NOT NULL,

                    title TEXT NOT NULL,

                    priority TEXT NOT NULL,

                    risk_score INTEGER NOT NULL,

                    risk_level TEXT NOT NULL,

                    selected_plan TEXT,

                    predicted_residual_risk INTEGER,

                    operational_impact TEXT,

                    explanation TEXT,

                    approval_required INTEGER NOT NULL DEFAULT 0,

                    approval_status TEXT,

                    assigned_analyst TEXT,

                    status TEXT NOT NULL,

                    created_at TEXT NOT NULL,

                    updated_at TEXT NOT NULL
                )
                """
            )


            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_soc_tickets_incident_id
                ON soc_tickets(incident_id)
                """
            )


            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_soc_tickets_priority
                ON soc_tickets(priority)
                """
            )


            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_soc_tickets_status
                ON soc_tickets(status)
                """
            )


            conn.commit()


    # ============================================================
    # SAVE TICKET
    # ============================================================

    def save_ticket(
        self,
        ticket: SOCTicket,
    ):

        if not isinstance(
            ticket,
            SOCTicket,
        ):

            raise TypeError(
                "ticket must be an SOCTicket."
            )


        data = ticket.to_dict()


        with self.get_connection() as conn:

            conn.execute(
                """
                INSERT OR REPLACE INTO soc_tickets (

                    ticket_id,
                    incident_id,
                    title,
                    priority,
                    risk_score,
                    risk_level,
                    selected_plan,
                    predicted_residual_risk,
                    operational_impact,
                    explanation,
                    approval_required,
                    approval_status,
                    assigned_analyst,
                    status,
                    created_at,
                    updated_at

                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,

                (
                    data[
                        "ticket_id"
                    ],

                    data[
                        "incident_id"
                    ],

                    data[
                        "title"
                    ],

                    data[
                        "priority"
                    ],

                    data[
                        "risk_score"
                    ],

                    data[
                        "risk_level"
                    ],

                    data[
                        "selected_plan"
                    ],

                    data[
                        "predicted_residual_risk"
                    ],

                    data[
                        "operational_impact"
                    ],

                    data[
                        "explanation"
                    ],

                    1
                    if data[
                        "approval_required"
                    ]
                    else 0,

                    data[
                        "approval_status"
                    ],

                    data[
                        "assigned_analyst"
                    ],

                    data[
                        "status"
                    ],

                    data[
                        "created_at"
                    ],

                    data[
                        "updated_at"
                    ],
                ),
            )


            conn.commit()


        return data[
            "ticket_id"
        ]


    # ============================================================
    # GET TICKET
    # ============================================================

    def get_ticket(
        self,
        ticket_id: str,
    ):

        with self.get_connection() as conn:

            row = conn.execute(
                """
                SELECT *
                FROM soc_tickets
                WHERE ticket_id = ?
                """,
                (
                    ticket_id,
                ),
            ).fetchone()


        if row is None:

            return None


        return dict(
            row
        )


    # ============================================================
    # GET BY INCIDENT
    # ============================================================

    def get_by_incident(
        self,
        incident_id: str,
    ):

        with self.get_connection() as conn:

            rows = conn.execute(
                """
                SELECT *
                FROM soc_tickets
                WHERE incident_id = ?
                ORDER BY created_at DESC
                """,
                (
                    incident_id,
                ),
            ).fetchall()


        return [
            dict(row)
            for row in rows
        ]


    # ============================================================
    # LIST TICKETS
    # ============================================================

    def list_tickets(
        self,
        limit=100,
    ):

        with self.get_connection() as conn:

            rows = conn.execute(
                """
                SELECT *
                FROM soc_tickets
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (
                    int(limit),
                ),
            ).fetchall()


        return [
            dict(row)
            for row in rows
        ]


    # ============================================================
    # UPDATE STATUS
    # ============================================================

    def update_status(
        self,
        ticket_id: str,
        status: str,
        updated_at: str,
    ):

        with self.get_connection() as conn:

            conn.execute(
                """
                UPDATE soc_tickets

                SET
                    status = ?,
                    updated_at = ?

                WHERE ticket_id = ?
                """,

                (
                    status,
                    updated_at,
                    ticket_id,
                ),
            )


            conn.commit()


    # ============================================================
    # COUNT TICKETS
    # ============================================================

    def count(self):

        with self.get_connection() as conn:

            row = conn.execute(
                """
                SELECT COUNT(*) AS total
                FROM soc_tickets
                """
            ).fetchone()


        return int(
            row[
                "total"
            ]
        )