from __future__ import annotations

import sqlite3

from datetime import (
    datetime,
    timezone,
)

from pathlib import Path

from typing import (
    Dict,
    Any,
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
# INITIALIZE HEARTBEAT TABLE
# ================================================================

def initialize_heartbeat_table() -> None:

    with get_connection() as connection:

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS collector_heartbeats (

                collector_name TEXT PRIMARY KEY,

                status TEXT NOT NULL,

                last_seen TEXT NOT NULL,

                thread_alive INTEGER NOT NULL DEFAULT 0,

                error TEXT,

                updated_at TEXT NOT NULL

            )
            """
        )


        connection.commit()


# ================================================================
# UPDATE COLLECTOR HEARTBEAT
# ================================================================

def update_collector_heartbeat(

    collector_name: str,

    status: str = "ACTIVE",

    thread_alive: bool = True,

    error: str | None = None,

) -> None:


    initialize_heartbeat_table()


    timestamp = (
        now_iso()
    )


    normalized_collector_name = (

        str(
            collector_name
            or "unknown"
        )
        .strip()
        .lower()
    )


    normalized_status = (

        str(
            status
            or "UNKNOWN"
        )
        .strip()
        .upper()
    )


    with get_connection() as connection:

        connection.execute(

            """
            INSERT INTO collector_heartbeats (

                collector_name,

                status,

                last_seen,

                thread_alive,

                error,

                updated_at

            )

            VALUES (?, ?, ?, ?, ?, ?)

            ON CONFLICT(collector_name)

            DO UPDATE SET

                status =
                    excluded.status,

                last_seen =
                    excluded.last_seen,

                thread_alive =
                    excluded.thread_alive,

                error =
                    excluded.error,

                updated_at =
                    excluded.updated_at
            """,

            (
                normalized_collector_name,

                normalized_status,

                timestamp,

                1
                if thread_alive
                else 0,

                error,

                timestamp,
            ),
        )


        connection.commit()


# ================================================================
# MARK COLLECTOR OFFLINE
# ================================================================

def mark_collector_offline(

    collector_name: str,

    error: str | None = None,

) -> None:


    update_collector_heartbeat(

        collector_name=
            collector_name,

        status=
            "OFFLINE",

        thread_alive=
            False,

        error=
            error,
    )


# ================================================================
# GET ALL COLLECTOR HEARTBEATS
# ================================================================

def get_collector_heartbeats() -> Dict[
    str,
    Dict[
        str,
        Any,
    ],
]:


    initialize_heartbeat_table()


    with get_connection() as connection:

        rows = connection.execute(
            """
            SELECT

                collector_name,

                status,

                last_seen,

                thread_alive,

                error,

                updated_at

            FROM collector_heartbeats

            ORDER BY collector_name
            """
        ).fetchall()


    result = {}


    for row in rows:

        collector_name = (
            row[
                "collector_name"
            ]
        )


        result[
            collector_name
        ] = {

            "collector_name":
                collector_name,

            "status":
                row[
                    "status"
                ],

            "last_seen":
                row[
                    "last_seen"
                ],

            "thread_alive":
                bool(
                    row[
                        "thread_alive"
                    ]
                ),

            "error":
                row[
                    "error"
                ],

            "updated_at":
                row[
                    "updated_at"
                ],
        }


    return result


# ================================================================
# GET SINGLE COLLECTOR HEARTBEAT
# ================================================================

def get_collector_heartbeat(

    collector_name: str,

) -> Dict[
    str,
    Any,
] | None:


    initialize_heartbeat_table()


    normalized_collector_name = (

        str(
            collector_name
            or ""
        )
        .strip()
        .lower()
    )


    if not normalized_collector_name:

        return None


    with get_connection() as connection:

        row = connection.execute(

            """
            SELECT

                collector_name,

                status,

                last_seen,

                thread_alive,

                error,

                updated_at

            FROM collector_heartbeats

            WHERE collector_name = ?
            """,

            (
                normalized_collector_name,
            ),

        ).fetchone()


    if row is None:

        return None


    return {

        "collector_name":
            row[
                "collector_name"
            ],

        "status":
            row[
                "status"
            ],

        "last_seen":
            row[
                "last_seen"
            ],

        "thread_alive":
            bool(
                row[
                    "thread_alive"
                ]
            ),

        "error":
            row[
                "error"
            ],

        "updated_at":
            row[
                "updated_at"
            ],
    }


# ================================================================
# DELETE ALL HEARTBEATS
# ================================================================

def clear_collector_heartbeats() -> None:

    initialize_heartbeat_table()


    with get_connection() as connection:

        connection.execute(
            """
            DELETE FROM collector_heartbeats
            """
        )


        connection.commit()


# ================================================================
# MANUAL TEST
# ================================================================

if __name__ == "__main__":

    initialize_heartbeat_table()


    update_collector_heartbeat(

        collector_name=
            "process",

        status=
            "ACTIVE",

        thread_alive=
            True,
    )


    update_collector_heartbeat(

        collector_name=
            "file",

        status=
            "ACTIVE",

        thread_alive=
            True,
    )


    update_collector_heartbeat(

        collector_name=
            "network",

        status=
            "ACTIVE",

        thread_alive=
            True,
    )


    update_collector_heartbeat(

        collector_name=
            "registry",

        status=
            "ACTIVE",

        thread_alive=
            True,
    )


    heartbeats = (
        get_collector_heartbeats()
    )


    for (
        collector_name,
        heartbeat,
    ) in heartbeats.items():

        print(
            collector_name,
            heartbeat,
        )