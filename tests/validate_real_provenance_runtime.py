from __future__ import annotations

import sqlite3
import sys

from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional


# ================================================================
# PROJECT ROOT
# ================================================================

PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[1]
)


if str(PROJECT_ROOT) not in sys.path:

    sys.path.insert(
        0,
        str(PROJECT_ROOT),
    )


# ================================================================
# SENTINEL-X IMPORTS
# ================================================================

from ai_detection.graph.provenance_graph_store import (
    ProvenanceGraphStore,
    DEFAULT_DATABASE_PATH,
)

from endpoint.runtime.collector_heartbeat import (
    get_collector_heartbeats,
)


# ================================================================
# CONFIGURATION
# ================================================================

EXPECTED_COLLECTORS = {
    "process",
    "file",
    "network",
    "registry",
}


CORE_CATEGORIES = {
    "PROCESS",
    "FILE",
    "NETWORK",
    "REGISTRY",
}


CORE_SOURCE_HINTS = {
    "process_monitor",
    "file_monitor",
    "network_monitor",
    "registry_monitor",
}


MAX_HEARTBEAT_AGE_SECONDS = 20.0


# ================================================================
# DISPLAY
# ================================================================

def heading(
    title: str,
):

    print()

    print(
        "=" * 100
    )

    print(
        title
    )

    print(
        "=" * 100
    )


# ================================================================
# DATETIME
# ================================================================

def parse_datetime(
    value,
) -> Optional[datetime]:

    if not value:

        return None


    try:

        parsed = datetime.fromisoformat(

            str(
                value
            ).replace(
                "Z",
                "+00:00",
            )
        )


        if parsed.tzinfo is None:

            parsed = parsed.replace(
                tzinfo=timezone.utc
            )


        return parsed.astimezone(
            timezone.utc
        )


    except (
        TypeError,
        ValueError,
    ):

        return None


# ================================================================
# DATABASE CONNECTION
# ================================================================

def get_connection():

    connection = sqlite3.connect(
        str(
            DEFAULT_DATABASE_PATH
        ),
        timeout=15,
    )


    connection.row_factory = (
        sqlite3.Row
    )


    return connection


# ================================================================
# CHECK TABLE EXISTS
# ================================================================

def table_exists(
    table_name: str,
) -> bool:

    with closing(
        get_connection()
    ) as connection:

        row = connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE
                type = 'table'
                AND name = ?
            """,
            (
                table_name,
            ),
        ).fetchone()


    return (
        row is not None
    )


# ================================================================
# HEARTBEATS
# ================================================================

def validate_collectors():

    heading(
        "1. REAL ENDPOINT COLLECTORS"
    )


    heartbeats = (
        get_collector_heartbeats()
    )


    now = datetime.now(
        timezone.utc
    )


    checks = {}


    print()

    print(
        f"{'Collector':<15}"
        f"{'Status':<12}"
        f"{'Thread':<10}"
        f"{'Age':<12}"
        f"{'Result'}"
    )


    print(
        "-" * 65
    )


    for name in sorted(
        EXPECTED_COLLECTORS
    ):

        heartbeat = (
            heartbeats.get(
                name
            )
        )


        if not heartbeat:

            checks[
                name
            ] = False


            print(
                f"{name:<15}"
                f"{'MISSING':<12}"
                f"{'-':<10}"
                f"{'-':<12}"
                f"REVIEW"
            )


            continue


        status = str(

            heartbeat.get(
                "status",
                "",
            )

        ).upper()


        thread_alive = bool(

            heartbeat.get(
                "thread_alive",
                False,
            )
        )


        last_seen = (
            parse_datetime(
                heartbeat.get(
                    "last_seen"
                )
            )
        )


        age = None


        if last_seen is not None:

            age = (
                now
                - last_seen
            ).total_seconds()


        fresh = (

            age is not None

            and

            age
            <= MAX_HEARTBEAT_AGE_SECONDS
        )


        no_error = (

            not heartbeat.get(
                "error"
            )
        )


        passed = (

            status == "ACTIVE"

            and

            thread_alive

            and

            fresh

            and

            no_error
        )


        checks[
            name
        ] = passed


        age_text = (

            f"{age:.1f}s"

            if age is not None

            else "UNKNOWN"
        )


        print(
            f"{name:<15}"
            f"{status:<12}"
            f"{str(thread_alive):<10}"
            f"{age_text:<12}"
            f"{'PASS' if passed else 'REVIEW'}"
        )


        if heartbeat.get(
            "error"
        ):

            print(
                "  Error:",
                heartbeat.get(
                    "error"
                ),
            )


    return {
        "passed":
            all(
                checks.values()
            ),

        "checks":
            checks,
    }


# ================================================================
# VERIFY TABLES
# ================================================================

def validate_graph_tables():

    heading(
        "2. PROVENANCE DATABASE TABLES"
    )


    required_tables = [

        "provenance_events",

        "provenance_nodes",

        "provenance_edges",
    ]


    checks = {}


    for table in required_tables:

        exists = (
            table_exists(
                table
            )
        )


        checks[
            table
        ] = exists


        print(
            f"{table:<30}: "
            f"{'PASS' if exists else 'MISSING'}"
        )


    return {
        "passed":
            all(
                checks.values()
            ),

        "checks":
            checks,
    }


# ================================================================
# GRAPH SUMMARY
# ================================================================

def validate_graph_summary():

    heading(
        "3. REAL PROVENANCE GRAPH SUMMARY"
    )


    store = (
        ProvenanceGraphStore()
    )


    summary = (
        store.get_summary()
    )


    print()

    print(
        "Database:",
        DEFAULT_DATABASE_PATH,
    )


    print()

    print(
        "Events:",
        summary.get(
            "event_count"
        ),
    )


    print(
        "Nodes:",
        summary.get(
            "node_count"
        ),
    )


    print(
        "Edges:",
        summary.get(
            "edge_count"
        ),
    )


    print()

    print(
        "Node types:"
    )


    for (
        node_type,
        count,
    ) in summary.get(
        "node_types",
        {}
    ).items():

        print(
            f"{node_type:<22}: "
            f"{count}"
        )


    print()

    print(
        "Edge types:"
    )


    for (
        edge_type,
        count,
    ) in summary.get(
        "edge_types",
        {}
    ).items():

        print(
            f"{edge_type:<26}: "
            f"{count}"
        )


    checks = {

        "events_exist":
            (
                summary.get(
                    "event_count",
                    0,
                )
                > 0
            ),

        "nodes_exist":
            (
                summary.get(
                    "node_count",
                    0,
                )
                > 0
            ),

        "edges_exist":
            (
                summary.get(
                    "edge_count",
                    0,
                )
                > 0
            ),

        "event_nodes_exist":
            (
                summary.get(
                    "node_types",
                    {}
                ).get(
                    "EVENT",
                    0,
                )
                > 0
            ),
    }


    print()

    for (
        name,
        passed,
    ) in checks.items():

        print(
            f"{name:<38}: "
            f"{'PASS' if passed else 'REVIEW'}"
        )


    return {
        "passed":
            all(
                checks.values()
            ),

        "summary":
            summary,
    }


# ================================================================
# RECENT PROVENANCE EVENTS
# ================================================================

def get_recent_events(
    limit: int = 30,
):

    with closing(
        get_connection()
    ) as connection:

        rows = connection.execute(
            """
            SELECT
                event_id,
                event_type,
                event_category,
                source,
                severity,
                device_id,
                timestamp,
                created_at

            FROM provenance_events

            ORDER BY created_at DESC

            LIMIT ?
            """,
            (
                int(
                    limit
                ),
            ),
        ).fetchall()


    return [

        dict(
            row
        )

        for row in rows
    ]


# ================================================================
# REAL TELEMETRY VALIDATION
# ================================================================

def validate_real_events():

    heading(
        "4. RECENT REAL PROVENANCE EVENTS"
    )


    events = (
        get_recent_events(
            limit=50
        )
    )


    if not events:

        print(
            "No provenance events found."
        )


        return {
            "passed":
                False,

            "events":
                [],
        }


    print()

    print(
        f"{'Type':<32}"
        f"{'Category':<12}"
        f"{'Source':<26}"
        f"{'Severity'}"
    )


    print(
        "-" * 85
    )


    for event in events[
        :20
    ]:

        print(
            f"{str(event.get('event_type')):<32}"
            f"{str(event.get('event_category')):<12}"
            f"{str(event.get('source')):<26}"
            f"{str(event.get('severity'))}"
        )


    observed_categories = {

        str(
            event.get(
                "event_category",
                "",
            )
        ).upper()

        for event in events
    }


    observed_sources = {

        str(
            event.get(
                "source",
                "",
            )
        ).lower()

        for event in events
    }


    core_categories_seen = (
        observed_categories
        &
        CORE_CATEGORIES
    )


    production_source_seen = any(

        any(
            hint in source

            for hint in CORE_SOURCE_HINTS
        )

        for source in observed_sources
    )


    print()

    print(
        "Core categories seen:",
        sorted(
            core_categories_seen
        ),
    )


    print(
        "Production collector source seen:",
        (
            "PASS"

            if production_source_seen

            else "REVIEW"
        ),
    )


    # ------------------------------------------------------------
    # Full coverage is useful information but NOT required for
    # runtime pass because file/registry changes may simply not
    # happen during a short validation window.
    # ------------------------------------------------------------

    full_category_coverage = (

        CORE_CATEGORIES
        .issubset(
            observed_categories
        )
    )


    print(
        "All four telemetry categories observed:",
        (
            "PASS"

            if full_category_coverage

            else "PARTIAL"
        ),
    )


    return {
        "passed":
            (
                len(
                    events
                )
                > 0

                and

                len(
                    core_categories_seen
                )
                > 0

                and

                production_source_seen
            ),

        "events":
            events,

        "core_categories_seen":
            core_categories_seen,

        "full_category_coverage":
            full_category_coverage,
    }


# ================================================================
# EDGE INTEGRITY
# ================================================================

def validate_edge_integrity():

    heading(
        "5. GRAPH EDGE INTEGRITY"
    )


    with closing(
        get_connection()
    ) as connection:

        total_edges = connection.execute(
            """
            SELECT COUNT(*) AS total
            FROM provenance_edges
            """
        ).fetchone()[
            "total"
        ]


        broken_source_edges = (
            connection.execute(
                """
                SELECT COUNT(*) AS total

                FROM provenance_edges e

                LEFT JOIN provenance_nodes n
                    ON
                    e.source_node_id
                    =
                    n.node_id

                WHERE
                    n.node_id IS NULL
                """
            )
            .fetchone()[
                "total"
            ]
        )


        broken_target_edges = (
            connection.execute(
                """
                SELECT COUNT(*) AS total

                FROM provenance_edges e

                LEFT JOIN provenance_nodes n
                    ON
                    e.target_node_id
                    =
                    n.node_id

                WHERE
                    n.node_id IS NULL
                """
            )
            .fetchone()[
                "total"
            ]
        )


    print()

    print(
        "Total edges:",
        total_edges,
    )


    print(
        "Missing source nodes:",
        broken_source_edges,
    )


    print(
        "Missing target nodes:",
        broken_target_edges,
    )


    passed = (

        total_edges > 0

        and

        broken_source_edges == 0

        and

        broken_target_edges == 0
    )


    print()

    print(
        "Edge integrity:",
        (
            "PASS"

            if passed

            else "REVIEW"
        ),
    )


    return {
        "passed":
            passed,
    }


# ================================================================
# PROCESS RELATIONSHIP CHECK
# ================================================================

def validate_process_relationships():

    heading(
        "6. PROCESS-CENTERED RELATIONSHIPS"
    )


    with closing(
        get_connection()
    ) as connection:

        rows = connection.execute(
            """
            SELECT
                e.edge_type,
                COUNT(*) AS total

            FROM provenance_edges e

            INNER JOIN provenance_nodes source
                ON
                source.node_id
                =
                e.source_node_id

            WHERE
                source.node_type = 'PROCESS'

            GROUP BY
                e.edge_type

            ORDER BY
                e.edge_type
            """
        ).fetchall()


    relationship_counts = {

        row[
            "edge_type"
        ]:
            int(
                row[
                    "total"
                ]
            )

        for row in rows
    }


    for (
        relationship,
        count,
    ) in relationship_counts.items():

        print(
            f"{relationship:<28}: "
            f"{count}"
        )


    process_relationships_exist = any(

        relationship_counts.get(
            edge_type,
            0,
        )
        > 0

        for edge_type in {

            "SPAWNED",

            "CONNECTED_TO",

            "TOUCHED_FILE",

            "MODIFIED_REGISTRY",
        }
    )


    print()

    print(
        "Process-centered relationships:",
        (
            "PASS"

            if process_relationships_exist

            else "REVIEW"
        ),
    )


    return {
        "passed":
            process_relationships_exist,

        "relationships":
            relationship_counts,
    }


# ================================================================
# LATEST PROCESS SUBGRAPH PREVIEW
# ================================================================

def show_process_preview():

    heading(
        "7. LATEST PROCESS GRAPH PREVIEW"
    )


    with closing(
        get_connection()
    ) as connection:

        process = connection.execute(
            """
            SELECT
                node_id,
                label,
                properties,
                last_seen

            FROM provenance_nodes

            WHERE
                node_type = 'PROCESS'

            ORDER BY
                last_seen DESC

            LIMIT 1
            """
        ).fetchone()


        if process is None:

            print(
                "No PROCESS node available."
            )


            return {
                "passed":
                    False,
            }


        edges = connection.execute(
            """
            SELECT
                edge_type,
                source_node_id,
                target_node_id,
                event_id,
                created_at

            FROM provenance_edges

            WHERE
                source_node_id = ?
                OR target_node_id = ?

            ORDER BY
                created_at DESC

            LIMIT 20
            """,
            (
                process[
                    "node_id"
                ],

                process[
                    "node_id"
                ],
            ),
        ).fetchall()


    print()

    print(
        "Process node:",
        process[
            "node_id"
        ],
    )


    print(
        "Label:",
        process[
            "label"
        ],
    )


    print(
        "Last seen:",
        process[
            "last_seen"
        ],
    )


    print()

    print(
        "Connected relationships:"
    )


    for edge in edges:

        print(
            " ",
            edge[
                "edge_type"
            ],
            "|",
            edge[
                "source_node_id"
            ],
            "->",
            edge[
                "target_node_id"
            ],
        )


    return {
        "passed":
            True,

        "relationship_count":
            len(
                edges
            ),
    }


# ================================================================
# MAIN
# ================================================================

def main():

    heading(
        "SENTINEL-X REAL PROVENANCE GRAPH RUNTIME VALIDATION"
    )


    print()

    print(
        "Production database:"
    )


    print(
        DEFAULT_DATABASE_PATH
    )


    print()

    print(
        "Run this while the real SentinelAgent is active:"
    )


    print(
        "python -m endpoint.agent.sentinel_agent"
    )


    # ============================================================
    # VALIDATIONS
    # ============================================================

    collectors = (
        validate_collectors()
    )


    tables = (
        validate_graph_tables()
    )


    graph = (
        validate_graph_summary()
    )


    events = (
        validate_real_events()
    )


    integrity = (
        validate_edge_integrity()
    )


    relationships = (
        validate_process_relationships()
    )


    preview = (
        show_process_preview()
    )


    # ============================================================
    # FINAL CHECKS
    # ============================================================

    checks = {

        "collector_runtime":
            collectors[
                "passed"
            ],

        "provenance_tables":
            tables[
                "passed"
            ],

        "graph_persistence":
            graph[
                "passed"
            ],

        "real_telemetry_ingestion":
            events[
                "passed"
            ],

        "edge_integrity":
            integrity[
                "passed"
            ],

        "process_relationships":
            relationships[
                "passed"
            ],

        "process_preview":
            preview[
                "passed"
            ],
    }


    heading(
        "FINAL REAL PROVENANCE RUNTIME STATUS"
    )


    for (
        name,
        passed,
    ) in checks.items():

        print(
            f"{name:<40}: "
            f"{'PASS' if passed else 'REVIEW'}"
        )


    overall_pass = all(
        checks.values()
    )


    print()

    print(
        "=" * 100
    )


    if overall_pass:

        print(
            "SENTINEL-X REAL PROVENANCE GRAPH RUNTIME: PASS"
        )


        print()

        print(
            "Real endpoint telemetry is now feeding "
            "the persistent provenance graph."
        )


    else:

        print(
            "SENTINEL-X REAL PROVENANCE GRAPH RUNTIME: "
            "REVIEW REQUIRED"
        )


        print()

        print(
            "Check the REVIEW items above before "
            "starting Graph-AI preparation."
        )


    print(
        "=" * 100
    )


    # ============================================================
    # COVERAGE NOTE
    # ============================================================

    if (
        events.get(
            "passed"
        )

        and

        not events.get(
            "full_category_coverage"
        )
    ):

        print()

        print(
            "NOTE:"
        )


        print(
            "The runtime integration is valid, but not all "
            "PROCESS/FILE/NETWORK/REGISTRY categories have "
            "generated recent events yet."
        )


        print(
            "This is normal if no file or registry changes "
            "occurred during the live run."
        )


if __name__ == "__main__":

    main()