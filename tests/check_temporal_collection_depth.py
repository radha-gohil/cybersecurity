from __future__ import annotations

from pathlib import Path
import sqlite3
import sys

from collections import defaultdict
from datetime import datetime


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


DATABASE_PATH = (
    PROJECT_ROOT
    / "data"
    / "database"
    / "sentinel_endpoint.db"
)


SEQUENCE_LENGTH = 8


# ================================================================
# TIMESTAMP
# ================================================================

def parse_timestamp(
    value,
):

    if not value:

        return None


    text = str(
        value
    )


    if text.endswith("Z"):

        text = (
            text[:-1]
            + "+00:00"
        )


    try:

        return datetime.fromisoformat(
            text
        )

    except ValueError:

        return None


# ================================================================
# MAIN
# ================================================================

def main():

    print()

    print(
        "=" * 82
    )

    print(
        "SENTINEL-X TEMPORAL COLLECTION DEPTH CHECK"
    )

    print(
        "=" * 82
    )


    connection = sqlite3.connect(
        DATABASE_PATH
    )


    connection.row_factory = (
        sqlite3.Row
    )


    # ============================================================
    # FEATURE RECORDS HAVING BOTH MODELS
    # ============================================================

    rows = (
        connection.execute(
            """
            SELECT

                f.id AS feature_record_id,

                f.pid,

                f.process_name,

                f.extracted_at

            FROM process_behavior_features AS f

            INNER JOIN (

                SELECT
                    feature_record_id

                FROM behavior_model_results

                WHERE model_family IN (
                    'isolation_forest',
                    'autoencoder'
                )

                GROUP BY feature_record_id

                HAVING COUNT(
                    DISTINCT model_family
                ) = 2

            ) AS paired

                ON paired.feature_record_id = f.id

            ORDER BY
                f.extracted_at ASC,
                f.id ASC
            """
        )
        .fetchall()
    )


    connection.close()


    print()

    print(
        "Paired feature records:",
        len(
            rows
        ),
    )


    # ============================================================
    # GROUP BY PID + PROCESS
    # ============================================================

    groups = defaultdict(
        list
    )


    for row in rows:

        try:

            pid = int(
                row[
                    "pid"
                ]
            )

        except (
            TypeError,
            ValueError,
        ):

            continue


        process_name = (

            str(

                row[
                    "process_name"
                ]

                or "UNKNOWN"
            )
            .strip()
            .lower()
        )


        timestamp = (
            parse_timestamp(

                row[
                    "extracted_at"
                ]
            )
        )


        if timestamp is None:

            continue


        groups[
            (
                pid,
                process_name,
            )
        ].append(
            timestamp
        )


    # ============================================================
    # STATISTICS
    # ============================================================

    results = []


    for (
        (
            pid,
            process_name,
        ),
        timestamps,

    ) in groups.items():

        timestamps.sort()


        gaps = []


        for index in range(
            1,
            len(
                timestamps
            ),
        ):

            gap = (

                timestamps[
                    index
                ]

                - timestamps[
                    index - 1
                ]

            ).total_seconds()


            gaps.append(
                gap
            )


        span_seconds = (

            (
                timestamps[
                    -1
                ]

                - timestamps[
                    0
                ]
            ).total_seconds()

            if len(
                timestamps
            )
            > 1

            else 0.0
        )


        results.append(
            {

                "pid":
                    pid,

                "process_name":
                    process_name,

                "samples":
                    len(
                        timestamps
                    ),

                "span_seconds":
                    span_seconds,

                "minimum_gap":
                    min(
                        gaps
                    )
                    if gaps
                    else None,

                "maximum_gap":
                    max(
                        gaps
                    )
                    if gaps
                    else None,

                "average_gap":
                    (
                        sum(
                            gaps
                        )
                        / len(
                            gaps
                        )

                        if gaps

                        else None
                    ),
            }
        )


    results.sort(

        key=lambda item:
            item[
                "samples"
            ],

        reverse=True,
    )


    # ============================================================
    # REPORT
    # ============================================================

    print()

    print(
        f"{'PID':<9}"
        f"{'Process':<30}"
        f"{'Samples':>9}"
        f"{'Span(s)':>12}"
        f"{'AvgGap':>12}"
    )


    print(
        "-" * 82
    )


    for item in results[
        :30
    ]:

        average_gap = (

            f"{item['average_gap']:.2f}"

            if item[
                "average_gap"
            ]
            is not None

            else "-"
        )


        print(

            f"{item['pid']:<9}"

            f"{item['process_name']:<30}"

            f"{item['samples']:>9}"

            f"{item['span_seconds']:>12.2f}"

            f"{average_gap:>12}"
        )


    # ============================================================
    # DEPTH DISTRIBUTION
    # ============================================================

    at_least_2 = sum(

        1

        for item in results

        if item[
            "samples"
        ] >= 2
    )


    at_least_4 = sum(

        1

        for item in results

        if item[
            "samples"
        ] >= 4
    )


    at_least_8 = sum(

        1

        for item in results

        if item[
            "samples"
        ] >= SEQUENCE_LENGTH
    )


    print()

    print(
        "=" * 82
    )

    print(
        "TEMPORAL DEPTH"
    )

    print(
        "=" * 82
    )


    print(
        "PID/process groups:",
        len(
            results
        ),
    )


    print(
        "Groups with >= 2 samples:",
        at_least_2,
    )


    print(
        "Groups with >= 4 samples:",
        at_least_4,
    )


    print(
        "Groups with >= 8 samples:",
        at_least_8,
    )


    print()

    print(
        "=" * 82
    )

    print(
        "RESULT"
    )

    print(
        "=" * 82
    )


    if at_least_8 > 0:

        print()

        print(
            "TEMPORAL COLLECTION IS WORKING."
        )

        print()

        print(
            "At least one process has enough repeated "
            "samples for an 8-step sequence."
        )


    elif at_least_2 > 0:

        print()

        print(
            "TEMPORAL COLLECTION IS WORKING, "
            "BUT MORE REPEATED SAMPLES ARE NEEDED."
        )


    else:

        print()

        print(
            "ONLY SINGLE-SNAPSHOT DATA IS CURRENTLY PRESENT."
        )

        print()

        print(
            "The agent has not yet accumulated repeated "
            "paired observations for stable processes."
        )


if __name__ == "__main__":

    main()