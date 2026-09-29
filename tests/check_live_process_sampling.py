from __future__ import annotations

from pathlib import Path
import sqlite3
import sys
import time

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


# ================================================================
# CONFIGURATION
#
# This script is READ-ONLY.
#
# Run SENTINEL-X in another terminal:
#
# python -m endpoint.agent.sentinel_agent
#
# Then run this diagnostic.
# ================================================================

CHECK_INTERVAL_SECONDS = 10


NUMBER_OF_CHECKS = 8


EXPECTED_PRODUCTION_SAMPLE_INTERVAL = 15.0


# ================================================================
# CONNECTION
# ================================================================

def get_connection():

    connection = sqlite3.connect(
        DATABASE_PATH
    )

    connection.row_factory = (
        sqlite3.Row
    )

    return connection


# ================================================================
# TIMESTAMP PARSER
# ================================================================

def parse_timestamp(
    value,
):

    if value is None:

        return None


    text = str(
        value
    ).strip()


    if not text:

        return None


    if text.endswith(
        "Z"
    ):

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
# TOTAL COUNTS
# ================================================================

def get_counts():

    connection = (
        get_connection()
    )


    try:

        feature_count = (
            connection.execute(
                """
                SELECT COUNT(*) AS count_value
                FROM process_behavior_features
                """
            )
            .fetchone()[
                "count_value"
            ]
        )


        isolation_count = (
            connection.execute(
                """
                SELECT COUNT(*) AS count_value
                FROM behavior_model_results
                WHERE model_family = 'isolation_forest'
                """
            )
            .fetchone()[
                "count_value"
            ]
        )


        autoencoder_count = (
            connection.execute(
                """
                SELECT COUNT(*) AS count_value
                FROM behavior_model_results
                WHERE model_family = 'autoencoder'
                """
            )
            .fetchone()[
                "count_value"
            ]
        )


        return {

            "features":
                int(
                    feature_count
                ),

            "isolation":
                int(
                    isolation_count
                ),

            "autoencoder":
                int(
                    autoencoder_count
                ),
        }


    finally:

        connection.close()


# ================================================================
# RECENT PAIRED FEATURE RECORDS
# ================================================================

def get_recent_paired_records(
    limit: int = 5000,
):

    connection = (
        get_connection()
    )


    try:

        rows = (
            connection.execute(
                """
                SELECT

                    f.id,

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

                ORDER BY f.id DESC

                LIMIT ?
                """,
                (
                    limit,
                ),
            )
            .fetchall()
        )


        return [

            dict(
                row
            )

            for row
            in rows
        ]


    finally:

        connection.close()


# ================================================================
# SAME-PID TEMPORAL DEPTH
# ================================================================

def analyze_depth():

    rows = (
        get_recent_paired_records()
    )


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

                row.get(
                    "process_name"
                )

                or "UNKNOWN"
            )
            .strip()
            .lower()
        )


        timestamp = (
            parse_timestamp(

                row.get(
                    "extracted_at"
                )
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


    summaries = []


    for (
        (
            pid,
            process_name,
        ),
        timestamps,

    ) in groups.items():

        timestamps.sort()


        if len(
            timestamps
        ) < 2:

            continue


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


        summaries.append(
            {

                "pid":
                    pid,

                "process_name":
                    process_name,

                "samples":
                    len(
                        timestamps
                    ),

                "latest_gap":
                    gaps[
                        -1
                    ],

                "minimum_gap":
                    min(
                        gaps
                    ),

                "average_gap":
                    (
                        sum(
                            gaps
                        )
                        / len(
                            gaps
                        )
                    ),

                "latest_timestamp":
                    timestamps[
                        -1
                    ],
            }
        )


    summaries.sort(

        key=lambda item:
            (
                item[
                    "samples"
                ],

                item[
                    "latest_timestamp"
                ],
            ),

        reverse=True,
    )


    return summaries


# ================================================================
# MAIN
# ================================================================

def main():

    print()

    print(
        "=" * 84
    )

    print(
        "SENTINEL-X LIVE PERIODIC PROCESS SAMPLING CHECK"
    )

    print(
        "=" * 84
    )


    print()

    print(
        "This test is READ-ONLY."
    )

    print(
        "SENTINEL-X should be running in another PowerShell window."
    )

    print()

    print(
        f"Expected production sampling interval: "
        f"{EXPECTED_PRODUCTION_SAMPLE_INTERVAL:.1f} seconds"
    )


    previous_counts = None


    total_feature_growth = 0

    total_isolation_growth = 0

    total_autoencoder_growth = 0


    # ============================================================
    # REPEATED DATABASE OBSERVATION
    # ============================================================

    for check_number in range(
        1,
        NUMBER_OF_CHECKS + 1,
    ):

        counts = (
            get_counts()
        )


        print()

        print(
            "-" * 84
        )

        print(
            f"CHECK {check_number}/{NUMBER_OF_CHECKS}"
        )

        print(
            "-" * 84
        )


        print(
            "Feature records    :",
            counts[
                "features"
            ],
        )


        print(
            "Isolation results  :",
            counts[
                "isolation"
            ],
        )


        print(
            "Autoencoder results:",
            counts[
                "autoencoder"
            ],
        )


        if previous_counts is not None:

            feature_growth = (

                counts[
                    "features"
                ]

                - previous_counts[
                    "features"
                ]
            )


            isolation_growth = (

                counts[
                    "isolation"
                ]

                - previous_counts[
                    "isolation"
                ]
            )


            autoencoder_growth = (

                counts[
                    "autoencoder"
                ]

                - previous_counts[
                    "autoencoder"
                ]
            )


            total_feature_growth += max(
                0,
                feature_growth,
            )


            total_isolation_growth += max(
                0,
                isolation_growth,
            )


            total_autoencoder_growth += max(
                0,
                autoencoder_growth,
            )


            print()

            print(
                "Growth since last check:"
            )


            print(
                "  Features    :",
                feature_growth,
            )


            print(
                "  Isolation   :",
                isolation_growth,
            )


            print(
                "  Autoencoder :",
                autoencoder_growth,
            )


        previous_counts = (
            counts
        )


        # --------------------------------------------------------
        # Current same-PID depth
        # --------------------------------------------------------

        summaries = (
            analyze_depth()
        )


        print()

        print(
            "Deepest current PID/process groups:"
        )


        if not summaries:

            print(
                "  No repeated paired observations yet."
            )

        else:

            for item in summaries[
                :5
            ]:

                print(

                    f"  PID={item['pid']:<7} "
                    f"{item['process_name']:<25} "
                    f"samples={item['samples']:<4} "
                    f"latest_gap={item['latest_gap']:.2f}s"
                )


        if check_number < NUMBER_OF_CHECKS:

            time.sleep(
                CHECK_INTERVAL_SECONDS
            )


    # ============================================================
    # FINAL ANALYSIS
    # ============================================================

    print()

    print(
        "=" * 84
    )

    print(
        "FINAL ANALYSIS"
    )

    print(
        "=" * 84
    )


    print()

    print(
        "Observed growth during diagnostic:"
    )


    print(
        "  Feature records    :",
        total_feature_growth,
    )


    print(
        "  Isolation results  :",
        total_isolation_growth,
    )


    print(
        "  Autoencoder results:",
        total_autoencoder_growth,
    )


    summaries = (
        analyze_depth()
    )


    near_expected = [

        item

        for item in summaries

        if (

            item[
                "latest_gap"
            ]
            >= 5.0

            and

            item[
                "latest_gap"
            ]
            <= 45.0
        )
    ]


    deep_sequences = [

        item

        for item in summaries

        if item[
            "samples"
        ] >= 8
    ]


    print()

    print(
        "Groups with a recent 5-45s gap:",
        len(
            near_expected
        ),
    )


    print(
        "Groups with >=8 samples:",
        len(
            deep_sequences
        ),
    )


    print()

    if (

        total_feature_growth > 0

        and

        total_isolation_growth > 0

        and

        total_autoencoder_growth > 0

        and

        len(
            near_expected
        ) > 0

    ):

        print(
            "PERIODIC MULTI-MODEL SAMPLING: WORKING"
        )


        if deep_sequences:

            print()

            print(
                "Temporal depth is already sufficient for "
                "at least one 8-step process sequence."
            )


        else:

            print()

            print(
                "Sampling is functioning, but the database "
                "does not yet contain an 8-step continuous "
                "process sequence."
            )


        return


    print(
        "PERIODIC MULTI-MODEL SAMPLING: NOT CONFIRMED"
    )


    print()

    print(
        "The database did not show the expected repeated "
        "15-second behavior observations during this diagnostic."
    )


    print()

    print(
        "This means we should inspect ProcessMonitor runtime "
        "execution before changing the temporal sequence builder."
    )


if __name__ == "__main__":

    main()