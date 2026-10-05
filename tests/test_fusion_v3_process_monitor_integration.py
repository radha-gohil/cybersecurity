from __future__ import annotations

import sys
import tempfile

from pathlib import Path


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
        str(
            PROJECT_ROOT
        ),
    )


from endpoint.collectors.fusion_v3_process_monitor import (
    FusionV3ProcessMonitor,
)


# ================================================================
# HELPERS
# ================================================================

def rule(
    score,
):

    return {
        "available":
            True,

        "score":
            float(
                score
            ),
    }


def statistical(
    score,
):

    return {
        "available":
            True,

        "score":
            float(
                score
            ),
    }


def isolation(
    score,
):

    return {
        "available":
            True,

        "anomaly_confidence":
            float(
                score
            ),
    }


def autoencoder(
    score,
):

    return {
        "available":
            True,

        "anomaly_confidence":
            float(
                score
            ),
    }


def temporal(
    score,
):

    return {
        "available":
            True,

        "anomaly_score":
            float(
                score
            ),

        "anomaly_confidence":
            float(
                score
            ),
    }


# ================================================================
# MAIN
# ================================================================

def main():

    print()

    print(
        "=" * 90
    )

    print(
        "SENTINEL-X FUSION V3 LIVE-INTEGRATION TEST"
    )

    print(
        "=" * 90
    )


    with tempfile.TemporaryDirectory() as directory:

        database_path = (

            Path(
                directory
            )

            / "fusion_v3_test.db"
        )


        # ========================================================
        # MONITOR
        # ========================================================

        print()

        print(
            "[1] Creating FusionV3ProcessMonitor..."
        )


        monitor = (
            FusionV3ProcessMonitor(

                poll_interval=2.0,

                fusion_database_path=
                    database_path,
            )
        )


        status = (
            monitor.get_fusion_v3_status()
        )


        print(
            "Fusion version:",
            status[
                "fusion_version"
            ],
        )


        print(
            "Mode:",
            status[
                "operating_mode"
            ],
        )


        print(
            "Temporal available:",
            status[
                "temporal"
            ][
                "predictor"
            ][
                "available"
            ],
        )


        assert (

            status[
                "operating_mode"
            ]

            == "SHADOW_VALIDATION"
        )


        assert (

            status[
                "temporal"
            ][
                "predictor"
            ][
                "available"
            ]

            is True
        )


        # ========================================================
        # PROCESS
        # ========================================================

        process_info = {
            "pid":
                9988,

            "name":
                "fusion_test.exe",

            "create_time":
                1700000000.0,
        }


        # ========================================================
        # CASE 1 — NORMAL
        # ========================================================

        print()

        print(
            "[2] Testing normal Fusion-v3 persistence..."
        )


        normal = (
            monitor
            .calculate_and_persist_fusion_v3(

                process_info=
                    process_info,

                feature_record_id=
                    7001,

                rule_result=
                    rule(
                        5
                    ),

                statistical_result=
                    statistical(
                        8
                    ),

                isolation_result=
                    isolation(
                        10
                    ),

                autoencoder_result=
                    autoencoder(
                        12
                    ),

                temporal_result=
                    temporal(
                        10
                    ),
            )
        )


        print(
            "Score:",
            normal[
                "fusion_score"
            ],
        )


        print(
            "Severity:",
            normal[
                "severity"
            ],
        )


        print(
            "Alert:",
            normal[
                "should_alert"
            ],
        )


        print(
            "Result ID:",
            normal[
                "result_id"
            ],
        )


        assert normal[
            "should_alert"
        ] is False


        assert normal[
            "result_id"
        ] > 0


        # ========================================================
        # CASE 2 — AI ONLY
        # ========================================================

        print()

        print(
            "[3] Testing AI-only critical protection..."
        )


        ai_only = (
            monitor
            .calculate_and_persist_fusion_v3(

                process_info=
                    process_info,

                feature_record_id=
                    7002,

                rule_result=
                    rule(
                        0
                    ),

                statistical_result=
                    statistical(
                        0
                    ),

                isolation_result=
                    isolation(
                        95
                    ),

                autoencoder_result=
                    autoencoder(
                        93
                    ),

                temporal_result=
                    temporal(
                        96
                    ),
            )
        )


        print(
            "Score:",
            ai_only[
                "fusion_score"
            ],
        )


        print(
            "Severity:",
            ai_only[
                "severity"
            ],
        )


        print(
            "Critical:",
            ai_only[
                "critical_allowed"
            ],
        )


        assert ai_only[
            "critical_allowed"
        ] is False


        assert ai_only[
            "fusion_score"
        ] <= 79


        # ========================================================
        # CASE 3 — RULE + TEMPORAL
        # ========================================================

        print()

        print(
            "[4] Testing corroborated critical result..."
        )


        critical = (
            monitor
            .calculate_and_persist_fusion_v3(

                process_info=
                    process_info,

                feature_record_id=
                    7003,

                rule_result=
                    rule(
                        90
                    ),

                statistical_result=
                    statistical(
                        10
                    ),

                isolation_result=
                    isolation(
                        10
                    ),

                autoencoder_result=
                    autoencoder(
                        12
                    ),

                temporal_result=
                    temporal(
                        95
                    ),
            )
        )


        print(
            "Score:",
            critical[
                "fusion_score"
            ],
        )


        print(
            "Severity:",
            critical[
                "severity"
            ],
        )


        print(
            "Critical:",
            critical[
                "critical_allowed"
            ],
        )


        assert critical[
            "critical_allowed"
        ] is True


        assert critical[
            "severity"
        ] == "CRITICAL"


        # ========================================================
        # PERSISTENCE
        # ========================================================

        print()

        print(
            "[5] Checking Fusion-v3 result store..."
        )


        count = (
            monitor
            .fusion_v3_store
            .count()
        )


        alerts = (
            monitor
            .fusion_v3_store
            .count_alerts()
        )


        print(
            "Stored results:",
            count,
        )


        print(
            "Alert candidates:",
            alerts,
        )


        assert count == 3


        assert alerts >= 1


        rows = (
            monitor
            .fusion_v3_store
            .get_recent(
                limit=10
            )
        )


        assert len(
            rows
        ) == 3


        for row in rows:

            print()

            print(
                "Record:",
                row[
                    "feature_record_id"
                ],
            )


            print(
                "Score:",
                row[
                    "fusion_score"
                ],
            )


            print(
                "Severity:",
                row[
                    "severity"
                ],
            )


            print(
                "Mode:",
                row[
                    "operating_mode"
                ],
            )


            assert (

                row[
                    "operating_mode"
                ]

                == "SHADOW_VALIDATION"
            )


        # ========================================================
        # FINAL
        # ========================================================

        print()

        print(
            "=" * 90
        )

        print(
            "FUSION V3 LIVE-INTEGRATION TEST: PASS"
        )

        print(
            "=" * 90
        )


if __name__ == "__main__":

    main()

# Pytest opt-in. These exercises require trained model artifacts and
# initialize runtime components; regular unit-test runs should stay fast.
def test_integration_entrypoint():
    import os
    import pytest

    if os.environ.get("SENTINEL_RUN_MODEL_INTEGRATION") != "1":
        pytest.skip(
            "Model integration is opt-in: set "
            "SENTINEL_RUN_MODEL_INTEGRATION=1"
        )
    main()
