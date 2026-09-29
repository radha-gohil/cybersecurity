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


# ================================================================
# IMPORT
# ================================================================

from endpoint.collectors.fusion_v3_evidence_bridge_monitor import (
    FusionV3EvidenceBridgeMonitor,
)


# ================================================================
# MAIN
# ================================================================

def main():

    print()

    print(
        "=" * 100
    )

    print(
        "SENTINEL-X FUSION V3 EVIDENCE BRIDGE TEST"
    )

    print(
        "=" * 100
    )


    with tempfile.TemporaryDirectory() as directory:

        database_path = (

            Path(
                directory
            )

            / "bridge_test.db"
        )


        monitor = (
            FusionV3EvidenceBridgeMonitor(

                poll_interval=2.0,

                fusion_database_path=
                    database_path,
            )
        )


        # ========================================================
        # PROCESS
        # ========================================================

        process_info = {
            "pid":
                7777,

            "ppid":
                100,

            "name":
                "bridge_test.exe",

            "create_time":
                1700000000.0,
        }


        context = {}


        # ========================================================
        # We do not call real collection here because this test is
        # checking the bridge semantics.
        #
        # Build a realistic AI-result package.
        # ========================================================

        isolation_result = {
            "available":
                True,

            "anomaly_confidence":
                20.0,

            "anomaly_score":
                20.0,

            "anomaly_label":
                "NORMAL",

            "severity":
                "INFO",
        }


        autoencoder_result = {
            "available":
                True,

            "anomaly_confidence":
                25.0,

            "anomaly_score":
                25.0,

            "anomaly_label":
                "NORMAL",

            "severity":
                "INFO",

            "behavior_embedding":
                [
                    0.1,
                    0.2,
                    0.3,
                    0.4,
                ],
        }


        temporal_result = {
            "available":
                True,

            "model_version":
                "v2",

            "calibration_version":
                "v2",

            "feature_count":
                26,

            "anomaly_score":
                30.0,

            "anomaly_confidence":
                30.0,

            "anomaly_label":
                "NORMAL",

            "severity":
                "INFO",

            "is_active":
                False,

            "is_strong":
                False,

            "should_alert":
                False,
        }


        ai_result = {
            "record_id":
                50001,

            "isolation_forest":
                isolation_result,

            "autoencoder":
                autoencoder_result,

            "temporal": {
                "available":
                    True,

                "state":
                    "TEMPORAL_INFERENCE_COMPLETE",

                "ready":
                    True,

                "depth":
                    8,

                "temporal_result":
                    temporal_result,
            },
        }


        # ========================================================
        # CACHE PACKAGE
        # ========================================================

        print()

        print(
            "[1] Creating pending bridge package..."
        )


        monitor.create_pending_package(

            process_info=
                process_info,

            context=
                context,

            ai_result=
                ai_result,
        )


        assert (

            monitor
            .get_evidence_bridge_status()[
                "pending_package"
            ]

            is True
        )


        # ========================================================
        # RULE RESULT
        # ========================================================

        behavior_result = {
            "score":
                75.0,

            "severity":
                "HIGH",

            "indicators":
                [
                    "TEST_RULE"
                ],
        }


        # ========================================================
        # STATISTICAL RESULT
        # ========================================================

        anomaly_result = {
            "score":
                65.0,

            "severity":
                "HIGH",

            "indicators":
                [
                    "TEST_STATISTICAL"
                ],
        }


        # ========================================================
        # CALCULATE
        #
        # This must:
        #
        #   return Fusion v2
        #   AND mutate ai_result with Fusion v3.
        # ========================================================

        print()

        print(
            "[2] Running real fusion call sequence..."
        )


        fusion_v2 = (
            monitor.calculate_fusion(

                behavior_result=
                    behavior_result,

                anomaly_result=
                    anomaly_result,

                isolation_result=
                    isolation_result,

                autoencoder_result=
                    autoencoder_result,
            )
        )


        assert isinstance(
            fusion_v2,
            dict,
        )


        print(
            "Fusion v2 score:",
            fusion_v2.get(
                "fusion_score"
            ),
        )


        # ========================================================
        # VERIFY V2 ATTACHED
        # ========================================================

        assert (

            "fusion_v2"

            in ai_result

        )


        # ========================================================
        # VERIFY V3 ATTACHED
        # ========================================================

        assert (

            "fusion_v3"

            in ai_result

        )


        fusion_v3 = (
            ai_result[
                "fusion_v3"
            ]
        )


        print()

        print(
            "[3] Fusion v3 complete evidence result..."
        )


        print(
            "Fusion v3 score:",
            fusion_v3[
                "fusion_score"
            ],
        )


        print(
            "Severity:",
            fusion_v3[
                "severity"
            ],
        )


        print(
            "Active categories:",
            fusion_v3[
                "active_categories"
            ],
        )


        print(
            "Available categories:",
            fusion_v3[
                "available_categories"
            ],
        )


        print(
            "Rule score:",
            fusion_v3[
                "scores"
            ][
                "rules"
            ],
        )


        print(
            "Statistical score:",
            fusion_v3[
                "scores"
            ][
                "statistical"
            ],
        )


        print(
            "Behavior AI:",
            fusion_v3[
                "scores"
            ][
                "behavioral_ai_consensus"
            ],
        )


        print(
            "Temporal AI:",
            fusion_v3[
                "scores"
            ][
                "temporal_ai"
            ],
        )


        print(
            "V2 comparison:",
            fusion_v3[
                "fusion_v2_comparison"
            ],
        )


        # ========================================================
        # CRITICAL ASSERTIONS
        # ========================================================

        assert (

            fusion_v3[
                "categories"
            ][
                "rules"
            ][
                "available"
            ]

            is True
        )


        assert (

            fusion_v3[
                "categories"
            ][
                "statistical"
            ][
                "available"
            ]

            is True
        )


        assert (

            fusion_v3[
                "categories"
            ][
                "behavioral_ai"
            ][
                "available"
            ]

            is True
        )


        assert (

            fusion_v3[
                "categories"
            ][
                "temporal_ai"
            ][
                "available"
            ]

            is True
        )


        assert (

            fusion_v3[
                "fusion_v2_comparison"
            ][
                "available"
            ]

            is True
        )


        assert (

            fusion_v3[
                "evidence_bridge_complete"
            ]

            is True
        )


        # ========================================================
        # PACKAGE MUST BE CONSUMED
        # ========================================================

        assert (

            monitor
            .get_evidence_bridge_status()[
                "pending_package"
            ]

            is False
        )


        # ========================================================
        # PERSISTENCE
        # ========================================================

        assert (

            monitor
            .fusion_v3_store
            .count()

            == 1
        )


        # ========================================================
        # STATUS
        # ========================================================

        status = (
            monitor
            .get_evidence_bridge_status()
        )


        print()

        print(
            "[4] Bridge status..."
        )


        print(
            status[
                "statistics"
            ]
        )


        assert (

            status[
                "statistics"
            ][
                "bridge_success"
            ]

            == 1
        )


        assert (

            status[
                "statistics"
            ][
                "bridge_exceptions"
            ]

            == 0
        )


        print()

        print(
            "=" * 100
        )

        print(
            "FUSION V3 EVIDENCE BRIDGE TEST: PASS"
        )

        print(
            "=" * 100
        )


if __name__ == "__main__":

    main()