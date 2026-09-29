from __future__ import annotations

import sys
import tempfile

from pathlib import Path


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


from endpoint.collectors.fusion_v3_primary_process_monitor import (
    FusionV3PrimaryProcessMonitor,
)


def main():

    print()

    print(
        "=" * 96
    )

    print(
        "SENTINEL-X FUSION V3 PRIMARY PROMOTION TEST"
    )

    print(
        "=" * 96
    )


    with tempfile.TemporaryDirectory() as directory:

        database_path = (

            Path(
                directory
            )

            / "primary_promotion.db"
        )


        monitor = (
            FusionV3PrimaryProcessMonitor(

                poll_interval=2.0,

                fusion_database_path=
                    database_path,
            )
        )


        # ========================================================
        # STATUS
        # ========================================================

        status = (
            monitor.get_primary_fusion_status()
        )


        print()

        print(
            "Primary engine:",
            status[
                "primary_engine"
            ],
        )


        print(
            "Mode:",
            status[
                "operating_mode"
            ],
        )


        print(
            "Fallback:",
            status[
                "fallback_engine"
            ],
        )


        assert (

            status[
                "primary_engine"
            ]

            == "process_threat_fusion_v3"
        )


        assert (

            status[
                "operating_mode"
            ]

            == "PRODUCTION_PRIMARY"
        )


        assert (

            status[
                "fallback_available"
            ]

            is True
        )


        # ========================================================
        # SYNTHETIC PROCESS
        # ========================================================

        process_info = {
            "pid":
                7070,

            "ppid":
                100,

            "name":
                "promotion_test.exe",

            "create_time":
                1700000000.0,
        }


        isolation_result = {
            "available":
                True,

            "anomaly_score":
                70.0,

            "anomaly_confidence":
                70.0,

            "anomaly_label":
                "SUSPICIOUS",

            "severity":
                "MEDIUM",
        }


        autoencoder_result = {
            "available":
                True,

            "anomaly_score":
                72.0,

            "anomaly_confidence":
                72.0,

            "anomaly_label":
                "SUSPICIOUS",

            "severity":
                "MEDIUM",

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
                75.0,

            "anomaly_confidence":
                75.0,

            "anomaly_label":
                "SUSPICIOUS",

            "severity":
                "MEDIUM",

            "is_active":
                True,

            "is_strong":
                False,

            "should_alert":
                True,
        }


        ai_result = {
            "record_id":
                90001,

            "isolation_forest":
                isolation_result,

            "autoencoder":
                autoencoder_result,

            "temporal": {
                "available":
                    True,

                "state":
                    "TEMPORAL_INFERENCE_COMPLETE",

                "depth":
                    8,

                "ready":
                    True,

                "temporal_result":
                    temporal_result,
            },
        }


        # ========================================================
        # CREATE BRIDGE PACKAGE
        # ========================================================

        monitor.create_pending_package(

            process_info=
                process_info,

            context=
                {},

            ai_result=
                ai_result,
        )


        # ========================================================
        # RULES
        # ========================================================

        behavior_result = {
            "score":
                80.0,

            "behavior_score":
                80.0,

            "suspicious":
                True,

            "severity":
                "HIGH",

            "indicators":
                [
                    "PRIMARY_TEST_RULE"
                ],

            "reasons":
                [
                    "Controlled primary promotion test"
                ],
        }


        # ========================================================
        # STATISTICAL
        # ========================================================

        anomaly_result = {
            "score":
                65.0,

            "anomaly_score":
                65.0,

            "anomalous":
                True,

            "severity":
                "HIGH",

            "indicators":
                [
                    "PRIMARY_TEST_STAT"
                ],

            "reasons":
                [
                    "Controlled statistical evidence"
                ],
        }


        # ========================================================
        # PRIMARY CALCULATION
        # ========================================================

        primary_result = (
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


        print()

        print(
            "Primary result:"
        )


        print(
            "  Engine:",
            primary_result.get(
                "primary_engine"
            ),
        )


        print(
            "  Version:",
            primary_result.get(
                "fusion_version"
            ),
        )


        print(
            "  Mode:",
            primary_result.get(
                "operating_mode"
            ),
        )


        print(
            "  Score:",
            primary_result.get(
                "fusion_score"
            ),
        )


        print(
            "  Severity:",
            primary_result.get(
                "severity"
            ),
        )


        print(
            "  Alert:",
            primary_result.get(
                "should_alert"
            ),
        )


        print(
            "  Rule:",
            primary_result.get(
                "rule_score"
            ),
        )


        print(
            "  Statistical:",
            primary_result.get(
                "statistical_score"
            ),
        )


        print(
            "  Behavioral AI:",
            primary_result.get(
                "ai_consensus_score"
            ),
        )


        print(
            "  Temporal:",
            primary_result.get(
                "temporal_ai_score"
            ),
        )


        # ========================================================
        # PRIMARY ASSERTIONS
        # ========================================================

        assert (

            primary_result[
                "primary_engine"
            ]

            == "process_threat_fusion_v3"
        )


        assert (

            primary_result[
                "fusion_version"
            ]

            == "v3"
        )


        assert (

            primary_result[
                "operating_mode"
            ]

            == "PRODUCTION_PRIMARY"
        )


        assert (

            primary_result[
                "promoted_to_primary"
            ]

            is True
        )


        # ========================================================
        # BACKWARD COMPATIBILITY
        # ========================================================

        assert (

            isinstance(
                primary_result.get(
                    "ai_consensus"
                ),
                dict,
            )
        )


        assert (

            "fusion_score"

            in primary_result
        )


        assert (

            "severity"

            in primary_result
        )


        assert (

            "suspicious"

            in primary_result
        )


        assert (

            "rule_score"

            in primary_result
        )


        assert (

            "statistical_score"

            in primary_result
        )


        # ========================================================
        # V2 ROLLBACK
        # ========================================================

        assert (

            isinstance(
                primary_result.get(
                    "fusion_v2_reference"
                ),
                dict,
            )
        )


        assert (

            primary_result[
                "rollback_available"
            ]

            is True
        )


        # ========================================================
        # AI RESULT UPDATED
        # ========================================================

        assert (

            ai_result[
                "primary_decision_candidate"
            ][
                "promoted_to_primary"
            ]

            is True
        )


        assert (

            ai_result[
                "primary_decision_candidate"
            ][
                "engine"
            ]

            == "process_threat_fusion_v3"
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


        print()

        print(
            "=" * 96
        )

        print(
            "FUSION V3 PRIMARY PROMOTION TEST: PASS"
        )

        print(
            "=" * 96
        )


if __name__ == "__main__":

    main()