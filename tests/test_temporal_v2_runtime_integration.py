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
        str(PROJECT_ROOT),
    )


# ================================================================
# IMPORT
# ================================================================

from endpoint.collectors.fusion_v3_process_monitor_v2 import (
    FusionV3ProcessMonitorV2,
)


# ================================================================
# TEST
# ================================================================

PID = 8123

CREATE_TIME = 1700000000.0


def main():

    print()

    print(
        "=" * 92
    )

    print(
        "SENTINEL-X TEMPORAL V2 RUNTIME INTEGRATION TEST"
    )

    print(
        "=" * 92
    )


    with tempfile.TemporaryDirectory() as directory:

        database_path = (

            Path(
                directory
            )

            / "temporal_v2_runtime.db"
        )


        # ========================================================
        # MONITOR
        # ========================================================

        print()

        print(
            "[1] Creating v2 runtime..."
        )


        monitor = (
            FusionV3ProcessMonitorV2(

                poll_interval=2.0,

                fusion_database_path=
                    database_path,
            )
        )


        status = (
            monitor.get_temporal_v2_status()
        )


        predictor = (
            status[
                "predictor"
            ]
        )


        print(
            "Model:",
            predictor[
                "model_version"
            ],
        )


        print(
            "Calibration:",
            predictor[
                "calibration_version"
            ],
        )


        print(
            "Feature count:",
            predictor[
                "feature_count"
            ],
        )


        print(
            "Removed feature:",
            predictor[
                "removed_feature"
            ],
        )


        assert predictor[
            "available"
        ] is True


        assert predictor[
            "model_version"
        ] == "v2"


        assert predictor[
            "calibration_version"
        ] == "v2"


        assert predictor[
            "feature_count"
        ] == 26


        # ========================================================
        # BUILD SNAPSHOT FEATURE RECORD
        #
        # Builder v2 expects all original fields to still be
        # available in the Phase-2 record, but excludes process age
        # from its temporal vector.
        # ========================================================

        base_names = (

            monitor
            .temporal_observation_builder
            .base_feature_names
        )


        assert len(
            base_names
        ) == 18


        assert (

            "process_age_seconds"

            not in base_names
        )


        feature_values = {}


        for (
            index,
            name,
        ) in enumerate(
            base_names
        ):

            feature_values[
                name
            ] = float(
                (
                    index
                    % 4
                )
                + 0.5
            )


        # ========================================================
        # PROCESS
        # ========================================================

        process_info = {
            "pid":
                PID,

            "ppid":
                100,

            "name":
                "temporal_v2_test.exe",

            "create_time":
                CREATE_TIME,
        }


        isolation_result = {
            "available":
                True,

            "anomaly_score":
                12.0,

            "anomaly_confidence":
                12.0,

            "anomaly_label":
                "NORMAL",
        }


        autoencoder_result = {
            "available":
                True,

            "anomaly_score":
                15.0,

            "anomaly_confidence":
                15.0,

            "anomaly_label":
                "NORMAL",

            "behavior_embedding":
                [
                    0.30,
                    0.10,
                    -0.20,
                    0.55,
                ],
        }


        # ========================================================
        # FEED 8 OBSERVATIONS
        # ========================================================

        print()

        print(
            "[2] Feeding 8 observations..."
        )


        base_timestamp = (
            1800000000.0
        )


        final_result = None


        for index in range(
            8
        ):

            current = dict(
                feature_values
            )


            # Slightly vary one real temporal-safe feature.
            current[
                base_names[
                    0
                ]
            ] += (

                index
                * 0.02
            )


            result = (
                monitor.process_temporal_sample(

                    process_info=
                        process_info,

                    feature_record={
                        "features":
                            current,
                    },

                    feature_record_id=
                        9000
                        + index,

                    isolation_result=
                        isolation_result,

                    autoencoder_result=
                        autoencoder_result,

                    timestamp=
                        (
                            base_timestamp

                            + index
                            * 15.0
                        ),
                )
            )


            final_result = (
                result
            )


            print(

                f"Observation={index + 1} | "
                f"State={result['state']} | "
                f"Depth={result.get('depth')} | "
                f"Ready={result.get('ready')}"
            )


            if index < 7:

                assert (

                    result[
                        "state"
                    ]

                    == "COLLECTING_HISTORY"
                )


        # ========================================================
        # TEMPORAL INFERENCE
        # ========================================================

        assert final_result is not None


        assert (

            final_result[
                "state"
            ]

            == "TEMPORAL_INFERENCE_COMPLETE"
        )


        temporal_result = (

            final_result[
                "temporal_result"
            ]
        )


        print()

        print(
            "[3] Temporal Transformer v2 result"
        )


        print(
            "Model:",
            temporal_result[
                "model_version"
            ],
        )


        print(
            "Schema:",
            temporal_result[
                "schema_version"
            ],
        )


        print(
            "Feature count:",
            temporal_result[
                "feature_count"
            ],
        )


        print(
            "Error:",
            temporal_result[
                "raw_temporal_reconstruction_error"
            ],
        )


        print(
            "Score:",
            temporal_result[
                "anomaly_score"
            ],
        )


        print(
            "Label:",
            temporal_result[
                "anomaly_label"
            ],
        )


        print(
            "Embedding:",
            temporal_result[
                "temporal_embedding_dimension"
            ],
        )


        assert temporal_result[
            "model_version"
        ] == "v2"


        assert temporal_result[
            "feature_count"
        ] == 26


        assert (

            temporal_result[
                "temporal_embedding_dimension"
            ]

            == 64
        )


        # ========================================================
        # BUFFER
        # ========================================================

        print()

        print(
            "[4] Checking 26D rolling buffer..."
        )


        sequence = (
            monitor
            .temporal_buffer
            .get_sequence(

                pid=
                    PID,

                create_time=
                    CREATE_TIME,
            )
        )


        assert sequence is not None


        print(
            "Sequence shape:",
            sequence.shape,
        )


        assert sequence.shape == (
            8,
            26,
        )


        print()

        print(
            "=" * 92
        )

        print(
            "TEMPORAL V2 RUNTIME INTEGRATION TEST: PASS"
        )

        print(
            "=" * 92
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
