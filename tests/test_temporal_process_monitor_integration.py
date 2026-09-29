from __future__ import annotations

import sys
import tempfile

from pathlib import Path

import numpy as np


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

from endpoint.collectors.temporal_process_monitor import (
    TemporalProcessMonitor,
)


# ================================================================
# TEST CONFIGURATION
# ================================================================

PID = 9876

CREATE_TIME = 1700000000.0


# ================================================================
# MAIN
# ================================================================

def main():

    print()

    print(
        "=" * 88
    )

    print(
        "SENTINEL-X TEMPORAL PROCESS MONITOR INTEGRATION TEST"
    )

    print(
        "=" * 88
    )


    # ============================================================
    # TEMP DATABASE
    # ============================================================

    with tempfile.TemporaryDirectory() as directory:

        temporal_database = (

            Path(
                directory
            )

            / "temporal_integration.db"
        )


        # ========================================================
        # CREATE MONITOR
        #
        # Do NOT call initialize().
        # ========================================================

        print()

        print(
            "[1] Creating TemporalProcessMonitor..."
        )


        monitor = (
            TemporalProcessMonitor(

                poll_interval=2.0,

                temporal_database_path=
                    temporal_database,
            )
        )


        status = (
            monitor.get_temporal_status()
        )


        predictor_status = (
            status[
                "predictor"
            ]
        )


        print(
            "Temporal model available:",
            predictor_status[
                "available"
            ],
        )


        print(
            "Model version:",
            predictor_status[
                "model_version"
            ],
        )


        print(
            "Embedding dimension:",
            predictor_status[
                "representation_dimension"
            ],
        )


        assert predictor_status[
            "available"
        ] is True


        # ========================================================
        # BUILD TRAINING-COMPATIBLE BASE FEATURE RECORD
        # ========================================================

        feature_names = (

            monitor
            .temporal_observation_builder
            .base_feature_names
        )


        feature_values = {}


        for (
            index,
            name,
        ) in enumerate(
            feature_names
        ):

            # Small controlled values.
            feature_values[
                name
            ] = float(
                (
                    index
                    % 5
                )
                + 1
            )


        # ========================================================
        # PROCESS INFO
        # ========================================================

        process_info = {
            "pid":
                PID,

            "ppid":
                100,

            "name":
                "temporal_test.exe",

            "create_time":
                CREATE_TIME,
        }


        # ========================================================
        # MODEL OUTPUT
        # ========================================================

        isolation_result = {
            "available":
                True,

            "anomaly_score":
                15.0,

            "anomaly_confidence":
                15.0,

            "anomaly_label":
                "NORMAL",
        }


        autoencoder_result = {
            "available":
                True,

            "anomaly_score":
                18.0,

            "anomaly_confidence":
                18.0,

            "anomaly_label":
                "NORMAL",

            "behavior_embedding":
                [
                    0.12,
                    -0.08,
                    0.22,
                    -0.15,
                ],
        }


        # ========================================================
        # ADD 8 OBSERVATIONS
        # ========================================================

        print()

        print(
            "[2] Feeding 8 live observations..."
        )


        base_timestamp = (
            1800000000.0
        )


        final_result = None


        for index in range(
            8
        ):

            # ----------------------------------------------------
            # Add slight variation through time.
            # ----------------------------------------------------

            current_features = dict(
                feature_values
            )


            current_features[
                feature_names[
                    0
                ]
            ] += (

                index
                * 0.05
            )


            feature_record = {
                "features":
                    current_features,
            }


            result = (
                monitor.process_temporal_sample(

                    process_info=
                        process_info,

                    feature_record=
                        feature_record,

                    feature_record_id=
                        5000
                        + index,

                    isolation_result=
                        isolation_result,

                    autoencoder_result=
                        autoencoder_result,

                    timestamp=
                        (
                            base_timestamp

                            + index
                            * 60.0
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


                assert result[
                    "ready"
                ] is False


        # ========================================================
        # OBSERVATION 8 MUST RUN TRANSFORMER
        # ========================================================

        assert final_result is not None


        assert (

            final_result[
                "state"
            ]

            == "TEMPORAL_INFERENCE_COMPLETE"
        )


        assert final_result[
            "ready"
        ] is True


        temporal_result = (
            final_result[
                "temporal_result"
            ]
        )


        print()

        print(
            "[3] Transformer result..."
        )


        print(
            "Available:",
            temporal_result[
                "available"
            ],
        )


        print(
            "Raw error:",
            temporal_result[
                "raw_temporal_reconstruction_error"
            ],
        )


        print(
            "Anomaly score:",
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
            "Most unusual timestep:",
            temporal_result[
                "most_unusual_timestep"
            ],
        )


        print(
            "Embedding dimension:",
            temporal_result[
                "temporal_embedding_dimension"
            ],
        )


        assert temporal_result[
            "available"
        ] is True


        assert (

            temporal_result[
                "temporal_embedding_dimension"
            ]

            == 64
        )


        # ========================================================
        # RESULT STORE
        # ========================================================

        print()

        print(
            "[4] Checking temporal persistence..."
        )


        count = (
            monitor
            .temporal_result_store
            .count()
        )


        print(
            "Stored temporal results:",
            count,
        )


        assert count == 1


        rows = (
            monitor
            .temporal_result_store
            .get_recent(
                limit=5
            )
        )


        assert len(
            rows
        ) == 1


        stored = (
            rows[
                0
            ]
        )


        print(
            "Stored PID:",
            stored[
                "pid"
            ],
        )


        print(
            "Stored process:",
            stored[
                "process_name"
            ],
        )


        print(
            "Stored score:",
            stored[
                "anomaly_score"
            ],
        )


        print(
            "Stored embedding:",
            stored[
                "temporal_embedding_dimension"
            ],
        )


        assert stored[
            "pid"
        ] == PID


        assert (

            stored[
                "temporal_embedding_dimension"
            ]

            == 64
        )


        # ========================================================
        # ROLLING OBSERVATION 9
        # ========================================================

        print()

        print(
            "[5] Testing rolling live inference..."
        )


        result9 = (
            monitor.process_temporal_sample(

                process_info=
                    process_info,

                feature_record={
                    "features":
                        feature_values
                },

                feature_record_id=
                    5008,

                isolation_result=
                    isolation_result,

                autoencoder_result=
                    autoencoder_result,

                timestamp=
                    (
                        base_timestamp
                        + 8
                        * 60.0
                    ),
            )
        )


        assert (

            result9[
                "state"
            ]

            == "TEMPORAL_INFERENCE_COMPLETE"
        )


        assert result9[
            "depth"
        ] == 8


        assert (

            monitor
            .temporal_result_store
            .count()

            == 2
        )


        print(
            "Rolling inference: PASS"
        )


        # ========================================================
        # STATUS
        # ========================================================

        print()

        print(
            "[6] Final temporal runtime status..."
        )


        final_status = (
            monitor.get_temporal_status()
        )


        print(
            "Buffered process instances:",
            final_status[
                "buffer"
            ][
                "process_instances"
            ],
        )


        print(
            "Ready process instances:",
            final_status[
                "buffer"
            ][
                "ready_process_instances"
            ],
        )


        print(
            "Maximum depth:",
            final_status[
                "buffer"
            ][
                "maximum_depth"
            ],
        )


        print(
            "Stored results:",
            final_status[
                "stored_results"
            ],
        )


        # ========================================================
        # FINAL
        # ========================================================

        print()

        print(
            "=" * 88
        )

        print(
            "TEMPORAL PROCESS MONITOR INTEGRATION TEST: PASS"
        )

        print(
            "=" * 88
        )


if __name__ == "__main__":

    main()