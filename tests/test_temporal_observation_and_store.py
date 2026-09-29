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
# IMPORTS
# ================================================================

from ai_detection.temporal.process_temporal_observation_builder import (
    ProcessTemporalObservationBuilder,
)

from ai_detection.temporal.process_temporal_result_store import (
    ProcessTemporalResultStore,
)


# ================================================================
# MAIN
# ================================================================

def main():

    print()

    print(
        "=" * 84
    )

    print(
        "SENTINEL-X TEMPORAL OBSERVATION + RESULT STORE E2E TEST"
    )

    print(
        "=" * 84
    )


    # ============================================================
    # BUILDER
    # ============================================================

    print()

    print(
        "[1] Loading live temporal observation builder..."
    )


    builder = (
        ProcessTemporalObservationBuilder()
    )


    print(
        "Base features:",
        len(
            builder.base_feature_names
        ),
    )


    print(
        "Temporal features:",
        len(
            builder.temporal_feature_names
        ),
    )


    assert len(
        builder.base_feature_names
    ) == 19


    assert len(
        builder.temporal_feature_names
    ) == 27


    print(
        "Schema validation: PASS"
    )


    # ============================================================
    # FAKE LIVE FEATURE RECORD
    #
    # This tests formatting only.
    # ============================================================

    feature_values = {}


    for (
        index,
        feature_name,
    ) in enumerate(
        builder.base_feature_names
    ):

        feature_values[
            feature_name
        ] = float(
            index + 1
        )


    feature_record = {
        "features":
            feature_values,
    }


    isolation_result = {
        "available":
            True,

        "anomaly_confidence":
            25.0,
    }


    autoencoder_result = {
        "available":
            True,

        "anomaly_confidence":
            31.0,

        "behavior_embedding":
            [
                0.10,
                -0.20,
                0.30,
                -0.40,
            ],
    }


    consensus_result = {
        "consensus_score":
            28.0,
    }


    # ============================================================
    # FIRST OBSERVATION
    # ============================================================

    print()

    print(
        "[2] Building first live temporal observation..."
    )


    first = (
        builder.build(

            feature_record=
                feature_record,

            isolation_result=
                isolation_result,

            autoencoder_result=
                autoencoder_result,

            consensus_result=
                consensus_result,

            timestamp=
                1000.0,

            previous_timestamp=
                None,
        )
    )


    assert len(
        first[
            "vector"
        ]
    ) == 27


    assert first[
        "delta_seconds"
    ] == 0.0


    assert first[
        "continuity_reset"
    ] is False


    print(
        "Vector shape:",
        np.asarray(
            first[
                "vector"
            ]
        ).shape,
    )


    print(
        "Delta:",
        first[
            "delta_seconds"
        ],
    )


    print(
        "First observation: PASS"
    )


    # ============================================================
    # SECOND CONTIGUOUS OBSERVATION
    # ============================================================

    print()

    print(
        "[3] Testing real delta_seconds..."
    )


    second = (
        builder.build(

            feature_record=
                feature_record,

            isolation_result=
                isolation_result,

            autoencoder_result=
                autoencoder_result,

            consensus_result=
                consensus_result,

            timestamp=
                1060.5,

            previous_timestamp=
                1000.0,
        )
    )


    assert abs(

        second[
            "delta_seconds"
        ]

        - 60.5

    ) < 1e-9


    assert second[
        "continuity_reset"
    ] is False


    print(
        "Real delta:",
        second[
            "delta_seconds"
        ],
    )


    print(
        "Real-delta test: PASS"
    )


    # ============================================================
    # LARGE GAP
    # ============================================================

    print()

    print(
        "[4] Testing broken temporal continuity..."
    )


    broken = (
        builder.build(

            feature_record=
                feature_record,

            isolation_result=
                isolation_result,

            autoencoder_result=
                autoencoder_result,

            consensus_result=
                consensus_result,

            timestamp=
                1500.0,

            previous_timestamp=
                1060.5,
        )
    )


    assert broken[
        "continuity_reset"
    ] is True


    assert broken[
        "delta_seconds"
    ] == 0.0


    print(
        "Continuity reason:",
        broken[
            "continuity_reason"
        ],
    )


    print(
        "Gap-reset vector test: PASS"
    )


    # ============================================================
    # TEMPORARY RESULT DATABASE
    # ============================================================

    print()

    print(
        "[5] Testing temporal result persistence..."
    )


    with tempfile.TemporaryDirectory() as directory:

        database_path = (

            Path(
                directory
            )

            / "temporal_test.db"
        )


        store = (
            ProcessTemporalResultStore(

                database_path=
                    database_path
            )
        )


        temporal_result = {
            "available":
                True,

            "predictor_name":
                "sentinelx_process_temporal_predictor",

            "predictor_version":
                "v1",

            "model_name":
                "sentinelx_process_temporal_transformer",

            "model_version":
                "v1",

            "calibration_version":
                "v1",

            "raw_temporal_reconstruction_error":
                0.314,

            "per_timestep_errors":
                [
                    0.1,
                    0.2,
                    0.3,
                    0.4,
                    0.2,
                    0.3,
                    0.5,
                    0.512,
                ],

            "most_unusual_timestep":
                7,

            "maximum_timestep_error":
                0.512,

            "anomaly_score":
                22.5,

            "anomaly_confidence":
                22.5,

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

            "temporal_embedding":
                [
                    float(
                        index
                    )
                    / 100.0

                    for index in range(
                        64
                    )
                ],

            "temporal_embedding_dimension":
                64,

            "critical_allowed_from_temporal_alone":
                False,
        }


        result_id = (
            store.save_result(

                feature_record_id=
                    8008,

                pid=
                    4321,

                process_name=
                    "test.exe",

                process_create_time=
                    1700000000.0,

                sequence_generation=
                    0,

                sequence_feature_record_ids=
                    [
                        8001,
                        8002,
                        8003,
                        8004,
                        8005,
                        8006,
                        8007,
                        8008,
                    ],

                sequence_start_timestamp=
                    2000.0,

                sequence_end_timestamp=
                    2420.0,

                temporal_result=
                    temporal_result,
            )
        )


        print(
            "Stored result ID:",
            result_id,
        )


        assert result_id > 0


        assert store.count() == 1


        loaded = (
            store.get_by_id(
                result_id
            )
        )


        assert loaded is not None


        assert loaded[
            "pid"
        ] == 4321


        assert loaded[
            "anomaly_label"
        ] == "NORMAL"


        assert loaded[
            "temporal_embedding_dimension"
        ] == 64


        assert len(
            loaded[
                "temporal_embedding"
            ]
        ) == 64


        assert loaded[
            "sequence_feature_record_ids"
        ] == [
            8001,
            8002,
            8003,
            8004,
            8005,
            8006,
            8007,
            8008,
        ]


        print(
            "Read-back test: PASS"
        )


        # ========================================================
        # UPSERT
        # ========================================================

        temporal_result[
            "anomaly_score"
        ] = 35.0


        temporal_result[
            "anomaly_confidence"
        ] = 35.0


        second_id = (
            store.save_result(

                feature_record_id=
                    8008,

                pid=
                    4321,

                process_name=
                    "test.exe",

                process_create_time=
                    1700000000.0,

                sequence_generation=
                    0,

                sequence_feature_record_ids=
                    [
                        8001,
                        8002,
                        8003,
                        8004,
                        8005,
                        8006,
                        8007,
                        8008,
                    ],

                sequence_start_timestamp=
                    2000.0,

                sequence_end_timestamp=
                    2420.0,

                temporal_result=
                    temporal_result,
            )
        )


        assert second_id == result_id


        assert store.count() == 1


        reloaded = (
            store.get_by_id(
                result_id
            )
        )


        assert reloaded is not None


        assert abs(

            reloaded[
                "anomaly_score"
            ]

            - 35.0

        ) < 1e-9


        print(
            "Upsert test: PASS"
        )


    # ============================================================
    # FINAL
    # ============================================================

    print()

    print(
        "=" * 84
    )

    print(
        "TEMPORAL OBSERVATION + RESULT STORE E2E TEST: PASS"
    )

    print(
        "=" * 84
    )


if __name__ == "__main__":

    main()