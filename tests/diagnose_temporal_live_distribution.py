from __future__ import annotations

import sys
import json

from pathlib import Path

import numpy as np
import joblib


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

from ai_detection.temporal.process_temporal_result_store import (
    ProcessTemporalResultStore,
)

from ai_detection.temporal.process_temporal_observation_builder import (
    ProcessTemporalObservationBuilder,
)


# ================================================================
# PATHS
# ================================================================

RAW_DATASET_PATH = (
    PROJECT_ROOT
    / "data"
    / "temporal"
    / "process_sequence_dataset_v2.npz"
)


SPLIT_DATASET_PATH = (
    PROJECT_ROOT
    / "data"
    / "temporal"
    / "process_sequence_splits_v1.npz"
)


SCALER_PATH = (
    PROJECT_ROOT
    / "models"
    / "temporal"
    / "process_temporal_scaler_v1.joblib"
)


DATABASE_PATH = (
    PROJECT_ROOT
    / "data"
    / "database"
    / "sentinel_endpoint.db"
)


# ================================================================
# CONFIG
# ================================================================

TOP_FEATURES = 27

EPSILON = 1e-8


# ================================================================
# HELPERS
# ================================================================

def finite_array(
    values,
):

    array = np.asarray(
        values,
        dtype=np.float64,
    )

    return array[
        np.isfinite(
            array
        )
    ]


def stats(
    values,
):

    values = finite_array(
        values
    )


    if len(
        values
    ) == 0:

        return {
            "count": 0,
            "mean": None,
            "std": None,
            "min": None,
            "p05": None,
            "p50": None,
            "p95": None,
            "max": None,
        }


    return {
        "count":
            int(
                len(
                    values
                )
            ),

        "mean":
            float(
                np.mean(
                    values
                )
            ),

        "std":
            float(
                np.std(
                    values
                )
            ),

        "min":
            float(
                np.min(
                    values
                )
            ),

        "p05":
            float(
                np.percentile(
                    values,
                    5,
                )
            ),

        "p50":
            float(
                np.percentile(
                    values,
                    50,
                )
            ),

        "p95":
            float(
                np.percentile(
                    values,
                    95,
                )
            ),

        "max":
            float(
                np.max(
                    values
                )
            ),
    }


def fmt(
    value,
):

    if value is None:

        return "None"


    return f"{float(value):.5f}"


# ================================================================
# LOAD TRAINING RAW DATA
# ================================================================

def load_raw_training_distribution():

    if not RAW_DATASET_PATH.exists():

        raise FileNotFoundError(
            f"Missing raw temporal dataset: "
            f"{RAW_DATASET_PATH}"
        )


    data = np.load(
        RAW_DATASET_PATH,
        allow_pickle=False,
    )


    X = np.asarray(
        data[
            "X"
        ],
        dtype=np.float64,
    )


    feature_names = [

        str(
            value
        )

        for value
        in data[
            "temporal_feature_names"
        ].tolist()
    ]


    if X.ndim != 3:

        raise RuntimeError(
            f"Unexpected raw dataset shape: {X.shape}"
        )


    return (
        X,
        feature_names,
    )


# ================================================================
# LOAD LIVE TEMPORAL SEQUENCES FROM RESULT STORE
#
# process_temporal_results stores predictor result, but not the
# entire 8x27 matrix. We reconstruct the sequence using its feature
# record IDs and behavior_model_results.
# ================================================================

def get_connection():

    import sqlite3


    connection = sqlite3.connect(
        DATABASE_PATH,
        timeout=30.0,
    )


    connection.row_factory = (
        sqlite3.Row
    )


    return connection


# ================================================================
# LOAD PHASE-2 FEATURE RECORD
# ================================================================

def load_feature_record(
    connection,
    record_id: int,
):

    row = (
        connection.execute(
            """
            SELECT *

            FROM process_behavior_features

            WHERE id = ?
            """,
            (
                int(
                    record_id
                ),
            ),
        )
        .fetchone()
    )


    if row is None:

        return None


    return dict(
        row
    )


# ================================================================
# LOAD MODEL RESULT
# ================================================================

def load_model_result(
    connection,
    record_id: int,
    model_family: str,
):

    row = (
        connection.execute(
            """
            SELECT *

            FROM behavior_model_results

            WHERE
                feature_record_id = ?

                AND model_family = ?

            ORDER BY id DESC

            LIMIT 1
            """,
            (
                int(
                    record_id
                ),
                str(
                    model_family
                ),
            ),
        )
        .fetchone()
    )


    if row is None:

        return None


    result = dict(
        row
    )


    raw = (
        result.get(
            "result_json"
        )
    )


    if raw:

        try:

            parsed = json.loads(
                raw
            )


            if isinstance(
                parsed,
                dict,
            ):

                result.update(
                    parsed
                )


        except json.JSONDecodeError:

            pass


    embedding_raw = (
        result.get(
            "embedding_json"
        )
    )


    if embedding_raw:

        try:

            embedding = json.loads(
                embedding_raw
            )


            result[
                "behavior_embedding"
            ] = embedding


        except json.JSONDecodeError:

            pass


    return result


# ================================================================
# REBUILD DUAL-AI CONSENSUS
# ================================================================

def get_consensus(
    builder,
    isolation_result,
    autoencoder_result,
):

    # The observation builder itself only consumes consensus,
    # therefore use the same Dual-AI implementation used live.

    from ai_detection.behavior.dual_ai_agreement import (
        DualAIAgreementEngine,
    )


    engine = (
        DualAIAgreementEngine()
    )


    return engine.calculate(

        isolation_result=
            isolation_result,

        autoencoder_result=
            autoencoder_result,
    )


# ================================================================
# RECONSTRUCT LIVE RAW SEQUENCES
# ================================================================

def load_live_sequences(
    feature_names,
):

    store = (
        ProcessTemporalResultStore(
            database_path=
                DATABASE_PATH
        )
    )


    rows = (
        store.get_recent(
            limit=200
        )
    )


    if not rows:

        raise RuntimeError(
            "No live temporal results exist."
        )


    builder = (
        ProcessTemporalObservationBuilder()
    )


    connection = (
        get_connection()
    )


    sequences = []

    sequence_processes = []


    try:

        for temporal_row in rows:

            record_ids = (
                temporal_row.get(
                    "sequence_feature_record_ids"
                )
            )


            if not isinstance(
                record_ids,
                list,
            ):

                continue


            if len(
                record_ids
            ) != 8:

                continue


            timestamps = []

            records = []


            # ----------------------------------------------------
            # First load all records.
            # ----------------------------------------------------

            for record_id in record_ids:

                feature_record = (
                    load_feature_record(
                        connection,
                        int(
                            record_id
                        ),
                    )
                )


                if feature_record is None:

                    records = []

                    break


                extracted_at = (
                    feature_record.get(
                        "extracted_at"
                    )
                )


                created_at = (
                    feature_record.get(
                        "created_at"
                    )
                )


                # We prefer numeric timestamp columns when they
                # exist. If not, we derive deltas from the stored
                # temporal sequence interval below.
                timestamp = (
                    feature_record.get(
                        "timestamp"
                    )
                )


                try:

                    timestamp = float(
                        timestamp
                    )


                except (
                    TypeError,
                    ValueError,
                ):

                    timestamp = None


                timestamps.append(
                    timestamp
                )


                records.append(
                    (
                        int(
                            record_id
                        ),
                        feature_record,
                    )
                )


            if len(
                records
            ) != 8:

                continue


            # ----------------------------------------------------
            # We know sequence start/end from temporal persistence.
            #
            # If feature rows do not store numeric timestamps,
            # interpolate only for this diagnostic.
            # ----------------------------------------------------

            start_timestamp = (
                temporal_row.get(
                    "sequence_start_timestamp"
                )
            )


            end_timestamp = (
                temporal_row.get(
                    "sequence_end_timestamp"
                )
            )


            if any(
                timestamp is None

                for timestamp
                in timestamps
            ):

                if (
                    start_timestamp is None
                    or end_timestamp is None
                ):

                    continue


                timestamps = np.linspace(

                    float(
                        start_timestamp
                    ),

                    float(
                        end_timestamp
                    ),

                    num=8,
                ).tolist()


            sequence = []

            previous_timestamp = None


            for (
                index,
                (
                    record_id,
                    feature_record,
                ),
            ) in enumerate(
                records
            ):

                isolation_result = (
                    load_model_result(

                        connection,
                        record_id,
                        "isolation_forest",
                    )
                )


                autoencoder_result = (
                    load_model_result(

                        connection,
                        record_id,
                        "autoencoder",
                    )
                )


                if (
                    isolation_result is None
                    or autoencoder_result is None
                ):

                    sequence = []

                    break


                consensus = (
                    get_consensus(

                        builder,

                        isolation_result,

                        autoencoder_result,
                    )
                )


                observation = (
                    builder.build(

                        feature_record=
                            feature_record,

                        isolation_result=
                            isolation_result,

                        autoencoder_result=
                            autoencoder_result,

                        consensus_result=
                            consensus,

                        timestamp=
                            float(
                                timestamps[
                                    index
                                ]
                            ),

                        previous_timestamp=
                            previous_timestamp,
                    )
                )


                previous_timestamp = float(
                    timestamps[
                        index
                    ]
                )


                sequence.append(
                    observation[
                        "vector"
                    ]
                )


            if len(
                sequence
            ) != 8:

                continue


            matrix = np.asarray(

                sequence,

                dtype=np.float64,
            )


            if matrix.shape != (
                8,
                27,
            ):

                continue


            sequences.append(
                matrix
            )


            sequence_processes.append(
                temporal_row.get(
                    "process_name"
                )
            )


    finally:

        connection.close()


    if not sequences:

        raise RuntimeError(

            "Could not reconstruct any live "
            "8x27 temporal sequences."
        )


    return (
        np.asarray(
            sequences,
            dtype=np.float64,
        ),
        sequence_processes,
    )


# ================================================================
# FEATURE COMPARISON
# ================================================================

def compare_distributions(
    train_X,
    live_X,
    feature_names,
):

    train_flat = (
        train_X.reshape(
            -1,
            train_X.shape[
                -1
            ],
        )
    )


    live_flat = (
        live_X.reshape(
            -1,
            live_X.shape[
                -1
            ],
        )
    )


    comparisons = []


    for index, name in enumerate(
        feature_names
    ):

        train_values = (
            train_flat[
                :,
                index
            ]
        )


        live_values = (
            live_flat[
                :,
                index
            ]
        )


        train_stats = (
            stats(
                train_values
            )
        )


        live_stats = (
            stats(
                live_values
            )
        )


        train_std = max(

            float(
                train_stats[
                    "std"
                ]
            ),

            EPSILON,
        )


        mean_shift_z = abs(

            float(
                live_stats[
                    "mean"
                ]
            )

            - float(
                train_stats[
                    "mean"
                ]
            )

        ) / train_std


        live_outside_p95 = float(

            np.mean(

                (
                    live_values

                    < float(
                        train_stats[
                            "p05"
                        ]
                    )
                )

                |

                (
                    live_values

                    > float(
                        train_stats[
                            "p95"
                        ]
                    )
                )
            )
            * 100.0
        )


        comparisons.append(
            {
                "index":
                    index,

                "name":
                    name,

                "train":
                    train_stats,

                "live":
                    live_stats,

                "mean_shift_z":
                    float(
                        mean_shift_z
                    ),

                "outside_train_p05_p95_percent":
                    live_outside_p95,
            }
        )


    comparisons.sort(

        key=lambda item: (
            item[
                "mean_shift_z"
            ],
            item[
                "outside_train_p05_p95_percent"
            ],
        ),

        reverse=True,
    )


    return comparisons


# ================================================================
# NORMALIZED DISTRIBUTION CHECK
# ================================================================

def normalized_diagnostics(
    train_X,
    live_X,
):

    bundle = (
        joblib.load(
            SCALER_PATH
        )
    )


    scaler = (
        bundle[
            "scaler"
        ]
    )


    train_flat = (
        train_X.reshape(
            -1,
            27,
        )
    )


    live_flat = (
        live_X.reshape(
            -1,
            27,
        )
    )


    train_scaled = (
        scaler.transform(
            train_flat
        )
    )


    live_scaled = (
        scaler.transform(
            live_flat
        )
    )


    return {
        "train_abs_mean":
            float(
                np.mean(
                    np.abs(
                        train_scaled
                    )
                )
            ),

        "live_abs_mean":
            float(
                np.mean(
                    np.abs(
                        live_scaled
                    )
                )
            ),

        "train_abs_p95":
            float(
                np.percentile(
                    np.abs(
                        train_scaled
                    ),
                    95,
                )
            ),

        "live_abs_p95":
            float(
                np.percentile(
                    np.abs(
                        live_scaled
                    ),
                    95,
                )
            ),

        "train_abs_max":
            float(
                np.max(
                    np.abs(
                        train_scaled
                    )
                )
            ),

        "live_abs_max":
            float(
                np.max(
                    np.abs(
                        live_scaled
                    )
                )
            ),

        "live_values_abs_gt_5_percent":
            float(
                np.mean(
                    np.abs(
                        live_scaled
                    )
                    > 5.0
                )
                * 100.0
            ),

        "live_values_abs_gt_10_percent":
            float(
                np.mean(
                    np.abs(
                        live_scaled
                    )
                    > 10.0
                )
                * 100.0
            ),
    }


# ================================================================
# DELTA DIAGNOSTIC
# ================================================================

def delta_report(
    train_X,
    live_X,
    feature_names,
):

    try:

        index = (
            feature_names.index(
                "delta_seconds"
            )
        )


    except ValueError:

        return


    train_delta = (
        train_X[
            :,
            :,
            index
        ]
        .reshape(
            -1
        )
    )


    live_delta = (
        live_X[
            :,
            :,
            index
        ]
        .reshape(
            -1
        )
    )


    print()

    print(
        "=" * 100
    )

    print(
        "DELTA_SECONDS DIAGNOSTIC"
    )

    print(
        "=" * 100
    )


    print(
        "TRAIN:",
        stats(
            train_delta
        ),
    )


    print(
        "LIVE :",
        stats(
            live_delta
        ),
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
        "SENTINEL-X TEMPORAL LIVE/TRAIN DISTRIBUTION DIAGNOSTIC"
    )

    print(
        "=" * 100
    )


    # ============================================================
    # LOAD TRAIN
    # ============================================================

    print()

    print(
        "[1] Loading raw Transformer training sequences..."
    )


    (
        train_X,
        feature_names,

    ) = load_raw_training_distribution()


    print(
        "Training shape:",
        train_X.shape,
    )


    # ============================================================
    # LOAD LIVE
    # ============================================================

    print()

    print(
        "[2] Reconstructing real live temporal sequences..."
    )


    (
        live_X,
        live_processes,

    ) = load_live_sequences(
        feature_names
    )


    print(
        "Live shape:",
        live_X.shape,
    )


    print(
        "Processes:",
        sorted(
            set(
                str(
                    process
                )

                for process
                in live_processes
            )
        ),
    )


    # ============================================================
    # FEATURE DISTRIBUTION
    # ============================================================

    print()

    print(
        "[3] Comparing all 27 raw feature distributions..."
    )


    comparisons = (
        compare_distributions(

            train_X=
                train_X,

            live_X=
                live_X,

            feature_names=
                feature_names,
        )
    )


    print()

    print(
        "=" * 100
    )

    print(
        "FEATURE DISTRIBUTION SHIFT — WORST FIRST"
    )

    print(
        "=" * 100
    )


    print(

        f"{'#':<4}"
        f"{'Feature':<34}"
        f"{'TrainMean':>12}"
        f"{'LiveMean':>12}"
        f"{'ShiftZ':>10}"
        f"{'Outside90%':>14}"
    )


    print(
        "-" * 100
    )


    for rank, item in enumerate(
        comparisons[
            :TOP_FEATURES
        ],
        start=1,
    ):

        print(

            f"{rank:<4}"

            f"{item['name']:<34}"

            f"{fmt(item['train']['mean']):>12}"

            f"{fmt(item['live']['mean']):>12}"

            f"{item['mean_shift_z']:>10.2f}"

            f"{item['outside_train_p05_p95_percent']:>13.2f}%"
        )


    # ============================================================
    # NORMALIZED DISTRIBUTION
    # ============================================================

    print()

    print(
        "[4] Checking scaler-domain mismatch..."
    )


    normalized = (
        normalized_diagnostics(

            train_X=
                train_X,

            live_X=
                live_X,
        )
    )


    print()

    print(
        "Train normalized |x| mean :",
        round(
            normalized[
                "train_abs_mean"
            ],
            4,
        ),
    )


    print(
        "Live normalized |x| mean  :",
        round(
            normalized[
                "live_abs_mean"
            ],
            4,
        ),
    )


    print(
        "Train normalized |x| P95  :",
        round(
            normalized[
                "train_abs_p95"
            ],
            4,
        ),
    )


    print(
        "Live normalized |x| P95   :",
        round(
            normalized[
                "live_abs_p95"
            ],
            4,
        ),
    )


    print(
        "Train normalized |x| max  :",
        round(
            normalized[
                "train_abs_max"
            ],
            4,
        ),
    )


    print(
        "Live normalized |x| max   :",
        round(
            normalized[
                "live_abs_max"
            ],
            4,
        ),
    )


    print(
        "Live |z| > 5              :",
        round(
            normalized[
                "live_values_abs_gt_5_percent"
            ],
            2,
        ),
        "%",
    )


    print(
        "Live |z| > 10             :",
        round(
            normalized[
                "live_values_abs_gt_10_percent"
            ],
            2,
        ),
        "%",
    )


    # ============================================================
    # DELTA
    # ============================================================

    delta_report(

        train_X=
            train_X,

        live_X=
            live_X,

        feature_names=
            feature_names,
    )


    # ============================================================
    # INTERPRETATION
    # ============================================================

    severe = [

        item

        for item
        in comparisons

        if (
            item[
                "mean_shift_z"
            ]
            >= 3.0

            or

            item[
                "outside_train_p05_p95_percent"
            ]
            >= 60.0
        )
    ]


    print()

    print(
        "=" * 100
    )

    print(
        "DIAGNOSTIC RESULT"
    )

    print(
        "=" * 100
    )


    print(
        "Severely shifted features:",
        len(
            severe
        ),
    )


    if severe:

        print()

        print(
            "TEMPORAL LIVE/TRAIN DISTRIBUTION: MISMATCH CONFIRMED"
        )


        print()

        print(
            "Do NOT promote Temporal AI or Fusion v3."
        )


        print()

        print(
            "Top shifted features:"
        )


        for item in severe[
            :10
        ]:

            print(

                " - "
                f"{item['name']} | "
                f"ShiftZ="
                f"{item['mean_shift_z']:.2f} | "
                f"Outside="
                f"{item['outside_train_p05_p95_percent']:.2f}%"
            )


    else:

        print(
            "TEMPORAL LIVE/TRAIN DISTRIBUTION: "
            "NO LARGE RAW SHIFT FOUND"
        )


        print()

        print(
            "If live Transformer errors still saturate, "
            "inspect sequence construction and model calibration."
        )


if __name__ == "__main__":

    main()