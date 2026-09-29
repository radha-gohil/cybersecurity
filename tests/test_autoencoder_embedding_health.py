from __future__ import annotations

from pathlib import Path
import sys

from collections import Counter

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


from ai_detection.behavior.behavior_feature_store import (
    BehaviorFeatureStore,
)

from ai_detection.behavior.process_autoencoder_predictor import (
    ProcessAutoencoderPredictor,
)


# ================================================================
# CONFIGURATION
# ================================================================

MAX_RECORDS = 1000


MINIMUM_VALID_EMBEDDINGS = 100


ZERO_EPSILON = 1e-8


MAX_ACCEPTABLE_ALL_ZERO_PERCENT = 30.0


MAX_ACCEPTABLE_DEAD_DIMENSION_PERCENT = 95.0


MINIMUM_DIMENSION_STD = 1e-5


# ================================================================
# HELPERS
# ================================================================

def percentage(
    value: int,
    total: int,
) -> float:

    if total <= 0:

        return 0.0

    return round(
        (
            value
            / total
        )
        * 100.0,
        2,
    )


def is_all_zero(
    embedding,
) -> bool:

    return all(

        abs(
            float(value)
        )
        <= ZERO_EPSILON

        for value
        in embedding
    )


# ================================================================
# MAIN
# ================================================================

def main() -> int:

    print()

    print(
        "=" * 82
    )

    print(
        "SENTINEL-X AUTOENCODER EMBEDDING HEALTH CHECK"
    )

    print(
        "=" * 82
    )


    # ============================================================
    # LOAD MODEL
    # ============================================================

    predictor = (
        ProcessAutoencoderPredictor()
    )


    status = (
        predictor.get_status()
    )


    print(
        "\nMODEL"
    )

    print(
        "-" * 82
    )

    print(
        "Available            :",
        status.get(
            "available"
        ),
    )

    print(
        "Model                :",
        status.get(
            "model_name"
        ),
    )

    print(
        "Version              :",
        status.get(
            "model_version"
        ),
    )

    print(
        "Bottleneck dimension :",
        status.get(
            "bottleneck_dimension"
        ),
    )


    if not status.get(
        "available"
    ):

        print(
            "\nERROR:",
            status.get(
                "load_error"
            ),
        )

        return 1


    # ============================================================
    # LOAD REAL ENDPOINT RECORDS
    # ============================================================

    store = (
        BehaviorFeatureStore()
    )


    records = (
        store.get_recent(
            limit=MAX_RECORDS
        )
    )


    print(
        "\nDATASET"
    )

    print(
        "-" * 82
    )

    print(
        "Recent records loaded:",
        len(
            records
        ),
    )


    # ============================================================
    # INFERENCE
    # ============================================================

    embeddings = []

    reconstruction_errors = []

    anomaly_confidences = []

    process_counter = Counter()

    failed = 0

    skipped = 0


    for record in records:

        feature_dict = (
            record.get(
                "features"
            )
        )


        if not isinstance(
            feature_dict,
            dict,
        ):

            skipped += 1

            continue


        result = (
            predictor.predict_feature_dict(

                feature_dict=
                    feature_dict,

                process_metadata={

                    "pid":
                        record.get(
                            "pid"
                        ),

                    "process_name":
                        record.get(
                            "process_name"
                        ),
                },
            )
        )


        if (

            not result.get(
                "available"
            )

            or

            result.get(
                "prediction_failed",
                False,
            )

        ):

            failed += 1

            continue


        embedding = (
            result.get(
                "behavior_embedding"
            )
        )


        if not embedding:

            failed += 1

            continue


        embeddings.append(
            embedding
        )


        reconstruction_errors.append(

            float(

                result.get(
                    "reconstruction_error",
                    0.0,
                )
            )
        )


        anomaly_confidences.append(

            float(

                result.get(
                    "anomaly_confidence",
                    0.0,
                )
            )
        )


        process_name = (

            str(

                record.get(
                    "process_name"
                )

                or "UNKNOWN"
            )
            .strip()
            .lower()
        )


        process_counter[
            process_name
        ] += 1


    # ============================================================
    # BASIC VALIDATION
    # ============================================================

    valid_count = len(
        embeddings
    )


    print(
        "Valid embeddings      :",
        valid_count,
    )

    print(
        "Failed predictions    :",
        failed,
    )

    print(
        "Skipped records       :",
        skipped,
    )

    print(
        "Unique processes      :",
        len(
            process_counter
        ),
    )


    if valid_count < MINIMUM_VALID_EMBEDDINGS:

        print()

        print(
            "RESULT: NOT ENOUGH VALID EMBEDDINGS"
        )

        print(
            f"Need at least {MINIMUM_VALID_EMBEDDINGS}."
        )

        return 1


    matrix = np.asarray(

        embeddings,

        dtype=np.float64,
    )


    if matrix.ndim != 2:

        print(
            "ERROR: embedding matrix is not 2-dimensional."
        )

        return 1


    dimension = (
        matrix.shape[
            1
        ]
    )


    # ============================================================
    # ALL-ZERO EMBEDDINGS
    # ============================================================

    all_zero_count = sum(

        1

        for embedding
        in embeddings

        if is_all_zero(
            embedding
        )
    )


    all_zero_percent = percentage(

        all_zero_count,

        valid_count,
    )


    # ============================================================
    # PER-DIMENSION STATISTICS
    # ============================================================

    dimension_statistics = []


    for index in range(
        dimension
    ):

        values = (
            matrix[
                :,
                index
            ]
        )


        zero_count = int(

            np.sum(

                np.abs(
                    values
                )

                <= ZERO_EPSILON
            )
        )


        zero_percent = percentage(

            zero_count,

            valid_count,
        )


        std_value = float(

            np.std(
                values
            )
        )


        dimension_statistics.append(
            {

                "dimension":
                    index,

                "min":
                    float(
                        np.min(
                            values
                        )
                    ),

                "max":
                    float(
                        np.max(
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
                    std_value,

                "zero_count":
                    zero_count,

                "zero_percent":
                    zero_percent,
            }
        )


    # ============================================================
    # UNIQUE EMBEDDINGS
    # ============================================================

    rounded_embeddings = {

        tuple(

            round(
                float(value),
                6,
            )

            for value
            in embedding
        )

        for embedding
        in embeddings
    }


    unique_embedding_count = len(
        rounded_embeddings
    )


    unique_embedding_percent = percentage(

        unique_embedding_count,

        valid_count,
    )


    # ============================================================
    # RECONSTRUCTION STATISTICS
    # ============================================================

    reconstruction_array = np.asarray(

        reconstruction_errors,

        dtype=np.float64,
    )


    confidence_array = np.asarray(

        anomaly_confidences,

        dtype=np.float64,
    )


    # ============================================================
    # REPORT
    # ============================================================

    print()

    print(
        "=" * 82
    )

    print(
        "BOTTLENECK EMBEDDING STATISTICS"
    )

    print(
        "=" * 82
    )


    print(
        "Embedding dimension         :",
        dimension,
    )


    print(
        "All-zero embeddings        :",
        all_zero_count,
    )


    print(
        "All-zero percentage        :",
        f"{all_zero_percent:.2f}%",
    )


    print(
        "Unique embeddings          :",
        unique_embedding_count,
    )


    print(
        "Unique embedding percentage:",
        f"{unique_embedding_percent:.2f}%",
    )


    print()

    print(
        f"{'Dim':<8}"
        f"{'Min':>13}"
        f"{'Max':>13}"
        f"{'Mean':>13}"
        f"{'Std':>13}"
        f"{'Zero %':>12}"
    )

    print(
        "-" * 72
    )


    for stats in (
        dimension_statistics
    ):

        print(

            f"{stats['dimension']:<8}"

            f"{stats['min']:>13.6f}"

            f"{stats['max']:>13.6f}"

            f"{stats['mean']:>13.6f}"

            f"{stats['std']:>13.6f}"

            f"{stats['zero_percent']:>11.2f}%"
        )


    # ============================================================
    # RECONSTRUCTION HEALTH
    # ============================================================

    print()

    print(
        "=" * 82
    )

    print(
        "RECONSTRUCTION STATISTICS"
    )

    print(
        "=" * 82
    )


    print(
        "Mean reconstruction error :",
        round(
            float(
                np.mean(
                    reconstruction_array
                )
            ),
            8,
        ),
    )


    print(
        "Median reconstruction error:",
        round(
            float(
                np.median(
                    reconstruction_array
                )
            ),
            8,
        ),
    )


    print(
        "P95 reconstruction error  :",
        round(
            float(
                np.percentile(
                    reconstruction_array,
                    95,
                )
            ),
            8,
        ),
    )


    print(
        "P99 reconstruction error  :",
        round(
            float(
                np.percentile(
                    reconstruction_array,
                    99,
                )
            ),
            8,
        ),
    )


    print(
        "Mean anomaly confidence   :",
        round(
            float(
                np.mean(
                    confidence_array
                )
            ),
            2,
        ),
    )


    print(
        "P95 anomaly confidence    :",
        round(
            float(
                np.percentile(
                    confidence_array,
                    95,
                )
            ),
            2,
        ),
    )


    # ============================================================
    # PROCESS DIVERSITY
    # ============================================================

    print()

    print(
        "=" * 82
    )

    print(
        "TOP PROCESS REPRESENTATION"
    )

    print(
        "=" * 82
    )


    for (
        process_name,
        count,
    ) in process_counter.most_common(
        15
    ):

        print(

            f"{process_name:<35}"
            f"{count:>8}"
        )


    # ============================================================
    # HEALTH CHECKS
    # ============================================================

    print()

    print(
        "=" * 82
    )

    print(
        "HEALTH CHECKS"
    )

    print(
        "=" * 82
    )


    checks = {}


    checks[
        "enough_embeddings"
    ] = (

        valid_count
        >= MINIMUM_VALID_EMBEDDINGS
    )


    checks[
        "all_zero_rate_acceptable"
    ] = (

        all_zero_percent
        <= MAX_ACCEPTABLE_ALL_ZERO_PERCENT
    )


    checks[
        "embedding_diversity"
    ] = (

        unique_embedding_percent
        >= 20.0
    )


    dead_dimensions = []


    for stats in (
        dimension_statistics
    ):

        dimension_dead = (

            stats[
                "zero_percent"
            ]

            >= MAX_ACCEPTABLE_DEAD_DIMENSION_PERCENT

            or

            stats[
                "std"
            ]

            < MINIMUM_DIMENSION_STD
        )


        if dimension_dead:

            dead_dimensions.append(

                stats[
                    "dimension"
                ]
            )


    checks[
        "no_dead_dimensions"
    ] = (

        len(
            dead_dimensions
        )
        == 0
    )


    for (
        name,
        passed,
    ) in checks.items():

        print(

            f"{name:<40}: "

            + (
                "PASS"
                if passed
                else "REVIEW"
            )
        )


    if dead_dimensions:

        print()

        print(
            "Dead/collapsed dimensions:",
            dead_dimensions,
        )


    # ============================================================
    # FINAL RESULT
    # ============================================================

    print()

    print(
        "=" * 82
    )

    print(
        "FINAL RESULT"
    )

    print(
        "=" * 82
    )


    healthy = all(
        checks.values()
    )


    if healthy:

        print(
            "AUTOENCODER EMBEDDING HEALTH: PASS"
        )

        print()

        print(
            "The bottleneck has sufficient variation to be "
            "used as a learned behavioral representation."
        )

        print()

        print(
            "NEXT:"
        )

        print(
            "Proceed to multi-model persistence and live "
            "Isolation Forest + Autoencoder integration."
        )

        return 0


    print(
        "AUTOENCODER EMBEDDING HEALTH: REVIEW REQUIRED"
    )

    print()

    print(
        "Do not store these embeddings system-wide yet."
    )


    if (

        not checks[
            "all_zero_rate_acceptable"
        ]

        or

        not checks[
            "no_dead_dimensions"
        ]

    ):

        print()

        print(
            "The ReLU bottleneck appears partially or fully collapsed."
        )

        print(
            "If confirmed, retrain Autoencoder v2 with a "
            "non-dead bottleneck activation such as tanh."
        )


    return 1


# ================================================================
# ENTRY POINT
# ================================================================

if __name__ == "__main__":

    sys.exit(
        main()
    )