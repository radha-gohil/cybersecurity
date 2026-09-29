from pathlib import Path
import sys


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
# SENTINEL-X AUTOENCODER REAL-SAMPLE TEST
# ================================================================


def main():

    predictor = (
        ProcessAutoencoderPredictor()
    )


    print()

    print(
        "=" * 78
    )

    print(
        "SENTINEL-X AUTOENCODER REAL SAMPLE TEST"
    )

    print(
        "=" * 78
    )


    status = (
        predictor.get_status()
    )


    print(
        "Available:",
        status.get(
            "available"
        ),
    )


    if not status.get(
        "available"
    ):

        print(
            "ERROR:",
            status.get(
                "load_error"
            ),
        )

        return


    store = (
        BehaviorFeatureStore()
    )


    records = (
        store.get_recent(
            limit=1000
        )
    )


    selected = None


    # ============================================================
    # PREFER A NORMAL ISOLATION FOREST SAMPLE
    # ============================================================

    for record in records:

        if (

            record.get(
                "anomaly_prediction"
            )

            == "NORMAL"

            and isinstance(
                record.get(
                    "features"
                ),
                dict,
            )

        ):

            selected = record

            break


    # ============================================================
    # FALLBACK
    # ============================================================

    if selected is None:

        for record in records:

            if isinstance(
                record.get(
                    "features"
                ),
                dict,
            ):

                selected = record

                break


    if selected is None:

        print(
            "No process behavior feature record found."
        )

        return


    print()

    print(
        "Behavior Record:"
    )


    print(
        "ID:",
        selected.get(
            "id"
        ),
    )


    print(
        "Process:",
        selected.get(
            "process_name"
        ),
    )


    print(
        "PID:",
        selected.get(
            "pid"
        ),
    )


    print(
        "Isolation Forest Label:",
        selected.get(
            "anomaly_prediction"
        ),
    )


    print(
        "Isolation Forest Score:",
        selected.get(
            "anomaly_score"
        ),
    )


    result = (

        predictor.predict_feature_dict(

            feature_dict=
                selected[
                    "features"
                ],

            process_metadata={

                "pid":
                    selected.get(
                        "pid"
                    ),

                "process_name":
                    selected.get(
                        "process_name"
                    ),

                "parent_process_name":
                    selected.get(
                        "parent_process_name"
                    ),

                "executable_path":
                    selected.get(
                        "executable_path"
                    ),
            },
        )
    )


    print()

    print(
        "-" * 78
    )

    print(
        "AUTOENCODER RESULT"
    )

    print(
        "-" * 78
    )


    print(
        "Reconstruction error:",
        result.get(
            "reconstruction_error"
        ),
    )


    print(
        "Region:",
        result.get(
            "reconstruction_region"
        ),
    )


    print(
        "Confidence:",
        result.get(
            "anomaly_confidence"
        ),
    )


    print(
        "Label:",
        result.get(
            "anomaly_label"
        ),
    )


    print(
        "Severity:",
        result.get(
            "severity"
        ),
    )


    print(
        "Candidate alert:",
        result.get(
            "candidate_alert"
        ),
    )


    print()

    print(
        "Behavior embedding:"
    )


    print(
        result.get(
            "behavior_embedding"
        )
    )


    print(
        "Embedding dimension:",
        result.get(
            "embedding_dimension"
        ),
    )


    print()

    print(
        "Top reconstruction errors:"
    )


    for item in (

        result.get(
            "feature_reconstruction_errors",
            []
        )
    ):

        print(

            f"{item['feature']:<30} "
            f"actual={item['actual_value']:<12} "
            f"reconstructed={item['reconstructed_value']:<12} "
            f"error={item['scaled_squared_error']}"
        )


    print()

    print(
        "=" * 78
    )

    print(
        "TEST COMPLETE"
    )

    print(
        "=" * 78
    )


if __name__ == "__main__":

    main()