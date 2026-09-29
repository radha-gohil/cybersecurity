from __future__ import annotations

import json

from datetime import (
    datetime,
    timezone,
)

from pathlib import Path

from typing import (
    Any,
    Dict,
)

import numpy as np
import torch

from torch.utils.data import (
    DataLoader,
    TensorDataset,
)


from ai_detection.temporal.process_temporal_transformer_v2_trainer import (
    MODEL_PATH,
    SEQUENCE_LENGTH,
    INPUT_FEATURE_COUNT,
    load_process_temporal_transformer_v2,
)


# ================================================================
# SENTINEL-X TEMPORAL ANOMALY CALIBRATION V2
#
# Uses:
#
#   Transformer v2
#   8 × 26 corrected temporal schema
#   validation split only
#
#
# Test split remains untouched.
#
#
# Reconstruction error:
#
#   hide timestep 1 → reconstruct
#   hide timestep 2 → reconstruct
#   ...
#   hide timestep 8 → reconstruct
#
#   final error = average error across all 8 timesteps
#
#
# IMPORTANT:
#
# anomaly score != malware probability
# ================================================================


PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[2]
)


DATASET_PATH = (
    PROJECT_ROOT
    / "data"
    / "temporal"
    / "process_sequence_splits_v2.npz"
)


CALIBRATION_PATH = (
    PROJECT_ROOT
    / "models"
    / "temporal"
    / "sentinelx_temporal_anomaly_calibration_v2.json"
)


CALIBRATION_NAME = (
    "sentinelx_temporal_anomaly_calibration"
)


CALIBRATION_VERSION = "v2"


SCHEMA_VERSION = (
    "process_temporal_schema_v2"
)


BATCH_SIZE = 64

MINIMUM_VALIDATION_WINDOWS = 5


# ================================================================
# HELPERS
# ================================================================

def now_iso() -> str:

    return (
        datetime
        .now(
            timezone.utc
        )
        .isoformat()
    )


def statistics(
    values: np.ndarray,
) -> Dict[str, float]:

    values = np.asarray(
        values,
        dtype=np.float64,
    )


    if values.size == 0:

        raise RuntimeError(
            "Cannot calculate statistics from empty array."
        )


    return {
        "count":
            int(
                len(
                    values
                )
            ),

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
            float(
                np.std(
                    values
                )
            ),

        "p50":
            float(
                np.percentile(
                    values,
                    50,
                )
            ),

        "p75":
            float(
                np.percentile(
                    values,
                    75,
                )
            ),

        "p90":
            float(
                np.percentile(
                    values,
                    90,
                )
            ),

        "p95":
            float(
                np.percentile(
                    values,
                    95,
                )
            ),

        "p97":
            float(
                np.percentile(
                    values,
                    97,
                )
            ),

        "p99":
            float(
                np.percentile(
                    values,
                    99,
                )
            ),
    }


# ================================================================
# CALIBRATOR
# ================================================================

class ProcessTemporalAnomalyCalibratorV2:

    def __init__(
        self,
    ):

        self.device = (
            torch.device(

                "cuda"

                if torch.cuda.is_available()

                else "cpu"
            )
        )


        (
            self.model,
            self.model_artifact,

        ) = load_process_temporal_transformer_v2(

            model_path=
                MODEL_PATH,

            device=
                self.device,
        )


    # ============================================================
    # LOAD VALIDATION DATA
    # ============================================================

    def load_validation_data(
        self,
    ) -> np.ndarray:

        if not DATASET_PATH.exists():

            raise FileNotFoundError(

                "Temporal split dataset v2 not found:\n"
                f"{DATASET_PATH}"
            )


        data = np.load(

            DATASET_PATH,

            allow_pickle=False,
        )


        if "X_validation" not in data.files:

            raise RuntimeError(

                "X_validation does not exist "
                "in corrected temporal dataset."
            )


        X_validation = np.asarray(

            data[
                "X_validation"
            ],

            dtype=np.float32,
        )


        expected_shape_tail = (

            SEQUENCE_LENGTH,

            INPUT_FEATURE_COUNT,
        )


        if (

            X_validation.ndim != 3

            or

            tuple(
                X_validation.shape[
                    1:
                ]
            )
            != expected_shape_tail

        ):

            raise RuntimeError(

                "Validation dataset shape mismatch. "
                f"Expected (*, {SEQUENCE_LENGTH}, "
                f"{INPUT_FEATURE_COUNT}), "
                f"received {X_validation.shape}."
            )


        if (

            len(
                X_validation
            )

            < MINIMUM_VALIDATION_WINDOWS

        ):

            raise RuntimeError(

                "Not enough validation windows "
                "for Temporal calibration v2."
            )


        if not np.all(
            np.isfinite(
                X_validation
            )
        ):

            raise RuntimeError(

                "Validation data contains "
                "NaN or infinity."
            )


        return X_validation


    # ============================================================
    # LEAVE-ONE-TIMESTEP-OUT ERROR
    # ============================================================

    def calculate_errors(
        self,
        matrix: np.ndarray,
    ) -> np.ndarray:

        tensor = torch.tensor(

            matrix,

            dtype=torch.float32,
        )


        loader = DataLoader(

            TensorDataset(
                tensor
            ),

            batch_size=
                BATCH_SIZE,

            shuffle=
                False,
        )


        sequence_errors = []


        self.model.eval()


        with torch.no_grad():

            for (
                batch,
            ) in loader:

                batch = (
                    batch.to(
                        self.device
                    )
                )


                timestep_errors = []


                for timestep in range(
                    SEQUENCE_LENGTH
                ):

                    mask = torch.zeros(

                        (
                            batch.shape[
                                0
                            ],

                            SEQUENCE_LENGTH,
                        ),

                        dtype=torch.bool,

                        device=
                            self.device,
                    )


                    mask[
                        :,
                        timestep
                    ] = True


                    (
                        reconstruction,
                        _,
                        _,

                    ) = self.model(

                        batch,

                        timestep_mask=
                            mask,
                    )


                    error = torch.mean(

                        (
                            reconstruction[
                                :,
                                timestep,
                                :
                            ]

                            - batch[
                                :,
                                timestep,
                                :
                            ]
                        )
                        ** 2,

                        dim=1,
                    )


                    timestep_errors.append(
                        error
                    )


                stacked = torch.stack(

                    timestep_errors,

                    dim=1,
                )


                averaged = torch.mean(

                    stacked,

                    dim=1,
                )


                sequence_errors.extend(

                    averaged
                    .detach()
                    .cpu()
                    .numpy()
                    .tolist()
                )


        return np.asarray(

            sequence_errors,

            dtype=np.float64,
        )


    # ============================================================
    # BUILD CALIBRATION
    # ============================================================

    def build_calibration(
        self,
        errors: np.ndarray,
    ) -> Dict[str, Any]:

        error_stats = (
            statistics(
                errors
            )
        )


        # ========================================================
        # CONSERVATIVE PERCENTILE CALIBRATION
        # ========================================================

        anchors = [

            {
                "name":
                    "minimum",

                "error":
                    error_stats[
                        "min"
                    ],

                "score":
                    0.0,
            },

            {
                "name":
                    "median",

                "error":
                    error_stats[
                        "p50"
                    ],

                "score":
                    10.0,
            },

            {
                "name":
                    "p90",

                "error":
                    error_stats[
                        "p90"
                    ],

                "score":
                    30.0,
            },

            {
                "name":
                    "p95",

                "error":
                    error_stats[
                        "p95"
                    ],

                "score":
                    40.0,
            },

            {
                "name":
                    "p97",

                "error":
                    error_stats[
                        "p97"
                    ],

                "score":
                    60.0,
            },

            {
                "name":
                    "p99",

                "error":
                    error_stats[
                        "p99"
                    ],

                "score":
                    80.0,
            },

            {
                "name":
                    "maximum",

                "error":
                    error_stats[
                        "max"
                    ],

                "score":
                    95.0,
            },
        ]


        tail_scale = max(

            error_stats[
                "p99"
            ]
            - error_stats[
                "p95"
            ],

            error_stats[
                "std"
            ],

            1e-6,
        )


        metadata = (
            self.model_artifact.get(
                "metadata",
                {}
            )
        )


        return {
            "calibration_name":
                CALIBRATION_NAME,

            "calibration_version":
                CALIBRATION_VERSION,

            "schema_version":
                SCHEMA_VERSION,

            "created_at":
                now_iso(),

            "model_name":
                self.model_artifact.get(
                    "model_name"
                ),

            "model_version":
                self.model_artifact.get(
                    "model_version"
                ),

            "model_path":
                str(
                    MODEL_PATH
                ),

            "input_feature_count":
                INPUT_FEATURE_COUNT,

            "sequence_length":
                SEQUENCE_LENGTH,

            "calibration_source":
                "validation_split_only",

            "validation_window_count":
                int(
                    len(
                        errors
                    )
                ),

            "reconstruction_error_method":
                (
                    "leave_one_complete_timestep_out_mse"
                ),

            "validation_error_statistics":
                error_stats,

            "score_anchors":
                anchors,

            "tail_scale":
                float(
                    tail_scale
                ),

            "labels": {
                "NORMAL": {
                    "minimum_score":
                        0.0,

                    "maximum_score_exclusive":
                        40.0,
                },

                "UNUSUAL": {
                    "minimum_score":
                        40.0,

                    "maximum_score_exclusive":
                        60.0,
                },

                "SUSPICIOUS": {
                    "minimum_score":
                        60.0,

                    "maximum_score_exclusive":
                        80.0,
                },

                "HIGH_ANOMALY": {
                    "minimum_score":
                        80.0,

                    "maximum_score":
                        100.0,
                },
            },

            "signal_policy": {
                "active_threshold":
                    60.0,

                "strong_threshold":
                    80.0,

                "critical_from_temporal_alone":
                    False,
            },

            "representation_dimension":
                (
                    self.model_artifact[
                        "config"
                    ][
                        "representation_dimension"
                    ]
                ),

            "representation_health":
                metadata.get(
                    "representation_health",
                    {}
                ),

            "removed_feature":
                "process_age_seconds",

            "test_split_used":
                False,

            "scientific_note":
                (
                    "The temporal anomaly score is calibrated "
                    "relative to validation reconstruction errors. "
                    "It is not malware probability."
                ),
        }


    # ============================================================
    # SAVE
    # ============================================================

    def save(
        self,
        calibration,
    ):

        CALIBRATION_PATH.parent.mkdir(

            parents=True,

            exist_ok=True,
        )


        with open(

            CALIBRATION_PATH,

            "w",

            encoding="utf-8",

        ) as file:

            json.dump(

                calibration,

                file,

                indent=4,

                sort_keys=False,
            )


    # ============================================================
    # RUN
    # ============================================================

    def run(
        self,
    ):

        print()

        print(
            "=" * 88
        )

        print(
            "SENTINEL-X TEMPORAL ANOMALY CALIBRATION V2"
        )

        print(
            "=" * 88
        )


        print()

        print(
            "Device:",
            self.device,
        )


        print()

        print(
            "[1/4] Loading corrected validation sequences..."
        )


        X_validation = (
            self.load_validation_data()
        )


        print(
            "Validation shape:",
            X_validation.shape,
        )


        print()

        print(
            "[2/4] Computing Transformer-v2 LOTO errors..."
        )


        errors = (
            self.calculate_errors(
                X_validation
            )
        )


        error_stats = (
            statistics(
                errors
            )
        )


        print()

        print(
            "Validation reconstruction distribution:"
        )


        for key in [

            "min",

            "mean",

            "std",

            "p50",

            "p90",

            "p95",

            "p97",

            "p99",

            "max",

        ]:

            print(

                f"{key:<8}: "
                f"{error_stats[key]:.8f}"
            )


        print()

        print(
            "[3/4] Building anomaly-score calibration..."
        )


        calibration = (
            self.build_calibration(
                errors
            )
        )


        print()

        print(
            "Score anchors:"
        )


        print(
            "-" * 64
        )


        for anchor in calibration[
            "score_anchors"
        ]:

            print(

                f"{anchor['name']:<12}"
                f"error="
                f"{anchor['error']:<16.8f}"
                f"score="
                f"{anchor['score']:.1f}"
            )


        print()

        print(
            "[4/4] Saving calibration v2..."
        )


        self.save(
            calibration
        )


        print()

        print(
            "=" * 88
        )

        print(
            "TEMPORAL ANOMALY CALIBRATION V2: COMPLETE"
        )

        print(
            "=" * 88
        )


        print()

        print(
            "Calibration:"
        )


        print(
            CALIBRATION_PATH
        )


        print()

        print(
            "Model version       : v2"
        )


        print(
            "Feature count       : 26"
        )


        print(
            "Test split used     : NO"
        )


        print(
            "Active threshold    : 60"
        )


        print(
            "Strong threshold    : 80"
        )


        return calibration


if __name__ == "__main__":

    ProcessTemporalAnomalyCalibratorV2().run()