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


from ai_detection.temporal.process_temporal_transformer_trainer import (
    MODEL_PATH,
    SEQUENCE_LENGTH,
    INPUT_FEATURE_COUNT,
    load_process_temporal_transformer,
)


# ================================================================
# SENTINEL-X TEMPORAL ANOMALY CALIBRATOR V1
#
# Calibration source:
#
#       VALIDATION SPLIT ONLY
#
# Test split remains untouched.
#
# Converts raw temporal reconstruction error into a conservative
# endpoint-relative 0–100 anomaly score.
#
#
# Calibration semantics:
#
#       validation median       -> score ~10
#       validation P90          -> score ~30
#       validation P95          -> score ~40
#       validation P97          -> score ~60
#       validation P99          -> score ~80
#       validation maximum      -> score ~95
#
#
# Therefore:
#
#       NORMAL         < 40
#       UNUSUAL        40–59
#       SUSPICIOUS     60–79
#       HIGH_ANOMALY   >=80
#
#
# These are NOT malware probabilities.
# ================================================================


# ================================================================
# PATHS
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
    / "process_sequence_splits_v1.npz"
)


CALIBRATION_PATH = (
    PROJECT_ROOT
    / "models"
    / "temporal"
    / "sentinelx_temporal_anomaly_calibration_v1.json"
)


# ================================================================
# IDENTITY
# ================================================================

CALIBRATION_NAME = (
    "sentinelx_temporal_anomaly_calibration"
)


CALIBRATION_VERSION = "v1"


# ================================================================
# CONFIGURATION
# ================================================================

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

class ProcessTemporalAnomalyCalibrator:

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

        ) = load_process_temporal_transformer(

            model_path=
                MODEL_PATH,

            device=
                self.device,
        )


    # ============================================================
    # LOAD VALIDATION SPLIT
    # ============================================================

    def load_validation_data(
        self,
    ) -> np.ndarray:

        if not DATASET_PATH.exists():

            raise FileNotFoundError(

                "Temporal split dataset does not exist:\n"
                f"{DATASET_PATH}"
            )


        data = np.load(
            DATASET_PATH,
            allow_pickle=False,
        )


        if "X_validation" not in data.files:

            raise RuntimeError(
                "X_validation is missing from temporal dataset."
            )


        X_validation = np.asarray(

            data[
                "X_validation"
            ],

            dtype=np.float32,
        )


        if X_validation.ndim != 3:

            raise RuntimeError(

                "X_validation must have shape "
                "(windows, sequence, features)."
            )


        if (

            X_validation.shape[
                1
            ]

            != SEQUENCE_LENGTH

        ):

            raise RuntimeError(
                "Unexpected sequence length."
            )


        if (

            X_validation.shape[
                2
            ]

            != INPUT_FEATURE_COUNT

        ):

            raise RuntimeError(
                "Unexpected temporal feature count."
            )


        if (

            len(
                X_validation
            )

            < MINIMUM_VALIDATION_WINDOWS

        ):

            raise RuntimeError(

                "Not enough validation windows for temporal "
                "calibration."
            )


        if not np.all(
            np.isfinite(
                X_validation
            )
        ):

            raise RuntimeError(

                "Validation data contains NaN or infinity."
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


        all_errors = []


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


                per_timestep_errors = []


                for timestep in range(
                    SEQUENCE_LENGTH
                ):

                    corrupted = (
                        batch.clone()
                    )


                    corrupted[
                        :,
                        timestep,
                        :
                    ] = 0.0


                    (
                        reconstruction,
                        _,
                        _,

                    ) = self.model(
                        corrupted
                    )


                    timestep_error = torch.mean(

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


                    per_timestep_errors.append(
                        timestep_error
                    )


                stacked = torch.stack(

                    per_timestep_errors,

                    dim=1,
                )


                sequence_error = torch.mean(

                    stacked,

                    dim=1,
                )


                all_errors.extend(

                    sequence_error
                    .detach()
                    .cpu()
                    .numpy()
                    .tolist()
                )


        return np.asarray(

            all_errors,

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
        # CONSERVATIVE SCORE ANCHORS
        #
        # High anomaly starts around the extreme tail.
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


        # --------------------------------------------------------
        # Used when live error exceeds anything in validation.
        # --------------------------------------------------------

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


        model_metadata = (

            self.model_artifact.get(
                "metadata",
                {}
            )
        )


        representation_health = (

            model_metadata.get(
                "representation_health",
                {}
            )
        )


        return {
            "calibration_name":
                CALIBRATION_NAME,

            "calibration_version":
                CALIBRATION_VERSION,

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
                    "leave_one_timestep_out_mean_squared_error"
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

                "should_alert_threshold":
                    60.0,

                "critical_from_temporal_model_alone":
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
                representation_health,

            "test_split_used":
                False,

            "scientific_note":
                (
                    "The 0-100 value is an endpoint-relative "
                    "temporal anomaly score calibrated from "
                    "validation reconstruction errors. It is not "
                    "a probability of malware or compromise."
                ),
        }


    # ============================================================
    # SAVE
    # ============================================================

    def save(
        self,
        calibration: Dict[str, Any],
    ) -> None:

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
            "=" * 86
        )

        print(
            "SENTINEL-X TEMPORAL ANOMALY CALIBRATION V1"
        )

        print(
            "=" * 86
        )


        print()

        print(
            "Device:",
            self.device,
        )


        print()

        print(
            "[1/4] Loading validation temporal sequences..."
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
            "[2/4] Computing leave-one-timestep-out errors..."
        )


        errors = (
            self.calculate_errors(
                X_validation
            )
        )


        stats = (
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
                f"{stats[key]:.8f}"
            )


        print()

        print(
            "[3/4] Building conservative anomaly calibration..."
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
            "-" * 60
        )


        for anchor in calibration[
            "score_anchors"
        ]:

            print(

                f"{anchor['name']:<12} "
                f"error={anchor['error']:<14.8f} "
                f"score={anchor['score']:.1f}"
            )


        print()

        print(
            "[4/4] Saving calibration..."
        )


        self.save(
            calibration
        )


        print()

        print(
            "=" * 86
        )

        print(
            "TEMPORAL ANOMALY CALIBRATION: COMPLETE"
        )

        print(
            "=" * 86
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
            "Active temporal signal threshold : 60"
        )


        print(
            "Strong temporal signal threshold : 80"
        )


        print()

        print(
            "TEST SPLIT USED: NO"
        )


        return calibration


# ================================================================
# ENTRY
# ================================================================

if __name__ == "__main__":

    calibrator = (
        ProcessTemporalAnomalyCalibrator()
    )


    calibrator.run()