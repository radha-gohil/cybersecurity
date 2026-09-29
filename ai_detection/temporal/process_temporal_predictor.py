from __future__ import annotations

import json
import math

from pathlib import Path

from typing import (
    Any,
    Dict,
    List,
)

import joblib
import numpy as np
import torch


from ai_detection.temporal.process_temporal_transformer_trainer import (
    MODEL_PATH,
    SEQUENCE_LENGTH,
    INPUT_FEATURE_COUNT,
    load_process_temporal_transformer,
)


# ================================================================
# SENTINEL-X TEMPORAL ANOMALY PREDICTOR V1
#
# Input:
#
#       raw temporal sequence
#       shape = (8, 27)
#
# Pipeline:
#
#       raw temporal sequence
#               ↓
#       training StandardScaler
#               ↓
#       normalized sequence
#               ↓
#       Temporal Transformer
#               ↓
#       leave-one-timestep-out reconstruction
#               ↓
#       raw temporal reconstruction error
#               ↓
#       validation-derived calibration
#               ↓
#       0–100 temporal anomaly score
#
#
# Also returns:
#
#       64D temporal representation
#
#
# IMPORTANT:
#
# anomaly_score != malware probability
# ================================================================


# ================================================================
# PATHS
# ================================================================

PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[2]
)


SCALER_PATH = (
    PROJECT_ROOT
    / "models"
    / "temporal"
    / "process_temporal_scaler_v1.joblib"
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

PREDICTOR_NAME = (
    "sentinelx_process_temporal_predictor"
)


PREDICTOR_VERSION = "v1"


# ================================================================
# SCORE POLICY
# ================================================================

UNUSUAL_THRESHOLD = 40.0

ACTIVE_THRESHOLD = 60.0

STRONG_THRESHOLD = 80.0


# ================================================================
# PREDICTOR
# ================================================================

class ProcessTemporalPredictor:

    def __init__(
        self,
        auto_load: bool = True,
    ):

        self.device = (
            torch.device(
                "cuda"
                if torch.cuda.is_available()
                else "cpu"
            )
        )


        self.model = None

        self.model_artifact = None

        self.scaler = None

        self.scaler_bundle = None

        self.calibration = None

        self.available = False

        self.load_error = None


        if auto_load:

            self.load()


    # ============================================================
    # LOAD
    # ============================================================

    def load(
        self,
    ) -> None:

        try:

            # ====================================================
            # MODEL
            # ====================================================

            (
                self.model,
                self.model_artifact,

            ) = load_process_temporal_transformer(

                model_path=
                    MODEL_PATH,

                device=
                    self.device,
            )


            # ====================================================
            # SCALER
            # ====================================================

            if not SCALER_PATH.exists():

                raise FileNotFoundError(

                    f"Temporal scaler missing: "
                    f"{SCALER_PATH}"
                )


            self.scaler_bundle = (
                joblib.load(
                    SCALER_PATH
                )
            )


            self.scaler = (
                self.scaler_bundle[
                    "scaler"
                ]
            )


            # ====================================================
            # CALIBRATION
            # ====================================================

            if not CALIBRATION_PATH.exists():

                raise FileNotFoundError(

                    "Temporal anomaly calibration missing: "
                    f"{CALIBRATION_PATH}"
                )


            with open(

                CALIBRATION_PATH,

                "r",

                encoding="utf-8",

            ) as file:

                self.calibration = (
                    json.load(
                        file
                    )
                )


            # ====================================================
            # COMPATIBILITY
            # ====================================================

            scaler_feature_count = int(

                self.scaler_bundle[
                    "feature_count"
                ]
            )


            if (

                scaler_feature_count
                != INPUT_FEATURE_COUNT

            ):

                raise RuntimeError(

                    "Temporal scaler feature count mismatch."
                )


            if (

                int(
                    self.scaler_bundle[
                        "sequence_length"
                    ]
                )

                != SEQUENCE_LENGTH

            ):

                raise RuntimeError(

                    "Temporal scaler sequence length mismatch."
                )


            representation_health = (

                self.model_artifact
                .get(
                    "metadata",
                    {}
                )
                .get(
                    "representation_health",
                    {}
                )
            )


            if (

                representation_health

                and

                not representation_health.get(
                    "healthy",
                    False,
                )

            ):

                raise RuntimeError(

                    "Saved Temporal Transformer representation "
                    "health is not marked healthy."
                )


            self.available = True

            self.load_error = None


        except Exception as error:

            self.available = False

            self.load_error = str(
                error
            )


    # ============================================================
    # STATUS
    # ============================================================

    def get_status(
        self,
    ) -> Dict[str, Any]:

        representation_dimension = None


        if self.model_artifact:

            representation_dimension = (

                self.model_artifact
                .get(
                    "config",
                    {}
                )
                .get(
                    "representation_dimension"
                )
            )


        return {
            "available":
                self.available,

            "predictor_name":
                PREDICTOR_NAME,

            "predictor_version":
                PREDICTOR_VERSION,

            "model_name":
                (
                    self.model_artifact.get(
                        "model_name"
                    )

                    if self.model_artifact

                    else None
                ),

            "model_version":
                (
                    self.model_artifact.get(
                        "model_version"
                    )

                    if self.model_artifact

                    else None
                ),

            "sequence_length":
                SEQUENCE_LENGTH,

            "feature_count":
                INPUT_FEATURE_COUNT,

            "representation_dimension":
                representation_dimension,

            "calibration_version":
                (
                    self.calibration.get(
                        "calibration_version"
                    )

                    if self.calibration

                    else None
                ),

            "device":
                str(
                    self.device
                ),

            "load_error":
                self.load_error,
        }


    # ============================================================
    # VALIDATE INPUT
    # ============================================================

    def validate_sequence(
        self,
        sequence,
    ) -> np.ndarray:

        matrix = np.asarray(

            sequence,

            dtype=np.float64,
        )


        if matrix.shape != (

            SEQUENCE_LENGTH,

            INPUT_FEATURE_COUNT,

        ):

            raise ValueError(

                "Temporal sequence must have shape "
                f"({SEQUENCE_LENGTH}, "
                f"{INPUT_FEATURE_COUNT}). "
                f"Received {matrix.shape}."
            )


        if not np.all(
            np.isfinite(
                matrix
            )
        ):

            raise ValueError(

                "Temporal sequence contains "
                "NaN or infinite values."
            )


        return matrix


    # ============================================================
    # NORMALIZE
    # ============================================================

    def normalize(
        self,
        raw_sequence: np.ndarray,
    ) -> np.ndarray:

        normalized = (
            self.scaler.transform(
                raw_sequence
            )
        )


        normalized = np.asarray(

            normalized,

            dtype=np.float32,
        )


        if not np.all(
            np.isfinite(
                normalized
            )
        ):

            raise RuntimeError(

                "Temporal normalization produced "
                "non-finite values."
            )


        return normalized


    # ============================================================
    # TEMPORAL ERROR
    # ============================================================

    def calculate_reconstruction_error(
        self,
        normalized_sequence: np.ndarray,
    ) -> Dict[str, Any]:

        tensor = torch.tensor(

            normalized_sequence[
                np.newaxis,
                :,
                :
            ],

            dtype=torch.float32,

            device=
                self.device,
        )


        per_timestep_errors = []


        self.model.eval()


        with torch.no_grad():

            for timestep in range(
                SEQUENCE_LENGTH
            ):

                corrupted = (
                    tensor.clone()
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


                error = torch.mean(

                    (
                        reconstruction[
                            0,
                            timestep,
                            :
                        ]

                        - tensor[
                            0,
                            timestep,
                            :
                        ]
                    )
                    ** 2

                ).item()


                per_timestep_errors.append(
                    float(
                        error
                    )
                )


        sequence_error = float(

            np.mean(
                per_timestep_errors
            )
        )


        most_unusual_timestep = int(

            np.argmax(
                per_timestep_errors
            )
        )


        return {
            "sequence_error":
                sequence_error,

            "per_timestep_errors":
                per_timestep_errors,

            "most_unusual_timestep":
                most_unusual_timestep,

            "maximum_timestep_error":
                float(
                    max(
                        per_timestep_errors
                    )
                ),
        }


    # ============================================================
    # TEMPORAL EMBEDDING
    # ============================================================

    def extract_embedding(
        self,
        normalized_sequence: np.ndarray,
    ) -> List[float]:

        tensor = torch.tensor(

            normalized_sequence[
                np.newaxis,
                :,
                :
            ],

            dtype=torch.float32,

            device=
                self.device,
        )


        self.model.eval()


        with torch.no_grad():

            (
                _,
                representation,

            ) = self.model.encode(
                tensor
            )


        embedding = (

            representation[
                0
            ]
            .detach()
            .cpu()
            .numpy()
            .astype(
                np.float64
            )
        )


        return embedding.tolist()


    # ============================================================
    # PREPARE SCORE ANCHORS
    # ============================================================

    def get_score_anchors(
        self,
    ):

        raw_anchors = (

            self.calibration[
                "score_anchors"
            ]
        )


        pairs = sorted(

            [
                (
                    float(
                        anchor[
                            "error"
                        ]
                    ),

                    float(
                        anchor[
                            "score"
                        ]
                    ),
                )

                for anchor
                in raw_anchors
            ],

            key=lambda item:
                item[
                    0
                ],
        )


        # --------------------------------------------------------
        # Percentiles can be equal in very small datasets.
        #
        # Collapse duplicate error values while keeping the highest
        # corresponding anomaly score.
        # --------------------------------------------------------

        collapsed = {}


        for (
            error,
            score,
        ) in pairs:

            collapsed[
                error
            ] = max(

                score,

                collapsed.get(
                    error,
                    0.0,
                ),
            )


        errors = np.asarray(

            sorted(
                collapsed.keys()
            ),

            dtype=np.float64,
        )


        scores = np.asarray(

            [
                collapsed[
                    error
                ]

                for error in errors
            ],

            dtype=np.float64,
        )


        return (
            errors,
            scores,
        )


    # ============================================================
    # CALIBRATE SCORE
    # ============================================================

    def calibrate_score(
        self,
        reconstruction_error: float,
    ) -> float:

        (
            anchor_errors,
            anchor_scores,

        ) = self.get_score_anchors()


        if len(
            anchor_errors
        ) == 0:

            raise RuntimeError(

                "Temporal calibration contains "
                "no score anchors."
            )


        reconstruction_error = float(
            reconstruction_error
        )


        # ========================================================
        # BELOW CALIBRATION RANGE
        # ========================================================

        if (

            reconstruction_error

            <= anchor_errors[
                0
            ]

        ):

            return 0.0


        # ========================================================
        # WITHIN CALIBRATION RANGE
        # ========================================================

        if (

            reconstruction_error

            <= anchor_errors[
                -1
            ]

        ):

            score = np.interp(

                reconstruction_error,

                anchor_errors,

                anchor_scores,
            )


            return float(

                np.clip(
                    score,
                    0.0,
                    95.0,
                )
            )


        # ========================================================
        # BEYOND OBSERVED VALIDATION MAXIMUM
        #
        # Validation max is mapped near 95.
        # Extremely larger errors asymptotically approach 100.
        # ========================================================

        tail_scale = max(

            float(
                self.calibration.get(
                    "tail_scale",
                    1.0,
                )
            ),

            1e-6,
        )


        excess = (

            reconstruction_error

            - anchor_errors[
                -1
            ]
        )


        extra_score = (

            5.0

            * (
                1.0

                - math.exp(
                    -excess
                    / tail_scale
                )
            )
        )


        return float(

            np.clip(

                95.0
                + extra_score,

                0.0,

                100.0,
            )
        )


    # ============================================================
    # CLASSIFICATION
    # ============================================================

    def classify(
        self,
        score: float,
    ) -> Dict[str, Any]:

        score = float(
            score
        )


        if score >= STRONG_THRESHOLD:

            return {
                "label":
                    "HIGH_ANOMALY",

                "severity":
                    "HIGH",

                "is_active":
                    True,

                "is_strong":
                    True,

                "should_alert":
                    True,
            }


        if score >= ACTIVE_THRESHOLD:

            return {
                "label":
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


        if score >= UNUSUAL_THRESHOLD:

            return {
                "label":
                    "UNUSUAL",

                "severity":
                    "LOW",

                "is_active":
                    False,

                "is_strong":
                    False,

                "should_alert":
                    False,
            }


        return {
            "label":
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


    # ============================================================
    # PREDICT
    # ============================================================

    def predict(
        self,
        sequence,
        input_is_normalized: bool = False,
    ) -> Dict[str, Any]:

        if not self.available:

            return {
                "available":
                    False,

                "predictor_name":
                    PREDICTOR_NAME,

                "predictor_version":
                    PREDICTOR_VERSION,

                "error":
                    self.load_error,
            }


        try:

            matrix = (
                self.validate_sequence(
                    sequence
                )
            )


            if input_is_normalized:

                normalized = (
                    matrix.astype(
                        np.float32
                    )
                )

            else:

                normalized = (
                    self.normalize(
                        matrix
                    )
                )


            # ====================================================
            # TEMPORAL CONSISTENCY
            # ====================================================

            reconstruction = (

                self.calculate_reconstruction_error(
                    normalized
                )
            )


            anomaly_score = (

                self.calibrate_score(

                    reconstruction[
                        "sequence_error"
                    ]
                )
            )


            classification = (
                self.classify(
                    anomaly_score
                )
            )


            # ====================================================
            # TEMPORAL REPRESENTATION
            # ====================================================

            embedding = (
                self.extract_embedding(
                    normalized
                )
            )


            return {
                "available":
                    True,

                "predictor_name":
                    PREDICTOR_NAME,

                "predictor_version":
                    PREDICTOR_VERSION,

                "model_name":
                    self.model_artifact.get(
                        "model_name"
                    ),

                "model_version":
                    self.model_artifact.get(
                        "model_version"
                    ),

                "calibration_version":
                    self.calibration.get(
                        "calibration_version"
                    ),

                "sequence_length":
                    SEQUENCE_LENGTH,

                "feature_count":
                    INPUT_FEATURE_COUNT,

                "raw_temporal_reconstruction_error":
                    reconstruction[
                        "sequence_error"
                    ],

                "per_timestep_errors":
                    reconstruction[
                        "per_timestep_errors"
                    ],

                "most_unusual_timestep":
                    reconstruction[
                        "most_unusual_timestep"
                    ],

                "maximum_timestep_error":
                    reconstruction[
                        "maximum_timestep_error"
                    ],

                "anomaly_score":
                    anomaly_score,

                "anomaly_confidence":
                    anomaly_score,

                "anomaly_label":
                    classification[
                        "label"
                    ],

                "severity":
                    classification[
                        "severity"
                    ],

                "is_active":
                    classification[
                        "is_active"
                    ],

                "is_strong":
                    classification[
                        "is_strong"
                    ],

                "should_alert":
                    classification[
                        "should_alert"
                    ],

                "temporal_embedding":
                    embedding,

                "temporal_embedding_dimension":
                    len(
                        embedding
                    ),

                "input_is_normalized":
                    input_is_normalized,

                "critical_allowed_from_temporal_alone":
                    False,

                "interpretation":
                    (
                        "Endpoint-relative temporal behavioral "
                        "anomaly score; not malware probability."
                    ),
            }


        except Exception as error:

            return {
                "available":
                    False,

                "predictor_name":
                    PREDICTOR_NAME,

                "predictor_version":
                    PREDICTOR_VERSION,

                "error":
                    str(
                        error
                    ),
            }


# ================================================================
# SHARED PREDICTOR
# ================================================================

shared_process_temporal_predictor = (
    ProcessTemporalPredictor(
        auto_load=True
    )
)


# ================================================================
# ENTRY / SELF TEST
# ================================================================

if __name__ == "__main__":

    predictor = (
        ProcessTemporalPredictor()
    )


    print()

    print(
        "=" * 82
    )

    print(
        "SENTINEL-X TEMPORAL PREDICTOR STATUS"
    )

    print(
        "=" * 82
    )


    status = (
        predictor.get_status()
    )


    for (
        key,
        value,
    ) in status.items():

        print(
            f"{key:<30}: {value}"
        )