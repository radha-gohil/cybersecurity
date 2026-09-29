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


from ai_detection.temporal.process_temporal_transformer_v2_trainer import (
    MODEL_PATH,
    SEQUENCE_LENGTH,
    INPUT_FEATURE_COUNT,
    load_process_temporal_transformer_v2,
)


# ================================================================
# SENTINEL-X TEMPORAL PREDICTOR V2
#
# Input:
#
#       raw sequence
#       shape = (8, 26)
#
#
# Pipeline:
#
#       raw sequence
#           ↓
#       StandardScaler v2
#           ↓
#       Transformer v2
#           ↓
#       leave-one-timestep-out reconstruction
#           ↓
#       calibration v2
#           ↓
#       0–100 anomaly score
#
#
# Also returns:
#
#       64D temporal representation
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
    / "process_temporal_scaler_v2.joblib"
)


CALIBRATION_PATH = (
    PROJECT_ROOT
    / "models"
    / "temporal"
    / "sentinelx_temporal_anomaly_calibration_v2.json"
)


PREDICTOR_NAME = (
    "sentinelx_process_temporal_predictor"
)


PREDICTOR_VERSION = "v2"


SCHEMA_VERSION = (
    "process_temporal_schema_v2"
)


UNUSUAL_THRESHOLD = 40.0

ACTIVE_THRESHOLD = 60.0

STRONG_THRESHOLD = 80.0


# ================================================================
# PREDICTOR
# ================================================================

class ProcessTemporalPredictorV2:

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
    ):

        try:

            (
                self.model,
                self.model_artifact,

            ) = load_process_temporal_transformer_v2(

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

                    "Temporal scaler v2 missing:\n"
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

                    "Temporal calibration v2 missing:\n"
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

            if (

                int(
                    self.scaler_bundle[
                        "feature_count"
                    ]
                )

                != INPUT_FEATURE_COUNT

            ):

                raise RuntimeError(

                    "Scaler v2 feature-count mismatch."
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

                    "Scaler v2 sequence-length mismatch."
                )


            if (

                self.scaler_bundle.get(
                    "schema_version"
                )

                != SCHEMA_VERSION

            ):

                raise RuntimeError(

                    "Scaler v2 schema-version mismatch."
                )


            if (

                self.calibration.get(
                    "model_version"
                )

                != "v2"

            ):

                raise RuntimeError(

                    "Temporal calibration does not "
                    "belong to Transformer v2."
                )


            if (

                int(
                    self.calibration.get(
                        "input_feature_count",
                        -1,
                    )
                )

                != INPUT_FEATURE_COUNT

            ):

                raise RuntimeError(

                    "Temporal calibration feature-count mismatch."
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

            "schema_version":
                SCHEMA_VERSION,

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

            "removed_feature":
                "process_age_seconds",

            "device":
                str(
                    self.device
                ),

            "load_error":
                self.load_error,
        }


    # ============================================================
    # VALIDATE
    # ============================================================

    def validate_sequence(
        self,
        sequence,
    ) -> np.ndarray:

        matrix = np.asarray(

            sequence,

            dtype=np.float64,
        )


        expected_shape = (

            SEQUENCE_LENGTH,

            INPUT_FEATURE_COUNT,
        )


        if matrix.shape != expected_shape:

            raise ValueError(

                "Temporal Transformer v2 expects "
                f"shape {expected_shape}; "
                f"received {matrix.shape}."
            )


        if not np.all(
            np.isfinite(
                matrix
            )
        ):

            raise ValueError(

                "Temporal sequence contains "
                "NaN or infinity."
            )


        return matrix


    # ============================================================
    # NORMALIZE
    # ============================================================

    def normalize(
        self,
        matrix: np.ndarray,
    ) -> np.ndarray:

        normalized = (
            self.scaler.transform(
                matrix
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

                "Temporal scaler v2 produced "
                "NaN or infinity."
            )


        return normalized


    # ============================================================
    # LOTO ERROR
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


        timestep_errors = []


        self.model.eval()


        with torch.no_grad():

            for timestep in range(
                SEQUENCE_LENGTH
            ):

                mask = torch.zeros(

                    (
                        1,
                        SEQUENCE_LENGTH,
                    ),

                    dtype=torch.bool,

                    device=
                        self.device,
                )


                mask[
                    0,
                    timestep
                ] = True


                (
                    reconstruction,
                    _,
                    _,

                ) = self.model(

                    tensor,

                    timestep_mask=
                        mask,
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


                timestep_errors.append(
                    float(
                        error
                    )
                )


        sequence_error = float(

            np.mean(
                timestep_errors
            )
        )


        unusual_timestep = int(

            np.argmax(
                timestep_errors
            )
        )


        return {
            "sequence_error":
                sequence_error,

            "per_timestep_errors":
                timestep_errors,

            "most_unusual_timestep":
                unusual_timestep,

            "maximum_timestep_error":
                float(
                    max(
                        timestep_errors
                    )
                ),
        }


    # ============================================================
    # EMBEDDING
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

                tensor,

                timestep_mask=
                    None,
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
    # SCORE ANCHORS
    # ============================================================

    def get_score_anchors(
        self,
    ):

        raw_anchors = (
            self.calibration[
                "score_anchors"
            ]
        )


        collapsed = {}


        for anchor in raw_anchors:

            error = float(
                anchor[
                    "error"
                ]
            )


            score = float(
                anchor[
                    "score"
                ]
            )


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

                for error
                in errors
            ],

            dtype=np.float64,
        )


        return (
            errors,
            scores,
        )


    # ============================================================
    # CALIBRATE
    # ============================================================

    def calibrate_score(
        self,
        reconstruction_error: float,
    ) -> float:

        (
            errors,
            scores,

        ) = self.get_score_anchors()


        error = float(
            reconstruction_error
        )


        if error <= errors[
            0
        ]:

            return 0.0


        if error <= errors[
            -1
        ]:

            value = np.interp(

                error,

                errors,

                scores,
            )


            return float(

                np.clip(

                    value,

                    0.0,

                    95.0,
                )
            )


        # ========================================================
        # OUTSIDE VALIDATION MAX
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

            error

            - errors[
                -1
            ]
        )


        extra = (

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
                + extra,

                0.0,

                100.0,
            )
        )


    # ============================================================
    # LABEL
    # ============================================================

    def classify(
        self,
        score: float,
    ):

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

                normalized = np.asarray(

                    matrix,

                    dtype=np.float32,
                )


            else:

                normalized = (
                    self.normalize(
                        matrix
                    )
                )


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

                "schema_version":
                    SCHEMA_VERSION,

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

                "removed_feature":
                    "process_age_seconds",

                "critical_allowed_from_temporal_alone":
                    False,

                "interpretation":
                    (
                        "Endpoint-relative temporal anomaly "
                        "score; not malware probability."
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
# SHARED INSTANCE
# ================================================================

shared_process_temporal_predictor_v2 = (
    ProcessTemporalPredictorV2(
        auto_load=True
    )
)


# ================================================================
# STATUS
# ================================================================

if __name__ == "__main__":

    predictor = (
        ProcessTemporalPredictorV2()
    )


    print()

    print(
        "=" * 84
    )

    print(
        "SENTINEL-X TEMPORAL PREDICTOR V2 STATUS"
    )

    print(
        "=" * 84
    )


    for (
        key,
        value,
    ) in predictor.get_status().items():

        print(
            f"{key:<32}: {value}"
        )