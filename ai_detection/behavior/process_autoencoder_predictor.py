from __future__ import annotations

from pathlib import Path

from typing import (
    Any,
    Dict,
    List,
    Optional,
)


import numpy as np


from ai_detection.behavior.process_feature_schema import (
    PROCESS_FEATURE_NAMES,
    PROCESS_FEATURE_SCHEMA_VERSION,
    ProcessFeatureRecord,
)

from ai_detection.behavior.process_autoencoder_v2_trainer import (
    MODEL_PATH,
    load_process_autoencoder_v2_bundle,
)


# ================================================================
# SENTINEL-X PROCESS AUTOENCODER REAL-TIME PREDICTOR
#
# Current model:
#
#       Autoencoder v2
#
# Features:
#
#       reconstruction anomaly detection
#       calibrated confidence
#       reconstruction explanation
#       4D tanh bottleneck embedding
#
# ================================================================


class ProcessAutoencoderPredictor:

    def __init__(

        self,

        model_path: Path | str = MODEL_PATH,

        auto_load: bool = True,

    ):

        self.model_path = Path(
            model_path
        )


        self.bundle = None

        self.model = None

        self.scaler = None

        self.metadata: Dict[
            str,
            Any,
        ] = {}


        self.feature_names: List[str] = []


        self.model_name: Optional[str] = None

        self.model_version: Optional[str] = None


        self.hidden_activation: Optional[str] = None


        self.bottleneck_hidden_layer_index: Optional[int] = None

        self.bottleneck_dimension: Optional[int] = None


        self.available = False

        self.load_error: Optional[str] = None


        # ========================================================
        # RECONSTRUCTION DISTRIBUTION
        # ========================================================

        self.error_min = 0.0

        self.error_p50 = 0.0

        self.error_p90 = 0.0

        self.error_p95 = 0.0

        self.error_p97 = 0.0

        self.error_p99 = 0.0

        self.error_max = 0.0


        if auto_load:

            self.load_model(
                raise_on_error=False
            )


    # ============================================================
    # LOAD
    # ============================================================

    def load_model(
        self,
        raise_on_error: bool = True,
    ) -> bool:

        try:

            bundle = (
                load_process_autoencoder_v2_bundle(
                    self.model_path
                )
            )


            model = (
                bundle.get(
                    "model"
                )
            )


            scaler = (
                bundle.get(
                    "scaler"
                )
            )


            metadata = (

                bundle.get(
                    "metadata"
                )

                or {}
            )


            feature_names = list(

                bundle.get(
                    "feature_names"
                )

                or []
            )


            hidden_activation = (

                bundle.get(
                    "hidden_activation"
                )

                or

                metadata.get(
                    "architecture",
                    {}
                ).get(
                    "hidden_activation"
                )
            )


            bottleneck_index = (
                bundle.get(
                    "bottleneck_hidden_layer_index"
                )
            )


            bottleneck_dimension = (
                bundle.get(
                    "bottleneck_dimension"
                )
            )


            # ----------------------------------------------------
            # Validation
            # ----------------------------------------------------

            if model is None:

                raise RuntimeError(

                    "Autoencoder model is missing."
                )


            if scaler is None:

                raise RuntimeError(

                    "Autoencoder scaler is missing."
                )


            if not feature_names:

                raise RuntimeError(

                    "Autoencoder feature list is empty."
                )


            if (

                bundle.get(
                    "feature_schema_version"
                )

                != PROCESS_FEATURE_SCHEMA_VERSION

            ):

                raise RuntimeError(

                    "Autoencoder feature schema mismatch."
                )


            unknown_features = [

                feature_name

                for feature_name
                in feature_names

                if feature_name
                not in PROCESS_FEATURE_NAMES
            ]


            if unknown_features:

                raise RuntimeError(

                    "Autoencoder contains unknown features: "
                    f"{unknown_features}"
                )


            if hidden_activation not in {

                "relu",

                "tanh",

                "logistic",

                "identity",

            }:

                raise RuntimeError(

                    "Unsupported Autoencoder hidden activation: "
                    f"{hidden_activation}"
                )


            if bottleneck_index is None:

                raise RuntimeError(

                    "Autoencoder bottleneck index is missing."
                )


            if bottleneck_dimension is None:

                raise RuntimeError(

                    "Autoencoder bottleneck dimension is missing."
                )


            # ----------------------------------------------------
            # Error calibration
            # ----------------------------------------------------

            error_stats = (

                metadata.get(
                    "validation_reconstruction_error"
                )

                or {}
            )


            required_stats = {

                "min",

                "max",

                "p50",

                "p90",

                "p95",

                "p97",

                "p99",
            }


            missing_stats = (

                required_stats

                - set(
                    error_stats.keys()
                )
            )


            if missing_stats:

                raise RuntimeError(

                    "Autoencoder validation reconstruction "
                    "statistics are incomplete: "
                    f"{sorted(missing_stats)}"
                )


            # ----------------------------------------------------
            # Assign
            # ----------------------------------------------------

            self.bundle = bundle

            self.model = model

            self.scaler = scaler

            self.metadata = metadata

            self.feature_names = (
                feature_names
            )


            self.model_name = (
                bundle.get(
                    "model_name"
                )
            )


            self.model_version = (
                bundle.get(
                    "model_version"
                )
            )


            self.hidden_activation = (
                hidden_activation
            )


            self.bottleneck_hidden_layer_index = int(
                bottleneck_index
            )


            self.bottleneck_dimension = int(
                bottleneck_dimension
            )


            self.error_min = float(
                error_stats[
                    "min"
                ]
            )


            self.error_p50 = float(
                error_stats[
                    "p50"
                ]
            )


            self.error_p90 = float(
                error_stats[
                    "p90"
                ]
            )


            self.error_p95 = float(
                error_stats[
                    "p95"
                ]
            )


            self.error_p97 = float(
                error_stats[
                    "p97"
                ]
            )


            self.error_p99 = float(
                error_stats[
                    "p99"
                ]
            )


            self.error_max = float(
                error_stats[
                    "max"
                ]
            )


            ordered = [

                self.error_min,

                self.error_p50,

                self.error_p90,

                self.error_p95,

                self.error_p97,

                self.error_p99,

                self.error_max,
            ]


            if ordered != sorted(
                ordered
            ):

                raise RuntimeError(

                    "Autoencoder reconstruction "
                    "distribution is invalid."
                )


            embedding_health = (

                metadata.get(
                    "embedding_health"
                )

                or {}
            )


            if not embedding_health.get(
                "healthy",
                False,
            ):

                raise RuntimeError(

                    "Autoencoder artifact does not contain "
                    "a healthy bottleneck representation."
                )


            self.available = True

            self.load_error = None

            return True


        except Exception as error:

            self.available = False

            self.load_error = str(
                error
            )


            if raise_on_error:

                raise


            return False


    # ============================================================
    # STATUS
    # ============================================================

    def get_status(
        self,
    ) -> Dict[
        str,
        Any,
    ]:

        return {

            "available":
                self.available,

            "model_path":
                str(
                    self.model_path
                ),

            "model_name":
                self.model_name,

            "model_version":
                self.model_version,

            "schema_version":
                PROCESS_FEATURE_SCHEMA_VERSION,

            "feature_count":
                len(
                    self.feature_names
                ),

            "features":
                list(
                    self.feature_names
                ),

            "hidden_activation":
                self.hidden_activation,

            "bottleneck_layer_index":
                self.bottleneck_hidden_layer_index,

            "bottleneck_dimension":
                self.bottleneck_dimension,

            "load_error":
                self.load_error,
        }


    # ============================================================
    # VECTOR
    # ============================================================

    def build_model_vector_from_dict(

        self,

        feature_dict: Dict[
            str,
            Any,
        ],

    ) -> np.ndarray:

        values = []


        for feature_name in (
            self.feature_names
        ):

            if feature_name not in feature_dict:

                raise RuntimeError(

                    "Required Autoencoder feature missing: "
                    f"{feature_name}"
                )


            try:

                value = float(

                    feature_dict[
                        feature_name
                    ]
                )


            except (
                TypeError,
                ValueError,
            ):

                raise RuntimeError(

                    f"Invalid Autoencoder feature: "
                    f"{feature_name}"
                )


            if not np.isfinite(
                value
            ):

                raise RuntimeError(

                    "Non-finite Autoencoder feature: "
                    f"{feature_name}"
                )


            values.append(
                value
            )


        return np.asarray(

            [
                values
            ],

            dtype=np.float64,
        )


    def build_model_vector(

        self,

        record: ProcessFeatureRecord,

    ) -> np.ndarray:

        if (

            record.schema_version

            != PROCESS_FEATURE_SCHEMA_VERSION

        ):

            raise RuntimeError(

                "Feature record schema does not match "
                "Autoencoder schema."
            )


        return (

            self.build_model_vector_from_dict(

                record.features.to_dict()
            )
        )


    # ============================================================
    # ACTIVATION
    # ============================================================

    def apply_hidden_activation(

        self,

        values: np.ndarray,

    ) -> np.ndarray:

        if self.hidden_activation == "tanh":

            return np.tanh(
                values
            )


        if self.hidden_activation == "relu":

            return np.maximum(
                values,
                0.0,
            )


        if self.hidden_activation == "logistic":

            clipped = np.clip(

                values,

                -60.0,

                60.0,
            )


            return (

                1.0

                / (
                    1.0

                    + np.exp(
                        -clipped
                    )
                )
            )


        if self.hidden_activation == "identity":

            return values


        raise RuntimeError(

            "Unsupported hidden activation: "
            f"{self.hidden_activation}"
        )


    # ============================================================
    # EMBEDDING
    # ============================================================

    def extract_embedding(

        self,

        scaled_matrix: np.ndarray,

    ) -> List[float]:

        if self.model is None:

            raise RuntimeError(

                "Autoencoder model unavailable."
            )


        if self.bottleneck_hidden_layer_index is None:

            raise RuntimeError(

                "Autoencoder bottleneck index unavailable."
            )


        activation = np.asarray(

            scaled_matrix,

            dtype=np.float64,
        )


        for layer_index in range(

            self.bottleneck_hidden_layer_index
            + 1

        ):

            activation = (

                activation

                @ self.model.coefs_[
                    layer_index
                ]

                + self.model.intercepts_[
                    layer_index
                ]
            )


            activation = (
                self.apply_hidden_activation(
                    activation
                )
            )


        embedding = (

            activation[
                0
            ]
        )


        if (

            self.bottleneck_dimension is not None

            and

            len(
                embedding
            )
            != self.bottleneck_dimension

        ):

            raise RuntimeError(

                "Autoencoder embedding dimension mismatch."
            )


        if not np.all(
            np.isfinite(
                embedding
            )
        ):

            raise RuntimeError(

                "Autoencoder embedding contains "
                "non-finite values."
            )


        return [

            round(
                float(
                    value
                ),
                8,
            )

            for value
            in embedding
        ]


    # ============================================================
    # INTERPOLATION
    # ============================================================

    def interpolate(

        self,

        value: float,

        lower_value: float,

        upper_value: float,

        lower_score: float,

        upper_score: float,

    ) -> float:

        if upper_value <= lower_value:

            return upper_score


        ratio = (

            (
                value
                - lower_value
            )

            / (
                upper_value
                - lower_value
            )
        )


        ratio = max(

            0.0,

            min(
                1.0,
                ratio,
            ),
        )


        return (

            lower_score

            + ratio
            * (
                upper_score
                - lower_score
            )
        )


    # ============================================================
    # RECONSTRUCTION ERROR → CONFIDENCE
    # ============================================================

    def calculate_anomaly_confidence(

        self,

        reconstruction_error: float,

    ) -> float:

        error = max(

            0.0,

            float(
                reconstruction_error
            ),
        )


        if error <= self.error_p50:

            confidence = (
                self.interpolate(

                    error,

                    self.error_min,

                    self.error_p50,

                    0.0,

                    19.0,
                )
            )


        elif error <= self.error_p90:

            confidence = (
                self.interpolate(

                    error,

                    self.error_p50,

                    self.error_p90,

                    20.0,

                    39.0,
                )
            )


        elif error <= self.error_p95:

            confidence = (
                self.interpolate(

                    error,

                    self.error_p90,

                    self.error_p95,

                    40.0,

                    59.0,
                )
            )


        elif error <= self.error_p97:

            confidence = (
                self.interpolate(

                    error,

                    self.error_p95,

                    self.error_p97,

                    60.0,

                    79.0,
                )
            )


        elif error <= self.error_p99:

            confidence = (
                self.interpolate(

                    error,

                    self.error_p97,

                    self.error_p99,

                    80.0,

                    89.0,
                )
            )


        else:

            extreme_reference = max(

                self.error_max,

                self.error_p99
                * 2.0,

                self.error_p99
                + 1e-9,
            )


            confidence = (
                self.interpolate(

                    error,

                    self.error_p99,

                    extreme_reference,

                    90.0,

                    100.0,
                )
            )


            if error >= extreme_reference:

                confidence = 100.0


        return round(

            max(
                0.0,
                min(
                    100.0,
                    confidence,
                ),
            ),

            2,
        )


    # ============================================================
    # LABEL
    # ============================================================

    def confidence_to_label(
        self,
        confidence: float,
    ) -> str:

        if confidence >= 80:

            return "HIGH_ANOMALY"


        if confidence >= 60:

            return "SUSPICIOUS"


        if confidence >= 40:

            return "UNUSUAL"


        return "NORMAL"


    # ============================================================
    # SEVERITY
    # ============================================================

    def confidence_to_severity(
        self,
        confidence: float,
    ) -> str:

        if confidence >= 90:

            return "CRITICAL"


        if confidence >= 80:

            return "HIGH"


        if confidence >= 60:

            return "MEDIUM"


        if confidence >= 40:

            return "LOW"


        return "INFO"


    # ============================================================
    # FEATURE RECONSTRUCTION
    # ============================================================

    def calculate_feature_reconstruction_errors(

        self,

        original_matrix: np.ndarray,

        scaled_matrix: np.ndarray,

        reconstructed_scaled: np.ndarray,

        limit: int = 5,

    ) -> List[
        Dict[
            str,
            Any,
        ]
    ]:

        reconstructed_original = (
            self.scaler.inverse_transform(
                reconstructed_scaled
            )
        )


        squared_scaled_error = np.square(

            scaled_matrix

            - reconstructed_scaled
        )


        results = []


        for (
            index,
            feature_name,
        ) in enumerate(
            self.feature_names
        ):

            actual = float(

                original_matrix[
                    0,
                    index
                ]
            )


            reconstructed = float(

                reconstructed_original[
                    0,
                    index
                ]
            )


            scaled_error = float(

                squared_scaled_error[
                    0,
                    index
                ]
            )


            results.append(
                {

                    "feature":
                        feature_name,

                    "actual_value":
                        round(
                            actual,
                            6,
                        ),

                    "reconstructed_value":
                        round(
                            reconstructed,
                            6,
                        ),

                    "scaled_squared_error":
                        round(
                            scaled_error,
                            8,
                        ),

                    "absolute_original_difference":
                        round(

                            abs(

                                actual

                                - reconstructed
                            ),

                            6,
                        ),
                }
            )


        results.sort(

            key=lambda item:
                item[
                    "scaled_squared_error"
                ],

            reverse=True,
        )


        return results[
            :max(
                1,
                int(
                    limit
                ),
            )
        ]


    # ============================================================
    # MATRIX PREDICTION
    # ============================================================

    def predict_matrix(

        self,

        matrix: np.ndarray,

        process_metadata: Optional[
            Dict[
                str,
                Any,
            ]
        ] = None,

    ) -> Dict[
        str,
        Any,
    ]:

        if not self.available:

            return {

                "available":
                    False,

                "error":
                    self.load_error
                    or "Autoencoder v2 unavailable.",

                "model_name":
                    self.model_name,

                "model_version":
                    self.model_version,
            }


        try:

            scaled = (
                self.scaler.transform(
                    matrix
                )
            )


            if not np.all(
                np.isfinite(
                    scaled
                )
            ):

                raise RuntimeError(

                    "Scaled Autoencoder input contains "
                    "non-finite values."
                )


            reconstructed = np.asarray(

                self.model.predict(
                    scaled
                ),

                dtype=np.float64,
            )


            if reconstructed.shape != scaled.shape:

                raise RuntimeError(

                    "Autoencoder reconstruction shape mismatch."
                )


            reconstruction_error = float(

                np.mean(

                    np.square(

                        scaled

                        - reconstructed
                    ),

                    axis=1,
                )[0]
            )


            confidence = (
                self.calculate_anomaly_confidence(
                    reconstruction_error
                )
            )


            label = (
                self.confidence_to_label(
                    confidence
                )
            )


            severity = (
                self.confidence_to_severity(
                    confidence
                )
            )


            embedding = (
                self.extract_embedding(
                    scaled
                )
            )


            feature_errors = (
                self.calculate_feature_reconstruction_errors(

                    original_matrix=
                        matrix,

                    scaled_matrix=
                        scaled,

                    reconstructed_scaled=
                        reconstructed,

                    limit=
                        5,
                )
            )


            if reconstruction_error <= self.error_p90:

                region = (
                    "NORMAL_BASELINE"
                )


            elif reconstruction_error <= self.error_p95:

                region = (
                    "UPPER_5_PERCENT"
                )


            elif reconstruction_error <= self.error_p97:

                region = (
                    "UPPER_3_PERCENT"
                )


            elif reconstruction_error <= self.error_p99:

                region = (
                    "UPPER_1_PERCENT"
                )


            else:

                region = (
                    "ABOVE_TRAINING_P99"
                )


            result = {

                "available":
                    True,

                "model_name":
                    self.model_name,

                "model_version":
                    self.model_version,

                "hidden_activation":
                    self.hidden_activation,

                "schema_version":
                    PROCESS_FEATURE_SCHEMA_VERSION,

                "feature_count":
                    len(
                        self.feature_names
                    ),

                "reconstruction_error":
                    round(
                        reconstruction_error,
                        10,
                    ),

                "reconstruction_region":
                    region,

                "anomaly_confidence":
                    confidence,

                "anomaly_label":
                    label,

                "severity":
                    severity,

                "candidate_alert":
                    confidence
                    >= 75.0,

                "embedding_dimension":
                    len(
                        embedding
                    ),

                "behavior_embedding":
                    embedding,

                "feature_reconstruction_errors":
                    feature_errors,

                "calibration": {

                    "p50":
                        self.error_p50,

                    "p90":
                        self.error_p90,

                    "p95":
                        self.error_p95,

                    "p97":
                        self.error_p97,

                    "p99":
                        self.error_p99,
                },
            }


            if process_metadata:

                result.update(
                    process_metadata
                )


            return result


        except Exception as error:

            result = {

                "available":
                    True,

                "prediction_failed":
                    True,

                "error":
                    str(
                        error
                    ),

                "model_name":
                    self.model_name,

                "model_version":
                    self.model_version,
            }


            if process_metadata:

                result.update(
                    process_metadata
                )


            return result


    # ============================================================
    # FEATURE DICT PREDICTION
    # ============================================================

    def predict_feature_dict(

        self,

        feature_dict: Dict[
            str,
            Any,
        ],

        process_metadata: Optional[
            Dict[
                str,
                Any,
            ]
        ] = None,

    ) -> Dict[
        str,
        Any,
    ]:

        try:

            matrix = (
                self.build_model_vector_from_dict(
                    feature_dict
                )
            )


        except Exception as error:

            return {

                "available":
                    self.available,

                "prediction_failed":
                    True,

                "error":
                    str(
                        error
                    ),

                "model_name":
                    self.model_name,

                "model_version":
                    self.model_version,
            }


        return self.predict_matrix(

            matrix=
                matrix,

            process_metadata=
                process_metadata,
        )


    # ============================================================
    # PROCESS FEATURE RECORD
    # ============================================================

    def predict(

        self,

        record: ProcessFeatureRecord,

    ) -> Dict[
        str,
        Any,
    ]:

        try:

            matrix = (
                self.build_model_vector(
                    record
                )
            )


        except Exception as error:

            return {

                "available":
                    self.available,

                "prediction_failed":
                    True,

                "error":
                    str(
                        error
                    ),

                "model_name":
                    self.model_name,

                "model_version":
                    self.model_version,

                "pid":
                    record.pid,

                "process_name":
                    record.process_name,
            }


        return (

            self.predict_matrix(

                matrix=
                    matrix,

                process_metadata={

                    "pid":
                        record.pid,

                    "process_name":
                        record.process_name,

                    "parent_process_name":
                        record.parent_process_name,

                    "executable_path":
                        record.executable_path,
                },
            )
        )


# ================================================================
# STATUS TEST
# ================================================================

if __name__ == "__main__":

    predictor = (
        ProcessAutoencoderPredictor()
    )


    print()

    print(
        "=" * 78
    )

    print(
        "SENTINEL-X PROCESS AUTOENCODER"
    )

    print(
        "=" * 78
    )


    for (
        key,
        value,
    ) in (
        predictor
        .get_status()
        .items()
    ):

        print(
            f"{key}: {value}"
        )


    print(
        "=" * 78
    )