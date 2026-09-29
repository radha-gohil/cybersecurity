from __future__ import annotations

from pathlib import Path

from typing import (
    Any,
    Dict,
    List,
    Optional,
)


import numpy as np


from ai_detection.behavior.behavior_feature_store import (
    BehaviorFeatureStore,
)

from ai_detection.behavior.process_feature_schema import (
    PROCESS_FEATURE_NAMES,
    PROCESS_FEATURE_SCHEMA_VERSION,
    ProcessFeatureRecord,
)

from ai_detection.behavior.isolation_forest_trainer import (
    MODEL_PATH,
    load_process_isolation_forest_bundle,
)


# ================================================================
# SENTINEL-X REAL-TIME PROCESS BEHAVIOR AI
#
# Purpose:
#
# Load the trained personalized Isolation Forest model and score
# real endpoint process behavior.
#
# Pipeline:
#
# ProcessFeatureRecord
#       ↓
# Exact training features
#       ↓
# Saved StandardScaler
#       ↓
# Saved IsolationForest
#       ↓
# decision_function()
#       ↓
# Baseline percentile calibration
#       ↓
# 0 - 100 anomaly confidence
#       ↓
# NORMAL / UNUSUAL / SUSPICIOUS / HIGH_ANOMALY
#
# IMPORTANT:
#
# This model is separate from the existing:
#
# - ProcessBehaviorDetector
# - ProcessAnomalyDetector
#
# We will fuse them later.
# ================================================================


class ProcessIsolationForestPredictor:

    def __init__(
        self,
        model_path: Path | str = MODEL_PATH,
        auto_load: bool = True,
    ):

        self.model_path = Path(
            model_path
        )

        self.feature_store = (
            BehaviorFeatureStore()
        )

        # ========================================================
        # MODEL STATE
        # ========================================================

        self.bundle = None

        self.model = None

        self.scaler = None

        self.metadata = {}

        self.feature_names: List[str] = []

        self.model_name = None

        self.model_version = None

        self.available = False

        self.load_error: Optional[str] = None

        # ========================================================
        # CALIBRATION THRESHOLDS
        # ========================================================

        self.p01 = 0.0
        self.p02 = 0.0
        self.p05 = 0.0
        self.p10 = 0.0
        self.p50 = 0.0

        self.training_min = 0.0
        self.training_max = 0.0

        if auto_load:

            self.load_model(
                raise_on_error=False
            )


    # ============================================================
    # LOAD MODEL
    # ============================================================

    def load_model(
        self,
        raise_on_error: bool = True,
    ) -> bool:

        try:

            bundle = (
                load_process_isolation_forest_bundle(
                    self.model_path
                )
            )

            # ----------------------------------------------------
            # REQUIRED OBJECTS
            # ----------------------------------------------------

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

            # ----------------------------------------------------
            # BASIC VALIDATION
            # ----------------------------------------------------

            if model is None:

                raise RuntimeError(
                    "Isolation Forest model is missing."
                )

            if scaler is None:

                raise RuntimeError(
                    "Behavior feature scaler is missing."
                )

            if not feature_names:

                raise RuntimeError(
                    "Model feature list is empty."
                )

            # ----------------------------------------------------
            # SCHEMA VERSION
            # ----------------------------------------------------

            if (

                bundle.get(
                    "feature_schema_version"
                )

                != PROCESS_FEATURE_SCHEMA_VERSION

            ):

                raise RuntimeError(

                    "Behavior model schema does not match "
                    "the current feature schema."
                )

            # ----------------------------------------------------
            # FEATURE NAMES
            # ----------------------------------------------------

            unknown_features = [

                feature_name

                for feature_name
                in feature_names

                if feature_name
                not in PROCESS_FEATURE_NAMES
            ]

            if unknown_features:

                raise RuntimeError(

                    "Model contains unknown behavior features: "
                    f"{unknown_features}"
                )

            # ----------------------------------------------------
            # SCORE CALIBRATION
            # ----------------------------------------------------

            score_statistics = (

                metadata.get(
                    "training_score_statistics"
                )

                or {}
            )

            percentiles = (

                score_statistics.get(
                    "percentiles"
                )

                or {}
            )

            required_percentiles = {

                "p01",
                "p02",
                "p05",
                "p10",
                "p50",
            }

            missing_percentiles = (

                required_percentiles

                - set(
                    percentiles.keys()
                )
            )

            if missing_percentiles:

                raise RuntimeError(

                    "Training metadata is missing decision-score "
                    f"percentiles: {sorted(missing_percentiles)}"
                )

            # ----------------------------------------------------
            # STORE MODEL
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

            # ----------------------------------------------------
            # STORE THRESHOLDS
            # ----------------------------------------------------

            self.p01 = float(
                percentiles[
                    "p01"
                ]
            )

            self.p02 = float(
                percentiles[
                    "p02"
                ]
            )

            self.p05 = float(
                percentiles[
                    "p05"
                ]
            )

            self.p10 = float(
                percentiles[
                    "p10"
                ]
            )

            self.p50 = float(
                percentiles[
                    "p50"
                ]
            )

            self.training_min = float(

                score_statistics.get(
                    "decision_score_min",
                    self.p01,
                )
            )

            self.training_max = float(

                score_statistics.get(
                    "decision_score_max",
                    self.p50,
                )
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

            "load_error":
                self.load_error,
        }


    # ============================================================
    # LINEAR INTERPOLATION
    # ============================================================

    def _linear_score(

        self,

        value: float,

        upper_value: float,

        lower_value: float,

        lower_score: float,

        upper_score: float,

    ) -> float:

        # --------------------------------------------------------
        # Same threshold
        # --------------------------------------------------------

        if upper_value == lower_value:

            return upper_score

        ratio = (

            (
                upper_value
                - value
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

            + (
                ratio
                * (
                    upper_score
                    - lower_score
                )
            )
        )


    # ============================================================
    # DECISION SCORE → 0-100 ANOMALY CONFIDENCE
    #
    # Lower Isolation Forest decision scores are more abnormal.
    #
    # Calibration uses the user's own training baseline:
    #
    # >= p10       → NORMAL
    # p05 - p10    → UNUSUAL
    # p02 - p05    → SUSPICIOUS
    # < p02        → HIGH_ANOMALY
    # ============================================================

    def calculate_anomaly_confidence(
        self,
        decision_score: float,
    ) -> float:

        score = float(
            decision_score
        )

        # --------------------------------------------------------
        # NORMAL REGION
        #
        # p50 or higher ≈ strongly normal
        # p10          ≈ approaching unusual region
        # --------------------------------------------------------

        if score >= self.p10:

            if score >= self.p50:

                confidence = 0.0

            else:

                confidence = (
                    self._linear_score(

                        value=score,

                        upper_value=self.p50,

                        lower_value=self.p10,

                        lower_score=0.0,

                        upper_score=39.0,
                    )
                )

        # --------------------------------------------------------
        # UNUSUAL REGION
        # --------------------------------------------------------

        elif score >= self.p05:

            confidence = (
                self._linear_score(

                    value=score,

                    upper_value=self.p10,

                    lower_value=self.p05,

                    lower_score=40.0,

                    upper_score=59.0,
                )
            )

        # --------------------------------------------------------
        # SUSPICIOUS REGION
        # --------------------------------------------------------

        elif score >= self.p02:

            confidence = (
                self._linear_score(

                    value=score,

                    upper_value=self.p05,

                    lower_value=self.p02,

                    lower_score=60.0,

                    upper_score=79.0,
                )
            )

        # --------------------------------------------------------
        # HIGH ANOMALY REGION
        # --------------------------------------------------------

        elif score >= self.p01:

            confidence = (
                self._linear_score(

                    value=score,

                    upper_value=self.p02,

                    lower_value=self.p01,

                    lower_score=80.0,

                    upper_score=89.0,
                )
            )

        # --------------------------------------------------------
        # EXTREME ANOMALY
        # --------------------------------------------------------

        else:

            reference_min = (
                self.training_min
            )

            if reference_min >= self.p01:

                reference_min = (

                    self.p01
                    - 0.10
                )

            confidence = (
                self._linear_score(

                    value=score,

                    upper_value=self.p01,

                    lower_value=reference_min,

                    lower_score=90.0,

                    upper_score=100.0,
                )
            )

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
    # CONFIDENCE → LABEL
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
    # CONFIDENCE → SECURITY SEVERITY
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
    # FEATURE VECTOR FOR MODEL
    # ============================================================

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
                "the trained model."
            )

        feature_dict = (
            record.features.to_dict()
        )

        values = []

        for feature_name in (
            self.feature_names
        ):

            if feature_name not in feature_dict:

                raise RuntimeError(

                    f"Required model feature missing: "
                    f"{feature_name}"
                )

            value = float(

                feature_dict[
                    feature_name
                ]
            )

            if not np.isfinite(
                value
            ):

                raise RuntimeError(

                    f"Invalid value for feature "
                    f"{feature_name}: {value}"
                )

            values.append(
                value
            )

        matrix = np.asarray(

            [
                values
            ],

            dtype=np.float64,
        )

        return matrix


    # ============================================================
    # FEATURE DEVIATION SUMMARY
    #
    # This is NOT SHAP.
    #
    # It simply shows which input features differ most strongly
    # from their training-baseline mean.
    # ============================================================

    def get_feature_deviations(

        self,

        record: ProcessFeatureRecord,

        limit: int = 5,

    ) -> List[
        Dict[
            str,
            Any,
        ]
    ]:


        feature_dict = (
            record.features.to_dict()
        )

        feature_summary = (

            self.metadata.get(
                "feature_summary"
            )

            or {}
        )

        deviations = []

        for feature_name in (
            self.feature_names
        ):

            stats = (
                feature_summary.get(
                    feature_name
                )

                or {}
            )

            if not stats:

                continue

            value = float(

                feature_dict.get(
                    feature_name,
                    0.0,
                )
            )

            baseline_mean = float(

                stats.get(
                    "mean",
                    0.0,
                )
            )

            baseline_std = float(

                stats.get(
                    "std",
                    0.0,
                )
            )

            # ----------------------------------------------------
            # AVOID DIVIDE BY ZERO
            # ----------------------------------------------------

            if baseline_std <= 1e-12:

                deviation_std = (

                    0.0

                    if value == baseline_mean

                    else abs(
                        value
                        - baseline_mean
                    )
                )

            else:

                deviation_std = abs(

                    (
                        value
                        - baseline_mean
                    )

                    / baseline_std
                )

            deviations.append(

                {

                    "feature":
                        feature_name,

                    "value":
                        round(
                            value,
                            4,
                        ),

                    "baseline_mean":
                        round(
                            baseline_mean,
                            4,
                        ),

                    "baseline_std":
                        round(
                            baseline_std,
                            4,
                        ),

                    "deviation_std":
                        round(
                            deviation_std,
                            4,
                        ),
                }
            )

        deviations.sort(

            key=lambda item:
                item[
                    "deviation_std"
                ],

            reverse=True,
        )

        return deviations[
            :max(
                1,
                int(
                    limit
                ),
            )
        ]


    # ============================================================
    # STORE RESULT
    # ============================================================

    def store_prediction(

        self,

        record_id: int,

        anomaly_confidence: float,

        anomaly_label: str,

    ) -> None:

        self.feature_store.update_ai_result(

            record_id=
                record_id,

            anomaly_score=
                anomaly_confidence,

            anomaly_prediction=
                anomaly_label,

            model_name=
                str(
                    self.model_name
                ),

            model_version=
                str(
                    self.model_version
                ),
        )


    # ============================================================
    # PREDICT
    # ============================================================

    def predict(

        self,

        record: ProcessFeatureRecord,

        record_id: Optional[int] = None,

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
                    or "Behavior model is unavailable.",

                "model_name":
                    self.model_name,

                "model_version":
                    self.model_version,
            }

        try:

            # ----------------------------------------------------
            # EXACT FEATURE ORDER USED DURING TRAINING
            # ----------------------------------------------------

            matrix = (
                self.build_model_vector(
                    record
                )
            )

            # ----------------------------------------------------
            # SAME SCALER USED DURING TRAINING
            # ----------------------------------------------------

            scaled_matrix = (
                self.scaler.transform(
                    matrix
                )
            )

            # ----------------------------------------------------
            # ISOLATION FOREST
            # ----------------------------------------------------

            decision_score = float(

                self.model
                .decision_function(
                    scaled_matrix
                )[0]
            )

            raw_score = float(

                self.model
                .score_samples(
                    scaled_matrix
                )[0]
            )

            model_prediction = int(

                self.model
                .predict(
                    scaled_matrix
                )[0]
            )

            # ----------------------------------------------------
            # PERSONALIZED CONFIDENCE CALIBRATION
            # ----------------------------------------------------

            anomaly_confidence = (
                self.calculate_anomaly_confidence(
                    decision_score
                )
            )

            anomaly_label = (
                self.confidence_to_label(
                    anomaly_confidence
                )
            )

            severity = (
                self.confidence_to_severity(
                    anomaly_confidence
                )
            )

            # ----------------------------------------------------
            # OPERATIONAL ALERT THRESHOLD
            #
            # A baseline percentile score alone should not create
            # large numbers of endpoint alerts.
            #
            # 75+ means strongly abnormal relative to this user's
            # learned baseline.
            # ----------------------------------------------------

            should_alert = (
                anomaly_confidence
                >= 75.0
            )

            # ----------------------------------------------------
            # FEATURE DIFFERENCES
            # ----------------------------------------------------

            feature_deviations = (
                self.get_feature_deviations(
                    record,
                    limit=5,
                )
            )

            result = {

                "available":
                    True,

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

                "decision_score":
                    round(
                        decision_score,
                        8,
                    ),

                "raw_score":
                    round(
                        raw_score,
                        8,
                    ),

                "model_prediction":
                    model_prediction,

                "model_outlier":
                    model_prediction == -1,

                "anomaly_confidence":
                    anomaly_confidence,

                "anomaly_label":
                    anomaly_label,

                "severity":
                    severity,

                "should_alert":
                    should_alert,

                "feature_deviations":
                    feature_deviations,

                "pid":
                    record.pid,

                "process_name":
                    record.process_name,

                "parent_process_name":
                    record.parent_process_name,

                "executable_path":
                    record.executable_path,
            }

            # ----------------------------------------------------
            # UPDATE FEATURE DATABASE ROW
            # ----------------------------------------------------

            if record_id is not None:

                try:

                    self.store_prediction(

                        record_id=
                            record_id,

                        anomaly_confidence=
                            anomaly_confidence,

                        anomaly_label=
                            anomaly_label,
                    )

                except Exception as error:

                    result[
                        "storage_error"
                    ] = str(
                        error
                    )

            return result

        except Exception as error:

            return {

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

                "pid":
                    record.pid,

                "process_name":
                    record.process_name,
            }


# ================================================================
# MANUAL MODEL STATUS TEST
# ================================================================

if __name__ == "__main__":

    predictor = (
        ProcessIsolationForestPredictor()
    )

    status = (
        predictor.get_status()
    )

    print(
        "\n"
        + "=" * 70
    )

    print(
        "SENTINEL-X PROCESS ISOLATION FOREST"
    )

    print(
        "=" * 70
    )

    for (
        key,
        value,
    ) in status.items():

        print(
            f"{key}: {value}"
        )

    print(
        "=" * 70
    )