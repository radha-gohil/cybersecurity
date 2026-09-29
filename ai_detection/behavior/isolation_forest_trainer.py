from __future__ import annotations

import hashlib
import json
import platform
import sys

from datetime import (
    datetime,
    timezone,
)

from pathlib import (
    Path,
)

from typing import (
    Any,
    Dict,
    List,
    Optional,
    Tuple,
)


import joblib
import numpy as np
import sklearn

from sklearn.ensemble import (
    IsolationForest,
)

from sklearn.preprocessing import (
    StandardScaler,
)


from ai_detection.behavior.baseline_dataset_validator import (
    BaselineDatasetValidator,
)

from ai_detection.behavior.process_feature_schema import (
    PROCESS_FEATURE_NAMES,
    PROCESS_FEATURE_SCHEMA_VERSION,
)


# ================================================================
# SENTINEL-X PROCESS BEHAVIOR ISOLATION FOREST TRAINER
#
# Purpose:
#
# Train the first machine-learning behavioral anomaly detector
# using normal endpoint process telemetry.
#
# This script:
#
#   1. validates the baseline dataset
#   2. selects usable features
#   3. builds the training matrix
#   4. scales features
#   5. trains Isolation Forest
#   6. calculates baseline anomaly-score statistics
#   7. stores model + scaler + metadata together
#
# It does NOT perform real-time detection yet.
# ================================================================


# ================================================================
# PROJECT PATHS
# ================================================================

PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[2]
)


MODEL_DIRECTORY = (
    PROJECT_ROOT
    / "models"
    / "behavior"
)


MODEL_FILENAME = (
    "sentinelx_process_isolation_forest_v1.joblib"
)


MODEL_PATH = (
    MODEL_DIRECTORY
    / MODEL_FILENAME
)


METADATA_FILENAME = (
    "sentinelx_process_isolation_forest_v1_metadata.json"
)


METADATA_PATH = (
    MODEL_DIRECTORY
    / METADATA_FILENAME
)


# ================================================================
# MODEL IDENTITY
# ================================================================

MODEL_NAME = (
    "sentinelx_process_isolation_forest"
)


MODEL_VERSION = (
    "v1"
)


# ================================================================
# MODEL CONFIGURATION
# ================================================================

N_ESTIMATORS = 300


MAX_SAMPLES = "auto"


MAX_FEATURES = 1.0


BOOTSTRAP = False


RANDOM_STATE = 42


N_JOBS = -1


# ================================================================
# CONTAMINATION
#
# We intentionally use "auto" initially.
#
# We do NOT yet know the true percentage of anomalous samples
# inside a user's normal endpoint baseline.
#
# A calibrated operational threshold will be added during the
# real-time inference step.
# ================================================================

CONTAMINATION = "auto"


# ================================================================
# MINIMUM TRAINING REQUIREMENTS
# ================================================================

MINIMUM_TRAINING_RECORDS = 500


MINIMUM_MODEL_FEATURES = 8


# ================================================================
# CURRENT TIME
# ================================================================

def now_iso() -> str:

    return (
        datetime
        .now(
            timezone.utc
        )
        .isoformat()
    )


# ================================================================
# SHA256 HELPER
#
# Used for reproducibility / dataset fingerprinting.
# ================================================================

def sha256_text(
    value: str,
) -> str:

    return (
        hashlib
        .sha256(
            value.encode(
                "utf-8"
            )
        )
        .hexdigest()
    )


# ================================================================
# SAFE FLOAT
# ================================================================

def safe_float(
    value: Any,
) -> Optional[float]:

    try:

        number = float(
            value
        )

    except (
        TypeError,
        ValueError,
    ):

        return None


    if not np.isfinite(
        number
    ):

        return None


    return number


# ================================================================
# TRAINER
# ================================================================

class ProcessIsolationForestTrainer:

    def __init__(
        self,
    ):

        self.validator = (
            BaselineDatasetValidator()
        )


    # ============================================================
    # ENSURE MODEL DIRECTORY
    # ============================================================

    def ensure_model_directory(
        self,
    ) -> None:

        MODEL_DIRECTORY.mkdir(
            parents=True,
            exist_ok=True,
        )


    # ============================================================
    # FEATURE INDEX MAP
    # ============================================================

    def build_feature_index(
        self,
    ) -> Dict[
        str,
        int,
    ]:

        return {

            feature_name:
                index

            for (
                index,
                feature_name,
            )
            in enumerate(
                PROCESS_FEATURE_NAMES
            )
        }


    # ============================================================
    # LOAD + VALIDATE BASELINE
    # ============================================================

    def validate_dataset(
        self,
    ) -> Dict[
        str,
        Any,
    ]:

        report = (
            self.validator.validate()
        )


        self.validator.print_report(
            report
        )


        if not report.get(
            "ready_for_training",
            False,
        ):

            raise RuntimeError(

                "Behavior baseline validation failed. "
                "Fix the dataset before training Isolation Forest."
            )


        return report


    # ============================================================
    # BUILD TRAINING MATRIX
    # ============================================================

    def build_training_matrix(

        self,

        validation_report: Dict[
            str,
            Any,
        ],

    ) -> Tuple[
        np.ndarray,
        List[str],
        List[int],
        List[str],
    ]:


        selected_features = list(

            validation_report.get(
                "recommended_model_features",
                [],
            )
        )


        if len(
            selected_features
        ) < MINIMUM_MODEL_FEATURES:

            raise RuntimeError(

                "Not enough useful features are available "
                "for behavioral model training."
            )


        feature_index = (
            self.build_feature_index()
        )


        selected_indices = []


        for feature_name in (
            selected_features
        ):

            if (
                feature_name
                not in feature_index
            ):

                raise RuntimeError(

                    f"Unknown feature selected for training: "
                    f"{feature_name}"
                )


            selected_indices.append(

                feature_index[
                    feature_name
                ]
            )


        records = (
            self.validator.load_records()
        )


        matrix_rows: List[
            List[float]
        ] = []


        process_names: List[str] = []


        record_ids: List[int] = []


        for record in records:

            # ----------------------------------------------------
            # SCHEMA CONSISTENCY
            # ----------------------------------------------------

            if (

                record.get(
                    "schema_version"
                )

                != PROCESS_FEATURE_SCHEMA_VERSION

            ):

                continue


            # ----------------------------------------------------
            # PARSE COMPLETE VECTOR
            # ----------------------------------------------------

            vector = (
                self.validator.parse_vector(

                    record.get(
                        "feature_vector_json"
                    )
                )
            )


            if vector is None:

                continue


            # ----------------------------------------------------
            # SELECT MODEL FEATURES
            # ----------------------------------------------------

            model_vector = []


            valid = True


            for index in (
                selected_indices
            ):

                number = safe_float(

                    vector[
                        index
                    ]
                )


                if number is None:

                    valid = False

                    break


                model_vector.append(
                    number
                )


            if not valid:

                continue


            matrix_rows.append(
                model_vector
            )


            process_names.append(

                str(

                    record.get(
                        "process_name"
                    )

                    or "UNKNOWN"
                )
            )


            record_ids.append(

                int(
                    record.get(
                        "id"
                    )
                )
            )


        if len(
            matrix_rows
        ) < MINIMUM_TRAINING_RECORDS:

            raise RuntimeError(

                f"Only {len(matrix_rows)} valid training records "
                f"remain after filtering. "
                f"At least {MINIMUM_TRAINING_RECORDS} are required."
            )


        matrix = np.asarray(

            matrix_rows,

            dtype=np.float64,
        )


        if matrix.ndim != 2:

            raise RuntimeError(
                "Training matrix is not two-dimensional."
            )


        if matrix.shape[1] != len(
            selected_features
        ):

            raise RuntimeError(
                "Training matrix feature count mismatch."
            )


        if not np.all(
            np.isfinite(
                matrix
            )
        ):

            raise RuntimeError(
                "Training matrix contains NaN or infinite values."
            )


        return (

            matrix,

            selected_features,

            record_ids,

            process_names,
        )


    # ============================================================
    # DATASET FINGERPRINT
    #
    # Allows us to identify the baseline snapshot used for
    # training without storing all raw user telemetry inside
    # the model file.
    # ============================================================

    def build_dataset_fingerprint(

        self,

        matrix: np.ndarray,

        selected_features: List[str],

    ) -> str:


        payload = {

            "schema":
                PROCESS_FEATURE_SCHEMA_VERSION,

            "features":
                selected_features,

            "shape":
                list(
                    matrix.shape
                ),

            "matrix":
                np.round(
                    matrix,
                    decimals=6,
                ).tolist(),
        }


        serialized = json.dumps(

            payload,

            sort_keys=True,

            separators=(
                ",",
                ":",
            ),
        )


        return sha256_text(
            serialized
        )


    # ============================================================
    # FIT SCALER
    # ============================================================

    def fit_scaler(

        self,

        matrix: np.ndarray,

    ) -> Tuple[
        StandardScaler,
        np.ndarray,
    ]:


        scaler = (
            StandardScaler()
        )


        transformed = (
            scaler.fit_transform(
                matrix
            )
        )


        if not np.all(
            np.isfinite(
                transformed
            )
        ):

            raise RuntimeError(

                "Scaled training matrix contains "
                "invalid numeric values."
            )


        return (
            scaler,
            transformed,
        )


    # ============================================================
    # TRAIN ISOLATION FOREST
    # ============================================================

    def fit_model(

        self,

        transformed_matrix: np.ndarray,

    ) -> IsolationForest:


        model = (
            IsolationForest(

                n_estimators=
                    N_ESTIMATORS,

                max_samples=
                    MAX_SAMPLES,

                contamination=
                    CONTAMINATION,

                max_features=
                    MAX_FEATURES,

                bootstrap=
                    BOOTSTRAP,

                n_jobs=
                    N_JOBS,

                random_state=
                    RANDOM_STATE,
            )
        )


        model.fit(
            transformed_matrix
        )


        return model


    # ============================================================
    # SCORE TRAINING BASELINE
    #
    # IsolationForest:
    #
    # decision_function:
    #
    #   higher value -> more normal
    #   lower value  -> more abnormal
    #
    # prediction:
    #
    #    1 = inlier
    #   -1 = outlier
    # ============================================================

    def analyze_training_scores(

        self,

        model: IsolationForest,

        transformed_matrix: np.ndarray,

    ) -> Dict[
        str,
        Any,
    ]:


        decision_scores = (
            model.decision_function(
                transformed_matrix
            )
        )


        raw_scores = (
            model.score_samples(
                transformed_matrix
            )
        )


        predictions = (
            model.predict(
                transformed_matrix
            )
        )


        anomaly_count = int(

            np.sum(
                predictions == -1
            )
        )


        normal_count = int(

            np.sum(
                predictions == 1
            )
        )


        total = len(
            predictions
        )


        # --------------------------------------------------------
        # DECISION SCORE PERCENTILES
        #
        # These become useful when we calibrate operational
        # anomaly confidence during real-time inference.
        # --------------------------------------------------------

        percentiles = {

            "p01":
                float(
                    np.percentile(
                        decision_scores,
                        1,
                    )
                ),

            "p02":
                float(
                    np.percentile(
                        decision_scores,
                        2,
                    )
                ),

            "p05":
                float(
                    np.percentile(
                        decision_scores,
                        5,
                    )
                ),

            "p10":
                float(
                    np.percentile(
                        decision_scores,
                        10,
                    )
                ),

            "p25":
                float(
                    np.percentile(
                        decision_scores,
                        25,
                    )
                ),

            "p50":
                float(
                    np.percentile(
                        decision_scores,
                        50,
                    )
                ),

            "p75":
                float(
                    np.percentile(
                        decision_scores,
                        75,
                    )
                ),

            "p90":
                float(
                    np.percentile(
                        decision_scores,
                        90,
                    )
                ),

            "p95":
                float(
                    np.percentile(
                        decision_scores,
                        95,
                    )
                ),

            "p99":
                float(
                    np.percentile(
                        decision_scores,
                        99,
                    )
                ),
        }


        return {

            "sample_count":
                total,

            "normal_count":
                normal_count,

            "anomaly_count":
                anomaly_count,

            "anomaly_percent":
                round(
                    (
                        anomaly_count
                        / total
                        * 100.0
                    )
                    if total
                    else 0.0,
                    4,
                ),

            "decision_score_min":
                float(
                    np.min(
                        decision_scores
                    )
                ),

            "decision_score_max":
                float(
                    np.max(
                        decision_scores
                    )
                ),

            "decision_score_mean":
                float(
                    np.mean(
                        decision_scores
                    )
                ),

            "decision_score_std":
                float(
                    np.std(
                        decision_scores
                    )
                ),

            "raw_score_min":
                float(
                    np.min(
                        raw_scores
                    )
                ),

            "raw_score_max":
                float(
                    np.max(
                        raw_scores
                    )
                ),

            "raw_score_mean":
                float(
                    np.mean(
                        raw_scores
                    )
                ),

            "percentiles":
                percentiles,
        }


    # ============================================================
    # FEATURE SUMMARY
    # ============================================================

    def build_feature_summary(

        self,

        matrix: np.ndarray,

        feature_names: List[str],

    ) -> Dict[
        str,
        Dict[
            str,
            float,
        ]
    ]:


        result = {}


        for (
            index,
            feature_name,
        ) in enumerate(
            feature_names
        ):

            values = (
                matrix[
                    :,
                    index
                ]
            )


            result[
                feature_name
            ] = {

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

                "max":
                    float(
                        np.max(
                            values
                        )
                    ),

                "median":
                    float(
                        np.median(
                            values
                        )
                    ),
            }


        return result


    # ============================================================
    # PROCESS SUMMARY
    # ============================================================

    def build_process_summary(

        self,

        process_names: List[str],

    ) -> Dict[
        str,
        Any,
    ]:


        counts = {}


        for process_name in (
            process_names
        ):

            normalized = (

                str(
                    process_name
                )
                .strip()
                .lower()

                or "unknown"
            )


            counts[
                normalized
            ] = (

                counts.get(
                    normalized,
                    0,
                )

                + 1
            )


        ordered = sorted(

            counts.items(),

            key=lambda item:
                item[1],

            reverse=True,
        )


        return {

            "unique_process_names":
                len(
                    counts
                ),

            "top_processes":
                [

                    {

                        "process_name":
                            name,

                        "sample_count":
                            count,
                    }

                    for (
                        name,
                        count,
                    )
                    in ordered[
                        :20
                    ]
                ],
        }


    # ============================================================
    # BUILD MODEL METADATA
    # ============================================================

    def build_metadata(

        self,

        matrix: np.ndarray,

        selected_features: List[str],

        process_names: List[str],

        dataset_fingerprint: str,

        score_statistics: Dict[
            str,
            Any,
        ],

        feature_summary: Dict[
            str,
            Any,
        ],

        validation_report: Dict[
            str,
            Any,
        ],

    ) -> Dict[
        str,
        Any,
    ]:


        return {

            # ----------------------------------------------------
            # MODEL
            # ----------------------------------------------------

            "model_name":
                MODEL_NAME,

            "model_version":
                MODEL_VERSION,

            "model_type":
                "IsolationForest",

            "purpose":
                (
                    "SENTINEL-X personalized endpoint "
                    "process behavior anomaly detection"
                ),

            "trained_at":
                now_iso(),


            # ----------------------------------------------------
            # SCHEMA
            # ----------------------------------------------------

            "feature_schema_version":
                PROCESS_FEATURE_SCHEMA_VERSION,

            "feature_count":
                len(
                    selected_features
                ),

            "feature_names":
                selected_features,


            # ----------------------------------------------------
            # DATASET
            # ----------------------------------------------------

            "training_samples":
                int(
                    matrix.shape[0]
                ),

            "training_features":
                int(
                    matrix.shape[1]
                ),

            "dataset_fingerprint_sha256":
                dataset_fingerprint,


            # ----------------------------------------------------
            # MODEL CONFIG
            # ----------------------------------------------------

            "model_parameters": {

                "n_estimators":
                    N_ESTIMATORS,

                "max_samples":
                    MAX_SAMPLES,

                "contamination":
                    CONTAMINATION,

                "max_features":
                    MAX_FEATURES,

                "bootstrap":
                    BOOTSTRAP,

                "random_state":
                    RANDOM_STATE,
            },


            # ----------------------------------------------------
            # PREPROCESSING
            # ----------------------------------------------------

            "preprocessing": {

                "scaler":
                    "StandardScaler",

                "scaler_required":
                    True,
            },


            # ----------------------------------------------------
            # TRAINING BASELINE SCORES
            # ----------------------------------------------------

            "training_score_statistics":
                score_statistics,


            # ----------------------------------------------------
            # FEATURE DISTRIBUTIONS
            # ----------------------------------------------------

            "feature_summary":
                feature_summary,


            # ----------------------------------------------------
            # PROCESS DISTRIBUTION
            # ----------------------------------------------------

            "process_summary":
                self.build_process_summary(
                    process_names
                ),


            # ----------------------------------------------------
            # VALIDATION SNAPSHOT
            # ----------------------------------------------------

            "validation_summary": {

                "total_records":
                    validation_report.get(
                        "total_records"
                    ),

                "valid_records":
                    validation_report.get(
                        "valid_records"
                    ),

                "unique_processes":
                    validation_report.get(
                        "unique_processes"
                    ),

                "duplicate_percent":
                    validation_report.get(
                        "duplicate_percent"
                    ),

                "network_coverage_percent":
                    validation_report.get(
                        "network_coverage_percent"
                    ),

                "ready_for_training":
                    validation_report.get(
                        "ready_for_training"
                    ),
            },


            # ----------------------------------------------------
            # SOFTWARE ENVIRONMENT
            #
            # Important because persisted sklearn models should
            # normally be loaded using a compatible environment.
            # ----------------------------------------------------

            "runtime": {

                "python_version":
                    sys.version,

                "platform":
                    platform.platform(),

                "numpy_version":
                    np.__version__,

                "scikit_learn_version":
                    sklearn.__version__,

                "joblib_version":
                    joblib.__version__,
            },


            # ----------------------------------------------------
            # SECURITY
            # ----------------------------------------------------

            "artifact_security": {

                "trusted_local_artifact_only":
                    True,

                "warning":
                    (
                        "Do not load untrusted joblib/pickle "
                        "model files."
                    ),
            },
        }


    # ============================================================
    # SAVE MODEL BUNDLE
    # ============================================================

    def save_model_bundle(

        self,

        model: IsolationForest,

        scaler: StandardScaler,

        metadata: Dict[
            str,
            Any,
        ],

    ) -> None:


        self.ensure_model_directory()


        model_bundle = {

            "model":
                model,

            "scaler":
                scaler,

            "metadata":
                metadata,

            "feature_names":
                list(
                    metadata[
                        "feature_names"
                    ]
                ),

            "feature_schema_version":
                PROCESS_FEATURE_SCHEMA_VERSION,

            "model_name":
                MODEL_NAME,

            "model_version":
                MODEL_VERSION,
        }


        # --------------------------------------------------------
        # JOBLIB MODEL
        # --------------------------------------------------------

        joblib.dump(

            model_bundle,

            MODEL_PATH,
        )


        # --------------------------------------------------------
        # HUMAN-READABLE METADATA
        # --------------------------------------------------------

        with open(

            METADATA_PATH,

            "w",

            encoding="utf-8",

        ) as file:

            json.dump(

                metadata,

                file,

                indent=4,

                sort_keys=False,
            )


    # ============================================================
    # VERIFY SAVED MODEL
    # ============================================================

    def verify_saved_model(
        self,
    ) -> Dict[
        str,
        Any,
    ]:


        if not MODEL_PATH.exists():

            raise RuntimeError(
                "Saved model file does not exist."
            )


        bundle = (
            joblib.load(
                MODEL_PATH
            )
        )


        required_keys = {

            "model",

            "scaler",

            "metadata",

            "feature_names",

            "feature_schema_version",

            "model_name",

            "model_version",
        }


        missing_keys = (

            required_keys

            - set(
                bundle.keys()
            )
        )


        if missing_keys:

            raise RuntimeError(

                f"Saved model bundle is missing keys: "
                f"{sorted(missing_keys)}"
            )


        if (

            bundle[
                "feature_schema_version"
            ]

            != PROCESS_FEATURE_SCHEMA_VERSION

        ):

            raise RuntimeError(
                "Saved model schema version mismatch."
            )


        if (

            bundle[
                "model_name"
            ]

            != MODEL_NAME

        ):

            raise RuntimeError(
                "Saved model name mismatch."
            )


        return bundle


    # ============================================================
    # TRAIN COMPLETE PIPELINE
    # ============================================================

    def train(
        self,
    ) -> Dict[
        str,
        Any,
    ]:


        print(
            "\n"
            + "=" * 78
        )

        print(
            "SENTINEL-X PROCESS BEHAVIOR ISOLATION FOREST TRAINING"
        )

        print(
            "=" * 78
        )


        # ========================================================
        # STEP 1 — VALIDATION
        # ========================================================

        print(
            "\n[1/8] Validating behavioral baseline..."
        )


        validation_report = (
            self.validate_dataset()
        )


        # ========================================================
        # STEP 2 — MATRIX
        # ========================================================

        print(
            "\n[2/8] Building training matrix..."
        )


        (
            matrix,
            selected_features,
            record_ids,
            process_names,

        ) = self.build_training_matrix(
            validation_report
        )


        print(
            f"Training samples : {matrix.shape[0]}"
        )


        print(
            f"Model features   : {matrix.shape[1]}"
        )


        # ========================================================
        # STEP 3 — DATASET FINGERPRINT
        # ========================================================

        print(
            "\n[3/8] Creating dataset fingerprint..."
        )


        dataset_fingerprint = (
            self.build_dataset_fingerprint(

                matrix,

                selected_features,
            )
        )


        print(
            "Dataset SHA256    : "
            f"{dataset_fingerprint}"
        )


        # ========================================================
        # STEP 4 — SCALING
        # ========================================================

        print(
            "\n[4/8] Fitting feature scaler..."
        )


        (
            scaler,
            transformed_matrix,

        ) = self.fit_scaler(
            matrix
        )


        print(
            "Scaler            : StandardScaler"
        )


        # ========================================================
        # STEP 5 — MODEL TRAINING
        # ========================================================

        print(
            "\n[5/8] Training Isolation Forest..."
        )


        model = (
            self.fit_model(
                transformed_matrix
            )
        )


        print(
            f"Trees             : {N_ESTIMATORS}"
        )


        print(
            f"Contamination     : {CONTAMINATION}"
        )


        # ========================================================
        # STEP 6 — SCORE BASELINE
        # ========================================================

        print(
            "\n[6/8] Evaluating baseline anomaly scores..."
        )


        score_statistics = (
            self.analyze_training_scores(

                model,

                transformed_matrix,
            )
        )


        print(
            "Normal baseline rows : "
            f"{score_statistics['normal_count']}"
        )


        print(
            "Outlier baseline rows: "
            f"{score_statistics['anomaly_count']}"
        )


        print(
            "Outlier percentage   : "
            f"{score_statistics['anomaly_percent']}%"
        )


        print(
            "Decision score mean  : "
            f"{score_statistics['decision_score_mean']:.6f}"
        )


        print(
            "Decision score min   : "
            f"{score_statistics['decision_score_min']:.6f}"
        )


        print(
            "Decision score max   : "
            f"{score_statistics['decision_score_max']:.6f}"
        )


        print(
            "\nBaseline decision-score percentiles:"
        )


        for (
            percentile,
            value,
        ) in (
            score_statistics[
                "percentiles"
            ].items()
        ):

            print(
                f"  {percentile:<4}: "
                f"{value:.6f}"
            )


        # ========================================================
        # STEP 7 — SAVE
        # ========================================================

        print(
            "\n[7/8] Saving model bundle..."
        )


        feature_summary = (
            self.build_feature_summary(

                matrix,

                selected_features,
            )
        )


        metadata = (
            self.build_metadata(

                matrix=
                    matrix,

                selected_features=
                    selected_features,

                process_names=
                    process_names,

                dataset_fingerprint=
                    dataset_fingerprint,

                score_statistics=
                    score_statistics,

                feature_summary=
                    feature_summary,

                validation_report=
                    validation_report,
            )
        )


        self.save_model_bundle(

            model=model,

            scaler=scaler,

            metadata=metadata,
        )


        print(
            f"Model saved       : {MODEL_PATH}"
        )


        print(
            f"Metadata saved    : {METADATA_PATH}"
        )


        # ========================================================
        # STEP 8 — VERIFY
        # ========================================================

        print(
            "\n[8/8] Verifying saved model..."
        )


        saved_bundle = (
            self.verify_saved_model()
        )


        print(
            "Saved model name   : "
            f"{saved_bundle['model_name']}"
        )


        print(
            "Saved model version: "
            f"{saved_bundle['model_version']}"
        )


        print(
            "Feature schema     : "
            f"{saved_bundle['feature_schema_version']}"
        )


        print(
            "Feature count      : "
            f"{len(saved_bundle['feature_names'])}"
        )


        # ========================================================
        # FINISHED
        # ========================================================

        print(
            "\n"
            + "=" * 78
        )

        print(
            "TRAINING COMPLETE"
        )

        print(
            "=" * 78
        )


        return {

            "success":
                True,

            "model_path":
                str(
                    MODEL_PATH
                ),

            "metadata_path":
                str(
                    METADATA_PATH
                ),

            "model_name":
                MODEL_NAME,

            "model_version":
                MODEL_VERSION,

            "feature_schema_version":
                PROCESS_FEATURE_SCHEMA_VERSION,

            "training_samples":
                int(
                    matrix.shape[0]
                ),

            "feature_count":
                int(
                    matrix.shape[1]
                ),

            "features":
                selected_features,

            "dataset_fingerprint":
                dataset_fingerprint,

            "score_statistics":
                score_statistics,
        }


# ================================================================
# MODEL LOADER
#
# This function will also be reused by the next real-time
# prediction module.
# ================================================================

def load_process_isolation_forest_bundle(
    model_path: Path | str = MODEL_PATH,
) -> Dict[
    str,
    Any,
]:

    model_path = Path(
        model_path
    )


    if not model_path.exists():

        raise FileNotFoundError(

            f"SENTINEL-X behavioral model not found: "
            f"{model_path}"
        )


    bundle = (
        joblib.load(
            model_path
        )
    )


    required_keys = {

        "model",

        "scaler",

        "metadata",

        "feature_names",

        "feature_schema_version",

        "model_name",

        "model_version",
    }


    missing_keys = (

        required_keys

        - set(
            bundle.keys()
        )
    )


    if missing_keys:

        raise RuntimeError(

            "Invalid SENTINEL-X model bundle. "
            f"Missing keys: {sorted(missing_keys)}"
        )


    # ------------------------------------------------------------
    # SCHEMA CHECK
    # ------------------------------------------------------------

    if (

        bundle[
            "feature_schema_version"
        ]

        != PROCESS_FEATURE_SCHEMA_VERSION

    ):

        raise RuntimeError(

            "Behavior model feature schema does not match "
            "the current process feature schema."
        )


    # ------------------------------------------------------------
    # MODEL NAME CHECK
    # ------------------------------------------------------------

    if (

        bundle[
            "model_name"
        ]

        != MODEL_NAME

    ):

        raise RuntimeError(

            "Unexpected model type loaded."
        )


    return bundle


# ================================================================
# MAIN
# ================================================================

if __name__ == "__main__":

    trainer = (
        ProcessIsolationForestTrainer()
    )


    trainer.train()