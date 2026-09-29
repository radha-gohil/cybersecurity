from __future__ import annotations

import hashlib
import json
import math
import platform
import random
import sys

from collections import (
    Counter,
    defaultdict,
)

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


from sklearn.model_selection import (
    train_test_split,
)

from sklearn.neural_network import (
    MLPRegressor,
)

from sklearn.preprocessing import (
    StandardScaler,
)


from ai_detection.behavior.behavior_feature_store import (
    BehaviorFeatureStore,
)

from ai_detection.behavior.process_feature_schema import (
    PROCESS_FEATURE_SCHEMA_VERSION,
)

from ai_detection.behavior.isolation_forest_trainer import (
    load_process_isolation_forest_bundle,
)


# ================================================================
# SENTINEL-X SELF-SUPERVISED PROCESS AUTOENCODER
#
# Purpose:
#
# Learn the normal behavioral representation of endpoint processes.
#
# Training objective:
#
#        input behavior vector
#                  ↓
#               encoder
#                  ↓
#              bottleneck
#                  ↓
#               decoder
#                  ↓
#       reconstructed behavior
#
#
# Target during training:
#
#        X -> X
#
# No malicious labels are required.
#
#
# IMPORTANT
# ---------
#
# We deliberately train this model only on records considered
# suitable for the NORMAL baseline.
#
# Records already marked:
#
#        UNUSUAL
#        SUSPICIOUS
#        HIGH_ANOMALY
#
# are excluded.
#
# Security-sensitive command combinations are also excluded from
# the trusted training baseline.
#
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
    "sentinelx_process_autoencoder_v1.joblib"
)


MODEL_PATH = (
    MODEL_DIRECTORY
    / MODEL_FILENAME
)


METADATA_FILENAME = (
    "sentinelx_process_autoencoder_v1_metadata.json"
)


METADATA_PATH = (
    MODEL_DIRECTORY
    / METADATA_FILENAME
)


# ================================================================
# MODEL IDENTITY
# ================================================================

MODEL_NAME = (
    "sentinelx_process_autoencoder"
)


MODEL_VERSION = (
    "v1"
)


# ================================================================
# AUTOENCODER ARCHITECTURE
#
# Input dimension is determined dynamically.
#
# Example:
#
# 19
# ↓
# 32
# ↓
# 12
# ↓
# 4   <- bottleneck
# ↓
# 12
# ↓
# 32
# ↓
# 19
#
# ================================================================

HIDDEN_LAYER_SIZES = (
    32,
    12,
    4,
    12,
    32,
)


BOTTLENECK_HIDDEN_LAYER_INDEX = 2


# ================================================================
# TRAINING CONFIGURATION
# ================================================================

RANDOM_STATE = 42


TEST_SIZE = 0.20


LEARNING_RATE = 0.001


MAX_ITERATIONS = 300


EARLY_STOPPING = True


VALIDATION_FRACTION = 0.10


N_ITER_NO_CHANGE = 20


# ================================================================
# DATASET CONFIGURATION
# ================================================================

MAX_RECORDS = 10000


MINIMUM_TRAINING_SAMPLES = 500


MAX_SAMPLES_PER_PROCESS = 500


MAX_IDENTICAL_VECTOR_COPIES = 3


# ================================================================
# SECURITY-SENSITIVE BASELINE FEATURES
#
# These do not automatically indicate malicious behavior.
#
# However, for the first self-supervised NORMAL baseline we exclude
# these records to reduce contamination.
# ================================================================

SECURITY_SENSITIVE_FLAGS = {

    "has_encoded_command",

    "has_hidden_flag",

    "has_download_keyword",

    "parent_is_office_app",
}


# ================================================================
# TIME
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


    if not math.isfinite(
        number
    ):

        return None


    return number


# ================================================================
# SHA256
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
# PERCENTILE
# ================================================================

def percentile(
    values: np.ndarray,
    value: float,
) -> float:

    return float(

        np.percentile(
            values,
            value,
        )
    )


# ================================================================
# TRAINER
# ================================================================

class ProcessAutoencoderTrainer:

    def __init__(
        self,
    ):

        self.store = (
            BehaviorFeatureStore()
        )


        # ========================================================
        # REUSE THE EXACT FEATURE SET FROM ISOLATION FOREST
        #
        # This gives us consistent behavioral representation
        # across both unsupervised models.
        # ========================================================

        isolation_bundle = (
            load_process_isolation_forest_bundle()
        )


        self.feature_names = list(

            isolation_bundle[
                "feature_names"
            ]
        )


        if not self.feature_names:

            raise RuntimeError(

                "Isolation Forest feature list is empty."
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
    # RECORD SAFE FOR BASELINE?
    # ============================================================

    def baseline_record_allowed(
        self,
        record: Dict[
            str,
            Any,
        ],
    ) -> Tuple[
        bool,
        str,
    ]:


        # --------------------------------------------------------
        # SCHEMA
        # --------------------------------------------------------

        if (

            record.get(
                "schema_version"
            )

            != PROCESS_FEATURE_SCHEMA_VERSION

        ):

            return (
                False,
                "schema_mismatch",
            )


        # --------------------------------------------------------
        # FEATURE PAYLOAD
        # --------------------------------------------------------

        features = (

            record.get(
                "features"
            )

            or {}
        )


        if not isinstance(
            features,
            dict,
        ):

            return (
                False,
                "missing_features",
            )


        # --------------------------------------------------------
        # EXISTING AI LABEL
        #
        # NULL is accepted because it may belong to baseline data
        # collected before live AI inference was enabled.
        # --------------------------------------------------------

        prediction = (
            record.get(
                "anomaly_prediction"
            )
        )


        if prediction is not None:

            prediction = (
                str(
                    prediction
                )
                .strip()
                .upper()
            )


            if prediction != "NORMAL":

                return (
                    False,
                    "existing_ai_anomaly",
                )


        # --------------------------------------------------------
        # SECURITY-SENSITIVE FLAGS
        # --------------------------------------------------------

        for feature_name in (
            SECURITY_SENSITIVE_FLAGS
        ):

            value = safe_float(

                features.get(
                    feature_name,
                    0.0,
                )
            )


            if (
                value is not None
                and value > 0
            ):

                return (
                    False,
                    f"sensitive:{feature_name}",
                )


        # --------------------------------------------------------
        # ADDITIONAL HIGH-RISK COMBINATION
        #
        # Script interpreter running from a temp path.
        # --------------------------------------------------------

        is_script = safe_float(

            features.get(
                "is_script_interpreter",
                0.0,
            )
        ) or 0.0


        is_temp = safe_float(

            features.get(
                "is_temp_path",
                0.0,
            )
        ) or 0.0


        if (
            is_script > 0

            and

            is_temp > 0
        ):

            return (
                False,
                "script_from_temp",
            )


        return (
            True,
            "accepted",
        )


    # ============================================================
    # BUILD MODEL VECTOR
    # ============================================================

    def build_model_vector(
        self,
        record: Dict[
            str,
            Any,
        ],
    ) -> Optional[
        List[
            float
        ]
    ]:


        features = (

            record.get(
                "features"
            )

            or {}
        )


        values = []


        for feature_name in (
            self.feature_names
        ):

            number = safe_float(

                features.get(
                    feature_name
                )
            )


            if number is None:

                return None


            values.append(
                number
            )


        return values


    # ============================================================
    # VECTOR SIGNATURE
    # ============================================================

    def vector_signature(
        self,
        vector: List[float],
    ) -> Tuple[
        float,
        ...
    ]:

        return tuple(

            round(
                value,
                6,
            )

            for value
            in vector
        )


    # ============================================================
    # LOAD TRUSTED BASELINE
    # ============================================================

    def load_training_records(
        self,
    ) -> Dict[
        str,
        Any,
    ]:


        records = (
            self.store.get_recent(
                limit=MAX_RECORDS
            )
        )


        if not records:

            raise RuntimeError(

                "No process behavior records exist."
            )


        accepted = []


        rejection_counter = Counter()


        # ========================================================
        # FIRST FILTER
        # ========================================================

        for record in records:

            (
                allowed,
                reason,

            ) = self.baseline_record_allowed(
                record
            )


            if not allowed:

                rejection_counter[
                    reason
                ] += 1

                continue


            vector = (
                self.build_model_vector(
                    record
                )
            )


            if vector is None:

                rejection_counter[
                    "invalid_model_vector"
                ] += 1

                continue


            accepted.append(

                {

                    "record":
                        record,

                    "vector":
                        vector,
                }
            )


        if not accepted:

            raise RuntimeError(

                "No trusted baseline records remain "
                "after filtering."
            )


        # ========================================================
        # DETERMINISTIC SHUFFLE
        # ========================================================

        random_generator = (
            random.Random(
                RANDOM_STATE
            )
        )


        random_generator.shuffle(
            accepted
        )


        # ========================================================
        # PROCESS BALANCING + DUPLICATE CONTROL
        # ========================================================

        process_counts = defaultdict(
            int
        )


        vector_counts = defaultdict(
            int
        )


        balanced = []


        for item in accepted:

            record = (
                item[
                    "record"
                ]
            )


            vector = (
                item[
                    "vector"
                ]
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


            if (

                process_counts[
                    process_name
                ]

                >= MAX_SAMPLES_PER_PROCESS

            ):

                rejection_counter[
                    "process_sample_cap"
                ] += 1

                continue


            signature = (
                self.vector_signature(
                    vector
                )
            )


            if (

                vector_counts[
                    signature
                ]

                >= MAX_IDENTICAL_VECTOR_COPIES

            ):

                rejection_counter[
                    "duplicate_vector_cap"
                ] += 1

                continue


            process_counts[
                process_name
            ] += 1


            vector_counts[
                signature
            ] += 1


            balanced.append(
                item
            )


        # ========================================================
        # FINAL REQUIREMENT
        # ========================================================

        if len(
            balanced
        ) < MINIMUM_TRAINING_SAMPLES:

            raise RuntimeError(

                f"Only {len(balanced)} trusted baseline samples "
                f"remain after filtering/balancing. "
                f"At least {MINIMUM_TRAINING_SAMPLES} are required."
            )


        matrix = np.asarray(

            [

                item[
                    "vector"
                ]

                for item
                in balanced
            ],

            dtype=np.float64,
        )


        process_names = [

            str(

                item[
                    "record"
                ].get(
                    "process_name"
                )

                or "UNKNOWN"
            )

            for item
            in balanced
        ]


        record_ids = [

            item[
                "record"
            ].get(
                "id"
            )

            for item
            in balanced
        ]


        return {

            "matrix":
                matrix,

            "process_names":
                process_names,

            "record_ids":
                record_ids,

            "raw_record_count":
                len(
                    records
                ),

            "initial_accepted_count":
                len(
                    accepted
                ),

            "final_training_pool_count":
                len(
                    balanced
                ),

            "rejections":
                dict(
                    rejection_counter
                ),

            "process_distribution":
                dict(
                    process_counts
                ),
        }


    # ============================================================
    # TRAIN / VALIDATION SPLIT
    # ============================================================

    def split_dataset(

        self,

        matrix: np.ndarray,

    ) -> Tuple[
        np.ndarray,
        np.ndarray,
    ]:


        (
            train_matrix,
            validation_matrix,

        ) = train_test_split(

            matrix,

            test_size=
                TEST_SIZE,

            random_state=
                RANDOM_STATE,

            shuffle=
                True,
        )


        if len(
            train_matrix
        ) < 100:

            raise RuntimeError(

                "Training split is too small."
            )


        if len(
            validation_matrix
        ) < 50:

            raise RuntimeError(

                "Validation split is too small."
            )


        return (
            train_matrix,
            validation_matrix,
        )


    # ============================================================
    # PREPROCESSING
    # ============================================================

    def fit_scaler(

        self,

        train_matrix: np.ndarray,

        validation_matrix: np.ndarray,

    ) -> Tuple[
        StandardScaler,
        np.ndarray,
        np.ndarray,
    ]:


        scaler = (
            StandardScaler()
        )


        train_scaled = (
            scaler.fit_transform(
                train_matrix
            )
        )


        validation_scaled = (
            scaler.transform(
                validation_matrix
            )
        )


        if not np.all(
            np.isfinite(
                train_scaled
            )
        ):

            raise RuntimeError(

                "Scaled training matrix contains "
                "invalid numeric values."
            )


        if not np.all(
            np.isfinite(
                validation_scaled
            )
        ):

            raise RuntimeError(

                "Scaled validation matrix contains "
                "invalid numeric values."
            )


        return (

            scaler,

            train_scaled,

            validation_scaled,
        )


    # ============================================================
    # CREATE AUTOENCODER
    # ============================================================

    def create_model(
        self,
    ) -> MLPRegressor:


        return (

            MLPRegressor(

                hidden_layer_sizes=
                    HIDDEN_LAYER_SIZES,

                activation=
                    "relu",

                solver=
                    "adam",

                learning_rate_init=
                    LEARNING_RATE,

                max_iter=
                    MAX_ITERATIONS,

                shuffle=
                    True,

                random_state=
                    RANDOM_STATE,

                early_stopping=
                    EARLY_STOPPING,

                validation_fraction=
                    VALIDATION_FRACTION,

                n_iter_no_change=
                    N_ITER_NO_CHANGE,

                tol=
                    1e-4,

                verbose=
                    False,
            )
        )


    # ============================================================
    # FIT MODEL
    #
    # Self-supervised objective:
    #
    #        X -> X
    # ============================================================

    def fit_model(

        self,

        train_scaled: np.ndarray,

    ) -> MLPRegressor:


        model = (
            self.create_model()
        )


        model.fit(

            train_scaled,

            train_scaled,
        )


        return model


    # ============================================================
    # RECONSTRUCTION ERROR
    # ============================================================

    def reconstruction_errors(

        self,

        model: MLPRegressor,

        matrix: np.ndarray,

    ) -> np.ndarray:


        reconstructed = (
            model.predict(
                matrix
            )
        )


        if reconstructed.shape != matrix.shape:

            raise RuntimeError(

                "Autoencoder reconstruction shape mismatch."
            )


        errors = np.mean(

            np.square(

                matrix

                - reconstructed
            ),

            axis=1,
        )


        if not np.all(
            np.isfinite(
                errors
            )
        ):

            raise RuntimeError(

                "Reconstruction errors contain invalid values."
            )


        return errors


    # ============================================================
    # ERROR STATISTICS
    # ============================================================

    def calculate_error_statistics(

        self,

        errors: np.ndarray,

    ) -> Dict[
        str,
        float,
    ]:


        return {

            "min":
                float(
                    np.min(
                        errors
                    )
                ),

            "max":
                float(
                    np.max(
                        errors
                    )
                ),

            "mean":
                float(
                    np.mean(
                        errors
                    )
                ),

            "std":
                float(
                    np.std(
                        errors
                    )
                ),

            "p50":
                percentile(
                    errors,
                    50,
                ),

            "p75":
                percentile(
                    errors,
                    75,
                ),

            "p90":
                percentile(
                    errors,
                    90,
                ),

            "p95":
                percentile(
                    errors,
                    95,
                ),

            "p97":
                percentile(
                    errors,
                    97,
                ),

            "p99":
                percentile(
                    errors,
                    99,
                ),
        }


    # ============================================================
    # FEATURE RECONSTRUCTION ERRORS
    # ============================================================

    def calculate_feature_errors(

        self,

        model: MLPRegressor,

        validation_scaled: np.ndarray,

    ) -> Dict[
        str,
        Dict[
            str,
            float,
        ]
    ]:


        reconstructed = (
            model.predict(
                validation_scaled
            )
        )


        squared_errors = np.square(

            validation_scaled

            - reconstructed
        )


        result = {}


        for (
            index,
            feature_name,
        ) in enumerate(
            self.feature_names
        ):

            values = (
                squared_errors[
                    :,
                    index
                ]
            )


            result[
                feature_name
            ] = {

                "mean_squared_error":
                    float(
                        np.mean(
                            values
                        )
                    ),

                "median_squared_error":
                    float(
                        np.median(
                            values
                        )
                    ),

                "p95_squared_error":
                    float(
                        np.percentile(
                            values,
                            95,
                        )
                    ),
            }


        return result


    # ============================================================
    # DATASET FINGERPRINT
    # ============================================================

    def build_dataset_fingerprint(

        self,

        matrix: np.ndarray,

    ) -> str:


        payload = {

            "schema":
                PROCESS_FEATURE_SCHEMA_VERSION,

            "features":
                self.feature_names,

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


        serialized = (
            json.dumps(

                payload,

                sort_keys=True,

                separators=(
                    ",",
                    ":",
                ),
            )
        )


        return sha256_text(
            serialized
        )


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


        counter = Counter(

            str(
                name
            )
            .strip()
            .lower()

            for name
            in process_names
        )


        return {

            "unique_processes":
                len(
                    counter
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
                    in counter.most_common(
                        20
                    )
                ],
        }


    # ============================================================
    # METADATA
    # ============================================================

    def build_metadata(

        self,

        dataset_info: Dict[
            str,
            Any,
        ],

        matrix: np.ndarray,

        train_matrix: np.ndarray,

        validation_matrix: np.ndarray,

        train_errors: np.ndarray,

        validation_errors: np.ndarray,

        feature_errors: Dict[
            str,
            Any,
        ],

        model: MLPRegressor,

        dataset_fingerprint: str,

    ) -> Dict[
        str,
        Any,
    ]:


        train_statistics = (
            self.calculate_error_statistics(
                train_errors
            )
        )


        validation_statistics = (
            self.calculate_error_statistics(
                validation_errors
            )
        )


        # --------------------------------------------------------
        # OPERATIONAL REFERENCES
        #
        # These are learned from trusted NORMAL validation data.
        #
        # They will be used by the real-time predictor next.
        # --------------------------------------------------------

        thresholds = {

            "normal_reference":
                validation_statistics[
                    "p90"
                ],

            "unusual_threshold":
                validation_statistics[
                    "p95"
                ],

            "suspicious_threshold":
                validation_statistics[
                    "p97"
                ],

            "high_anomaly_threshold":
                validation_statistics[
                    "p99"
                ],
        }


        return {

            # ----------------------------------------------------
            # MODEL IDENTITY
            # ----------------------------------------------------

            "model_name":
                MODEL_NAME,

            "model_version":
                MODEL_VERSION,

            "model_type":
                "SelfSupervisedMLPAutoencoder",

            "purpose":
                (
                    "Personalized endpoint process behavior "
                    "reconstruction and representation learning"
                ),

            "trained_at":
                now_iso(),


            # ----------------------------------------------------
            # SCHEMA
            # ----------------------------------------------------

            "feature_schema_version":
                PROCESS_FEATURE_SCHEMA_VERSION,

            "feature_names":
                list(
                    self.feature_names
                ),

            "feature_count":
                len(
                    self.feature_names
                ),


            # ----------------------------------------------------
            # ARCHITECTURE
            # ----------------------------------------------------

            "architecture": {

                "input_dimension":
                    len(
                        self.feature_names
                    ),

                "hidden_layers":
                    list(
                        HIDDEN_LAYER_SIZES
                    ),

                "bottleneck_hidden_layer_index":
                    BOTTLENECK_HIDDEN_LAYER_INDEX,

                "bottleneck_dimension":
                    HIDDEN_LAYER_SIZES[
                        BOTTLENECK_HIDDEN_LAYER_INDEX
                    ],

                "activation":
                    "relu",

                "output_dimension":
                    len(
                        self.feature_names
                    ),
            },


            # ----------------------------------------------------
            # TRAINING CONFIGURATION
            # ----------------------------------------------------

            "training_parameters": {

                "learning_rate":
                    LEARNING_RATE,

                "maximum_iterations":
                    MAX_ITERATIONS,

                "early_stopping":
                    EARLY_STOPPING,

                "validation_fraction_internal":
                    VALIDATION_FRACTION,

                "n_iter_no_change":
                    N_ITER_NO_CHANGE,

                "random_state":
                    RANDOM_STATE,

                "external_validation_fraction":
                    TEST_SIZE,

                "actual_iterations":
                    int(
                        model.n_iter_
                    ),

                "final_training_loss":
                    float(
                        model.loss_
                    ),
            },


            # ----------------------------------------------------
            # DATASET
            # ----------------------------------------------------

            "dataset": {

                "raw_records":
                    dataset_info[
                        "raw_record_count"
                    ],

                "initial_accepted_records":
                    dataset_info[
                        "initial_accepted_count"
                    ],

                "final_training_pool":
                    dataset_info[
                        "final_training_pool_count"
                    ],

                "training_samples":
                    int(
                        train_matrix.shape[
                            0
                        ]
                    ),

                "validation_samples":
                    int(
                        validation_matrix.shape[
                            0
                        ]
                    ),

                "total_features":
                    int(
                        matrix.shape[
                            1
                        ]
                    ),

                "rejections":
                    dataset_info[
                        "rejections"
                    ],

                "dataset_fingerprint_sha256":
                    dataset_fingerprint,
            },


            # ----------------------------------------------------
            # PROCESS DISTRIBUTION
            # ----------------------------------------------------

            "process_summary":
                self.build_process_summary(

                    dataset_info[
                        "process_names"
                    ]
                ),


            # ----------------------------------------------------
            # RECONSTRUCTION ERROR
            # ----------------------------------------------------

            "training_reconstruction_error":
                train_statistics,

            "validation_reconstruction_error":
                validation_statistics,


            # ----------------------------------------------------
            # OPERATIONAL THRESHOLDS
            # ----------------------------------------------------

            "reconstruction_thresholds":
                thresholds,


            # ----------------------------------------------------
            # PER-FEATURE ERROR
            # ----------------------------------------------------

            "feature_reconstruction_error":
                feature_errors,


            # ----------------------------------------------------
            # PREPROCESSING
            # ----------------------------------------------------

            "preprocessing": {

                "scaler":
                    "StandardScaler",

                "scaler_fit":
                    "training_split_only",

                "scaler_required":
                    True,
            },


            # ----------------------------------------------------
            # SOFTWARE
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
            # ARTIFACT SECURITY
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
    # SAVE
    # ============================================================

    def save_model(

        self,

        model: MLPRegressor,

        scaler: StandardScaler,

        metadata: Dict[
            str,
            Any,
        ],

    ) -> None:


        self.ensure_model_directory()


        bundle = {

            "model":
                model,

            "scaler":
                scaler,

            "metadata":
                metadata,

            "feature_names":
                list(
                    self.feature_names
                ),

            "feature_schema_version":
                PROCESS_FEATURE_SCHEMA_VERSION,

            "model_name":
                MODEL_NAME,

            "model_version":
                MODEL_VERSION,

            "bottleneck_hidden_layer_index":
                BOTTLENECK_HIDDEN_LAYER_INDEX,
        }


        joblib.dump(

            bundle,

            MODEL_PATH,
        )


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
    # VERIFY SAVED BUNDLE
    # ============================================================

    def verify_saved_model(
        self,
    ) -> Dict[
        str,
        Any,
    ]:


        if not MODEL_PATH.exists():

            raise RuntimeError(

                "Saved autoencoder model does not exist."
            )


        bundle = (
            joblib.load(
                MODEL_PATH
            )
        )


        required = {

            "model",

            "scaler",

            "metadata",

            "feature_names",

            "feature_schema_version",

            "model_name",

            "model_version",

            "bottleneck_hidden_layer_index",
        }


        missing = (

            required

            - set(
                bundle.keys()
            )
        )


        if missing:

            raise RuntimeError(

                "Invalid autoencoder bundle. "
                f"Missing keys: {sorted(missing)}"
            )


        if (

            bundle[
                "feature_schema_version"
            ]

            != PROCESS_FEATURE_SCHEMA_VERSION

        ):

            raise RuntimeError(

                "Autoencoder schema mismatch."
            )


        if (

            bundle[
                "model_name"
            ]

            != MODEL_NAME

        ):

            raise RuntimeError(

                "Unexpected autoencoder model name."
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


        print()

        print(
            "=" * 82
        )

        print(
            "SENTINEL-X SELF-SUPERVISED PROCESS AUTOENCODER TRAINING"
        )

        print(
            "=" * 82
        )


        # ========================================================
        # STEP 1
        # ========================================================

        print(
            "\n[1/9] Loading trusted normal-behavior dataset..."
        )


        dataset_info = (
            self.load_training_records()
        )


        matrix = (
            dataset_info[
                "matrix"
            ]
        )


        print(
            "Raw behavior records      :",
            dataset_info[
                "raw_record_count"
            ],
        )


        print(
            "Initially accepted         :",
            dataset_info[
                "initial_accepted_count"
            ],
        )


        print(
            "Final balanced baseline    :",
            dataset_info[
                "final_training_pool_count"
            ],
        )


        print(
            "Feature count              :",
            matrix.shape[
                1
            ],
        )


        print(
            "\nFiltered records:"
        )


        for (
            reason,
            count,
        ) in (
            sorted(

                dataset_info[
                    "rejections"
                ].items(),

                key=lambda item:
                    item[
                        1
                    ],

                reverse=True,
            )
        ):

            print(
                f"  {reason:<35} {count}"
            )


        # ========================================================
        # STEP 2
        # ========================================================

        print(
            "\n[2/9] Creating train/validation split..."
        )


        (
            train_matrix,
            validation_matrix,

        ) = self.split_dataset(
            matrix
        )


        print(
            "Training samples           :",
            train_matrix.shape[
                0
            ],
        )


        print(
            "Validation samples         :",
            validation_matrix.shape[
                0
            ],
        )


        # ========================================================
        # STEP 3
        # ========================================================

        print(
            "\n[3/9] Creating dataset fingerprint..."
        )


        dataset_fingerprint = (
            self.build_dataset_fingerprint(
                matrix
            )
        )


        print(
            "Dataset SHA256             :",
            dataset_fingerprint,
        )


        # ========================================================
        # STEP 4
        # ========================================================

        print(
            "\n[4/9] Fitting StandardScaler..."
        )


        (
            scaler,
            train_scaled,
            validation_scaled,

        ) = self.fit_scaler(

            train_matrix,

            validation_matrix,
        )


        print(
            "Scaler                     : StandardScaler"
        )


        # ========================================================
        # STEP 5
        # ========================================================

        print(
            "\n[5/9] Training self-supervised autoencoder..."
        )


        print(
            "Architecture               :",
            (
                f"{len(self.feature_names)} "
                f"-> 32 -> 12 -> 4 -> 12 -> 32 "
                f"-> {len(self.feature_names)}"
            ),
        )


        model = (
            self.fit_model(
                train_scaled
            )
        )


        print(
            "Iterations                 :",
            model.n_iter_,
        )


        print(
            "Final training loss         :",
            round(
                float(
                    model.loss_
                ),
                8,
            ),
        )


        # ========================================================
        # STEP 6
        # ========================================================

        print(
            "\n[6/9] Measuring reconstruction error..."
        )


        train_errors = (
            self.reconstruction_errors(

                model,

                train_scaled,
            )
        )


        validation_errors = (
            self.reconstruction_errors(

                model,

                validation_scaled,
            )
        )


        train_stats = (
            self.calculate_error_statistics(
                train_errors
            )
        )


        validation_stats = (
            self.calculate_error_statistics(
                validation_errors
            )
        )


        print(
            "\nTraining reconstruction:"
        )


        print(
            f"  Mean : {train_stats['mean']:.8f}"
        )


        print(
            f"  P95  : {train_stats['p95']:.8f}"
        )


        print(
            f"  P99  : {train_stats['p99']:.8f}"
        )


        print(
            "\nValidation reconstruction:"
        )


        print(
            f"  Mean : {validation_stats['mean']:.8f}"
        )


        print(
            f"  P90  : {validation_stats['p90']:.8f}"
        )


        print(
            f"  P95  : {validation_stats['p95']:.8f}"
        )


        print(
            f"  P97  : {validation_stats['p97']:.8f}"
        )


        print(
            f"  P99  : {validation_stats['p99']:.8f}"
        )


        # ========================================================
        # STEP 7
        # ========================================================

        print(
            "\n[7/9] Calculating per-feature reconstruction error..."
        )


        feature_errors = (
            self.calculate_feature_errors(

                model,

                validation_scaled,
            )
        )


        ordered_features = sorted(

            feature_errors.items(),

            key=lambda item:
                item[
                    1
                ][
                    "mean_squared_error"
                ],

            reverse=True,
        )


        print(
            "\nHighest reconstruction-error features:"
        )


        for (
            feature_name,
            stats,
        ) in ordered_features[
            :10
        ]:

            print(

                f"  {feature_name:<31} "
                f"MSE={stats['mean_squared_error']:.6f}"
            )


        # ========================================================
        # STEP 8
        # ========================================================

        print(
            "\n[8/9] Saving autoencoder model..."
        )


        metadata = (
            self.build_metadata(

                dataset_info=
                    dataset_info,

                matrix=
                    matrix,

                train_matrix=
                    train_matrix,

                validation_matrix=
                    validation_matrix,

                train_errors=
                    train_errors,

                validation_errors=
                    validation_errors,

                feature_errors=
                    feature_errors,

                model=
                    model,

                dataset_fingerprint=
                    dataset_fingerprint,
            )
        )


        self.save_model(

            model=
                model,

            scaler=
                scaler,

            metadata=
                metadata,
        )


        print(
            "Model saved                :",
            MODEL_PATH,
        )


        print(
            "Metadata saved             :",
            METADATA_PATH,
        )


        # ========================================================
        # STEP 9
        # ========================================================

        print(
            "\n[9/9] Verifying saved model..."
        )


        bundle = (
            self.verify_saved_model()
        )


        print(
            "Model name                 :",
            bundle[
                "model_name"
            ],
        )


        print(
            "Version                    :",
            bundle[
                "model_version"
            ],
        )


        print(
            "Feature count              :",
            len(
                bundle[
                    "feature_names"
                ]
            ),
        )


        print(
            "Bottleneck dimension       :",
            HIDDEN_LAYER_SIZES[
                BOTTLENECK_HIDDEN_LAYER_INDEX
            ],
        )


        thresholds = (

            metadata[
                "reconstruction_thresholds"
            ]
        )


        print(
            "\nLearned reconstruction thresholds:"
        )


        print(
            "  Normal reference :",
            thresholds[
                "normal_reference"
            ],
        )


        print(
            "  Unusual          :",
            thresholds[
                "unusual_threshold"
            ],
        )


        print(
            "  Suspicious       :",
            thresholds[
                "suspicious_threshold"
            ],
        )


        print(
            "  High anomaly     :",
            thresholds[
                "high_anomaly_threshold"
            ],
        )


        print()

        print(
            "=" * 82
        )

        print(
            "SELF-SUPERVISED AUTOENCODER TRAINING COMPLETE"
        )

        print(
            "=" * 82
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

            "feature_count":
                len(
                    self.feature_names
                ),

            "training_samples":
                int(
                    train_matrix.shape[
                        0
                    ]
                ),

            "validation_samples":
                int(
                    validation_matrix.shape[
                        0
                    ]
                ),

            "bottleneck_dimension":
                HIDDEN_LAYER_SIZES[
                    BOTTLENECK_HIDDEN_LAYER_INDEX
                ],

            "validation_reconstruction_error":
                validation_stats,

            "thresholds":
                thresholds,
        }


# ================================================================
# LOAD AUTOENCODER
# ================================================================

def load_process_autoencoder_bundle(
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

            f"SENTINEL-X process autoencoder not found: "
            f"{model_path}"
        )


    bundle = (
        joblib.load(
            model_path
        )
    )


    required = {

        "model",

        "scaler",

        "metadata",

        "feature_names",

        "feature_schema_version",

        "model_name",

        "model_version",

        "bottleneck_hidden_layer_index",
    }


    missing = (

        required

        - set(
            bundle.keys()
        )
    )


    if missing:

        raise RuntimeError(

            "Invalid SENTINEL-X process autoencoder bundle. "
            f"Missing keys: {sorted(missing)}"
        )


    if (

        bundle[
            "feature_schema_version"
        ]

        != PROCESS_FEATURE_SCHEMA_VERSION

    ):

        raise RuntimeError(

            "Process autoencoder feature schema mismatch."
        )


    if (

        bundle[
            "model_name"
        ]

        != MODEL_NAME

    ):

        raise RuntimeError(

            "Unexpected process autoencoder model."
        )


    return bundle


# ================================================================
# MAIN
# ================================================================

if __name__ == "__main__":

    trainer = (
        ProcessAutoencoderTrainer()
    )


    trainer.train()