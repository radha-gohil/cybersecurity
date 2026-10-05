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

from ai_detection.behavior.baseline_dataset_validator import (
    is_epoch_process_age_artifact,
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
# SENTINEL-X PROCESS AUTOENCODER V2
#
# Main change from v1:
#
#       v1: ReLU bottleneck
#           ↓
#           many zero embeddings
#           one dead dimension
#
#       v2: tanh hidden representation
#
# Architecture:
#
#       input
#         ↓
#        32
#         ↓
#        16
#         ↓
#         4     <- bottleneck
#         ↓
#        16
#         ↓
#        32
#         ↓
#       output
#
#
# The trainer also performs an automatic embedding health check.
#
# A candidate model is NOT accepted only because its reconstruction
# error is small.
#
# The bottleneck must also contain useful representation variance.
# ================================================================


# ================================================================
# PATHS
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
    "sentinelx_process_autoencoder_v2.joblib"
)


MODEL_PATH = (
    MODEL_DIRECTORY
    / MODEL_FILENAME
)


METADATA_FILENAME = (
    "sentinelx_process_autoencoder_v2_metadata.json"
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
    "v2"
)


# ================================================================
# ARCHITECTURE
# ================================================================

HIDDEN_LAYER_SIZES = (
    32,
    16,
    4,
    16,
    32,
)


BOTTLENECK_HIDDEN_LAYER_INDEX = 2


BOTTLENECK_DIMENSION = (
    HIDDEN_LAYER_SIZES[
        BOTTLENECK_HIDDEN_LAYER_INDEX
    ]
)


HIDDEN_ACTIVATION = (
    "tanh"
)


# ================================================================
# TRAINING
# ================================================================

TEST_SIZE = 0.20


LEARNING_RATE = 0.001


MAX_ITERATIONS = 400


VALIDATION_FRACTION = 0.10


N_ITER_NO_CHANGE = 25


# Train several independent initializations and accept the best
# healthy representation.

CANDIDATE_RANDOM_STATES = (
    42,
    17,
    73,
)


DATA_SPLIT_RANDOM_STATE = 42


# ================================================================
# DATA
# ================================================================

MAX_RECORDS = 10000


MINIMUM_TRAINING_SAMPLES = 500


MAX_SAMPLES_PER_PROCESS = 500


MAX_IDENTICAL_VECTOR_COPIES = 3


SECURITY_SENSITIVE_FLAGS = {

    "has_encoded_command",

    "has_hidden_flag",

    "has_download_keyword",

    "parent_is_office_app",
}


# ================================================================
# EMBEDDING HEALTH
# ================================================================

NEAR_ZERO_EPSILON = 1e-5


SATURATION_THRESHOLD = 0.98


MIN_DIMENSION_STD = 0.01


MIN_DIMENSION_RANGE = 0.05


MAX_NEAR_ZERO_DIMENSION_PERCENT = 95.0


MAX_SATURATION_DIMENSION_PERCENT = 95.0


MAX_ALL_NEAR_ZERO_PERCENT = 20.0


MIN_UNIQUE_EMBEDDING_PERCENT = 40.0


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

        4,
    )


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
# TRAINER
# ================================================================

class ProcessAutoencoderV2Trainer:

    def __init__(
        self,
    ):

        self.store = (
            BehaviorFeatureStore()
        )


        # --------------------------------------------------------
        # Keep exactly the same feature set used by Isolation
        # Forest.
        # --------------------------------------------------------

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
    # MODEL DIRECTORY
    # ============================================================

    def ensure_model_directory(
        self,
    ) -> None:

        MODEL_DIRECTORY.mkdir(

            parents=True,

            exist_ok=True,
        )


    # ============================================================
    # BASELINE FILTER
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
        # Schema
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
        # Existing Isolation Forest classification
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
        # Security-sensitive combinations
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

                and

                value > 0.0

            ):

                return (
                    False,
                    f"sensitive:{feature_name}",
                )


        # --------------------------------------------------------
        # Script execution from temporary path
        # --------------------------------------------------------

        script_interpreter = (

            safe_float(

                features.get(
                    "is_script_interpreter",
                    0.0,
                )
            )

            or 0.0
        )


        temp_path = (

            safe_float(

                features.get(
                    "is_temp_path",
                    0.0,
                )
            )

            or 0.0
        )


        if (

            script_interpreter > 0.0

            and

            temp_path > 0.0

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
    # BUILD VECTOR
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


        vector = []


        for feature_name in (
            self.feature_names
        ):

            value = safe_float(

                features.get(
                    feature_name
                )
            )


            if value is None:

                return None


            vector.append(
                value
            )


        return vector


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
    # LOAD TRAINING DATA
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

                "No behavioral records are available."
            )


        accepted = []

        rejection_counter = Counter()


        # --------------------------------------------------------
        # Clean baseline
        # --------------------------------------------------------

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
            # Reject historical epoch-timestamp artifacts.
            # Autoencoder uses the Isolation Forest selected
            # feature order, not the full 25-feature schema.

            features = record.get("features") or {}

            age = features.get("process_age_seconds")

            try:
                age = float(age)
            except (TypeError, ValueError):
                age = None

            if age is not None and age > 1_000_000_000:
                rejection_counter[
                    "invalid_process_age"
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

                "No trusted baseline records remain."
            )


        # --------------------------------------------------------
        # Deterministic randomization
        # --------------------------------------------------------

        random_generator = (
            random.Random(
                DATA_SPLIT_RANDOM_STATE
            )
        )


        random_generator.shuffle(
            accepted
        )


        process_counts = defaultdict(
            int
        )


        vector_counts = defaultdict(
            int
        )


        balanced = []


        # --------------------------------------------------------
        # Avoid one process or one identical vector dominating
        # the representation.
        # --------------------------------------------------------

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


        if len(
            balanced
        ) < MINIMUM_TRAINING_SAMPLES:

            raise RuntimeError(

                f"Only {len(balanced)} trusted samples remain. "
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


        if not np.all(
            np.isfinite(
                matrix
            )
        ):

            raise RuntimeError(

                "Training matrix contains non-finite values."
            )


        return {

            "matrix":
                matrix,

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

            "process_names":
                [

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
                ],
        }


    # ============================================================
    # SPLIT
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
                DATA_SPLIT_RANDOM_STATE,

            shuffle=
                True,
        )


        if len(
            train_matrix
        ) < 100:

            raise RuntimeError(

                "Autoencoder training split is too small."
            )


        if len(
            validation_matrix
        ) < 50:

            raise RuntimeError(

                "Autoencoder validation split is too small."
            )


        return (
            train_matrix,
            validation_matrix,
        )


    # ============================================================
    # SCALING
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
                "non-finite values."
            )


        if not np.all(
            np.isfinite(
                validation_scaled
            )
        ):

            raise RuntimeError(

                "Scaled validation matrix contains "
                "non-finite values."
            )


        return (

            scaler,

            train_scaled,

            validation_scaled,
        )


    # ============================================================
    # MODEL
    # ============================================================

    def create_model(
        self,
        random_state: int,
    ) -> MLPRegressor:

        return (

            MLPRegressor(

                hidden_layer_sizes=
                    HIDDEN_LAYER_SIZES,

                activation=
                    HIDDEN_ACTIVATION,

                solver=
                    "adam",

                learning_rate_init=
                    LEARNING_RATE,

                max_iter=
                    MAX_ITERATIONS,

                shuffle=
                    True,

                random_state=
                    random_state,

                early_stopping=
                    True,

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


        reconstructed = np.asarray(

            reconstructed,

            dtype=np.float64,
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

                "Autoencoder reconstruction errors "
                "contain non-finite values."
            )


        return errors


    # ============================================================
    # TANH HIDDEN FORWARD PASS
    # ============================================================

    def extract_embeddings(

        self,

        model: MLPRegressor,

        matrix: np.ndarray,

    ) -> np.ndarray:

        activation = np.asarray(

            matrix,

            dtype=np.float64,
        )


        for layer_index in range(

            BOTTLENECK_HIDDEN_LAYER_INDEX
            + 1

        ):

            activation = (

                activation

                @ model.coefs_[
                    layer_index
                ]

                + model.intercepts_[
                    layer_index
                ]
            )


            activation = np.tanh(
                activation
            )


        if (

            activation.ndim != 2

            or

            activation.shape[
                1
            ] != BOTTLENECK_DIMENSION

        ):

            raise RuntimeError(

                "Unexpected bottleneck embedding shape."
            )


        if not np.all(
            np.isfinite(
                activation
            )
        ):

            raise RuntimeError(

                "Bottleneck embeddings contain "
                "non-finite values."
            )


        return activation


    # ============================================================
    # EMBEDDING HEALTH
    # ============================================================

    def analyze_embedding_health(

        self,

        embeddings: np.ndarray,

    ) -> Dict[
        str,
        Any,
    ]:

        sample_count = (
            embeddings.shape[
                0
            ]
        )


        dimension_count = (
            embeddings.shape[
                1
            ]
        )


        all_near_zero_mask = np.all(

            np.abs(
                embeddings
            )

            <= NEAR_ZERO_EPSILON,

            axis=1,
        )


        all_near_zero_count = int(

            np.sum(
                all_near_zero_mask
            )
        )


        all_near_zero_percent = (
            percentage(

                all_near_zero_count,

                sample_count,
            )
        )


        rounded = np.round(

            embeddings,

            decimals=5,
        )


        unique_embeddings = {

            tuple(
                row.tolist()
            )

            for row
            in rounded
        }


        unique_count = len(
            unique_embeddings
        )


        unique_percent = (
            percentage(

                unique_count,

                sample_count,
            )
        )


        dimensions = []

        dead_dimensions = []


        for index in range(
            dimension_count
        ):

            values = (

                embeddings[
                    :,
                    index
                ]
            )


            minimum = float(

                np.min(
                    values
                )
            )


            maximum = float(

                np.max(
                    values
                )
            )


            mean_value = float(

                np.mean(
                    values
                )
            )


            std_value = float(

                np.std(
                    values
                )
            )


            value_range = (

                maximum
                - minimum
            )


            near_zero_count = int(

                np.sum(

                    np.abs(
                        values
                    )

                    <= NEAR_ZERO_EPSILON
                )
            )


            near_zero_percent = (
                percentage(

                    near_zero_count,

                    sample_count,
                )
            )


            saturated_count = int(

                np.sum(

                    np.abs(
                        values
                    )

                    >= SATURATION_THRESHOLD
                )
            )


            saturated_percent = (
                percentage(

                    saturated_count,

                    sample_count,
                )
            )


            dimension_dead = (

                std_value
                < MIN_DIMENSION_STD

                or

                value_range
                < MIN_DIMENSION_RANGE

                or

                near_zero_percent
                >= MAX_NEAR_ZERO_DIMENSION_PERCENT

                or

                saturated_percent
                >= MAX_SATURATION_DIMENSION_PERCENT
            )


            if dimension_dead:

                dead_dimensions.append(
                    index
                )


            dimensions.append(
                {

                    "dimension":
                        index,

                    "min":
                        minimum,

                    "max":
                        maximum,

                    "mean":
                        mean_value,

                    "std":
                        std_value,

                    "range":
                        value_range,

                    "near_zero_percent":
                        near_zero_percent,

                    "saturated_percent":
                        saturated_percent,

                    "dead":
                        dimension_dead,
                }
            )


        # --------------------------------------------------------
        # Matrix rank gives another useful representation check.
        # --------------------------------------------------------

        centered = (

            embeddings

            - np.mean(
                embeddings,
                axis=0,
            )
        )


        matrix_rank = int(

            np.linalg.matrix_rank(
                centered
            )
        )


        checks = {

            "all_near_zero_acceptable":

                all_near_zero_percent
                <= MAX_ALL_NEAR_ZERO_PERCENT,


            "embedding_diversity":

                unique_percent
                >= MIN_UNIQUE_EMBEDDING_PERCENT,


            "no_dead_dimensions":

                len(
                    dead_dimensions
                )
                == 0,


            "full_embedding_rank":

                matrix_rank
                == BOTTLENECK_DIMENSION,
        }


        healthy = all(
            checks.values()
        )


        return {

            "healthy":
                healthy,

            "sample_count":
                sample_count,

            "dimension_count":
                dimension_count,

            "all_near_zero_count":
                all_near_zero_count,

            "all_near_zero_percent":
                all_near_zero_percent,

            "unique_embedding_count":
                unique_count,

            "unique_embedding_percent":
                unique_percent,

            "matrix_rank":
                matrix_rank,

            "dead_dimensions":
                dead_dimensions,

            "dimensions":
                dimensions,

            "checks":
                checks,
        }


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
                float(
                    np.percentile(
                        errors,
                        50,
                    )
                ),

            "p75":
                float(
                    np.percentile(
                        errors,
                        75,
                    )
                ),

            "p90":
                float(
                    np.percentile(
                        errors,
                        90,
                    )
                ),

            "p95":
                float(
                    np.percentile(
                        errors,
                        95,
                    )
                ),

            "p97":
                float(
                    np.percentile(
                        errors,
                        97,
                    )
                ),

            "p99":
                float(
                    np.percentile(
                        errors,
                        99,
                    )
                ),
        }


    # ============================================================
    # FEATURE ERRORS
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

        reconstructed = np.asarray(

            model.predict(
                validation_scaled
            ),

            dtype=np.float64,
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
                process_name
            )
            .strip()
            .lower()

            for process_name
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
    # TRAIN CANDIDATES
    # ============================================================

    def train_candidates(

        self,

        train_scaled: np.ndarray,

        validation_scaled: np.ndarray,

    ) -> Tuple[
        MLPRegressor,
        Dict[
            str,
            Any,
        ],
        List[
            Dict[
                str,
                Any,
            ]
        ],
    ]:

        candidate_results = []

        healthy_candidates = []


        for random_state in (
            CANDIDATE_RANDOM_STATES
        ):

            print()

            print(
                f"Training candidate seed={random_state} ..."
            )


            model = (
                self.create_model(
                    random_state
                )
            )


            model.fit(

                train_scaled,

                train_scaled,
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


            embeddings = (
                self.extract_embeddings(

                    model,

                    validation_scaled,
                )
            )


            embedding_health = (
                self.analyze_embedding_health(
                    embeddings
                )
            )


            validation_stats = (
                self.calculate_error_statistics(
                    validation_errors
                )
            )


            candidate = {

                "random_state":
                    random_state,

                "iterations":
                    int(
                        model.n_iter_
                    ),

                "training_loss":
                    float(
                        model.loss_
                    ),

                "training_error_mean":
                    float(
                        np.mean(
                            train_errors
                        )
                    ),

                "validation_error_mean":
                    validation_stats[
                        "mean"
                    ],

                "validation_error_p95":
                    validation_stats[
                        "p95"
                    ],

                "embedding_health":
                    embedding_health,
            }


            candidate_results.append(
                candidate
            )


            print(
                "  validation mean error :",
                round(
                    candidate[
                        "validation_error_mean"
                    ],
                    8,
                ),
            )


            print(
                "  unique embeddings     :",
                f"{embedding_health['unique_embedding_percent']:.2f}%",
            )


            print(
                "  all-near-zero         :",
                f"{embedding_health['all_near_zero_percent']:.2f}%",
            )


            print(
                "  embedding rank        :",
                embedding_health[
                    "matrix_rank"
                ],
            )


            print(
                "  dead dimensions       :",
                embedding_health[
                    "dead_dimensions"
                ],
            )


            print(
                "  embedding healthy     :",
                embedding_health[
                    "healthy"
                ],
            )


            if embedding_health[
                "healthy"
            ]:

                healthy_candidates.append(
                    (
                        candidate[
                            "validation_error_mean"
                        ],

                        model,

                        candidate,
                    )
                )


        # --------------------------------------------------------
        # Refuse to save another collapsed representation.
        # --------------------------------------------------------

        if not healthy_candidates:

            raise RuntimeError(

                "No Autoencoder v2 candidate produced a healthy "
                "4D bottleneck representation. "
                "No v2 model was saved."
            )


        healthy_candidates.sort(

            key=lambda item:
                item[
                    0
                ]
        )


        (
            _,
            best_model,
            best_candidate,

        ) = healthy_candidates[
            0
        ]


        return (

            best_model,

            best_candidate,

            candidate_results,
        )


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

        train_scaled: np.ndarray,

        validation_scaled: np.ndarray,

        model: MLPRegressor,

        best_candidate: Dict[
            str,
            Any,
        ],

        candidate_results: List[
            Dict[
                str,
                Any,
            ]
        ],

        dataset_fingerprint: str,

    ) -> Dict[
        str,
        Any,
    ]:

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


        validation_embeddings = (
            self.extract_embeddings(

                model,

                validation_scaled,
            )
        )


        training_stats = (
            self.calculate_error_statistics(
                train_errors
            )
        )


        validation_stats = (
            self.calculate_error_statistics(
                validation_errors
            )
        )


        embedding_health = (
            self.analyze_embedding_health(
                validation_embeddings
            )
        )


        feature_errors = (
            self.calculate_feature_errors(

                model,

                validation_scaled,
            )
        )


        thresholds = {

            "normal_reference":
                validation_stats[
                    "p90"
                ],

            "unusual_threshold":
                validation_stats[
                    "p95"
                ],

            "suspicious_threshold":
                validation_stats[
                    "p97"
                ],

            "high_anomaly_threshold":
                validation_stats[
                    "p99"
                ],
        }


        return {

            # ----------------------------------------------------
            # Identity
            # ----------------------------------------------------

            "model_name":
                MODEL_NAME,

            "model_version":
                MODEL_VERSION,

            "model_type":
                "SelfSupervisedMLPAutoencoder",

            "trained_at":
                now_iso(),


            # ----------------------------------------------------
            # Schema
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
            # Architecture
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

                "hidden_activation":
                    HIDDEN_ACTIVATION,

                "output_activation":
                    "identity",

                "bottleneck_hidden_layer_index":
                    BOTTLENECK_HIDDEN_LAYER_INDEX,

                "bottleneck_dimension":
                    BOTTLENECK_DIMENSION,

                "output_dimension":
                    len(
                        self.feature_names
                    ),
            },


            # ----------------------------------------------------
            # Selected candidate
            # ----------------------------------------------------

            "selected_candidate": {

                "random_state":
                    best_candidate[
                        "random_state"
                    ],

                "iterations":
                    best_candidate[
                        "iterations"
                    ],

                "training_loss":
                    best_candidate[
                        "training_loss"
                    ],

                "validation_error_mean":
                    best_candidate[
                        "validation_error_mean"
                    ],
            },


            # ----------------------------------------------------
            # All candidate diagnostics
            # ----------------------------------------------------

            "candidate_results":
                candidate_results,


            # ----------------------------------------------------
            # Data
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
                        train_scaled.shape[
                            0
                        ]
                    ),

                "validation_samples":
                    int(
                        validation_scaled.shape[
                            0
                        ]
                    ),

                "dataset_fingerprint_sha256":
                    dataset_fingerprint,

                "rejections":
                    dataset_info[
                        "rejections"
                    ],
            },


            "process_summary":
                self.build_process_summary(

                    dataset_info[
                        "process_names"
                    ]
                ),


            # ----------------------------------------------------
            # Reconstruction
            # ----------------------------------------------------

            "training_reconstruction_error":
                training_stats,

            "validation_reconstruction_error":
                validation_stats,

            "reconstruction_thresholds":
                thresholds,

            "feature_reconstruction_error":
                feature_errors,


            # ----------------------------------------------------
            # Representation health
            # ----------------------------------------------------

            "embedding_health":
                embedding_health,


            # ----------------------------------------------------
            # Training
            # ----------------------------------------------------

            "training_parameters": {

                "learning_rate":
                    LEARNING_RATE,

                "max_iterations":
                    MAX_ITERATIONS,

                "validation_fraction_internal":
                    VALIDATION_FRACTION,

                "n_iter_no_change":
                    N_ITER_NO_CHANGE,

                "external_validation_fraction":
                    TEST_SIZE,

                "candidate_random_states":
                    list(
                        CANDIDATE_RANDOM_STATES
                    ),
            },


            # ----------------------------------------------------
            # Preprocessing
            # ----------------------------------------------------

            "preprocessing": {

                "scaler":
                    "StandardScaler",

                "scaler_required":
                    True,

                "scaler_fit":
                    "training_split_only",
            },


            # ----------------------------------------------------
            # Runtime
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


            "artifact_security": {

                "trusted_local_artifact_only":
                    True,

                "warning":
                    (
                        "Do not load untrusted joblib/pickle "
                        "model artifacts."
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


        if not metadata[
            "embedding_health"
        ][
            "healthy"
        ]:

            raise RuntimeError(

                "Refusing to save Autoencoder v2 because "
                "the bottleneck health check failed."
            )


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

            "hidden_activation":
                HIDDEN_ACTIVATION,

            "bottleneck_hidden_layer_index":
                BOTTLENECK_HIDDEN_LAYER_INDEX,

            "bottleneck_dimension":
                BOTTLENECK_DIMENSION,
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
    # VERIFY
    # ============================================================

    def verify_saved_model(
        self,
    ) -> Dict[
        str,
        Any,
    ]:

        if not MODEL_PATH.exists():

            raise RuntimeError(

                "Autoencoder v2 model file was not created."
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

            "hidden_activation",

            "bottleneck_hidden_layer_index",

            "bottleneck_dimension",
        }


        missing = (

            required

            - set(
                bundle.keys()
            )
        )


        if missing:

            raise RuntimeError(

                f"Invalid Autoencoder v2 bundle: "
                f"{sorted(missing)}"
            )


        if (

            bundle[
                "model_version"
            ]

            != MODEL_VERSION

        ):

            raise RuntimeError(

                "Unexpected Autoencoder model version."
            )


        if (

            bundle[
                "hidden_activation"
            ]

            != HIDDEN_ACTIVATION

        ):

            raise RuntimeError(

                "Unexpected hidden activation."
            )


        return bundle


    # ============================================================
    # TRAIN
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
            "SENTINEL-X PROCESS AUTOENCODER V2 TRAINING"
        )

        print(
            "=" * 82
        )


        # ========================================================
        # 1
        # ========================================================

        print(
            "\n[1/8] Loading trusted behavior baseline..."
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
            "Raw records       :",
            dataset_info[
                "raw_record_count"
            ],
        )


        print(
            "Accepted          :",
            dataset_info[
                "initial_accepted_count"
            ],
        )


        print(
            "Balanced baseline :",
            dataset_info[
                "final_training_pool_count"
            ],
        )


        print(
            "Features          :",
            matrix.shape[
                1
            ],
        )


        # ========================================================
        # 2
        # ========================================================

        print(
            "\n[2/8] Creating train/validation split..."
        )


        (
            train_matrix,
            validation_matrix,

        ) = self.split_dataset(
            matrix
        )


        print(
            "Training samples  :",
            len(
                train_matrix
            ),
        )


        print(
            "Validation samples:",
            len(
                validation_matrix
            ),
        )


        # ========================================================
        # 3
        # ========================================================

        print(
            "\n[3/8] Scaling behavior features..."
        )


        (
            scaler,
            train_scaled,
            validation_scaled,

        ) = self.fit_scaler(

            train_matrix,

            validation_matrix,
        )


        # ========================================================
        # 4
        # ========================================================

        print(
            "\n[4/8] Training candidate Autoencoders..."
        )


        print(
            "Architecture:",
            (
                f"{len(self.feature_names)} "
                "-> 32 -> 16 -> 4 -> 16 -> 32 "
                f"-> {len(self.feature_names)}"
            ),
        )


        print(
            "Activation:",
            HIDDEN_ACTIVATION,
        )


        (
            model,
            best_candidate,
            candidate_results,

        ) = self.train_candidates(

            train_scaled,

            validation_scaled,
        )


        print()

        print(
            "Selected seed:",
            best_candidate[
                "random_state"
            ],
        )


        # ========================================================
        # 5
        # ========================================================

        print(
            "\n[5/8] Calculating dataset fingerprint..."
        )


        dataset_fingerprint = (
            self.build_dataset_fingerprint(
                matrix
            )
        )


        print(
            "Dataset SHA256:",
            dataset_fingerprint,
        )


        # ========================================================
        # 6
        # ========================================================

        print(
            "\n[6/8] Building final model metadata..."
        )


        metadata = (
            self.build_metadata(

                dataset_info=
                    dataset_info,

                matrix=
                    matrix,

                train_scaled=
                    train_scaled,

                validation_scaled=
                    validation_scaled,

                model=
                    model,

                best_candidate=
                    best_candidate,

                candidate_results=
                    candidate_results,

                dataset_fingerprint=
                    dataset_fingerprint,
            )
        )


        health = (
            metadata[
                "embedding_health"
            ]
        )


        validation_stats = (
            metadata[
                "validation_reconstruction_error"
            ]
        )


        print()

        print(
            "FINAL BOTTLENECK HEALTH"
        )


        print(
            "  All near-zero :",
            f"{health['all_near_zero_percent']:.2f}%",
        )


        print(
            "  Unique        :",
            f"{health['unique_embedding_percent']:.2f}%",
        )


        print(
            "  Rank          :",
            health[
                "matrix_rank"
            ],
        )


        print(
            "  Dead dims     :",
            health[
                "dead_dimensions"
            ],
        )


        for dimension in (
            health[
                "dimensions"
            ]
        ):

            print(

                "  Dim "
                f"{dimension['dimension']} | "
                f"std={dimension['std']:.6f} | "
                f"range={dimension['range']:.6f} | "
                f"near-zero={dimension['near_zero_percent']:.2f}% | "
                f"saturated={dimension['saturated_percent']:.2f}%"
            )


        print()

        print(
            "VALIDATION RECONSTRUCTION"
        )


        print(
            f"  Mean : {validation_stats['mean']:.8f}"
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
        # 7
        # ========================================================

        print(
            "\n[7/8] Saving healthy Autoencoder v2..."
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
            "Model:",
            MODEL_PATH,
        )


        print(
            "Metadata:",
            METADATA_PATH,
        )


        # ========================================================
        # 8
        # ========================================================

        print(
            "\n[8/8] Verifying model artifact..."
        )


        bundle = (
            self.verify_saved_model()
        )


        print(
            "Model family :",
            bundle[
                "model_name"
            ],
        )


        print(
            "Version      :",
            bundle[
                "model_version"
            ],
        )


        print(
            "Activation   :",
            bundle[
                "hidden_activation"
            ],
        )


        print(
            "Bottleneck   :",
            bundle[
                "bottleneck_dimension"
            ],
        )


        print()

        print(
            "=" * 82
        )

        print(
            "AUTOENCODER V2 TRAINING COMPLETE"
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

            "activation":
                HIDDEN_ACTIVATION,

            "embedding_health":
                health,

            "validation_reconstruction_error":
                validation_stats,
        }


# ================================================================
# LOAD V2
# ================================================================

def load_process_autoencoder_v2_bundle(

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

            "SENTINEL-X Autoencoder v2 not found: "
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

        "hidden_activation",

        "bottleneck_hidden_layer_index",

        "bottleneck_dimension",
    }


    missing = (

        required

        - set(
            bundle.keys()
        )
    )


    if missing:

        raise RuntimeError(

            "Invalid Autoencoder v2 bundle. "
            f"Missing keys: {sorted(missing)}"
        )


    if (

        bundle[
            "feature_schema_version"
        ]

        != PROCESS_FEATURE_SCHEMA_VERSION

    ):

        raise RuntimeError(

            "Autoencoder v2 feature schema mismatch."
        )


    if (

        bundle[
            "model_version"
        ]

        != MODEL_VERSION

    ):

        raise RuntimeError(

            "Expected Autoencoder v2 artifact."
        )


    return bundle


# ================================================================
# MAIN
# ================================================================

if __name__ == "__main__":

    trainer = (
        ProcessAutoencoderV2Trainer()
    )


    trainer.train()