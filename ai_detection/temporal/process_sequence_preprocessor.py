from __future__ import annotations

import hashlib
import json
import math

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

import joblib
import numpy as np

from sklearn.preprocessing import StandardScaler


# ================================================================
# SENTINEL-X
# TEMPORAL SEQUENCE PREPROCESSOR V1
#
# Input:
#
#   data/temporal/process_sequence_dataset_v2.npz
#
# Performs:
#
#   1. Dataset validation
#   2. Session-aware train/validation/test split
#   3. Leakage detection
#   4. StandardScaler fit on TRAIN ONLY
#   5. Train/val/test normalization
#   6. Split diagnostics
#   7. Persistent scaler
#
#
# IMPORTANT:
#
# Windows belonging to the same temporal process session are NEVER
# placed into different dataset splits.
#
# This prevents overlap leakage between training and evaluation.
# ================================================================


# ================================================================
# PROJECT PATHS
# ================================================================

PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[2]
)


TEMPORAL_DIRECTORY = (
    PROJECT_ROOT
    / "data"
    / "temporal"
)


SOURCE_DATASET_PATH = (
    TEMPORAL_DIRECTORY
    / "process_sequence_dataset_v2.npz"
)


OUTPUT_DATASET_PATH = (
    TEMPORAL_DIRECTORY
    / "process_sequence_splits_v1.npz"
)


METADATA_PATH = (
    TEMPORAL_DIRECTORY
    / "process_sequence_splits_v1_metadata.json"
)


SCALER_PATH = (
    PROJECT_ROOT
    / "models"
    / "temporal"
    / "process_temporal_scaler_v1.joblib"
)


# ================================================================
# IDENTITY
# ================================================================

PREPROCESSOR_NAME = (
    "sentinelx_process_temporal_preprocessor"
)


PREPROCESSOR_VERSION = "v1"


# ================================================================
# SPLIT CONFIGURATION
# ================================================================

TRAIN_RATIO = 0.70

VALIDATION_RATIO = 0.15

TEST_RATIO = 0.15


RANDOM_STATE = 42


# ================================================================
# EXPECTED DATASET
# ================================================================

EXPECTED_SEQUENCE_LENGTH = 8

EXPECTED_FEATURE_COUNT = 27


# ================================================================
# MINIMUM REQUIREMENTS
# ================================================================

MINIMUM_TOTAL_WINDOWS = 20

MINIMUM_TOTAL_SESSIONS = 3


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


def sha256_file(
    path: Path,
) -> str:

    digest = hashlib.sha256()

    with open(
        path,
        "rb",
    ) as file:

        while True:

            chunk = file.read(
                1024 * 1024
            )

            if not chunk:
                break

            digest.update(
                chunk
            )

    return digest.hexdigest()


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
        2,
    )


def ensure_finite(
    name: str,
    array: np.ndarray,
) -> None:

    if not np.all(
        np.isfinite(
            array
        )
    ):

        raise RuntimeError(
            f"{name} contains NaN or infinite values."
        )


# ================================================================
# PREPROCESSOR
# ================================================================

class ProcessSequencePreprocessor:

    def __init__(
        self,
    ):

        self.scaler = (
            StandardScaler()
        )


    # ============================================================
    # DIRECTORIES
    # ============================================================

    def ensure_directories(
        self,
    ) -> None:

        TEMPORAL_DIRECTORY.mkdir(
            parents=True,
            exist_ok=True,
        )

        SCALER_PATH.parent.mkdir(
            parents=True,
            exist_ok=True,
        )


    # ============================================================
    # LOAD SOURCE DATASET
    # ============================================================

    def load_dataset(
        self,
    ) -> Dict[str, np.ndarray]:

        if not SOURCE_DATASET_PATH.exists():

            raise FileNotFoundError(
                "Temporal dataset v2 does not exist:\n"
                f"{SOURCE_DATASET_PATH}\n\n"
                "Run:\n"
                "python -m "
                "ai_detection.temporal."
                "process_sequence_dataset_builder_v2"
            )


        data = np.load(
            SOURCE_DATASET_PATH,
            allow_pickle=False,
        )


        required_arrays = {
            "X",
            "feature_record_ids",
            "process_names",
            "pids",
            "session_ids",
            "temporal_feature_names",
        }


        missing = (
            required_arrays
            - set(
                data.files
            )
        )


        if missing:

            raise RuntimeError(
                "Temporal dataset is missing arrays: "
                f"{sorted(missing)}"
            )


        dataset = {
            name:
                np.asarray(
                    data[name]
                )

            for name in required_arrays
        }


        return dataset


    # ============================================================
    # VALIDATE DATASET
    # ============================================================

    def validate_dataset(
        self,
        dataset: Dict[str, np.ndarray],
    ) -> None:

        X = dataset[
            "X"
        ]


        feature_record_ids = dataset[
            "feature_record_ids"
        ]


        process_names = dataset[
            "process_names"
        ]


        pids = dataset[
            "pids"
        ]


        session_ids = dataset[
            "session_ids"
        ]


        feature_names = dataset[
            "temporal_feature_names"
        ]


        # --------------------------------------------------------
        # Dimensions
        # --------------------------------------------------------

        if X.ndim != 3:

            raise RuntimeError(
                "Temporal X must have shape "
                "(windows, sequence_length, features). "
                f"Received: {X.shape}"
            )


        window_count = (
            X.shape[
                0
            ]
        )


        sequence_length = (
            X.shape[
                1
            ]
        )


        feature_count = (
            X.shape[
                2
            ]
        )


        if window_count < MINIMUM_TOTAL_WINDOWS:

            raise RuntimeError(
                f"Only {window_count} temporal windows exist. "
                f"At least {MINIMUM_TOTAL_WINDOWS} are required "
                "for preprocessing."
            )


        if (
            sequence_length
            != EXPECTED_SEQUENCE_LENGTH
        ):

            raise RuntimeError(
                "Unexpected sequence length. "
                f"Expected {EXPECTED_SEQUENCE_LENGTH}, "
                f"received {sequence_length}."
            )


        if (
            feature_count
            != EXPECTED_FEATURE_COUNT
        ):

            raise RuntimeError(
                "Unexpected temporal feature count. "
                f"Expected {EXPECTED_FEATURE_COUNT}, "
                f"received {feature_count}."
            )


        if (
            len(
                feature_names
            )
            != feature_count
        ):

            raise RuntimeError(
                "Feature-name count does not match X."
            )


        # --------------------------------------------------------
        # Window metadata lengths
        # --------------------------------------------------------

        metadata_arrays = {
            "feature_record_ids":
                feature_record_ids,

            "process_names":
                process_names,

            "pids":
                pids,

            "session_ids":
                session_ids,
        }


        for (
            name,
            array,
        ) in metadata_arrays.items():

            if len(
                array
            ) != window_count:

                raise RuntimeError(
                    f"{name} contains {len(array)} rows "
                    f"but X contains {window_count} windows."
                )


        # --------------------------------------------------------
        # Feature-record shape
        # --------------------------------------------------------

        if (
            feature_record_ids.ndim != 2

            or

            feature_record_ids.shape[
                1
            ]
            != sequence_length
        ):

            raise RuntimeError(
                "feature_record_ids must have shape "
                "(windows, sequence_length)."
            )


        # --------------------------------------------------------
        # Numerical validity
        # --------------------------------------------------------

        ensure_finite(
            "Temporal X",
            X,
        )


        # --------------------------------------------------------
        # Session count
        # --------------------------------------------------------

        unique_sessions = np.unique(
            session_ids
        )


        if (
            len(
                unique_sessions
            )
            < MINIMUM_TOTAL_SESSIONS
        ):

            raise RuntimeError(
                "Not enough independent temporal sessions. "
                f"Found {len(unique_sessions)}, "
                f"need at least {MINIMUM_TOTAL_SESSIONS}."
            )


    # ============================================================
    # SESSION → PROCESS MAP
    # ============================================================

    def build_session_process_map(
        self,
        session_ids: np.ndarray,
        process_names: np.ndarray,
    ) -> Dict[str, str]:

        mapping = {}


        for (
            session_id,
            process_name,
        ) in zip(
            session_ids,
            process_names,
        ):

            session_text = str(
                session_id
            )


            process_text = str(
                process_name
            )


            if session_text not in mapping:

                mapping[
                    session_text
                ] = process_text


        return mapping


    # ============================================================
    # SESSION-AWARE SPLIT
    # ============================================================

    def split_sessions(
        self,
        session_ids: np.ndarray,
    ) -> Dict[str, List[str]]:

        unique_sessions = np.unique(
            session_ids
        ).astype(
            str
        )


        total_sessions = len(
            unique_sessions
        )


        if total_sessions < 3:

            raise RuntimeError(
                "At least 3 independent sessions are required "
                "to create train/validation/test splits."
            )


        rng = np.random.default_rng(
            RANDOM_STATE
        )


        shuffled = (
            unique_sessions.copy()
        )


        rng.shuffle(
            shuffled
        )


        # --------------------------------------------------------
        # Ensure validation and test always get at least one
        # session.
        # --------------------------------------------------------

        validation_count = max(
            1,
            int(
                round(
                    total_sessions
                    * VALIDATION_RATIO
                )
            ),
        )


        test_count = max(
            1,
            int(
                round(
                    total_sessions
                    * TEST_RATIO
                )
            ),
        )


        train_count = (
            total_sessions
            - validation_count
            - test_count
        )


        # --------------------------------------------------------
        # Protect training set
        # --------------------------------------------------------

        if train_count < 1:

            validation_count = 1

            test_count = 1

            train_count = (
                total_sessions
                - 2
            )


        if train_count < 1:

            raise RuntimeError(
                "Unable to produce non-empty train/val/test "
                "session splits."
            )


        train_sessions = (
            shuffled[
                :train_count
            ]
            .tolist()
        )


        validation_sessions = (
            shuffled[
                train_count:
                train_count
                + validation_count
            ]
            .tolist()
        )


        test_sessions = (
            shuffled[
                train_count
                + validation_count:
            ]
            .tolist()
        )


        return {
            "train":
                train_sessions,

            "validation":
                validation_sessions,

            "test":
                test_sessions,
        }


    # ============================================================
    # WINDOWS FOR SESSION SET
    # ============================================================

    def indices_for_sessions(
        self,
        session_ids: np.ndarray,
        selected_sessions: List[str],
    ) -> np.ndarray:

        selected = set(
            str(
                value
            )
            for value in selected_sessions
        )


        mask = np.asarray(
            [
                str(
                    session_id
                )
                in selected

                for session_id in session_ids
            ],
            dtype=bool,
        )


        return np.flatnonzero(
            mask
        )


    # ============================================================
    # SPLIT LEAKAGE CHECK
    # ============================================================

    def check_session_leakage(
        self,
        split_sessions: Dict[str, List[str]],
    ) -> Dict[str, bool]:

        train = set(
            split_sessions[
                "train"
            ]
        )


        validation = set(
            split_sessions[
                "validation"
            ]
        )


        test = set(
            split_sessions[
                "test"
            ]
        )


        return {
            "train_validation_disjoint":
                train.isdisjoint(
                    validation
                ),

            "train_test_disjoint":
                train.isdisjoint(
                    test
                ),

            "validation_test_disjoint":
                validation.isdisjoint(
                    test
                ),
        }


    # ============================================================
    # TRAIN SCALER
    # ============================================================

    def fit_scaler(
        self,
        X_train: np.ndarray,
    ) -> StandardScaler:

        # --------------------------------------------------------
        # Transformers receive sequences, but StandardScaler is
        # fit feature-wise.
        #
        # Convert:
        #
        #   (windows, 8, 27)
        #
        # into:
        #
        #   (windows * 8, 27)
        # --------------------------------------------------------

        flattened = (
            X_train.reshape(
                -1,
                X_train.shape[
                    -1
                ],
            )
        )


        ensure_finite(
            "Flattened training data",
            flattened,
        )


        self.scaler.fit(
            flattened
        )


        return self.scaler


    # ============================================================
    # TRANSFORM SPLIT
    # ============================================================

    def transform(
        self,
        X: np.ndarray,
    ) -> np.ndarray:

        original_shape = (
            X.shape
        )


        flattened = (
            X.reshape(
                -1,
                X.shape[
                    -1
                ],
            )
        )


        transformed = (
            self.scaler.transform(
                flattened
            )
        )


        transformed = (
            transformed.reshape(
                original_shape
            )
        )


        transformed = (
            transformed.astype(
                np.float32
            )
        )


        ensure_finite(
            "Normalized temporal data",
            transformed,
        )


        return transformed


    # ============================================================
    # FEATURE STATISTICS
    # ============================================================

    def feature_statistics(
        self,
        X: np.ndarray,
        feature_names: np.ndarray,
    ) -> Dict[str, Dict[str, float]]:

        flattened = (
            X.reshape(
                -1,
                X.shape[
                    -1
                ],
            )
        )


        results = {}


        for index, name in enumerate(
            feature_names
        ):

            values = (
                flattened[
                    :,
                    index
                ]
            )


            results[
                str(
                    name
                )
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

                "p50":
                    float(
                        np.percentile(
                            values,
                            50,
                        )
                    ),

                "p95":
                    float(
                        np.percentile(
                            values,
                            95,
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


        return results


    # ============================================================
    # SPLIT SUMMARY
    # ============================================================

    def split_summary(
        self,
        name: str,
        indices: np.ndarray,
        session_ids: np.ndarray,
        process_names: np.ndarray,
    ) -> Dict[str, Any]:

        split_sessions = np.unique(
            session_ids[
                indices
            ]
        )


        split_processes = (
            process_names[
                indices
            ]
        )


        process_counter = Counter(
            str(
                process
            ).lower()

            for process in split_processes
        )


        return {
            "name":
                name,

            "windows":
                int(
                    len(
                        indices
                    )
                ),

            "sessions":
                int(
                    len(
                        split_sessions
                    )
                ),

            "unique_processes":
                int(
                    len(
                        process_counter
                    )
                ),

            "top_processes":
                [
                    {
                        "process_name":
                            process,

                        "window_count":
                            count,
                    }

                    for (
                        process,
                        count,
                    )
                    in process_counter.most_common(
                        15
                    )
                ],
        }


    # ============================================================
    # SAVE SCALER
    # ============================================================

    def save_scaler(
        self,
        feature_names: np.ndarray,
        source_fingerprint: str,
    ) -> None:

        bundle = {
            "scaler":
                self.scaler,

            "preprocessor_name":
                PREPROCESSOR_NAME,

            "preprocessor_version":
                PREPROCESSOR_VERSION,

            "feature_names":
                [
                    str(
                        name
                    )
                    for name in feature_names
                ],

            "feature_count":
                int(
                    len(
                        feature_names
                    )
                ),

            "sequence_length":
                EXPECTED_SEQUENCE_LENGTH,

            "source_dataset":
                str(
                    SOURCE_DATASET_PATH
                ),

            "source_dataset_sha256":
                source_fingerprint,

            "trained_at":
                now_iso(),

            "warning":
                (
                    "Load only trusted local joblib artifacts."
                ),
        }


        joblib.dump(
            bundle,
            SCALER_PATH,
        )


    # ============================================================
    # SAVE SPLIT DATASET
    # ============================================================

    def save_dataset(
        self,
        dataset: Dict[str, np.ndarray],
        train_indices: np.ndarray,
        validation_indices: np.ndarray,
        test_indices: np.ndarray,
        X_train: np.ndarray,
        X_validation: np.ndarray,
        X_test: np.ndarray,
    ) -> None:

        np.savez_compressed(

            OUTPUT_DATASET_PATH,


            # ====================================================
            # NORMALIZED MODEL INPUT
            # ====================================================

            X_train=
                X_train,

            X_validation=
                X_validation,

            X_test=
                X_test,


            # ====================================================
            # RECORD IDs
            # ====================================================

            feature_record_ids_train=
                dataset[
                    "feature_record_ids"
                ][
                    train_indices
                ],

            feature_record_ids_validation=
                dataset[
                    "feature_record_ids"
                ][
                    validation_indices
                ],

            feature_record_ids_test=
                dataset[
                    "feature_record_ids"
                ][
                    test_indices
                ],


            # ====================================================
            # PROCESS NAMES
            # ====================================================

            process_names_train=
                dataset[
                    "process_names"
                ][
                    train_indices
                ],

            process_names_validation=
                dataset[
                    "process_names"
                ][
                    validation_indices
                ],

            process_names_test=
                dataset[
                    "process_names"
                ][
                    test_indices
                ],


            # ====================================================
            # PIDS
            # ====================================================

            pids_train=
                dataset[
                    "pids"
                ][
                    train_indices
                ],

            pids_validation=
                dataset[
                    "pids"
                ][
                    validation_indices
                ],

            pids_test=
                dataset[
                    "pids"
                ][
                    test_indices
                ],


            # ====================================================
            # SESSION IDS
            # ====================================================

            session_ids_train=
                dataset[
                    "session_ids"
                ][
                    train_indices
                ],

            session_ids_validation=
                dataset[
                    "session_ids"
                ][
                    validation_indices
                ],

            session_ids_test=
                dataset[
                    "session_ids"
                ][
                    test_indices
                ],


            # ====================================================
            # SCHEMA
            # ====================================================

            temporal_feature_names=
                dataset[
                    "temporal_feature_names"
                ],
        )


    # ============================================================
    # BUILD METADATA
    # ============================================================

    def build_metadata(
        self,
        dataset: Dict[str, np.ndarray],
        split_sessions: Dict[str, List[str]],
        train_indices: np.ndarray,
        validation_indices: np.ndarray,
        test_indices: np.ndarray,
        X_train_raw: np.ndarray,
        leakage_checks: Dict[str, bool],
        source_fingerprint: str,
    ) -> Dict[str, Any]:

        total_windows = (
            dataset[
                "X"
            ].shape[
                0
            ]
        )


        train_summary = (
            self.split_summary(
                "train",
                train_indices,
                dataset[
                    "session_ids"
                ],
                dataset[
                    "process_names"
                ],
            )
        )


        validation_summary = (
            self.split_summary(
                "validation",
                validation_indices,
                dataset[
                    "session_ids"
                ],
                dataset[
                    "process_names"
                ],
            )
        )


        test_summary = (
            self.split_summary(
                "test",
                test_indices,
                dataset[
                    "session_ids"
                ],
                dataset[
                    "process_names"
                ],
            )
        )


        scaler_mean = (
            self.scaler.mean_
            .astype(
                float
            )
            .tolist()
        )


        scaler_scale = (
            self.scaler.scale_
            .astype(
                float
            )
            .tolist()
        )


        readiness_checks = {
            **leakage_checks,

            "train_not_empty":
                len(
                    train_indices
                ) > 0,

            "validation_not_empty":
                len(
                    validation_indices
                ) > 0,

            "test_not_empty":
                len(
                    test_indices
                ) > 0,

            "all_windows_assigned":
                (
                    len(
                        train_indices
                    )
                    + len(
                        validation_indices
                    )
                    + len(
                        test_indices
                    )
                )
                == total_windows,

            "scaler_feature_count_correct":
                len(
                    scaler_mean
                )
                == EXPECTED_FEATURE_COUNT,
        }


        ready = all(
            readiness_checks.values()
        )


        return {
            "preprocessor_name":
                PREPROCESSOR_NAME,

            "preprocessor_version":
                PREPROCESSOR_VERSION,

            "created_at":
                now_iso(),

            "source_dataset":
                str(
                    SOURCE_DATASET_PATH
                ),

            "source_dataset_sha256":
                source_fingerprint,

            "output_dataset":
                str(
                    OUTPUT_DATASET_PATH
                ),

            "scaler_path":
                str(
                    SCALER_PATH
                ),

            "split_strategy": {
                "type":
                    "session_aware",

                "random_state":
                    RANDOM_STATE,

                "train_ratio":
                    TRAIN_RATIO,

                "validation_ratio":
                    VALIDATION_RATIO,

                "test_ratio":
                    TEST_RATIO,

                "important":
                    (
                        "All overlapping windows belonging to "
                        "one session remain in the same split."
                    ),
            },

            "dataset": {
                "total_windows":
                    int(
                        total_windows
                    ),

                "sequence_length":
                    int(
                        dataset[
                            "X"
                        ].shape[
                            1
                        ]
                    ),

                "feature_count":
                    int(
                        dataset[
                            "X"
                        ].shape[
                            2
                        ]
                    ),

                "total_sessions":
                    int(
                        len(
                            np.unique(
                                dataset[
                                    "session_ids"
                                ]
                            )
                        )
                    ),

                "total_process_names":
                    int(
                        len(
                            np.unique(
                                dataset[
                                    "process_names"
                                ]
                            )
                        )
                    ),
            },

            "splits": {
                "train":
                    {
                        **train_summary,

                        "window_percent":
                            percentage(
                                train_summary[
                                    "windows"
                                ],
                                total_windows,
                            ),

                        "session_ids":
                            split_sessions[
                                "train"
                            ],
                    },

                "validation":
                    {
                        **validation_summary,

                        "window_percent":
                            percentage(
                                validation_summary[
                                    "windows"
                                ],
                                total_windows,
                            ),

                        "session_ids":
                            split_sessions[
                                "validation"
                            ],
                    },

                "test":
                    {
                        **test_summary,

                        "window_percent":
                            percentage(
                                test_summary[
                                    "windows"
                                ],
                                total_windows,
                            ),

                        "session_ids":
                            split_sessions[
                                "test"
                            ],
                    },
            },

            "normalization": {
                "type":
                    "StandardScaler",

                "fit_on":
                    "training_split_only",

                "training_timesteps_used":
                    int(
                        X_train_raw.shape[
                            0
                        ]
                        * X_train_raw.shape[
                            1
                        ]
                    ),

                "feature_names":
                    [
                        str(
                            name
                        )
                        for name in dataset[
                            "temporal_feature_names"
                        ]
                    ],

                "mean":
                    scaler_mean,

                "scale":
                    scaler_scale,
            },

            "training_feature_statistics_before_normalization":
                self.feature_statistics(
                    X_train_raw,
                    dataset[
                        "temporal_feature_names"
                    ],
                ),

            "readiness_checks":
                readiness_checks,

            "ready_for_transformer_training":
                ready,

            "ground_truth_note":
                (
                    "These temporal sequences are unlabeled "
                    "behavioral observations. Train/validation/test "
                    "splits must not be interpreted as malicious "
                    "versus benign ground-truth partitions."
                ),
        }


    # ============================================================
    # REPORT
    # ============================================================

    def print_report(
        self,
        metadata: Dict[str, Any],
        X_train: np.ndarray,
        X_validation: np.ndarray,
        X_test: np.ndarray,
    ) -> None:

        print()

        print(
            "=" * 86
        )

        print(
            "SENTINEL-X TEMPORAL PREPROCESSING REPORT"
        )

        print(
            "=" * 86
        )


        print()

        print(
            "SOURCE DATASET"
        )

        print(
            "-" * 86
        )


        print(
            "Total windows   :",
            metadata[
                "dataset"
            ][
                "total_windows"
            ],
        )


        print(
            "Sessions        :",
            metadata[
                "dataset"
            ][
                "total_sessions"
            ],
        )


        print(
            "Sequence length :",
            metadata[
                "dataset"
            ][
                "sequence_length"
            ],
        )


        print(
            "Features / step :",
            metadata[
                "dataset"
            ][
                "feature_count"
            ],
        )


        print()

        print(
            "SESSION-AWARE SPLITS"
        )

        print(
            "-" * 86
        )


        for split_name in (
            "train",
            "validation",
            "test",
        ):

            split = (
                metadata[
                    "splits"
                ][
                    split_name
                ]
            )


            print(
                f"{split_name.upper():<12} "
                f"windows={split['windows']:<6} "
                f"({split['window_percent']:>6.2f}%) | "
                f"sessions={split['sessions']:<4} | "
                f"processes={split['unique_processes']}"
            )


        print()

        print(
            "NORMALIZED MATRIX SHAPES"
        )

        print(
            "-" * 86
        )


        print(
            "Train      :",
            X_train.shape,
        )


        print(
            "Validation :",
            X_validation.shape,
        )


        print(
            "Test       :",
            X_test.shape,
        )


        print()

        print(
            "LEAKAGE / READINESS CHECKS"
        )

        print(
            "-" * 86
        )


        for (
            check,
            passed,
        ) in (
            metadata[
                "readiness_checks"
            ].items()
        ):

            print(
                f"{check:<50}: "
                + (
                    "PASS"
                    if passed
                    else "FAIL"
                )
            )


        print()

        print(
            "NORMALIZATION SANITY"
        )

        print(
            "-" * 86
        )


        flattened_train = (
            X_train.reshape(
                -1,
                X_train.shape[
                    -1
                ],
            )
        )


        feature_means = np.mean(
            flattened_train,
            axis=0,
        )


        feature_stds = np.std(
            flattened_train,
            axis=0,
        )


        print(
            "Maximum absolute train feature mean:",
            round(
                float(
                    np.max(
                        np.abs(
                            feature_means
                        )
                    )
                ),
                6,
            ),
        )


        non_constant_mask = (
            np.asarray(
                metadata[
                    "normalization"
                ][
                    "scale"
                ]
            )
            > 0
        )


        if np.any(
            non_constant_mask
        ):

            print(
                "Mean normalized train feature std:",
                round(
                    float(
                        np.mean(
                            feature_stds[
                                non_constant_mask
                            ]
                        )
                    ),
                    6,
                ),
            )


        print()

        print(
            "=" * 86
        )

        print(
            "FINAL RESULT"
        )

        print(
            "=" * 86
        )


        if metadata[
            "ready_for_transformer_training"
        ]:

            print()

            print(
                "TEMPORAL PREPROCESSING: PASS"
            )

            print()

            print(
                "Dataset is ready for Transformer model training."
            )

        else:

            print()

            print(
                "TEMPORAL PREPROCESSING: REVIEW REQUIRED"
            )


        print()

        print(
            "Normalized dataset:"
        )

        print(
            OUTPUT_DATASET_PATH
        )


        print()

        print(
            "Scaler:"
        )

        print(
            SCALER_PATH
        )


        print()

        print(
            "Metadata:"
        )

        print(
            METADATA_PATH
        )


    # ============================================================
    # RUN
    # ============================================================

    def run(
        self,
    ) -> Dict[str, Any]:

        self.ensure_directories()


        print()

        print(
            "[1/7] Loading temporal dataset v2..."
        )


        dataset = (
            self.load_dataset()
        )


        print(
            "Shape:",
            dataset[
                "X"
            ].shape,
        )


        # ========================================================
        # VALIDATE
        # ========================================================

        print()

        print(
            "[2/7] Validating dataset..."
        )


        self.validate_dataset(
            dataset
        )


        print(
            "Dataset validation: PASS"
        )


        # ========================================================
        # SESSION SPLIT
        # ========================================================

        print()

        print(
            "[3/7] Creating session-aware split..."
        )


        split_sessions = (
            self.split_sessions(

                dataset[
                    "session_ids"
                ]
            )
        )


        train_indices = (
            self.indices_for_sessions(

                dataset[
                    "session_ids"
                ],

                split_sessions[
                    "train"
                ],
            )
        )


        validation_indices = (
            self.indices_for_sessions(

                dataset[
                    "session_ids"
                ],

                split_sessions[
                    "validation"
                ],
            )
        )


        test_indices = (
            self.indices_for_sessions(

                dataset[
                    "session_ids"
                ],

                split_sessions[
                    "test"
                ],
            )
        )


        print(
            "Train windows     :",
            len(
                train_indices
            ),
        )


        print(
            "Validation windows:",
            len(
                validation_indices
            ),
        )


        print(
            "Test windows      :",
            len(
                test_indices
            ),
        )


        # ========================================================
        # LEAKAGE
        # ========================================================

        print()

        print(
            "[4/7] Checking temporal-session leakage..."
        )


        leakage_checks = (
            self.check_session_leakage(
                split_sessions
            )
        )


        if not all(
            leakage_checks.values()
        ):

            raise RuntimeError(
                "Temporal session leakage detected."
            )


        print(
            "Session leakage check: PASS"
        )


        # ========================================================
        # RAW SPLITS
        # ========================================================

        X_train_raw = (
            dataset[
                "X"
            ][
                train_indices
            ]
            .astype(
                np.float64
            )
        )


        X_validation_raw = (
            dataset[
                "X"
            ][
                validation_indices
            ]
            .astype(
                np.float64
            )
        )


        X_test_raw = (
            dataset[
                "X"
            ][
                test_indices
            ]
            .astype(
                np.float64
            )
        )


        # ========================================================
        # NORMALIZATION
        # ========================================================

        print()

        print(
            "[5/7] Fitting StandardScaler on TRAIN only..."
        )


        self.fit_scaler(
            X_train_raw
        )


        X_train = (
            self.transform(
                X_train_raw
            )
        )


        X_validation = (
            self.transform(
                X_validation_raw
            )
        )


        X_test = (
            self.transform(
                X_test_raw
            )
        )


        print(
            "Normalization: COMPLETE"
        )


        # ========================================================
        # SAVE SCALER
        # ========================================================

        print()

        print(
            "[6/7] Saving preprocessing artifacts..."
        )


        source_fingerprint = (
            sha256_file(
                SOURCE_DATASET_PATH
            )
        )


        self.save_scaler(

            feature_names=
                dataset[
                    "temporal_feature_names"
                ],

            source_fingerprint=
                source_fingerprint,
        )


        self.save_dataset(

            dataset=
                dataset,

            train_indices=
                train_indices,

            validation_indices=
                validation_indices,

            test_indices=
                test_indices,

            X_train=
                X_train,

            X_validation=
                X_validation,

            X_test=
                X_test,
        )


        # ========================================================
        # METADATA
        # ========================================================

        metadata = (
            self.build_metadata(

                dataset=
                    dataset,

                split_sessions=
                    split_sessions,

                train_indices=
                    train_indices,

                validation_indices=
                    validation_indices,

                test_indices=
                    test_indices,

                X_train_raw=
                    X_train_raw,

                leakage_checks=
                    leakage_checks,

                source_fingerprint=
                    source_fingerprint,
            )
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


        print(
            "Artifacts saved."
        )


        # ========================================================
        # REPORT
        # ========================================================

        print()

        print(
            "[7/7] Running final integrity checks..."
        )


        self.print_report(

            metadata=
                metadata,

            X_train=
                X_train,

            X_validation=
                X_validation,

            X_test=
                X_test,
        )


        return metadata


# ================================================================
# LOAD SAVED TEMPORAL PREPROCESSOR
# ================================================================

def load_temporal_scaler():

    if not SCALER_PATH.exists():

        raise FileNotFoundError(
            f"Temporal scaler not found: {SCALER_PATH}"
        )


    bundle = joblib.load(
        SCALER_PATH
    )


    required = {
        "scaler",
        "feature_names",
        "feature_count",
        "sequence_length",
        "preprocessor_version",
    }


    missing = (
        required
        - set(
            bundle.keys()
        )
    )


    if missing:

        raise RuntimeError(
            "Invalid temporal scaler artifact. "
            f"Missing: {sorted(missing)}"
        )


    return bundle


# ================================================================
# ENTRY POINT
# ================================================================

if __name__ == "__main__":

    preprocessor = (
        ProcessSequencePreprocessor()
    )


    preprocessor.run()