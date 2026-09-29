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
    List,
)

import joblib
import numpy as np

from sklearn.preprocessing import (
    StandardScaler,
)


# ================================================================
# SENTINEL-X
# TEMPORAL DATASET V3
#
# Purpose:
#
# Remove the non-stationary absolute feature:
#
#       process_age_seconds
#
# from the Temporal Transformer input.
#
#
# Why?
#
# Live diagnostic:
#
#       process_age_seconds
#       Shift Z ≈ 51.55
#       100% live values outside training P05-P95
#
#
# Absolute process age is unsuitable for long-term temporal
# reconstruction because it grows continuously with uptime.
#
# It is retained in:
#
#       Isolation Forest
#       Autoencoder feature extraction
#       snapshot behavior analysis
#
# but excluded from the Temporal Transformer.
#
#
# Temporal schema:
#
#       OLD = 27 features
#       NEW = 26 features
#
#
# The script:
#
#       1. Loads dataset v2
#       2. Removes process_age_seconds
#       3. Performs session-aware split
#       4. Fits scaler on TRAIN ONLY
#       5. Normalizes train/validation/test
#       6. Verifies no session leakage
#       7. Saves versioned artifacts
# ================================================================


# ================================================================
# PATHS
# ================================================================

PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[2]
)


SOURCE_DATASET_PATH = (
    PROJECT_ROOT
    / "data"
    / "temporal"
    / "process_sequence_dataset_v2.npz"
)


OUTPUT_RAW_DATASET_PATH = (
    PROJECT_ROOT
    / "data"
    / "temporal"
    / "process_sequence_dataset_v3.npz"
)


OUTPUT_SPLIT_DATASET_PATH = (
    PROJECT_ROOT
    / "data"
    / "temporal"
    / "process_sequence_splits_v2.npz"
)


MODEL_DIRECTORY = (
    PROJECT_ROOT
    / "models"
    / "temporal"
)


SCALER_PATH = (
    MODEL_DIRECTORY
    / "process_temporal_scaler_v2.joblib"
)


METADATA_PATH = (
    PROJECT_ROOT
    / "data"
    / "temporal"
    / "process_sequence_dataset_v3_metadata.json"
)


# ================================================================
# VERSION
# ================================================================

DATASET_VERSION = "v3"

SCHEMA_VERSION = (
    "process_temporal_schema_v2"
)

SCALER_VERSION = "v2"


# ================================================================
# FEATURE POLICY
# ================================================================

REMOVED_FEATURE_NAME = (
    "process_age_seconds"
)


EXPECTED_SOURCE_FEATURE_COUNT = 27

EXPECTED_OUTPUT_FEATURE_COUNT = 26

EXPECTED_SEQUENCE_LENGTH = 8


# ================================================================
# SPLIT CONFIGURATION
# ================================================================

TRAIN_RATIO = 0.70

VALIDATION_RATIO = 0.15

TEST_RATIO = 0.15

RANDOM_STATE = 42


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


def python_value(
    value,
):

    if isinstance(
        value,
        np.generic,
    ):

        return value.item()


    return value


# ================================================================
# LOAD SOURCE
# ================================================================

def load_source_dataset():

    if not SOURCE_DATASET_PATH.exists():

        raise FileNotFoundError(

            "Source temporal dataset does not exist:\n"
            f"{SOURCE_DATASET_PATH}"
        )


    data = np.load(
        SOURCE_DATASET_PATH,
        allow_pickle=False,
    )


    required = {
        "X",
        "temporal_feature_names",
        "session_ids",
    }


    missing = (
        required
        - set(
            data.files
        )
    )


    if missing:

        raise RuntimeError(

            "Source dataset is missing required arrays: "
            f"{sorted(missing)}"
        )


    X = np.asarray(

        data[
            "X"
        ],

        dtype=np.float64,
    )


    feature_names = [

        str(
            value
        )

        for value in data[
            "temporal_feature_names"
        ].tolist()
    ]


    session_ids = np.asarray(

        data[
            "session_ids"
        ]
    )


    if X.ndim != 3:

        raise RuntimeError(

            "Temporal source X must have shape "
            "(windows, sequence, features). "
            f"Received {X.shape}."
        )


    if X.shape[
        1
    ] != EXPECTED_SEQUENCE_LENGTH:

        raise RuntimeError(

            "Unexpected sequence length: "
            f"{X.shape[1]}"
        )


    if X.shape[
        2
    ] != EXPECTED_SOURCE_FEATURE_COUNT:

        raise RuntimeError(

            "Unexpected source feature count: "
            f"{X.shape[2]}"
        )


    if len(
        feature_names
    ) != EXPECTED_SOURCE_FEATURE_COUNT:

        raise RuntimeError(

            "Feature-name count does not match "
            "source feature dimension."
        )


    if len(
        session_ids
    ) != len(
        X
    ):

        raise RuntimeError(

            "session_ids length does not match "
            "window count."
        )


    if not np.all(
        np.isfinite(
            X
        )
    ):

        raise RuntimeError(

            "Source temporal dataset contains "
            "NaN or infinity."
        )


    return (
        data,
        X,
        feature_names,
        session_ids,
    )


# ================================================================
# REMOVE PROCESS AGE
# ================================================================

def remove_nonstationary_feature(
    X: np.ndarray,
    feature_names: List[str],
):

    if (

        REMOVED_FEATURE_NAME

        not in feature_names

    ):

        raise RuntimeError(

            f"Required feature "
            f"'{REMOVED_FEATURE_NAME}' "
            "was not found."
        )


    removed_index = (
        feature_names.index(
            REMOVED_FEATURE_NAME
        )
    )


    keep_indices = [

        index

        for index in range(
            len(
                feature_names
            )
        )

        if index != removed_index
    ]


    corrected_X = (
        X[
            :,
            :,
            keep_indices
        ]
    )


    corrected_feature_names = [

        feature_names[
            index
        ]

        for index
        in keep_indices
    ]


    if corrected_X.shape[
        2
    ] != EXPECTED_OUTPUT_FEATURE_COUNT:

        raise RuntimeError(

            "Corrected temporal feature count mismatch."
        )


    if (

        REMOVED_FEATURE_NAME

        in corrected_feature_names

    ):

        raise RuntimeError(

            "process_age_seconds was not removed."
        )


    return (
        corrected_X,
        corrected_feature_names,
        removed_index,
    )


# ================================================================
# SESSION-AWARE SPLIT
# ================================================================

def split_sessions(
    session_ids: np.ndarray,
):

    unique_sessions = np.unique(
        session_ids
    )


    session_count = len(
        unique_sessions
    )


    if session_count < 3:

        raise RuntimeError(

            "At least 3 unique sessions are required "
            "for train/validation/test splitting."
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


    train_count = int(

        round(
            session_count
            * TRAIN_RATIO
        )
    )


    validation_count = int(

        round(
            session_count
            * VALIDATION_RATIO
        )
    )


    # ------------------------------------------------------------
    # Guarantee every split gets at least one session.
    # ------------------------------------------------------------

    train_count = max(
        1,
        train_count,
    )


    validation_count = max(
        1,
        validation_count,
    )


    if (

        train_count
        + validation_count

        >= session_count

    ):

        train_count = max(
            1,
            session_count - 2,
        )


        validation_count = 1


    test_count = (

        session_count

        - train_count

        - validation_count
    )


    if test_count < 1:

        raise RuntimeError(

            "Unable to allocate test sessions."
        )


    train_sessions = (
        shuffled[
            :train_count
        ]
    )


    validation_sessions = (
        shuffled[
            train_count:
            train_count
            + validation_count
        ]
    )


    test_sessions = (
        shuffled[
            train_count
            + validation_count:
        ]
    )


    return (
        train_sessions,
        validation_sessions,
        test_sessions,
    )


# ================================================================
# MASKS
# ================================================================

def build_split_masks(
    session_ids,
    train_sessions,
    validation_sessions,
    test_sessions,
):

    train_mask = np.isin(

        session_ids,
        train_sessions,
    )


    validation_mask = np.isin(

        session_ids,
        validation_sessions,
    )


    test_mask = np.isin(

        session_ids,
        test_sessions,
    )


    if not np.all(

        train_mask

        | validation_mask

        | test_mask

    ):

        raise RuntimeError(

            "Some windows were not assigned "
            "to a dataset split."
        )


    if np.any(

        train_mask
        & validation_mask

    ):

        raise RuntimeError(

            "Train/validation leakage detected."
        )


    if np.any(

        train_mask
        & test_mask

    ):

        raise RuntimeError(

            "Train/test leakage detected."
        )


    if np.any(

        validation_mask
        & test_mask

    ):

        raise RuntimeError(

            "Validation/test leakage detected."
        )


    return (
        train_mask,
        validation_mask,
        test_mask,
    )


# ================================================================
# FIT SCALER
# ================================================================

def fit_scaler(
    X_train_raw,
):

    flattened = (
        X_train_raw.reshape(

            -1,

            X_train_raw.shape[
                -1
            ],
        )
    )


    scaler = (
        StandardScaler()
    )


    scaler.fit(
        flattened
    )


    return scaler


# ================================================================
# TRANSFORM
# ================================================================

def transform_sequences(
    scaler,
    X,
):

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
        scaler.transform(
            flattened
        )
    )


    transformed = (
        transformed.reshape(
            original_shape
        )
    )


    transformed = np.asarray(

        transformed,

        dtype=np.float32,
    )


    if not np.all(
        np.isfinite(
            transformed
        )
    ):

        raise RuntimeError(

            "Scaler produced NaN or infinity."
        )


    return transformed


# ================================================================
# SAVE RAW CORRECTED DATASET
# ================================================================

def save_corrected_raw_dataset(
    source_data,
    corrected_X,
    corrected_feature_names,
):

    output = {}


    for name in source_data.files:

        if name == "X":

            output[
                "X"
            ] = corrected_X.astype(
                np.float32
            )


        elif name == "temporal_feature_names":

            output[
                "temporal_feature_names"
            ] = np.asarray(
                corrected_feature_names
            )


        else:

            output[
                name
            ] = np.asarray(
                source_data[
                    name
                ]
            )


    np.savez_compressed(

        OUTPUT_RAW_DATASET_PATH,

        **output,
    )


# ================================================================
# SAVE SPLIT DATASET
# ================================================================

def save_split_dataset(
    *,
    X_train,
    X_validation,
    X_test,
    X_train_raw,
    X_validation_raw,
    X_test_raw,
    feature_names,
    session_ids,
    train_mask,
    validation_mask,
    test_mask,
):

    np.savez_compressed(

        OUTPUT_SPLIT_DATASET_PATH,

        X_train=
            X_train,

        X_validation=
            X_validation,

        X_test=
            X_test,

        X_train_raw=
            X_train_raw.astype(
                np.float32
            ),

        X_validation_raw=
            X_validation_raw.astype(
                np.float32
            ),

        X_test_raw=
            X_test_raw.astype(
                np.float32
            ),

        temporal_feature_names=
            np.asarray(
                feature_names
            ),

        train_session_ids=
            session_ids[
                train_mask
            ],

        validation_session_ids=
            session_ids[
                validation_mask
            ],

        test_session_ids=
            session_ids[
                test_mask
            ],
    )


# ================================================================
# MAIN
# ================================================================

def main():

    OUTPUT_RAW_DATASET_PATH.parent.mkdir(

        parents=True,

        exist_ok=True,
    )


    MODEL_DIRECTORY.mkdir(

        parents=True,

        exist_ok=True,
    )


    print()

    print(
        "=" * 92
    )

    print(
        "SENTINEL-X TEMPORAL DATASET V3 — NON-STATIONARY FEATURE CORRECTION"
    )

    print(
        "=" * 92
    )


    # ============================================================
    # LOAD
    # ============================================================

    print()

    print(
        "[1/7] Loading temporal dataset v2..."
    )


    (
        source_data,
        X,
        feature_names,
        session_ids,

    ) = load_source_dataset()


    print(
        "Source shape:",
        X.shape,
    )


    print(
        "Source features:",
        len(
            feature_names
        ),
    )


    # ============================================================
    # REMOVE AGE
    # ============================================================

    print()

    print(
        "[2/7] Removing process_age_seconds..."
    )


    (
        corrected_X,
        corrected_feature_names,
        removed_index,

    ) = remove_nonstationary_feature(

        X,
        feature_names,
    )


    print(
        "Removed feature:",
        REMOVED_FEATURE_NAME,
    )


    print(
        "Removed index:",
        removed_index,
    )


    print(
        "Corrected shape:",
        corrected_X.shape,
    )


    print(
        "Corrected feature count:",
        len(
            corrected_feature_names
        ),
    )


    # ============================================================
    # SPLIT
    # ============================================================

    print()

    print(
        "[3/7] Performing session-aware split..."
    )


    (
        train_sessions,
        validation_sessions,
        test_sessions,

    ) = split_sessions(
        session_ids
    )


    (
        train_mask,
        validation_mask,
        test_mask,

    ) = build_split_masks(

        session_ids=
            session_ids,

        train_sessions=
            train_sessions,

        validation_sessions=
            validation_sessions,

        test_sessions=
            test_sessions,
    )


    X_train_raw = (
        corrected_X[
            train_mask
        ]
    )


    X_validation_raw = (
        corrected_X[
            validation_mask
        ]
    )


    X_test_raw = (
        corrected_X[
            test_mask
        ]
    )


    print(
        "Train windows:",
        len(
            X_train_raw
        ),
    )


    print(
        "Validation windows:",
        len(
            X_validation_raw
        ),
    )


    print(
        "Test windows:",
        len(
            X_test_raw
        ),
    )


    print(
        "Train sessions:",
        len(
            train_sessions
        ),
    )


    print(
        "Validation sessions:",
        len(
            validation_sessions
        ),
    )


    print(
        "Test sessions:",
        len(
            test_sessions
        ),
    )


    # ============================================================
    # FIT SCALER
    # ============================================================

    print()

    print(
        "[4/7] Fitting StandardScaler on TRAIN only..."
    )


    scaler = (
        fit_scaler(
            X_train_raw
        )
    )


    scaler_bundle = {
        "scaler":
            scaler,

        "scaler_version":
            SCALER_VERSION,

        "schema_version":
            SCHEMA_VERSION,

        "sequence_length":
            EXPECTED_SEQUENCE_LENGTH,

        "feature_count":
            EXPECTED_OUTPUT_FEATURE_COUNT,

        "feature_names":
            list(
                corrected_feature_names
            ),

        "removed_feature":
            REMOVED_FEATURE_NAME,

        "trained_on":
            "training_split_only",

        "created_at":
            now_iso(),
    }


    joblib.dump(

        scaler_bundle,

        SCALER_PATH,
    )


    # ============================================================
    # NORMALIZE
    # ============================================================

    print()

    print(
        "[5/7] Normalizing train/validation/test..."
    )


    X_train = (
        transform_sequences(

            scaler,
            X_train_raw,
        )
    )


    X_validation = (
        transform_sequences(

            scaler,
            X_validation_raw,
        )
    )


    X_test = (
        transform_sequences(

            scaler,
            X_test_raw,
        )
    )


    train_flat = (
        X_train.reshape(
            -1,
            EXPECTED_OUTPUT_FEATURE_COUNT,
        )
    )


    print(
        "Normalized train mean:",
        round(
            float(
                np.mean(
                    train_flat
                )
            ),
            6,
        ),
    )


    print(
        "Normalized train std:",
        round(
            float(
                np.std(
                    train_flat
                )
            ),
            6,
        ),
    )


    # ============================================================
    # SAVE
    # ============================================================

    print()

    print(
        "[6/7] Saving corrected datasets..."
    )


    save_corrected_raw_dataset(

        source_data=
            source_data,

        corrected_X=
            corrected_X,

        corrected_feature_names=
            corrected_feature_names,
    )


    save_split_dataset(

        X_train=
            X_train,

        X_validation=
            X_validation,

        X_test=
            X_test,

        X_train_raw=
            X_train_raw,

        X_validation_raw=
            X_validation_raw,

        X_test_raw=
            X_test_raw,

        feature_names=
            corrected_feature_names,

        session_ids=
            session_ids,

        train_mask=
            train_mask,

        validation_mask=
            validation_mask,

        test_mask=
            test_mask,
    )


    # ============================================================
    # METADATA
    # ============================================================

    print()

    print(
        "[7/7] Writing metadata..."
    )


    metadata: Dict[str, Any] = {
        "dataset_version":
            DATASET_VERSION,

        "schema_version":
            SCHEMA_VERSION,

        "created_at":
            now_iso(),

        "source_dataset":
            str(
                SOURCE_DATASET_PATH
            ),

        "output_dataset":
            str(
                OUTPUT_RAW_DATASET_PATH
            ),

        "output_split_dataset":
            str(
                OUTPUT_SPLIT_DATASET_PATH
            ),

        "scaler":
            str(
                SCALER_PATH
            ),

        "source_shape":
            list(
                X.shape
            ),

        "corrected_shape":
            list(
                corrected_X.shape
            ),

        "source_feature_count":
            EXPECTED_SOURCE_FEATURE_COUNT,

        "corrected_feature_count":
            EXPECTED_OUTPUT_FEATURE_COUNT,

        "removed_feature": {
            "name":
                REMOVED_FEATURE_NAME,

            "source_index":
                removed_index,

            "reason":
                (
                    "Absolute process age showed severe "
                    "live/training distribution shift and is "
                    "non-stationary across endpoint uptime."
                ),
        },

        "feature_names":
            corrected_feature_names,

        "split": {
            "random_state":
                RANDOM_STATE,

            "train_ratio":
                TRAIN_RATIO,

            "validation_ratio":
                VALIDATION_RATIO,

            "test_ratio":
                TEST_RATIO,

            "train_windows":
                int(
                    len(
                        X_train
                    )
                ),

            "validation_windows":
                int(
                    len(
                        X_validation
                    )
                ),

            "test_windows":
                int(
                    len(
                        X_test
                    )
                ),

            "train_sessions":
                int(
                    len(
                        train_sessions
                    )
                ),

            "validation_sessions":
                int(
                    len(
                        validation_sessions
                    )
                ),

            "test_sessions":
                int(
                    len(
                        test_sessions
                    )
                ),
        },

        "leakage_policy":
            (
                "Complete sessions are assigned to exactly "
                "one train/validation/test split."
            ),

        "scientific_note":
            (
                "process_age_seconds remains available to snapshot "
                "behavioral models but is intentionally excluded "
                "from the Temporal Transformer because absolute "
                "process age is non-stationary and redundant with "
                "sequence timing information."
            ),
    }


    with open(

        METADATA_PATH,

        "w",

        encoding="utf-8",

    ) as file:

        json.dump(

            metadata,

            file,

            indent=4,
        )


    # ============================================================
    # FINAL VERIFICATION
    # ============================================================

    train_set = set(
        python_value(
            value
        )

        for value
        in train_sessions
    )


    validation_set = set(
        python_value(
            value
        )

        for value
        in validation_sessions
    )


    test_set = set(
        python_value(
            value
        )

        for value
        in test_sessions
    )


    leakage = bool(

        train_set
        & validation_set

        or

        train_set
        & test_set

        or

        validation_set
        & test_set
    )


    print()

    print(
        "=" * 92
    )

    print(
        "TEMPORAL DATASET V3 BUILD COMPLETE"
    )

    print(
        "=" * 92
    )


    print()

    print(
        "Input:"
    )

    print(
        SOURCE_DATASET_PATH
    )


    print()

    print(
        "Corrected raw dataset:"
    )

    print(
        OUTPUT_RAW_DATASET_PATH
    )


    print()

    print(
        "Normalized splits:"
    )

    print(
        OUTPUT_SPLIT_DATASET_PATH
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
        "Sequence shape:"
    )

    print(
        (
            "(*, "
            f"{EXPECTED_SEQUENCE_LENGTH}, "
            f"{EXPECTED_OUTPUT_FEATURE_COUNT})"
        )
    )


    print()

    print(
        "Removed:"
    )

    print(
        REMOVED_FEATURE_NAME
    )


    print()

    print(
        "Session leakage:",
        (
            "DETECTED"

            if leakage

            else "NONE"
        ),
    )


    if leakage:

        raise RuntimeError(

            "Session leakage detected."
        )


    print()

    print(
        "TEMPORAL PREPROCESSING V2: PASS"
    )


if __name__ == "__main__":

    main()