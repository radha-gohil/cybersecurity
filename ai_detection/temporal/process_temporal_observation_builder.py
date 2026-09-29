from __future__ import annotations

import json
import math
import time

from pathlib import Path

from typing import (
    Any,
    Dict,
    List,
    Optional,
)

import joblib
import numpy as np


from ai_detection.behavior.isolation_forest_trainer import (
    load_process_isolation_forest_bundle,
)


# ================================================================
# SENTINEL-X LIVE TEMPORAL OBSERVATION BUILDER V1
#
# Converts one live Phase-2 behavioral observation into exactly the
# same raw 27-dimensional timestep format used to build and train
# the Temporal Transformer.
#
#
# Final timestep:
#
#       19 selected behavior features
#        4 Autoencoder embedding dimensions
#        1 Isolation Forest anomaly score
#        1 Autoencoder anomaly score
#        1 Dual-AI consensus score
#        1 real delta_seconds
#       --------------------------------
#       27 dimensions
#
#
# IMPORTANT:
#
# This builder produces RAW values.
#
# It does NOT normalize them.
#
# ProcessTemporalPredictor later applies the exact StandardScaler
# fitted on the training split.
# ================================================================


# ================================================================
# PATHS
# ================================================================

PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[2]
)


TEMPORAL_SCALER_PATH = (
    PROJECT_ROOT
    / "models"
    / "temporal"
    / "process_temporal_scaler_v1.joblib"
)


# ================================================================
# IDENTITY
# ================================================================

BUILDER_NAME = (
    "sentinelx_process_temporal_observation_builder"
)


BUILDER_VERSION = "v1"


# ================================================================
# EXPECTED SCHEMA
# ================================================================

EXPECTED_BASE_FEATURE_COUNT = 19

EXPECTED_AUTOENCODER_EMBEDDING_DIMENSION = 4

EXPECTED_TEMPORAL_FEATURE_COUNT = 27


# ================================================================
# CONTINUITY
#
# This must match the live temporal buffer.
# ================================================================

MAX_OBSERVATION_GAP_SECONDS = 180.0


# ================================================================
# HELPERS
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


def parse_json(
    value: Any,
):

    if value is None:

        return None


    if isinstance(
        value,
        (
            dict,
            list,
        ),
    ):

        return value


    try:

        return json.loads(
            value
        )

    except (
        TypeError,
        json.JSONDecodeError,
    ):

        return None


# ================================================================
# BUILDER
# ================================================================

class ProcessTemporalObservationBuilder:

    def __init__(
        self,
    ):

        # ========================================================
        # LOAD PHASE-2 FEATURE SCHEMA
        # ========================================================

        isolation_bundle = (
            load_process_isolation_forest_bundle()
        )


        self.base_feature_names = list(

            isolation_bundle[
                "feature_names"
            ]
        )


        if (

            len(
                self.base_feature_names
            )

            != EXPECTED_BASE_FEATURE_COUNT

        ):

            raise RuntimeError(

                "Unexpected behavioral feature count. "
                f"Expected {EXPECTED_BASE_FEATURE_COUNT}, "
                f"received {len(self.base_feature_names)}."
            )


        # ========================================================
        # LOAD TEMPORAL SCALER SCHEMA
        #
        # This validates that live feature ordering exactly matches
        # training-time ordering.
        # ========================================================

        if not TEMPORAL_SCALER_PATH.exists():

            raise FileNotFoundError(

                "Temporal scaler does not exist:\n"
                f"{TEMPORAL_SCALER_PATH}"
            )


        scaler_bundle = (
            joblib.load(
                TEMPORAL_SCALER_PATH
            )
        )


        self.temporal_feature_names = [

            str(
                name
            )

            for name in scaler_bundle[
                "feature_names"
            ]
        ]


        if (

            len(
                self.temporal_feature_names
            )

            != EXPECTED_TEMPORAL_FEATURE_COUNT

        ):

            raise RuntimeError(

                "Temporal scaler schema mismatch. "
                f"Expected {EXPECTED_TEMPORAL_FEATURE_COUNT} "
                f"features, received "
                f"{len(self.temporal_feature_names)}."
            )


        expected_base = (

            self.temporal_feature_names[
                :EXPECTED_BASE_FEATURE_COUNT
            ]
        )


        if (

            expected_base

            != self.base_feature_names

        ):

            raise RuntimeError(

                "Live behavioral feature ordering does not "
                "match the Temporal Transformer training schema."
            )


        self.expected_embedding_names = [

            f"behavior_embedding_{index}"

            for index in range(
                EXPECTED_AUTOENCODER_EMBEDDING_DIMENSION
            )
        ]


        actual_embedding_names = (

            self.temporal_feature_names[
                EXPECTED_BASE_FEATURE_COUNT:
                EXPECTED_BASE_FEATURE_COUNT
                + EXPECTED_AUTOENCODER_EMBEDDING_DIMENSION
            ]
        )


        if (

            actual_embedding_names

            != self.expected_embedding_names

        ):

            raise RuntimeError(

                "Temporal Autoencoder embedding schema mismatch."
            )


        expected_tail = [

            "isolation_forest_score",

            "autoencoder_score",

            "dual_ai_consensus_score",

            "delta_seconds",
        ]


        actual_tail = (

            self.temporal_feature_names[
                -4:
            ]
        )


        if actual_tail != expected_tail:

            raise RuntimeError(

                "Temporal score/delta feature ordering mismatch."
            )


    # ============================================================
    # RECORD → FEATURE DICTIONARY
    # ============================================================

    def extract_feature_dict(
        self,
        record: Any,
    ) -> Dict[str, Any]:

        # ========================================================
        # DICTIONARY INPUT
        # ========================================================

        if isinstance(
            record,
            dict,
        ):

            # ----------------------------------------------------
            # Normal live record representation.
            # ----------------------------------------------------

            if isinstance(
                record.get(
                    "features"
                ),
                dict,
            ):

                return dict(
                    record[
                        "features"
                    ]
                )


            # ----------------------------------------------------
            # SQLite representation.
            # ----------------------------------------------------

            feature_json = (
                record.get(
                    "feature_json"
                )
            )


            parsed = (
                parse_json(
                    feature_json
                )
            )


            if isinstance(
                parsed,
                dict,
            ):

                return parsed


            # ----------------------------------------------------
            # Maybe the dictionary itself already contains all
            # feature names.
            # ----------------------------------------------------

            if all(

                feature_name in record

                for feature_name
                in self.base_feature_names

            ):

                return record


        # ========================================================
        # OBJECT WITH .features
        # ========================================================

        if hasattr(
            record,
            "features",
        ):

            features = (
                getattr(
                    record,
                    "features"
                )
            )


            if isinstance(
                features,
                dict,
            ):

                return dict(
                    features
                )


            if hasattr(
                features,
                "to_dict",
            ):

                converted = (
                    features.to_dict()
                )


                if isinstance(
                    converted,
                    dict,
                ):

                    return converted


        # ========================================================
        # OBJECT WITH .to_dict()
        # ========================================================

        if hasattr(
            record,
            "to_dict",
        ):

            converted = (
                record.to_dict()
            )


            if isinstance(
                converted,
                dict,
            ):

                if isinstance(
                    converted.get(
                        "features"
                    ),
                    dict,
                ):

                    return dict(
                        converted[
                            "features"
                        ]
                    )


                if all(

                    feature_name in converted

                    for feature_name
                    in self.base_feature_names

                ):

                    return converted


        raise ValueError(

            "Unable to extract behavioral features "
            "from feature record."
        )


    # ============================================================
    # BASE FEATURE VECTOR
    # ============================================================

    def build_base_vector(
        self,
        record: Any,
    ) -> List[float]:

        feature_dict = (
            self.extract_feature_dict(
                record
            )
        )


        vector = []


        for feature_name in (
            self.base_feature_names
        ):

            value = safe_float(

                feature_dict.get(
                    feature_name
                )
            )


            if value is None:

                raise ValueError(

                    "Invalid/missing temporal base feature: "
                    f"{feature_name}"
                )


            vector.append(
                value
            )


        return vector


    # ============================================================
    # MODEL SCORE
    # ============================================================

    def extract_anomaly_score(
        self,
        result: Dict[str, Any],
        result_name: str,
    ) -> float:

        if not isinstance(
            result,
            dict,
        ):

            raise ValueError(

                f"{result_name} result is unavailable."
            )


        if (

            result.get(
                "available"
            )
            is False

        ):

            raise ValueError(

                f"{result_name} model is unavailable."
            )


        # --------------------------------------------------------
        # Different Phase-2 components historically used either
        # anomaly_score or anomaly_confidence.
        # Support both.
        # --------------------------------------------------------

        for key in [

            "anomaly_score",

            "anomaly_confidence",

        ]:

            if key in result:

                value = safe_float(

                    result.get(
                        key
                    )
                )


                if value is not None:

                    return value


        raise ValueError(

            f"{result_name} does not contain "
            "a valid anomaly score."
        )


    # ============================================================
    # AUTOENCODER EMBEDDING
    # ============================================================

    def extract_autoencoder_embedding(
        self,
        autoencoder_result: Dict[str, Any],
    ) -> List[float]:

        if not isinstance(
            autoencoder_result,
            dict,
        ):

            raise ValueError(

                "Autoencoder result is unavailable."
            )


        embedding = None


        for key in [

            "behavior_embedding",

            "embedding",

        ]:

            candidate = (
                autoencoder_result.get(
                    key
                )
            )


            if candidate is not None:

                embedding = candidate

                break


        if embedding is None:

            raise ValueError(

                "Autoencoder result does not contain "
                "the learned behavior embedding."
            )


        if isinstance(
            embedding,
            str,
        ):

            embedding = (
                parse_json(
                    embedding
                )
            )


        if not isinstance(
            embedding,
            (
                list,
                tuple,
                np.ndarray,
            ),
        ):

            raise ValueError(

                "Autoencoder embedding has invalid format."
            )


        array = np.asarray(

            embedding,

            dtype=np.float64,
        )


        if array.shape != (

            EXPECTED_AUTOENCODER_EMBEDDING_DIMENSION,

        ):

            raise ValueError(

                "Autoencoder embedding dimension mismatch. "
                f"Expected "
                f"{EXPECTED_AUTOENCODER_EMBEDDING_DIMENSION}, "
                f"received {array.shape}."
            )


        if not np.all(
            np.isfinite(
                array
            )
        ):

            raise ValueError(

                "Autoencoder embedding contains "
                "NaN or infinity."
            )


        return (
            array
            .astype(
                np.float64
            )
            .tolist()
        )


    # ============================================================
    # DUAL-AI CONSENSUS SCORE
    # ============================================================

    def extract_consensus_score(
        self,
        consensus_result: Dict[str, Any],
    ) -> float:

        if not isinstance(
            consensus_result,
            dict,
        ):

            raise ValueError(

                "Dual-AI consensus result is unavailable."
            )


        for key in [

            "consensus_score",

            "anomaly_score",

            "anomaly_confidence",

        ]:

            if key in consensus_result:

                score = safe_float(

                    consensus_result.get(
                        key
                    )
                )


                if score is not None:

                    return score


        raise ValueError(

            "Dual-AI consensus result contains "
            "no valid score."
        )


    # ============================================================
    # DELTA
    # ============================================================

    def calculate_delta_seconds(
        self,
        *,
        timestamp: float,
        previous_timestamp: Optional[float],
    ) -> Dict[str, Any]:

        if previous_timestamp is None:

            return {
                "delta_seconds":
                    0.0,

                "continuity_reset":
                    False,

                "reason":
                    "first_observation",
            }


        delta = (

            float(
                timestamp
            )

            - float(
                previous_timestamp
            )
        )


        # --------------------------------------------------------
        # The temporal buffer will also reset on this condition.
        #
        # For the first observation after a broken sequence, use
        # delta=0 so the Transformer does not receive an artificial
        # giant time-gap value that was not part of its continuous
        # training windows.
        # --------------------------------------------------------

        if (

            delta <= 0.0

            or

            delta
            > MAX_OBSERVATION_GAP_SECONDS

        ):

            return {
                "delta_seconds":
                    0.0,

                "continuity_reset":
                    True,

                "reason":
                    (
                        "non_monotonic_timestamp"

                        if delta <= 0.0

                        else "gap_exceeded"
                    ),

                "raw_delta_seconds":
                    delta,
            }


        return {
            "delta_seconds":
                float(
                    delta
                ),

            "continuity_reset":
                False,

            "reason":
                "continuous",

            "raw_delta_seconds":
                float(
                    delta
                ),
        }


    # ============================================================
    # BUILD LIVE TEMPORAL OBSERVATION
    # ============================================================

    def build(
        self,
        *,
        feature_record: Any,
        isolation_result: Dict[str, Any],
        autoencoder_result: Dict[str, Any],
        consensus_result: Dict[str, Any],
        timestamp: Optional[float] = None,
        previous_timestamp: Optional[float] = None,
    ) -> Dict[str, Any]:

        observation_timestamp = (

            float(
                timestamp
            )

            if timestamp is not None

            else time.time()
        )


        if not math.isfinite(
            observation_timestamp
        ):

            raise ValueError(

                "Observation timestamp must be finite."
            )


        # ========================================================
        # 19 BEHAVIOR FEATURES
        # ========================================================

        base_vector = (
            self.build_base_vector(
                feature_record
            )
        )


        # ========================================================
        # 4D SELF-SUPERVISED EMBEDDING
        # ========================================================

        embedding = (
            self.extract_autoencoder_embedding(
                autoencoder_result
            )
        )


        # ========================================================
        # MODEL SCORES
        # ========================================================

        isolation_score = (
            self.extract_anomaly_score(

                isolation_result,

                "Isolation Forest",
            )
        )


        autoencoder_score = (
            self.extract_anomaly_score(

                autoencoder_result,

                "Autoencoder",
            )
        )


        consensus_score = (
            self.extract_consensus_score(
                consensus_result
            )
        )


        # ========================================================
        # REAL TEMPORAL DELTA
        # ========================================================

        delta_info = (
            self.calculate_delta_seconds(

                timestamp=
                    observation_timestamp,

                previous_timestamp=
                    previous_timestamp,
            )
        )


        # ========================================================
        # FINAL 27D VECTOR
        # ========================================================

        vector = (

            base_vector

            + embedding

            + [

                isolation_score,

                autoencoder_score,

                consensus_score,

                delta_info[
                    "delta_seconds"
                ],
            ]
        )


        array = np.asarray(

            vector,

            dtype=np.float64,
        )


        if array.shape != (

            EXPECTED_TEMPORAL_FEATURE_COUNT,

        ):

            raise RuntimeError(

                "Live temporal observation dimension mismatch. "
                f"Expected "
                f"{EXPECTED_TEMPORAL_FEATURE_COUNT}, "
                f"received {array.shape}."
            )


        if not np.all(
            np.isfinite(
                array
            )
        ):

            raise RuntimeError(

                "Live temporal observation contains "
                "NaN or infinity."
            )


        feature_map = {

            feature_name:
                float(
                    value
                )

            for (
                feature_name,
                value,
            ) in zip(

                self.temporal_feature_names,

                array.tolist(),
            )
        }


        return {
            "builder_name":
                BUILDER_NAME,

            "builder_version":
                BUILDER_VERSION,

            "timestamp":
                observation_timestamp,

            "feature_count":
                EXPECTED_TEMPORAL_FEATURE_COUNT,

            "feature_names":
                list(
                    self.temporal_feature_names
                ),

            "vector":
                array.tolist(),

            "feature_map":
                feature_map,

            "base_feature_count":
                len(
                    base_vector
                ),

            "embedding_dimension":
                len(
                    embedding
                ),

            "isolation_forest_score":
                isolation_score,

            "autoencoder_score":
                autoencoder_score,

            "dual_ai_consensus_score":
                consensus_score,

            "delta_seconds":
                delta_info[
                    "delta_seconds"
                ],

            "continuity_reset":
                delta_info[
                    "continuity_reset"
                ],

            "continuity_reason":
                delta_info[
                    "reason"
                ],

            "raw_delta_seconds":
                delta_info.get(
                    "raw_delta_seconds"
                ),
        }


# ================================================================
# SHARED BUILDER
# ================================================================

shared_process_temporal_observation_builder = (
    ProcessTemporalObservationBuilder()
)