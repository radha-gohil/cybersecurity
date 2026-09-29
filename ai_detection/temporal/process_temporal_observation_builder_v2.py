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
# SENTINEL-X TEMPORAL OBSERVATION BUILDER V2
#
# Output:
#
#       18 temporal-safe behavioral features
#        4 AE embedding dimensions
#        1 Isolation Forest score
#        1 Autoencoder score
#        1 Dual-AI consensus score
#        1 delta_seconds
#       --------------------------------
#       26 total
#
#
# process_age_seconds is deliberately excluded ONLY from the
# temporal representation.
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
    / "process_temporal_scaler_v2.joblib"
)


BUILDER_NAME = (
    "sentinelx_process_temporal_observation_builder"
)


BUILDER_VERSION = "v2"


SCHEMA_VERSION = (
    "process_temporal_schema_v2"
)


REMOVED_FEATURE = (
    "process_age_seconds"
)


EXPECTED_ORIGINAL_BASE_FEATURE_COUNT = 19

EXPECTED_TEMPORAL_BASE_FEATURE_COUNT = 18

EXPECTED_EMBEDDING_DIMENSION = 4

EXPECTED_TEMPORAL_FEATURE_COUNT = 26


MAX_OBSERVATION_GAP_SECONDS = 180.0


# ================================================================
# HELPERS
# ================================================================

def safe_float(
    value,
) -> Optional[float]:

    try:

        value = float(
            value
        )


    except (
        TypeError,
        ValueError,
    ):

        return None


    if not math.isfinite(
        value
    ):

        return None


    return value


def parse_json(
    value,
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

class ProcessTemporalObservationBuilderV2:

    def __init__(
        self,
    ):

        isolation_bundle = (
            load_process_isolation_forest_bundle()
        )


        original_feature_names = list(

            isolation_bundle[
                "feature_names"
            ]
        )


        if (

            len(
                original_feature_names
            )

            != EXPECTED_ORIGINAL_BASE_FEATURE_COUNT

        ):

            raise RuntimeError(

                "Isolation Forest feature-schema mismatch."
            )


        if REMOVED_FEATURE not in original_feature_names:

            raise RuntimeError(

                "process_age_seconds was not found "
                "in the snapshot feature schema."
            )


        # ========================================================
        # TEMPORAL BASE FEATURES
        # ========================================================

        self.base_feature_names = [

            name

            for name
            in original_feature_names

            if name != REMOVED_FEATURE
        ]


        if (

            len(
                self.base_feature_names
            )

            != EXPECTED_TEMPORAL_BASE_FEATURE_COUNT

        ):

            raise RuntimeError(

                "Corrected temporal base-feature "
                "count must equal 18."
            )


        # ========================================================
        # LOAD SCALER SCHEMA
        # ========================================================

        if not TEMPORAL_SCALER_PATH.exists():

            raise FileNotFoundError(

                "Temporal scaler v2 missing:\n"
                f"{TEMPORAL_SCALER_PATH}"
            )


        scaler_bundle = (
            joblib.load(
                TEMPORAL_SCALER_PATH
            )
        )


        if (

            scaler_bundle.get(
                "schema_version"
            )

            != SCHEMA_VERSION

        ):

            raise RuntimeError(

                "Temporal scaler v2 schema mismatch."
            )


        self.temporal_feature_names = [

            str(
                name
            )

            for name
            in scaler_bundle[
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

                "Temporal v2 feature count must be 26."
            )


        if (

            REMOVED_FEATURE

            in self.temporal_feature_names

        ):

            raise RuntimeError(

                "process_age_seconds unexpectedly exists "
                "in temporal v2 schema."
            )


        expected_prefix = (
            self.temporal_feature_names[
                :EXPECTED_TEMPORAL_BASE_FEATURE_COUNT
            ]
        )


        if expected_prefix != self.base_feature_names:

            raise RuntimeError(

                "Live temporal v2 base-feature ordering "
                "does not match training schema."
            )


        embedding_names = [

            f"behavior_embedding_{index}"

            for index in range(
                EXPECTED_EMBEDDING_DIMENSION
            )
        ]


        actual_embeddings = (
            self.temporal_feature_names[
                EXPECTED_TEMPORAL_BASE_FEATURE_COUNT:
                EXPECTED_TEMPORAL_BASE_FEATURE_COUNT
                + EXPECTED_EMBEDDING_DIMENSION
            ]
        )


        if actual_embeddings != embedding_names:

            raise RuntimeError(

                "Temporal v2 embedding schema mismatch."
            )


        expected_tail = [

            "isolation_forest_score",

            "autoencoder_score",

            "dual_ai_consensus_score",

            "delta_seconds",
        ]


        if (

            self.temporal_feature_names[
                -4:
            ]

            != expected_tail

        ):

            raise RuntimeError(

                "Temporal v2 tail schema mismatch."
            )


    # ============================================================
    # FEATURE DICTIONARY
    # ============================================================

    def extract_feature_dict(
        self,
        record,
    ) -> Dict[str, Any]:

        if isinstance(
            record,
            dict,
        ):

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


            parsed = parse_json(

                record.get(
                    "feature_json"
                )
            )


            if isinstance(
                parsed,
                dict,
            ):

                return parsed


            if all(

                name in record

                for name
                in self.base_feature_names

            ):

                return record


        if hasattr(
            record,
            "features",
        ):

            features = getattr(
                record,
                "features"
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

                result = (
                    features.to_dict()
                )


                if isinstance(
                    result,
                    dict,
                ):

                    return result


        if hasattr(
            record,
            "to_dict",
        ):

            result = (
                record.to_dict()
            )


            if isinstance(
                result,
                dict,
            ):

                if isinstance(
                    result.get(
                        "features"
                    ),
                    dict,
                ):

                    return dict(
                        result[
                            "features"
                        ]
                    )


                return result


        raise ValueError(

            "Unable to extract behavioral "
            "feature dictionary."
        )


    # ============================================================
    # BASE VECTOR
    # ============================================================

    def build_base_vector(
        self,
        record,
    ) -> List[float]:

        features = (
            self.extract_feature_dict(
                record
            )
        )


        vector = []


        for name in (
            self.base_feature_names
        ):

            value = safe_float(

                features.get(
                    name
                )
            )


            if value is None:

                raise ValueError(

                    "Missing/invalid temporal v2 feature: "
                    f"{name}"
                )


            vector.append(
                value
            )


        return vector


    # ============================================================
    # SCORE
    # ============================================================

    def extract_score(
        self,
        result,
        name,
    ):

        if not isinstance(
            result,
            dict,
        ):

            raise ValueError(
                f"{name} result unavailable."
            )


        if result.get(
            "available"
        ) is False:

            raise ValueError(
                f"{name} model unavailable."
            )


        for key in [

            "anomaly_score",

            "anomaly_confidence",

        ]:

            value = safe_float(
                result.get(
                    key
                )
            )


            if value is not None:

                return value


        raise ValueError(

            f"{name} does not contain "
            "a valid anomaly score."
        )


    # ============================================================
    # EMBEDDING
    # ============================================================

    def extract_embedding(
        self,
        autoencoder_result,
    ):

        embedding = (

            autoencoder_result.get(
                "behavior_embedding"
            )

            or

            autoencoder_result.get(
                "embedding"
            )
        )


        if isinstance(
            embedding,
            str,
        ):

            embedding = parse_json(
                embedding
            )


        array = np.asarray(

            embedding,

            dtype=np.float64,
        )


        if array.shape != (
            EXPECTED_EMBEDDING_DIMENSION,
        ):

            raise ValueError(

                "Autoencoder embedding must contain "
                "exactly 4 values."
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


        return array.tolist()


    # ============================================================
    # CONSENSUS SCORE
    # ============================================================

    def extract_consensus_score(
        self,
        result,
    ):

        if not isinstance(
            result,
            dict,
        ):

            raise ValueError(

                "Dual-AI consensus result unavailable."
            )


        for key in [

            "consensus_score",

            "anomaly_score",

            "anomaly_confidence",

        ]:

            value = safe_float(
                result.get(
                    key
                )
            )


            if value is not None:

                return value


        raise ValueError(

            "Dual-AI consensus score unavailable."
        )


    # ============================================================
    # DELTA
    # ============================================================

    def calculate_delta_seconds(
        self,
        *,
        timestamp,
        previous_timestamp,
    ):

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

                        if delta <= 0

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
    # BUILD
    # ============================================================

    def build(
        self,
        *,
        feature_record,
        isolation_result,
        autoencoder_result,
        consensus_result,
        timestamp=None,
        previous_timestamp=None,
    ):

        observation_timestamp = (

            float(
                timestamp
            )

            if timestamp is not None

            else time.time()
        )


        base_vector = (
            self.build_base_vector(
                feature_record
            )
        )


        embedding = (
            self.extract_embedding(
                autoencoder_result
            )
        )


        isolation_score = (
            self.extract_score(

                isolation_result,

                "Isolation Forest",
            )
        )


        autoencoder_score = (
            self.extract_score(

                autoencoder_result,

                "Autoencoder",
            )
        )


        consensus_score = (
            self.extract_consensus_score(
                consensus_result
            )
        )


        delta = (
            self.calculate_delta_seconds(

                timestamp=
                    observation_timestamp,

                previous_timestamp=
                    previous_timestamp,
            )
        )


        vector = (

            base_vector

            + embedding

            + [

                isolation_score,

                autoencoder_score,

                consensus_score,

                delta[
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

                "Temporal v2 observation must "
                "contain exactly 26 features."
            )


        if not np.all(
            np.isfinite(
                array
            )
        ):

            raise RuntimeError(

                "Temporal v2 observation contains "
                "NaN or infinity."
            )


        feature_map = {

            name:
                float(
                    value
                )

            for (
                name,
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

            "schema_version":
                SCHEMA_VERSION,

            "timestamp":
                observation_timestamp,

            "feature_count":
                EXPECTED_TEMPORAL_FEATURE_COUNT,

            "removed_feature":
                REMOVED_FEATURE,

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
                delta[
                    "delta_seconds"
                ],

            "continuity_reset":
                delta[
                    "continuity_reset"
                ],

            "continuity_reason":
                delta[
                    "reason"
                ],

            "raw_delta_seconds":
                delta.get(
                    "raw_delta_seconds"
                ),
        }


# ================================================================
# SHARED INSTANCE
# ================================================================

shared_process_temporal_observation_builder_v2 = (
    ProcessTemporalObservationBuilderV2()
)