from __future__ import annotations

import hashlib
import json
import math

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
)

import numpy as np


from ai_detection.behavior.behavior_feature_store import (
    get_connection,
)

from ai_detection.behavior.dual_ai_agreement import (
    DualAIAgreementEngine,
)

from ai_detection.behavior.isolation_forest_trainer import (
    load_process_isolation_forest_bundle,
)

from ai_detection.behavior.process_autoencoder_predictor import (
    ProcessAutoencoderPredictor,
)


# ================================================================
# SENTINEL-X TEMPORAL PROCESS SEQUENCE DATASET BUILDER
#
# Phase 3 foundation.
#
# Converts independent endpoint behavior observations:
#
#       sample t1
#       sample t2
#       sample t3
#       ...
#
# into chronological fixed-length windows:
#
#       [t1, t2, t3, ... t8]
#
#
# Each timestep contains:
#
#   - selected process behavior features
#   - healthy Autoencoder v2 embedding
#   - Isolation Forest confidence
#   - Autoencoder confidence
#   - dual-AI consensus confidence
#   - time delta
#
#
# IMPORTANT:
#
# This builder does NOT label data as malicious.
#
# It creates a temporal representation dataset for later
# self-supervised Transformer training.
# ================================================================


# ================================================================
# PROJECT PATHS
# ================================================================

PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[2]
)


OUTPUT_DIRECTORY = (
    PROJECT_ROOT
    / "data"
    / "temporal"
)


DATASET_PATH = (
    OUTPUT_DIRECTORY
    / "process_sequence_dataset_v1.npz"
)


METADATA_PATH = (
    OUTPUT_DIRECTORY
    / "process_sequence_dataset_v1_metadata.json"
)


# ================================================================
# DATASET IDENTITY
# ================================================================

DATASET_NAME = (
    "sentinelx_process_temporal_sequence_dataset"
)


DATASET_VERSION = (
    "v1"
)


# ================================================================
# SEQUENCE CONFIGURATION
#
# ProcessMonitor currently samples approximately every 15 seconds.
#
# 8 steps ~= 2 minutes of behavior.
#
# Stride 2 reduces extreme overlap between adjacent windows.
# ================================================================

SEQUENCE_LENGTH = 8


WINDOW_STRIDE = 2


# If the gap between two observations is >45 seconds, consider
# them separate process sessions.
#
# This also protects against accidental PID reuse.

MAX_SESSION_GAP_SECONDS = 45.0


# ================================================================
# DATA LIMIT
# ================================================================

MAX_MODEL_RESULT_ROWS = 30000


# ================================================================
# DATASET READINESS
# ================================================================

MINIMUM_PAIRED_SAMPLES = 500


MINIMUM_SESSIONS = 20


MINIMUM_WINDOWS = 300


MINIMUM_UNIQUE_PROCESSES = 10


# ================================================================
# EXPECTED EMBEDDING
# ================================================================

EXPECTED_EMBEDDING_DIMENSION = 4


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

        2,
    )


def parse_timestamp(
    value: Any,
) -> Optional[datetime]:

    if value is None:

        return None


    text = str(
        value
    ).strip()


    if not text:

        return None


    try:

        if text.endswith(
            "Z"
        ):

            text = (
                text[:-1]
                + "+00:00"
            )


        parsed = (
            datetime.fromisoformat(
                text
            )
        )


        if parsed.tzinfo is None:

            parsed = (
                parsed.replace(
                    tzinfo=timezone.utc
                )
            )


        return parsed.astimezone(
            timezone.utc
        )


    except ValueError:

        return None


def sha256_bytes(
    value: bytes,
) -> str:

    return (
        hashlib
        .sha256(
            value
        )
        .hexdigest()
    )


# ================================================================
# DATASET BUILDER
# ================================================================

class ProcessSequenceDatasetBuilder:

    def __init__(
        self,
    ):

        # --------------------------------------------------------
        # Reuse the exact behavior feature set selected for the
        # Isolation Forest.
        # --------------------------------------------------------

        isolation_bundle = (
            load_process_isolation_forest_bundle()
        )


        self.base_feature_names = list(

            isolation_bundle[
                "feature_names"
            ]
        )


        self.expected_isolation_version = str(

            isolation_bundle.get(
                "model_version"
            )

            or "v1"
        )


        # --------------------------------------------------------
        # Resolve current healthy Autoencoder.
        # --------------------------------------------------------

        autoencoder_predictor = (
            ProcessAutoencoderPredictor()
        )


        autoencoder_status = (
            autoencoder_predictor
            .get_status()
        )


        if not autoencoder_status.get(
            "available",
            False,
        ):

            raise RuntimeError(

                "Healthy Autoencoder model is unavailable: "
                f"{autoencoder_status.get('load_error')}"
            )


        self.expected_autoencoder_version = str(

            autoencoder_status.get(
                "model_version"
            )

            or "v2"
        )


        self.embedding_dimension = int(

            autoencoder_status.get(
                "bottleneck_dimension"
            )

            or 0
        )


        if (

            self.embedding_dimension

            != EXPECTED_EMBEDDING_DIMENSION

        ):

            raise RuntimeError(

                "Unexpected Autoencoder embedding dimension: "
                f"{self.embedding_dimension}"
            )


        self.ai_agreement = (
            DualAIAgreementEngine()
        )


        # --------------------------------------------------------
        # Final timestep feature schema
        # --------------------------------------------------------

        self.embedding_feature_names = [

            f"behavior_embedding_{index}"

            for index
            in range(
                self.embedding_dimension
            )
        ]


        self.temporal_feature_names = (

            list(
                self.base_feature_names
            )

            + self.embedding_feature_names

            + [

                "isolation_forest_score",

                "autoencoder_score",

                "dual_ai_consensus_score",

                "delta_seconds",
            ]
        )


    # ============================================================
    # ENSURE OUTPUT DIRECTORY
    # ============================================================

    def ensure_output_directory(
        self,
    ) -> None:

        OUTPUT_DIRECTORY.mkdir(

            parents=True,

            exist_ok=True,
        )


    # ============================================================
    # LOAD RAW MODEL RESULTS
    # ============================================================

    def load_rows(
        self,
    ) -> List[
        Dict[
            str,
            Any,
        ]
    ]:

        connection = (
            get_connection()
        )


        try:

            rows = (
                connection.execute(
                    """
                    SELECT

                        r.id AS result_id,

                        r.feature_record_id,

                        r.model_family,

                        r.model_name,

                        r.model_version,

                        r.anomaly_score,

                        r.anomaly_label,

                        r.embedding_json,

                        r.created_at AS result_created_at,

                        f.schema_version,

                        f.extracted_at,

                        f.pid,

                        f.process_name,

                        f.parent_process_name,

                        f.executable_path,

                        f.feature_json

                    FROM behavior_model_results AS r

                    INNER JOIN process_behavior_features AS f

                        ON f.id = r.feature_record_id

                    WHERE r.model_family IN (
                        'isolation_forest',
                        'autoencoder'
                    )

                    ORDER BY r.id DESC

                    LIMIT ?
                    """,
                    (
                        MAX_MODEL_RESULT_ROWS,
                    ),
                )
                .fetchall()
            )


            return [

                dict(
                    row
                )

                for row
                in rows
            ]


        finally:

            connection.close()


    # ============================================================
    # PARSE JSON
    # ============================================================

    def parse_json(
        self,
        value: Any,
    ) -> Any:

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


    # ============================================================
    # GROUP BY FEATURE RECORD
    # ============================================================

    def build_paired_samples(

        self,

        rows: List[
            Dict[
                str,
                Any,
            ]
        ],

    ) -> Dict[
        str,
        Any,
    ]:

        grouped = {}


        rejection_counter = Counter()


        # --------------------------------------------------------
        # Newest result for each model/version wins.
        # --------------------------------------------------------

        for row in rows:

            try:

                feature_record_id = int(

                    row[
                        "feature_record_id"
                    ]
                )

            except (
                TypeError,
                ValueError,
                KeyError,
            ):

                rejection_counter[
                    "invalid_feature_record_id"
                ] += 1

                continue


            family = str(

                row.get(
                    "model_family"
                )

                or ""
            )


            model_version = str(

                row.get(
                    "model_version"
                )

                or ""
            )


            # ----------------------------------------------------
            # Only use the currently active model generations.
            # ----------------------------------------------------

            if family == "isolation_forest":

                if (

                    model_version

                    != self.expected_isolation_version

                ):

                    rejection_counter[
                        "old_isolation_version"
                    ] += 1

                    continue


            elif family == "autoencoder":

                if (

                    model_version

                    != self.expected_autoencoder_version

                ):

                    rejection_counter[
                        "old_autoencoder_version"
                    ] += 1

                    continue


            else:

                continue


            if feature_record_id not in grouped:

                grouped[
                    feature_record_id
                ] = {

                    "feature_record_id":
                        feature_record_id,

                    "schema_version":
                        row.get(
                            "schema_version"
                        ),

                    "extracted_at":
                        row.get(
                            "extracted_at"
                        ),

                    "pid":
                        row.get(
                            "pid"
                        ),

                    "process_name":
                        row.get(
                            "process_name"
                        ),

                    "parent_process_name":
                        row.get(
                            "parent_process_name"
                        ),

                    "executable_path":
                        row.get(
                            "executable_path"
                        ),

                    "feature_json":
                        row.get(
                            "feature_json"
                        ),

                    "isolation_forest":
                        None,

                    "autoencoder":
                        None,
                }


            sample = (
                grouped[
                    feature_record_id
                ]
            )


            if (

                family
                == "isolation_forest"

                and

                sample[
                    "isolation_forest"
                ]
                is None

            ):

                sample[
                    "isolation_forest"
                ] = row


            elif (

                family
                == "autoencoder"

                and

                sample[
                    "autoencoder"
                ]
                is None

            ):

                sample[
                    "autoencoder"
                ] = row


        paired = []


        for sample in (
            grouped.values()
        ):

            isolation_row = (
                sample[
                    "isolation_forest"
                ]
            )


            autoencoder_row = (
                sample[
                    "autoencoder"
                ]
            )


            if isolation_row is None:

                rejection_counter[
                    "missing_isolation_forest"
                ] += 1

                continue


            if autoencoder_row is None:

                rejection_counter[
                    "missing_autoencoder"
                ] += 1

                continue


            # ----------------------------------------------------
            # Timestamp
            # ----------------------------------------------------

            timestamp = (
                parse_timestamp(
                    sample[
                        "extracted_at"
                    ]
                )
            )


            if timestamp is None:

                rejection_counter[
                    "invalid_timestamp"
                ] += 1

                continue


            # ----------------------------------------------------
            # PID
            # ----------------------------------------------------

            try:

                pid = int(
                    sample[
                        "pid"
                    ]
                )

            except (
                TypeError,
                ValueError,
            ):

                rejection_counter[
                    "invalid_pid"
                ] += 1

                continue


            # ----------------------------------------------------
            # Process name
            # ----------------------------------------------------

            process_name = (

                str(

                    sample.get(
                        "process_name"
                    )

                    or "UNKNOWN"
                )
                .strip()
            )


            # ----------------------------------------------------
            # Raw behavior features
            # ----------------------------------------------------

            feature_dict = (
                self.parse_json(

                    sample[
                        "feature_json"
                    ]
                )
            )


            if not isinstance(
                feature_dict,
                dict,
            ):

                rejection_counter[
                    "invalid_feature_json"
                ] += 1

                continue


            base_vector = []


            valid_features = True


            for feature_name in (
                self.base_feature_names
            ):

                value = safe_float(

                    feature_dict.get(
                        feature_name
                    )
                )


                if value is None:

                    rejection_counter[
                        f"invalid_feature:{feature_name}"
                    ] += 1

                    valid_features = False

                    break


                base_vector.append(
                    value
                )


            if not valid_features:

                continue


            # ----------------------------------------------------
            # Autoencoder embedding
            # ----------------------------------------------------

            embedding = (
                self.parse_json(

                    autoencoder_row.get(
                        "embedding_json"
                    )
                )
            )


            if not isinstance(
                embedding,
                list,
            ):

                rejection_counter[
                    "missing_embedding"
                ] += 1

                continue


            if len(
                embedding
            ) != self.embedding_dimension:

                rejection_counter[
                    "embedding_dimension_mismatch"
                ] += 1

                continue


            parsed_embedding = []


            embedding_valid = True


            for value in embedding:

                number = safe_float(
                    value
                )


                if number is None:

                    embedding_valid = False

                    break


                parsed_embedding.append(
                    number
                )


            if not embedding_valid:

                rejection_counter[
                    "invalid_embedding"
                ] += 1

                continue


            # ----------------------------------------------------
            # Model scores
            # ----------------------------------------------------

            isolation_score = safe_float(

                isolation_row.get(
                    "anomaly_score"
                )
            )


            autoencoder_score = safe_float(

                autoencoder_row.get(
                    "anomaly_score"
                )
            )


            if isolation_score is None:

                rejection_counter[
                    "invalid_isolation_score"
                ] += 1

                continue


            if autoencoder_score is None:

                rejection_counter[
                    "invalid_autoencoder_score"
                ] += 1

                continue


            # ----------------------------------------------------
            # Recompute dual-AI consensus using current policy.
            # ----------------------------------------------------

            consensus = (

                self.ai_agreement.calculate(

                    isolation_result={

                        "available":
                            True,

                        "anomaly_confidence":
                            isolation_score,
                    },

                    autoencoder_result={

                        "available":
                            True,

                        "anomaly_confidence":
                            autoencoder_score,
                    },
                )
            )


            consensus_score = safe_float(

                consensus.get(
                    "consensus_score"
                )
            )


            if consensus_score is None:

                rejection_counter[
                    "invalid_consensus_score"
                ] += 1

                continue


            paired.append(
                {

                    "feature_record_id":
                        sample[
                            "feature_record_id"
                        ],

                    "timestamp":
                        timestamp,

                    "timestamp_iso":
                        timestamp.isoformat(),

                    "pid":
                        pid,

                    "process_name":
                        process_name,

                    "parent_process_name":
                        sample.get(
                            "parent_process_name"
                        ),

                    "executable_path":
                        sample.get(
                            "executable_path"
                        ),

                    "base_vector":
                        base_vector,

                    "embedding":
                        parsed_embedding,

                    "isolation_score":
                        isolation_score,

                    "autoencoder_score":
                        autoencoder_score,

                    "consensus_score":
                        consensus_score,
                }
            )


        paired.sort(

            key=lambda item:
                (
                    item[
                        "timestamp"
                    ],

                    item[
                        "feature_record_id"
                    ],
                )
        )


        return {

            "samples":
                paired,

            "raw_group_count":
                len(
                    grouped
                ),

            "paired_count":
                len(
                    paired
                ),

            "rejections":
                dict(
                    rejection_counter
                ),
        }


    # ============================================================
    # SESSIONIZE PROCESS SAMPLES
    #
    # Key:
    #
    #   PID + process name
    #
    # We additionally break the sequence whenever the sampling gap
    # is too large.
    #
    # This reduces accidental joining of reused Windows PIDs.
    # ============================================================

    def build_sessions(

        self,

        samples: List[
            Dict[
                str,
                Any,
            ]
        ],

    ) -> List[
        Dict[
            str,
            Any,
        ]
    ]:

        grouped = defaultdict(
            list
        )


        for sample in samples:

            key = (

                sample[
                    "pid"
                ],

                sample[
                    "process_name"
                ].lower(),
            )


            grouped[
                key
            ].append(
                sample
            )


        sessions = []


        for (
            (
                pid,
                normalized_process_name,
            ),
            process_samples,

        ) in grouped.items():

            process_samples.sort(

                key=lambda item:
                    item[
                        "timestamp"
                    ]
            )


            current = []


            for sample in process_samples:

                if not current:

                    current.append(
                        sample
                    )

                    continue


                previous = (
                    current[
                        -1
                    ]
                )


                gap = (

                    sample[
                        "timestamp"
                    ]

                    - previous[
                        "timestamp"
                    ]
                ).total_seconds()


                if (

                    gap <= 0.0

                    or

                    gap
                    > MAX_SESSION_GAP_SECONDS

                ):

                    sessions.append(

                        self.finalize_session(
                            current
                        )
                    )


                    current = [
                        sample
                    ]

                else:

                    current.append(
                        sample
                    )


            if current:

                sessions.append(

                    self.finalize_session(
                        current
                    )
                )


        sessions.sort(

            key=lambda item:
                item[
                    "start_timestamp"
                ]
        )


        return sessions


    # ============================================================
    # FINALIZE SESSION
    # ============================================================

    def finalize_session(

        self,

        samples: List[
            Dict[
                str,
                Any,
            ]
        ],

    ) -> Dict[
        str,
        Any,
    ]:

        first = (
            samples[
                0
            ]
        )


        last = (
            samples[
                -1
            ]
        )


        session_id = (

            f"{first['pid']}::"

            f"{first['process_name']}::"

            f"{first['timestamp_iso']}"
        )


        return {

            "session_id":
                session_id,

            "pid":
                first[
                    "pid"
                ],

            "process_name":
                first[
                    "process_name"
                ],

            "start_timestamp":
                first[
                    "timestamp"
                ],

            "end_timestamp":
                last[
                    "timestamp"
                ],

            "samples":
                list(
                    samples
                ),
        }


    # ============================================================
    # BUILD ONE TIMESTEP VECTOR
    # ============================================================

    def build_timestep_vector(

        self,

        sample: Dict[
            str,
            Any,
        ],

        delta_seconds: float,

    ) -> List[
        float
    ]:

        vector = (

            list(
                sample[
                    "base_vector"
                ]
            )

            + list(
                sample[
                    "embedding"
                ]
            )

            + [

                float(
                    sample[
                        "isolation_score"
                    ]
                ),

                float(
                    sample[
                        "autoencoder_score"
                    ]
                ),

                float(
                    sample[
                        "consensus_score"
                    ]
                ),

                float(
                    delta_seconds
                ),
            ]
        )


        if len(
            vector
        ) != len(
            self.temporal_feature_names
        ):

            raise RuntimeError(

                "Temporal timestep feature dimension mismatch."
            )


        if not all(

            math.isfinite(
                value
            )

            for value
            in vector

        ):

            raise RuntimeError(

                "Temporal timestep contains "
                "non-finite values."
            )


        return vector


    # ============================================================
    # BUILD WINDOWS
    # ============================================================

    def build_windows(

        self,

        sessions: List[
            Dict[
                str,
                Any,
            ]
        ],

    ) -> Dict[
        str,
        Any,
    ]:

        windows = []


        short_session_count = 0


        for session in sessions:

            samples = (
                session[
                    "samples"
                ]
            )


            if len(
                samples
            ) < SEQUENCE_LENGTH:

                short_session_count += 1

                continue


            max_start = (

                len(
                    samples
                )

                - SEQUENCE_LENGTH
            )


            for start_index in range(

                0,

                max_start + 1,

                WINDOW_STRIDE,
            ):

                selected = (

                    samples[
                        start_index:
                        start_index
                        + SEQUENCE_LENGTH
                    ]
                )


                sequence_vectors = []


                feature_record_ids = []


                previous_timestamp = None


                for sample in selected:

                    if previous_timestamp is None:

                        delta_seconds = 0.0

                    else:

                        delta_seconds = (

                            sample[
                                "timestamp"
                            ]

                            - previous_timestamp
                        ).total_seconds()


                    sequence_vectors.append(

                        self.build_timestep_vector(

                            sample=
                                sample,

                            delta_seconds=
                                delta_seconds,
                        )
                    )


                    feature_record_ids.append(

                        int(

                            sample[
                                "feature_record_id"
                            ]
                        )
                    )


                    previous_timestamp = (
                        sample[
                            "timestamp"
                        ]
                    )


                windows.append(
                    {

                        "session_id":
                            session[
                                "session_id"
                            ],

                        "pid":
                            session[
                                "pid"
                            ],

                        "process_name":
                            session[
                                "process_name"
                            ],

                        "start_timestamp":
                            selected[
                                0
                            ][
                                "timestamp_iso"
                            ],

                        "end_timestamp":
                            selected[
                                -1
                            ][
                                "timestamp_iso"
                            ],

                        "feature_record_ids":
                            feature_record_ids,

                        "sequence":
                            sequence_vectors,
                    }
                )


        return {

            "windows":
                windows,

            "short_session_count":
                short_session_count,
        }


    # ============================================================
    # DATASET FINGERPRINT
    # ============================================================

    def dataset_fingerprint(

        self,

        matrix: np.ndarray,

    ) -> str:

        payload = (

            matrix.astype(
                np.float32
            )
            .tobytes()

            +

            json.dumps(
                self.temporal_feature_names,
                separators=(
                    ",",
                    ":",
                ),
            ).encode(
                "utf-8"
            )
        )


        return sha256_bytes(
            payload
        )


    # ============================================================
    # SAVE DATASET
    # ============================================================

    def save_dataset(

        self,

        windows: List[
            Dict[
                str,
                Any,
            ]
        ],

        metadata: Dict[
            str,
            Any,
        ],

    ) -> None:

        self.ensure_output_directory()


        sequence_matrix = np.asarray(

            [

                window[
                    "sequence"
                ]

                for window
                in windows
            ],

            dtype=np.float32,
        )


        feature_record_ids = np.asarray(

            [

                window[
                    "feature_record_ids"
                ]

                for window
                in windows
            ],

            dtype=np.int64,
        )


        pids = np.asarray(

            [

                window[
                    "pid"
                ]

                for window
                in windows
            ],

            dtype=np.int64,
        )


        process_names = np.asarray(

            [

                window[
                    "process_name"
                ]

                for window
                in windows
            ],

            dtype=np.str_,
        )


        session_ids = np.asarray(

            [

                window[
                    "session_id"
                ]

                for window
                in windows
            ],

            dtype=np.str_,
        )


        start_timestamps = np.asarray(

            [

                window[
                    "start_timestamp"
                ]

                for window
                in windows
            ],

            dtype=np.str_,
        )


        end_timestamps = np.asarray(

            [

                window[
                    "end_timestamp"
                ]

                for window
                in windows
            ],

            dtype=np.str_,
        )


        temporal_feature_names = np.asarray(

            self.temporal_feature_names,

            dtype=np.str_,
        )


        np.savez_compressed(

            DATASET_PATH,

            X=
                sequence_matrix,

            feature_record_ids=
                feature_record_ids,

            pids=
                pids,

            process_names=
                process_names,

            session_ids=
                session_ids,

            start_timestamps=
                start_timestamps,

            end_timestamps=
                end_timestamps,

            temporal_feature_names=
                temporal_feature_names,
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
    # BUILD METADATA
    # ============================================================

    def build_metadata(

        self,

        paired_info: Dict[
            str,
            Any,
        ],

        sessions: List[
            Dict[
                str,
                Any,
            ]
        ],

        window_info: Dict[
            str,
            Any,
        ],

    ) -> Dict[
        str,
        Any,
    ]:

        windows = (
            window_info[
                "windows"
            ]
        )


        if windows:

            matrix = np.asarray(

                [

                    window[
                        "sequence"
                    ]

                    for window
                    in windows
                ],

                dtype=np.float32,
            )

        else:

            matrix = np.empty(

                (
                    0,
                    SEQUENCE_LENGTH,
                    len(
                        self.temporal_feature_names
                    ),
                ),

                dtype=np.float32,
            )


        process_counter = Counter(

            window[
                "process_name"
            ].lower()

            for window
            in windows
        )


        session_lengths = [

            len(
                session[
                    "samples"
                ]
            )

            for session
            in sessions
        ]


        eligible_sessions = sum(

            1

            for length
            in session_lengths

            if length
            >= SEQUENCE_LENGTH
        )


        checks = {

            "enough_paired_samples":

                paired_info[
                    "paired_count"
                ]
                >= MINIMUM_PAIRED_SAMPLES,


            "enough_sessions":

                eligible_sessions
                >= MINIMUM_SESSIONS,


            "enough_windows":

                len(
                    windows
                )
                >= MINIMUM_WINDOWS,


            "enough_process_diversity":

                len(
                    process_counter
                )
                >= MINIMUM_UNIQUE_PROCESSES,


            "correct_sequence_length":

                (
                    matrix.shape[
                        1
                    ]
                    == SEQUENCE_LENGTH

                    if len(
                        windows
                    )
                    > 0

                    else False
                ),


            "correct_timestep_dimension":

                (
                    matrix.shape[
                        2
                    ]
                    == len(
                        self.temporal_feature_names
                    )

                    if len(
                        windows
                    )
                    > 0

                    else False
                ),
        }


        ready = all(
            checks.values()
        )


        fingerprint = (

            self.dataset_fingerprint(
                matrix
            )

            if len(
                windows
            )
            > 0

            else None
        )


        return {

            "dataset_name":
                DATASET_NAME,

            "dataset_version":
                DATASET_VERSION,

            "created_at":
                now_iso(),

            "purpose":
                (
                    "Self-supervised temporal endpoint process "
                    "sequence modeling"
                ),

            "sequence_configuration": {

                "sequence_length":
                    SEQUENCE_LENGTH,

                "window_stride":
                    WINDOW_STRIDE,

                "max_session_gap_seconds":
                    MAX_SESSION_GAP_SECONDS,
            },

            "model_sources": {

                "isolation_forest_version":
                    self.expected_isolation_version,

                "autoencoder_version":
                    self.expected_autoencoder_version,

                "autoencoder_embedding_dimension":
                    self.embedding_dimension,
            },

            "feature_schema": {

                "base_behavior_features":
                    list(
                        self.base_feature_names
                    ),

                "embedding_features":
                    list(
                        self.embedding_feature_names
                    ),

                "temporal_feature_names":
                    list(
                        self.temporal_feature_names
                    ),

                "timestep_feature_count":
                    len(
                        self.temporal_feature_names
                    ),
            },

            "dataset_statistics": {

                "raw_paired_groups":
                    paired_info[
                        "raw_group_count"
                    ],

                "valid_paired_samples":
                    paired_info[
                        "paired_count"
                    ],

                "sessions":
                    len(
                        sessions
                    ),

                "eligible_sessions":
                    eligible_sessions,

                "short_sessions":
                    window_info[
                        "short_session_count"
                    ],

                "windows":
                    len(
                        windows
                    ),

                "unique_window_processes":
                    len(
                        process_counter
                    ),

                "sequence_matrix_shape":
                    list(
                        matrix.shape
                    ),

                "session_length_min":
                    (
                        min(
                            session_lengths
                        )

                        if session_lengths

                        else 0
                    ),

                "session_length_max":
                    (
                        max(
                            session_lengths
                        )

                        if session_lengths

                        else 0
                    ),

                "session_length_mean":
                    (
                        float(

                            np.mean(
                                session_lengths
                            )
                        )

                        if session_lengths

                        else 0.0
                    ),
            },

            "top_window_processes": [

                {

                    "process_name":
                        process_name,

                    "window_count":
                        count,
                }

                for (
                    process_name,
                    count,
                )
                in process_counter.most_common(
                    20
                )
            ],

            "rejections":
                paired_info[
                    "rejections"
                ],

            "readiness_checks":
                checks,

            "ready_for_temporal_training":
                ready,

            "dataset_fingerprint_sha256":
                fingerprint,

            "dataset_path":
                str(
                    DATASET_PATH
                ),

            "metadata_path":
                str(
                    METADATA_PATH
                ),

            "important_note":
                (
                    "Windows are unlabeled behavioral sequences. "
                    "They must not be treated as malicious/benign "
                    "ground truth."
                ),
        }


    # ============================================================
    # PRINT REPORT
    # ============================================================

    def print_report(

        self,

        metadata: Dict[
            str,
            Any,
        ],

    ) -> None:

        statistics = (
            metadata[
                "dataset_statistics"
            ]
        )


        print()

        print(
            "=" * 82
        )

        print(
            "SENTINEL-X TEMPORAL PROCESS SEQUENCE DATASET"
        )

        print(
            "=" * 82
        )


        print()

        print(
            "MODEL SOURCES"
        )

        print(
            "-" * 82
        )


        print(
            "Isolation Forest :",
            metadata[
                "model_sources"
            ][
                "isolation_forest_version"
            ],
        )


        print(
            "Autoencoder      :",
            metadata[
                "model_sources"
            ][
                "autoencoder_version"
            ],
        )


        print(
            "Embedding        :",
            metadata[
                "model_sources"
            ][
                "autoencoder_embedding_dimension"
            ],
        )


        print()

        print(
            "SEQUENCE CONFIGURATION"
        )

        print(
            "-" * 82
        )


        print(
            "Sequence length  :",
            SEQUENCE_LENGTH,
        )


        print(
            "Window stride    :",
            WINDOW_STRIDE,
        )


        print(
            "Maximum gap      :",
            MAX_SESSION_GAP_SECONDS,
            "seconds",
        )


        print(
            "Features / step  :",
            metadata[
                "feature_schema"
            ][
                "timestep_feature_count"
            ],
        )


        print()

        print(
            "DATASET"
        )

        print(
            "-" * 82
        )


        print(
            "Valid paired samples:",
            statistics[
                "valid_paired_samples"
            ],
        )


        print(
            "Sessions            :",
            statistics[
                "sessions"
            ],
        )


        print(
            "Eligible sessions   :",
            statistics[
                "eligible_sessions"
            ],
        )


        print(
            "Short sessions      :",
            statistics[
                "short_sessions"
            ],
        )


        print(
            "Temporal windows    :",
            statistics[
                "windows"
            ],
        )


        print(
            "Unique processes    :",
            statistics[
                "unique_window_processes"
            ],
        )


        print(
            "Matrix shape        :",
            statistics[
                "sequence_matrix_shape"
            ],
        )


        print()

        print(
            "Expected shape:"
        )


        print(

            "(windows, "

            f"{SEQUENCE_LENGTH}, "

            f"{len(self.temporal_feature_names)})"
        )


        print()

        print(
            "TOP WINDOW PROCESSES"
        )

        print(
            "-" * 82
        )


        for item in (
            metadata[
                "top_window_processes"
            ]
        ):

            print(

                f"{item['process_name']:<35}"
                f"{item['window_count']:>8}"
            )


        print()

        print(
            "READINESS CHECKS"
        )

        print(
            "-" * 82
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

                f"{check:<45}: "

                + (
                    "PASS"
                    if passed
                    else "REVIEW"
                )
            )


        print()

        print(
            "=" * 82
        )

        print(
            "FINAL RESULT"
        )

        print(
            "=" * 82
        )


        if metadata[
            "ready_for_temporal_training"
        ]:

            print()

            print(
                "TEMPORAL DATASET: READY"
            )

            print()

            print(
                "The endpoint now contains enough chronological "
                "process behavior to begin temporal model design."
            )


        else:

            print()

            print(
                "TEMPORAL DATASET: MORE DATA / REVIEW REQUIRED"
            )

            print()

            print(
                "Continue normal endpoint collection and rebuild "
                "the dataset before Transformer training."
            )


        print()

        print(
            "Dataset:"
        )

        print(
            DATASET_PATH
        )


        print()

        print(
            "Metadata:"
        )

        print(
            METADATA_PATH
        )


    # ============================================================
    # COMPLETE BUILD
    # ============================================================

    def build(
        self,
    ) -> Dict[
        str,
        Any,
    ]:

        print()

        print(
            "[1/5] Loading paired Isolation Forest + "
            "Autoencoder observations..."
        )


        rows = (
            self.load_rows()
        )


        print(
            "Model-result rows:",
            len(
                rows
            ),
        )


        print()

        print(
            "[2/5] Building valid chronological behavior samples..."
        )


        paired_info = (
            self.build_paired_samples(
                rows
            )
        )


        print(
            "Valid paired samples:",
            paired_info[
                "paired_count"
            ],
        )


        print()

        print(
            "[3/5] Creating process sessions..."
        )


        sessions = (
            self.build_sessions(

                paired_info[
                    "samples"
                ]
            )
        )


        print(
            "Sessions:",
            len(
                sessions
            ),
        )


        print()

        print(
            "[4/5] Creating fixed temporal windows..."
        )


        window_info = (
            self.build_windows(
                sessions
            )
        )


        print(
            "Windows:",
            len(
                window_info[
                    "windows"
                ]
            ),
        )


        print()

        print(
            "[5/5] Saving temporal dataset..."
        )


        metadata = (
            self.build_metadata(

                paired_info=
                    paired_info,

                sessions=
                    sessions,

                window_info=
                    window_info,
            )
        )


        # Even if readiness is not yet sufficient, save the current
        # dataset for diagnostics if at least one window exists.

        if window_info[
            "windows"
        ]:

            self.save_dataset(

                windows=
                    window_info[
                        "windows"
                    ],

                metadata=
                    metadata,
            )


        else:

            self.ensure_output_directory()


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


        self.print_report(
            metadata
        )


        return metadata


# ================================================================
# MAIN
# ================================================================

if __name__ == "__main__":

    builder = (
        ProcessSequenceDatasetBuilder()
    )


    builder.build()