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

from pathlib import Path

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
# SENTINEL-X TEMPORAL PROCESS SEQUENCE DATASET BUILDER V2
#
# Main improvement over v1:
#
#     v1:
#         fixed session gap = 45 seconds
#
#     v2:
#         measures the actual live per-PID sampling cadence
#         and derives a safe session-gap threshold.
#
#
# Example from current endpoint:
#
#     actual cadence ≈ 60 sec
#
#     inferred session threshold ≈ 120 sec
#
#
# This still prevents old runs separated by hundreds/thousands
# of seconds from being joined together.
# ================================================================


# ================================================================
# PATHS
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
    / "process_sequence_dataset_v2.npz"
)


METADATA_PATH = (
    OUTPUT_DIRECTORY
    / "process_sequence_dataset_v2_metadata.json"
)


# ================================================================
# DATASET IDENTITY
# ================================================================

DATASET_NAME = (
    "sentinelx_process_temporal_sequence_dataset"
)


DATASET_VERSION = "v2"


# ================================================================
# TEMPORAL CONFIGURATION
# ================================================================

SEQUENCE_LENGTH = 8


WINDOW_STRIDE = 2


# ================================================================
# CADENCE DETECTION
#
# We only use relatively short gaps to estimate the real production
# sampling cadence.
#
# Old agent launches such as:
#
#     258 seconds
#     1000 seconds
#
# should not influence the live cadence estimate.
# ================================================================

MAX_CADENCE_CANDIDATE_GAP_SECONDS = 180.0


DEFAULT_CADENCE_SECONDS = 60.0


SESSION_GAP_MULTIPLIER = 2.0


MIN_SESSION_GAP_SECONDS = 45.0


MAX_SESSION_GAP_SECONDS = 180.0


# ================================================================
# DATA
# ================================================================

MAX_MODEL_RESULT_ROWS = 50000


EXPECTED_EMBEDDING_DIMENSION = 4


# ================================================================
# READINESS
# ================================================================

MINIMUM_PAIRED_SAMPLES = 500


MINIMUM_ELIGIBLE_SESSIONS = 10


MINIMUM_WINDOWS = 100


MINIMUM_UNIQUE_PROCESSES = 5


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


    if text.endswith("Z"):

        text = (
            text[:-1]
            + "+00:00"
        )


    try:

        timestamp = (
            datetime.fromisoformat(
                text
            )
        )


        if timestamp.tzinfo is None:

            timestamp = (
                timestamp.replace(
                    tzinfo=timezone.utc
                )
            )


        return timestamp.astimezone(
            timezone.utc
        )


    except ValueError:

        return None


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
# BUILDER
# ================================================================

class ProcessSequenceDatasetBuilderV2:

    def __init__(
        self,
    ):

        # ========================================================
        # ISOLATION FOREST
        # ========================================================

        isolation_bundle = (
            load_process_isolation_forest_bundle()
        )


        self.base_feature_names = list(

            isolation_bundle[
                "feature_names"
            ]
        )


        self.isolation_version = str(

            isolation_bundle.get(
                "model_version"
            )

            or "v1"
        )


        # ========================================================
        # AUTOENCODER
        # ========================================================

        autoencoder = (
            ProcessAutoencoderPredictor()
        )


        status = (
            autoencoder.get_status()
        )


        if not status.get(
            "available",
            False,
        ):

            raise RuntimeError(

                "Autoencoder v2 unavailable: "
                f"{status.get('load_error')}"
            )


        self.autoencoder_version = str(

            status.get(
                "model_version"
            )

            or "v2"
        )


        self.embedding_dimension = int(

            status.get(
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


        # ========================================================
        # DUAL AI
        # ========================================================

        self.ai_agreement = (
            DualAIAgreementEngine()
        )


        # ========================================================
        # TEMPORAL FEATURE SCHEMA
        # ========================================================

        self.embedding_feature_names = [

            f"behavior_embedding_{index}"

            for index in range(
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
    # OUTPUT DIRECTORY
    # ============================================================

    def ensure_output_directory(
        self,
    ):

        OUTPUT_DIRECTORY.mkdir(

            parents=True,

            exist_ok=True,
        )


    # ============================================================
    # LOAD MODEL RESULTS
    # ============================================================

    def load_rows(
        self,
    ):

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

                        f.pid,

                        f.process_name,

                        f.parent_process_name,

                        f.executable_path,

                        f.extracted_at,

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
    # PAIR IF + AUTOENCODER
    # ============================================================

    def build_paired_samples(
        self,
        rows,
    ):

        grouped = {}


        rejected = Counter()


        # Rows are newest first.
        # Keep latest result per model family.

        for row in rows:

            try:

                feature_record_id = int(

                    row[
                        "feature_record_id"
                    ]
                )

            except (
                KeyError,
                TypeError,
                ValueError,
            ):

                rejected[
                    "invalid_feature_record_id"
                ] += 1

                continue


            family = str(

                row.get(
                    "model_family"
                )

                or ""
            )


            version = str(

                row.get(
                    "model_version"
                )

                or ""
            )


            if family == "isolation_forest":

                if version != self.isolation_version:

                    rejected[
                        "old_isolation_version"
                    ] += 1

                    continue


            elif family == "autoencoder":

                if version != self.autoencoder_version:

                    rejected[
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

                    "extracted_at":
                        row.get(
                            "extracted_at"
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

                family == "isolation_forest"

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

                family == "autoencoder"

                and

                sample[
                    "autoencoder"
                ]
                is None

            ):

                sample[
                    "autoencoder"
                ] = row


        valid_samples = []


        for sample in (
            grouped.values()
        ):

            isolation = (
                sample[
                    "isolation_forest"
                ]
            )


            autoencoder = (
                sample[
                    "autoencoder"
                ]
            )


            if isolation is None:

                rejected[
                    "missing_isolation_forest"
                ] += 1

                continue


            if autoencoder is None:

                rejected[
                    "missing_autoencoder"
                ] += 1

                continue


            # ====================================================
            # PID
            # ====================================================

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

                rejected[
                    "invalid_pid"
                ] += 1

                continue


            # ====================================================
            # TIMESTAMP
            # ====================================================

            timestamp = (
                parse_timestamp(

                    sample[
                        "extracted_at"
                    ]
                )
            )


            if timestamp is None:

                rejected[
                    "invalid_timestamp"
                ] += 1

                continue


            # ====================================================
            # RAW FEATURES
            # ====================================================

            feature_dict = (
                parse_json(

                    sample[
                        "feature_json"
                    ]
                )
            )


            if not isinstance(
                feature_dict,
                dict,
            ):

                rejected[
                    "invalid_feature_json"
                ] += 1

                continue


            base_vector = []


            valid = True


            for feature_name in (
                self.base_feature_names
            ):

                value = safe_float(

                    feature_dict.get(
                        feature_name
                    )
                )


                if value is None:

                    rejected[
                        f"invalid_feature:{feature_name}"
                    ] += 1

                    valid = False

                    break


                base_vector.append(
                    value
                )


            if not valid:

                continue


            # ====================================================
            # EMBEDDING
            # ====================================================

            embedding = (
                parse_json(

                    autoencoder.get(
                        "embedding_json"
                    )
                )
            )


            if not isinstance(
                embedding,
                list,
            ):

                rejected[
                    "missing_embedding"
                ] += 1

                continue


            if (

                len(
                    embedding
                )

                != self.embedding_dimension

            ):

                rejected[
                    "embedding_dimension"
                ] += 1

                continue


            parsed_embedding = []


            for value in embedding:

                number = (
                    safe_float(
                        value
                    )
                )


                if number is None:

                    valid = False

                    break


                parsed_embedding.append(
                    number
                )


            if not valid:

                rejected[
                    "invalid_embedding"
                ] += 1

                continue


            # ====================================================
            # MODEL SCORES
            # ====================================================

            isolation_score = safe_float(

                isolation.get(
                    "anomaly_score"
                )
            )


            autoencoder_score = safe_float(

                autoencoder.get(
                    "anomaly_score"
                )
            )


            if isolation_score is None:

                rejected[
                    "invalid_isolation_score"
                ] += 1

                continue


            if autoencoder_score is None:

                rejected[
                    "invalid_autoencoder_score"
                ] += 1

                continue


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

                rejected[
                    "invalid_consensus_score"
                ] += 1

                continue


            process_name = (

                str(

                    sample.get(
                        "process_name"
                    )

                    or "UNKNOWN"
                )
                .strip()
            )


            valid_samples.append(
                {

                    "feature_record_id":
                        sample[
                            "feature_record_id"
                        ],

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

                    "timestamp":
                        timestamp,

                    "timestamp_iso":
                        timestamp.isoformat(),

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


        valid_samples.sort(

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
                valid_samples,

            "paired_count":
                len(
                    valid_samples
                ),

            "grouped_count":
                len(
                    grouped
                ),

            "rejections":
                dict(
                    rejected
                ),
        }


    # ============================================================
    # INFER REAL SAMPLING CADENCE
    # ============================================================

    def infer_sampling_cadence(
        self,
        samples,
    ):

        groups = defaultdict(
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


            groups[
                key
            ].append(

                sample[
                    "timestamp"
                ]
            )


        candidate_gaps = []


        for timestamps in (
            groups.values()
        ):

            timestamps.sort()


            for index in range(
                1,
                len(
                    timestamps
                ),
            ):

                gap = (

                    timestamps[
                        index
                    ]

                    - timestamps[
                        index - 1
                    ]

                ).total_seconds()


                if (

                    gap > 0.0

                    and

                    gap
                    <= MAX_CADENCE_CANDIDATE_GAP_SECONDS

                ):

                    candidate_gaps.append(
                        gap
                    )


        if candidate_gaps:

            measured_cadence = float(

                np.median(
                    candidate_gaps
                )
            )


            source = (
                "measured"
            )


        else:

            measured_cadence = (
                DEFAULT_CADENCE_SECONDS
            )


            source = (
                "fallback"
            )


        session_gap = (

            measured_cadence

            * SESSION_GAP_MULTIPLIER
        )


        session_gap = max(

            MIN_SESSION_GAP_SECONDS,

            min(

                MAX_SESSION_GAP_SECONDS,

                session_gap,
            ),
        )


        return {

            "source":
                source,

            "candidate_gap_count":
                len(
                    candidate_gaps
                ),

            "median_cadence_seconds":
                measured_cadence,

            "p25_seconds":
                (
                    float(

                        np.percentile(
                            candidate_gaps,
                            25,
                        )
                    )

                    if candidate_gaps

                    else None
                ),

            "p75_seconds":
                (
                    float(

                        np.percentile(
                            candidate_gaps,
                            75,
                        )
                    )

                    if candidate_gaps

                    else None
                ),

            "session_gap_seconds":
                session_gap,
        }


    # ============================================================
    # BUILD SESSIONS
    # ============================================================

    def build_sessions(
        self,
        samples,
        session_gap_seconds: float,
    ):

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
            key,
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

                    current = [
                        sample
                    ]

                    continue


                gap = (

                    sample[
                        "timestamp"
                    ]

                    - current[
                        -1
                    ][
                        "timestamp"
                    ]

                ).total_seconds()


                if (

                    gap <= 0.0

                    or

                    gap > session_gap_seconds

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
        samples,
    ):

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


        return {

            "session_id":
                (
                    f"{first['pid']}::"
                    f"{first['process_name']}::"
                    f"{first['timestamp_iso']}"
                ),

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
    # TIMESTEP VECTOR
    # ============================================================

    def build_timestep(
        self,
        sample,
        delta_seconds,
    ):

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


        if (

            len(
                vector
            )

            != len(
                self.temporal_feature_names
            )

        ):

            raise RuntimeError(

                "Temporal timestep dimension mismatch."
            )


        if not all(

            math.isfinite(
                value
            )

            for value in vector

        ):

            raise RuntimeError(

                "Temporal timestep contains "
                "non-finite values."
            )


        return vector


    # ============================================================
    # WINDOWS
    # ============================================================

    def build_windows(
        self,
        sessions,
    ):

        windows = []


        for session in sessions:

            samples = (
                session[
                    "samples"
                ]
            )


            if (

                len(
                    samples
                )

                < SEQUENCE_LENGTH

            ):

                continue


            final_start = (

                len(
                    samples
                )

                - SEQUENCE_LENGTH
            )


            for start_index in range(

                0,

                final_start + 1,

                WINDOW_STRIDE,
            ):

                selected = (

                    samples[
                        start_index:
                        start_index
                        + SEQUENCE_LENGTH
                    ]
                )


                sequence = []

                record_ids = []


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


                    sequence.append(

                        self.build_timestep(

                            sample,

                            delta_seconds,
                        )
                    )


                    record_ids.append(

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
                            record_ids,

                        "sequence":
                            sequence,
                    }
                )


        return windows


    # ============================================================
    # SAVE
    # ============================================================

    def save(
        self,
        windows,
        metadata,
    ):

        self.ensure_output_directory()


        X = np.asarray(

            [

                window[
                    "sequence"
                ]

                for window in windows
            ],

            dtype=np.float32,
        )


        feature_record_ids = np.asarray(

            [

                window[
                    "feature_record_ids"
                ]

                for window in windows
            ],

            dtype=np.int64,
        )


        process_names = np.asarray(

            [

                window[
                    "process_name"
                ]

                for window in windows
            ],

            dtype=np.str_,
        )


        pids = np.asarray(

            [

                window[
                    "pid"
                ]

                for window in windows
            ],

            dtype=np.int64,
        )


        session_ids = np.asarray(

            [

                window[
                    "session_id"
                ]

                for window in windows
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
                X,

            feature_record_ids=
                feature_record_ids,

            process_names=
                process_names,

            pids=
                pids,

            session_ids=
                session_ids,

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
            )


    # ============================================================
    # BUILD
    # ============================================================

    def build(
        self,
    ):

        print()

        print(
            "=" * 82
        )

        print(
            "SENTINEL-X TEMPORAL DATASET BUILDER V2"
        )

        print(
            "=" * 82
        )


        # ========================================================
        # 1
        # ========================================================

        print()

        print(
            "[1/6] Loading model results..."
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


        # ========================================================
        # 2
        # ========================================================

        print()

        print(
            "[2/6] Pairing Isolation Forest + Autoencoder..."
        )


        paired = (
            self.build_paired_samples(
                rows
            )
        )


        samples = (
            paired[
                "samples"
            ]
        )


        print(
            "Valid paired samples:",
            len(
                samples
            ),
        )


        # ========================================================
        # 3
        # ========================================================

        print()

        print(
            "[3/6] Measuring actual endpoint sampling cadence..."
        )


        cadence = (
            self.infer_sampling_cadence(
                samples
            )
        )


        print(
            "Cadence source       :",
            cadence[
                "source"
            ],
        )


        print(
            "Candidate gaps       :",
            cadence[
                "candidate_gap_count"
            ],
        )


        print(
            "Median cadence       :",
            f"{cadence['median_cadence_seconds']:.2f}s",
        )


        print(
            "Derived session gap  :",
            f"{cadence['session_gap_seconds']:.2f}s",
        )


        # ========================================================
        # 4
        # ========================================================

        print()

        print(
            "[4/6] Building continuous process sessions..."
        )


        sessions = (
            self.build_sessions(

                samples,

                cadence[
                    "session_gap_seconds"
                ],
            )
        )


        session_lengths = [

            len(
                session[
                    "samples"
                ]
            )

            for session in sessions
        ]


        eligible_sessions = sum(

            1

            for length in session_lengths

            if length >= SEQUENCE_LENGTH
        )


        maximum_depth = (

            max(
                session_lengths
            )

            if session_lengths

            else 0
        )


        print(
            "Sessions          :",
            len(
                sessions
            ),
        )


        print(
            "Eligible sessions :",
            eligible_sessions,
        )


        print(
            "Maximum depth     :",
            maximum_depth,
        )


        # ========================================================
        # 5
        # ========================================================

        print()

        print(
            "[5/6] Building temporal windows..."
        )


        windows = (
            self.build_windows(
                sessions
            )
        )


        print(
            "Temporal windows:",
            len(
                windows
            ),
        )


        # ========================================================
        # METADATA
        # ========================================================

        process_counter = Counter(

            window[
                "process_name"
            ].lower()

            for window in windows
        )


        ready_checks = {

            "enough_paired_samples":

                len(
                    samples
                )
                >= MINIMUM_PAIRED_SAMPLES,


            "enough_eligible_sessions":

                eligible_sessions
                >= MINIMUM_ELIGIBLE_SESSIONS,


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
        }


        ready = all(
            ready_checks.values()
        )


        fingerprint = None


        if windows:

            matrix = np.asarray(

                [

                    window[
                        "sequence"
                    ]

                    for window in windows
                ],

                dtype=np.float32,
            )


            fingerprint = (
                sha256_bytes(

                    matrix.tobytes()
                )
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


        metadata = {

            "dataset_name":
                DATASET_NAME,

            "dataset_version":
                DATASET_VERSION,

            "created_at":
                now_iso(),

            "sequence_length":
                SEQUENCE_LENGTH,

            "window_stride":
                WINDOW_STRIDE,

            "measured_sampling_cadence":
                cadence,

            "feature_count":
                len(
                    self.temporal_feature_names
                ),

            "temporal_feature_names":
                self.temporal_feature_names,

            "paired_samples":
                len(
                    samples
                ),

            "session_count":
                len(
                    sessions
                ),

            "eligible_sessions":
                eligible_sessions,

            "maximum_session_depth":
                maximum_depth,

            "temporal_windows":
                len(
                    windows
                ),

            "unique_window_processes":
                len(
                    process_counter
                ),

            "matrix_shape":
                list(
                    matrix.shape
                ),

            "top_processes": [

                {
                    "process_name":
                        name,

                    "windows":
                        count,
                }

                for (
                    name,
                    count,
                )
                in process_counter.most_common(
                    20
                )
            ],

            "rejections":
                paired[
                    "rejections"
                ],

            "readiness_checks":
                ready_checks,

            "ready_for_training":
                ready,

            "dataset_fingerprint_sha256":
                fingerprint,

            "note":
                (
                    "Temporal sequences are unlabeled endpoint "
                    "behavior and are not malicious/benign "
                    "ground-truth labels."
                ),
        }


        # ========================================================
        # 6
        # ========================================================

        print()

        print(
            "[6/6] Saving dataset..."
        )


        self.ensure_output_directory()


        if windows:

            self.save(

                windows,

                metadata,
            )


            print(
                "Dataset:",
                DATASET_PATH,
            )

        else:

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


            print(
                "No .npz saved because there are "
                "currently zero temporal windows."
            )


        print(
            "Metadata:",
            METADATA_PATH,
        )


        # ========================================================
        # REPORT
        # ========================================================

        print()

        print(
            "=" * 82
        )

        print(
            "DATASET SUMMARY"
        )

        print(
            "=" * 82
        )


        print(
            "Paired samples       :",
            len(
                samples
            ),
        )


        print(
            "Measured cadence     :",
            f"{cadence['median_cadence_seconds']:.2f}s",
        )


        print(
            "Session threshold    :",
            f"{cadence['session_gap_seconds']:.2f}s",
        )


        print(
            "Sessions             :",
            len(
                sessions
            ),
        )


        print(
            "Maximum depth        :",
            maximum_depth,
        )


        print(
            "Eligible sessions    :",
            eligible_sessions,
        )


        print(
            "Temporal windows     :",
            len(
                windows
            ),
        )


        print(
            "Unique processes     :",
            len(
                process_counter
            ),
        )


        print(
            "Matrix shape         :",
            list(
                matrix.shape
            ),
        )


        print()

        print(
            "READINESS"
        )

        print(
            "-" * 82
        )


        for (
            check,
            passed,
        ) in (
            ready_checks.items()
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


        if ready:

            print(
                "TEMPORAL DATASET V2: READY FOR PHASE 3 TRAINING"
            )

        elif maximum_depth >= SEQUENCE_LENGTH:

            print(
                "TEMPORAL WINDOWS EXIST, BUT MORE DATA IS "
                "RECOMMENDED BEFORE TRAINING."
            )

        else:

            print(
                "COLLECTION IS WORKING, BUT NO 8-STEP "
                "CONTINUOUS SESSION EXISTS YET."
            )


        print(
            "=" * 82
        )


        return metadata


# ================================================================
# MAIN
# ================================================================

if __name__ == "__main__":

    builder = (
        ProcessSequenceDatasetBuilderV2()
    )


    builder.build()