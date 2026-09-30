from __future__ import annotations

import sqlite3
import time
import zlib

from pathlib import Path

from typing import (
    Any,
    Dict,
    Optional,
)


# ================================================================
# EXISTING WORKING PROCESS MONITOR
# ================================================================

from endpoint.collectors.process_monitor import (
    ProcessMonitor,
)


# ================================================================
# LOGGER
# ================================================================

from endpoint.utils.logger import (
    get_logger,
)


# ================================================================
# DUAL-AI CONSENSUS
# ================================================================

from ai_detection.behavior.dual_ai_agreement import (
    DualAIAgreementEngine,
)


# ================================================================
# TEMPORAL COMPONENTS
# ================================================================

from ai_detection.temporal.process_temporal_observation_builder import (
    ProcessTemporalObservationBuilder,
)

from ai_detection.temporal.process_temporal_buffer import (
    ProcessTemporalBuffer,
)

from ai_detection.temporal.process_temporal_predictor import (
    ProcessTemporalPredictor,
)

from ai_detection.temporal.process_temporal_result_store import (
    ProcessTemporalResultStore,
)


logger = get_logger(
    __name__
)


# ================================================================
# PROJECT PATH
# ================================================================

PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[2]
)


DEFAULT_DATABASE_PATH = (
    PROJECT_ROOT
    / "data"
    / "database"
    / "sentinel_endpoint.db"
)


# ================================================================
# CONFIGURATION
# ================================================================

TEMPORAL_SEQUENCE_LENGTH = 8

TEMPORAL_ALERT_COOLDOWN_SECONDS = 300.0

TEMPORAL_STALE_CLEANUP_INTERVAL_SECONDS = 120.0


# ================================================================
# SENTINEL-X TEMPORAL PROCESS MONITOR
#
# Existing Phase-2 flow:
#
# Process
#     ↓
# Feature Collection
#     ↓
# Isolation Forest
#     ↓
# Autoencoder
#     ↓
# Dual-AI Agreement
#     ↓
# Temporal Observation
#     ↓
# Rolling Temporal Buffer
#     ↓
# Transformer
#     ↓
# Temporal Result Store
#
#
# PROCESS IDENTITY
#
# Preferred:
#
#       PID + real create_time
#
#
# Fallback:
#
#       PID + deterministic process-name fingerprint
#
#
# IMPORTANT:
#
# time.time() must NEVER be used as process create_time fallback.
#
# Otherwise the same process receives a different identity during
# every polling cycle and its temporal buffer will never reach the
# required sequence depth.
# ================================================================


class TemporalProcessMonitor(
    ProcessMonitor,
):

    # ============================================================
    # INITIALIZATION
    # ============================================================

    def __init__(
        self,
        *args,
        temporal_database_path: Optional[
            str | Path
        ] = None,
        **kwargs,
    ):

        # ========================================================
        # BASE PROCESS MONITOR
        # ========================================================

        super().__init__(
            *args,
            **kwargs,
        )

        # ========================================================
        # TEMPORAL OBSERVATION BUILDER
        # ========================================================

        self.temporal_observation_builder = (
            ProcessTemporalObservationBuilder()
        )

        # ========================================================
        # TEMPORAL BUFFER
        # ========================================================

        self.temporal_buffer = (
            ProcessTemporalBuffer()
        )

        # ========================================================
        # TEMPORAL TRANSFORMER
        # ========================================================

        self.temporal_predictor = (
            ProcessTemporalPredictor(
                auto_load=True,
            )
        )

        # ========================================================
        # TEMPORAL RESULT STORE
        # ========================================================

        database_path = (
            Path(
                temporal_database_path
            )
            if temporal_database_path
            is not None
            else DEFAULT_DATABASE_PATH
        )

        self.temporal_result_store = (
            ProcessTemporalResultStore(
                database_path=
                    database_path,
            )
        )

        # ========================================================
        # DUAL AI AGREEMENT
        # ========================================================

        self.temporal_ai_agreement = (
            DualAIAgreementEngine()
        )

        # ========================================================
        # ALERT COOLDOWN
        # ========================================================

        self.temporal_alert_last_emitted: Dict[
            tuple[int, float],
            float,
        ] = {}

        self.temporal_alert_cooldown_seconds = (
            TEMPORAL_ALERT_COOLDOWN_SECONDS
        )

        # ========================================================
        # CLEANUP
        # ========================================================

        self.last_temporal_cleanup_time = (
            0.0
        )

        # ========================================================
        # TEMPORAL STATUS
        # ========================================================

        temporal_status = (
            self.temporal_predictor
            .get_status()
        )

        logger.info(
            "Temporal Transformer | "
            "Available=%s | "
            "Version=%s | "
            "Sequence=%s | "
            "Features=%s | "
            "Embedding=%s | "
            "Calibration=%s",

            temporal_status.get(
                "available"
            ),

            temporal_status.get(
                "model_version"
            ),

            temporal_status.get(
                "sequence_length"
            ),

            temporal_status.get(
                "feature_count"
            ),

            temporal_status.get(
                "representation_dimension"
            ),

            temporal_status.get(
                "calibration_version"
            ),
        )

    # ============================================================
    # TEMPORAL STATUS
    # ============================================================

    def get_temporal_status(
        self,
    ) -> Dict[str, Any]:

        return {

            "predictor":
                self.temporal_predictor
                .get_status(),

            "buffer":
                self.temporal_buffer
                .get_status(),

            "stored_results":
                self.temporal_result_store
                .count(),

            "stored_alert_candidates":
                self.temporal_result_store
                .count_alert_candidates(),
        }

    # ============================================================
    # LOAD FEATURE RECORD FROM DATABASE
    # ============================================================

    def load_feature_record_from_database(
        self,
        record_id: int,
    ) -> Optional[
        Dict[str, Any]
    ]:

        connection = (
            sqlite3.connect(
                DEFAULT_DATABASE_PATH,
                timeout=30.0,
            )
        )

        connection.row_factory = (
            sqlite3.Row
        )

        try:

            row = (
                connection.execute(
                    """
                    SELECT *

                    FROM process_behavior_features

                    WHERE id = ?
                    """,
                    (
                        int(
                            record_id
                        ),
                    ),
                )
                .fetchone()
            )

            if row is None:
                return None

            return dict(
                row
            )

        finally:

            connection.close()

    # ============================================================
    # RESOLVE FEATURE RECORD
    # ============================================================

    def resolve_feature_record(
        self,
        phase2_result: Dict[
            str,
            Any,
        ],
    ) -> Optional[Any]:

        if not isinstance(
            phase2_result,
            dict,
        ):

            return None

        # --------------------------------------------------------
        # POSSIBLE DIRECT FEATURE RECORD KEYS
        # --------------------------------------------------------

        for key in [

            "record",

            "feature_record",

            "feature_record_data",

        ]:

            value = (
                phase2_result.get(
                    key
                )
            )

            if value is not None:
                return value

        # --------------------------------------------------------
        # OTHERWISE LOAD USING RECORD ID
        # --------------------------------------------------------

        record_id = (
            phase2_result.get(
                "record_id"
            )
        )

        if record_id is None:

            record_id = (
                phase2_result.get(
                    "feature_record_id"
                )
            )

        if record_id is None:
            return None

        try:

            return (
                self
                .load_feature_record_from_database(
                    int(
                        record_id
                    )
                )
            )

        except Exception as error:

            logger.warning(
                "Temporal feature-record reload failed | "
                "Record=%s | "
                "Error=%s",

                record_id,

                error,
            )

            return None

    # ============================================================
    # RESOLVE FEATURE RECORD ID
    # ============================================================

    def resolve_feature_record_id(
        self,
        phase2_result: Dict[
            str,
            Any,
        ],
    ) -> Optional[int]:

        if not isinstance(
            phase2_result,
            dict,
        ):

            return None

        for key in [

            "record_id",

            "feature_record_id",

        ]:

            value = (
                phase2_result.get(
                    key
                )
            )

            if value is None:
                continue

            try:

                return int(
                    value
                )

            except (
                TypeError,
                ValueError,
            ):

                continue

        return None

    # ============================================================
    # NORMALIZE TEMPORAL PROCESS IDENTITY
    # ============================================================

    def normalize_temporal_identity(
        self,
        identity: Any,
        process_info: Optional[
            Dict[str, Any]
        ] = None,
    ) -> Optional[
        Dict[str, Any]
    ]:
        """
        Normalize identity before it reaches the Temporal buffer.

        Preferred identity:

            PID + real process creation time

        Fallback:

            PID + deterministic process-name fingerprint

        This function guarantees a numeric create_time whenever PID
        itself is valid.

        IMPORTANT:

        Never use time.time() here.

        Doing that would generate a different identity on each poll,
        destroying Temporal sequence continuity.
        """

        # --------------------------------------------------------
        # INPUT SAFETY
        # --------------------------------------------------------

        if not isinstance(
            identity,
            dict,
        ):

            identity = {}

        if not isinstance(
            process_info,
            dict,
        ):

            process_info = {}

        # --------------------------------------------------------
        # PID
        # --------------------------------------------------------

        pid = (
            identity.get(
                "pid"
            )
        )

        if pid is None:

            pid = (
                process_info.get(
                    "pid"
                )
            )

        try:

            pid = int(
                pid
            )

        except (
            TypeError,
            ValueError,
        ):

            return None

        # --------------------------------------------------------
        # PROCESS NAME
        # --------------------------------------------------------

        process_name = (

            identity.get(
                "process_name"
            )

            or identity.get(
                "name"
            )

            or process_info.get(
                "process_name"
            )

            or process_info.get(
                "name"
            )

            or "UNKNOWN"
        )

        process_name = (
            str(
                process_name
            )
            .strip()
        )

        if not process_name:

            process_name = (
                "UNKNOWN"
            )

        # --------------------------------------------------------
        # CREATE TIME
        #
        # Try all known keys.
        # --------------------------------------------------------

        create_time = (
            identity.get(
                "create_time"
            )
        )

        if create_time is None:

            create_time = (
                identity.get(
                    "process_create_time"
                )
            )

        if create_time is None:

            create_time = (
                process_info.get(
                    "create_time"
                )
            )

        if create_time is None:

            create_time = (
                process_info.get(
                    "process_create_time"
                )
            )

        identity_source = (
            "PID_CREATE_TIME"
        )

        # --------------------------------------------------------
        # VALID REAL CREATE TIME
        # --------------------------------------------------------

        try:

            normalized_create_time = (
                float(
                    create_time
                )
            )

            # Reject NaN
            if (
                normalized_create_time
                != normalized_create_time
            ):

                raise ValueError(
                    "NaN create_time"
                )

        except (
            TypeError,
            ValueError,
        ):

            # ====================================================
            # FALLBACK:
            #
            # PID + PROCESS NAME
            #
            # ProcessTemporalBuffer currently expects create_time
            # to be numeric.
            #
            # Therefore create a deterministic numeric token from
            # the process name.
            # ====================================================

            normalized_name = (
                process_name
                .strip()
                .casefold()
            )

            if not normalized_name:

                normalized_name = (
                    "unknown"
                )

            name_fingerprint = (
                zlib.crc32(
                    normalized_name.encode(
                        "utf-8",
                        errors="replace",
                    )
                )
                & 0xFFFFFFFF
            )

            # ----------------------------------------------------
            # Real Unix timestamps are positive.
            #
            # Negative values clearly indicate a fallback identity.
            # ----------------------------------------------------

            normalized_create_time = (
                -float(
                    name_fingerprint
                    + 1
                )
            )

            identity_source = (
                "PID_PROCESS_NAME_FALLBACK"
            )

        # --------------------------------------------------------
        # ALWAYS RETURN REQUIRED KEYS
        # --------------------------------------------------------

        return {

            "pid":
                pid,

            "create_time":
                normalized_create_time,

            "process_name":
                process_name,

            "identity_source":
                identity_source,
        }

    # ============================================================
    # RESOLVE PROCESS IDENTITY
    # ============================================================

    def resolve_process_identity(
        self,
        process_info: Dict[
            str,
            Any,
        ],
    ) -> Optional[
        Dict[str, Any]
    ]:

        if not isinstance(
            process_info,
            dict,
        ):

            return None

        pid = (
            process_info.get(
                "pid"
            )
        )

        process_name = (

            process_info.get(
                "name"
            )

            or process_info.get(
                "process_name"
            )

            or "UNKNOWN"
        )

        create_time = (
            process_info.get(
                "create_time"
            )
        )

        if create_time is None:

            create_time = (
                process_info.get(
                    "process_create_time"
                )
            )

        raw_identity = {

            "pid":
                pid,

            "process_name":
                process_name,

            "create_time":
                create_time,
        }

        normalized = (
            self
            .normalize_temporal_identity(
                identity=
                    raw_identity,

                process_info=
                    process_info,
            )
        )

        if normalized is None:

            return None

        # --------------------------------------------------------
        # FINAL INVARIANT CHECK
        # --------------------------------------------------------

        if normalized.get(
            "pid"
        ) is None:

            return None

        if normalized.get(
            "create_time"
        ) is None:

            logger.error(
                "Temporal identity normalization failed | "
                "PID=%s | "
                "Process=%s",

                pid,

                process_name,
            )

            return None

        return normalized

    # ============================================================
    # GET TEMPORAL PROCESS KEY
    #
    # IMPORTANT:
    #
    # This method is intentionally defensive.
    #
    # Even if a future subclass or caller passes an incomplete
    # identity, this method will normalize it again instead of
    # directly calling identity["create_time"].
    # ============================================================

    def get_temporal_process_key(
        self,
        identity: Dict[
            str,
            Any,
        ],
    ) -> tuple[
        int,
        float,
    ]:

        if not isinstance(
            identity,
            dict,
        ):

            raise ValueError(
                "Temporal process identity "
                "must be a dictionary."
            )

        # --------------------------------------------------------
        # FINAL NORMALIZATION BOUNDARY
        # --------------------------------------------------------

        normalized = (
            self
            .normalize_temporal_identity(
                identity=
                    identity,

                process_info=
                    identity,
            )
        )

        if normalized is None:

            raise ValueError(
                "Unable to construct "
                "Temporal process identity."
            )

        pid = (
            normalized.get(
                "pid"
            )
        )

        create_time = (
            normalized.get(
                "create_time"
            )
        )

        process_name = (
            normalized.get(
                "process_name",
                "UNKNOWN",
            )
        )

        # --------------------------------------------------------
        # PID VALIDATION
        # --------------------------------------------------------

        try:

            pid = int(
                pid
            )

        except (
            TypeError,
            ValueError,
        ) as error:

            raise ValueError(
                "Temporal identity "
                "contains invalid PID."
            ) from error

        # --------------------------------------------------------
        # CREATE TIME EMERGENCY FALLBACK
        #
        # normalize_temporal_identity normally guarantees this,
        # but keeping another guard here makes KeyError impossible.
        # --------------------------------------------------------

        if create_time is None:

            normalized_name = (
                str(
                    process_name
                )
                .strip()
                .casefold()
            )

            if not normalized_name:

                normalized_name = (
                    "unknown"
                )

            name_fingerprint = (
                zlib.crc32(
                    normalized_name.encode(
                        "utf-8",
                        errors="replace",
                    )
                )
                & 0xFFFFFFFF
            )

            create_time = (
                -float(
                    name_fingerprint
                    + 1
                )
            )

            logger.warning(
                "Temporal identity emergency fallback | "
                "PID=%s | "
                "Process=%s",

                pid,

                process_name,
            )

        try:

            create_time = (
                float(
                    create_time
                )
            )

        except (
            TypeError,
            ValueError,
        ) as error:

            raise ValueError(
                "Temporal identity contains "
                "invalid create_time."
            ) from error

        return (
            pid,
            create_time,
        )

    # ============================================================
    # GET PREVIOUS TEMPORAL TIMESTAMP
    # ============================================================

    def get_previous_temporal_timestamp(
        self,
        *,
        pid: int,
        create_time: float,
    ) -> Optional[float]:

        observations = (
            self.temporal_buffer
            .get_observation_metadata(
                pid=
                    pid,

                create_time=
                    create_time,
            )
        )

        if not observations:
            return None

        last_observation = (
            observations[
                -1
            ]
        )

        timestamp = (
            last_observation.get(
                "timestamp"
            )
        )

        if timestamp is None:
            return None

        try:

            return float(
                timestamp
            )

        except (
            TypeError,
            ValueError,
        ):

            return None

    # ============================================================
    # CALCULATE DUAL-AI CONSENSUS
    # ============================================================

    def calculate_temporal_ai_consensus(
        self,
        isolation_result: Dict[
            str,
            Any,
        ],
        autoencoder_result: Dict[
            str,
            Any,
        ],
    ) -> Dict[
        str,
        Any,
    ]:

        return (
            self.temporal_ai_agreement
            .calculate(
                isolation_result=
                    isolation_result,

                autoencoder_result=
                    autoencoder_result,
            )
        )

    # ============================================================
    # TEMPORAL ALERT COOLDOWN
    # ============================================================

    def temporal_alert_allowed(
        self,
        *,
        pid: int,
        create_time: float,
        current_time: float,
    ) -> bool:

        key = (
            int(
                pid
            ),

            float(
                create_time
            ),
        )

        previous = (
            self
            .temporal_alert_last_emitted
            .get(
                key
            )
        )

        if previous is None:
            return True

        elapsed = (
            current_time
            - previous
        )

        return (
            elapsed
            >=
            self.temporal_alert_cooldown_seconds
        )

    # ============================================================
    # MARK TEMPORAL ALERT
    # ============================================================

    def mark_temporal_alert(
        self,
        *,
        pid: int,
        create_time: float,
        current_time: float,
    ) -> None:

        key = (
            int(
                pid
            ),

            float(
                create_time
            ),
        )

        self.temporal_alert_last_emitted[
            key
        ] = float(
            current_time
        )

    # ============================================================
    # CLEAN TEMPORAL STATE
    # ============================================================

    def cleanup_temporal_state_if_needed(
        self,
        current_time: float,
    ) -> None:

        elapsed = (
            current_time
            - self.last_temporal_cleanup_time
        )

        if (
            elapsed
            <
            TEMPORAL_STALE_CLEANUP_INTERVAL_SECONDS
        ):

            return

        try:

            removed = (
                self.temporal_buffer
                .cleanup_stale(
                    now=
                        current_time
                )
            )

        except Exception:

            logger.exception(
                "Temporal stale-buffer cleanup failed."
            )

            self.last_temporal_cleanup_time = (
                current_time
            )

            return

        self.last_temporal_cleanup_time = (
            current_time
        )

        if removed > 0:

            logger.info(
                "Temporal buffer cleanup | "
                "Removed=%s",

                removed,
            )

    # ============================================================
    # PROCESS TEMPORAL SAMPLE
    # ============================================================

    def process_temporal_sample(
        self,
        *,
        process_info: Dict[
            str,
            Any,
        ],
        feature_record: Any,
        feature_record_id: int,
        isolation_result: Dict[
            str,
            Any,
        ],
        autoencoder_result: Dict[
            str,
            Any,
        ],
        timestamp: Optional[
            float
        ] = None,
    ) -> Dict[
        str,
        Any,
    ]:

        # ========================================================
        # CURRENT TIMESTAMP
        # ========================================================

        current_time = (
            float(
                timestamp
            )

            if timestamp
            is not None

            else time.time()
        )

        # ========================================================
        # TEMPORAL MODEL AVAILABILITY
        # ========================================================

        if not (
            self.temporal_predictor
            .available
        ):

            return {

                "available":
                    False,

                "state":
                    "TEMPORAL_MODEL_UNAVAILABLE",

                "error":
                    self.temporal_predictor
                    .load_error,
            }

        # ========================================================
        # RESOLVE PROCESS IDENTITY
        # ========================================================

        identity = (
            self
            .resolve_process_identity(
                process_info
            )
        )

        if identity is None:

            logger.warning(
                "Temporal sample skipped | "
                "Reason=INVALID_PROCESS_IDENTITY | "
                "PID=%s | "
                "Process=%s",

                process_info.get(
                    "pid"
                )
                if isinstance(
                    process_info,
                    dict,
                )
                else None,

                process_info.get(
                    "name"
                )
                if isinstance(
                    process_info,
                    dict,
                )
                else None,
            )

            return {

                "available":
                    False,

                "state":
                    "INVALID_PROCESS_IDENTITY",

                "error":
                    "Temporal sample requires "
                    "a valid process PID.",
            }

        # ========================================================
        # SECOND NORMALIZATION BOUNDARY
        #
        # Do this intentionally.
        #
        # This guarantees create_time exists immediately before
        # using it as a Temporal buffer key.
        # ========================================================

        identity = (
            self
            .normalize_temporal_identity(
                identity=
                    identity,

                process_info=
                    process_info,
            )
        )

        if identity is None:

            return {

                "available":
                    False,

                "state":
                    "INVALID_PROCESS_IDENTITY",

                "error":
                    "Unable to normalize "
                    "Temporal process identity.",
            }

        # ========================================================
        # SAFE TEMPORAL PROCESS KEY
        # ========================================================

        try:

            pid, create_time = (
                self
                .get_temporal_process_key(
                    identity
                )
            )

        except Exception as error:

            logger.warning(
                "Temporal identity key failure | "
                "PID=%s | "
                "Process=%s | "
                "Error=%s",

                process_info.get(
                    "pid"
                ),

                process_info.get(
                    "name"
                ),

                error,
            )

            return {

                "available":
                    False,

                "state":
                    "TEMPORAL_IDENTITY_KEY_FAILED",

                "error":
                    str(
                        error
                    ),
            }

        process_name = (
            identity.get(
                "process_name",
                "UNKNOWN",
            )
        )

        identity_source = (
            identity.get(
                "identity_source",
                "UNKNOWN",
            )
        )

        # --------------------------------------------------------
        # LOG FALLBACK IDENTITY AT DEBUG LEVEL
        # --------------------------------------------------------

        if (
            identity_source
            ==
            "PID_PROCESS_NAME_FALLBACK"
        ):

            logger.debug(
                "Temporal identity fallback | "
                "PID=%s | "
                "Process=%s | "
                "Mode=PID_PROCESS_NAME",

                pid,

                process_name,
            )

        # ========================================================
        # PREVIOUS TEMPORAL TIMESTAMP
        # ========================================================

        previous_timestamp = (
            self
            .get_previous_temporal_timestamp(
                pid=
                    pid,

                create_time=
                    create_time,
            )
        )

        # ========================================================
        # DUAL-AI CONSENSUS
        # ========================================================

        consensus_result = (
            self
            .calculate_temporal_ai_consensus(
                isolation_result=
                    isolation_result,

                autoencoder_result=
                    autoencoder_result,
            )
        )

        # ========================================================
        # BUILD TEMPORAL OBSERVATION
        #
        # Temporal v1 expects exact training-compatible vector.
        # ========================================================

        observation = (
            self
            .temporal_observation_builder
            .build(
                feature_record=
                    feature_record,

                isolation_result=
                    isolation_result,

                autoencoder_result=
                    autoencoder_result,

                consensus_result=
                    consensus_result,

                timestamp=
                    current_time,

                previous_timestamp=
                    previous_timestamp,
            )
        )

        if not isinstance(
            observation,
            dict,
        ):

            return {

                "available":
                    False,

                "state":
                    "TEMPORAL_OBSERVATION_FAILED",

                "error":
                    "Observation builder "
                    "did not return a dictionary.",
            }

        vector = (
            observation.get(
                "vector"
            )
        )

        if vector is None:

            return {

                "available":
                    False,

                "state":
                    "TEMPORAL_VECTOR_MISSING",

                "error":
                    "Temporal observation "
                    "contains no vector.",
            }

        # ========================================================
        # ADD TO TEMPORAL BUFFER
        # ========================================================

        buffer_result = (
            self.temporal_buffer
            .add_observation(
                pid=
                    pid,

                create_time=
                    create_time,

                vector=
                    vector,

                timestamp=
                    current_time,

                feature_record_id=
                    int(
                        feature_record_id
                    ),

                process_name=
                    process_name,

                metadata={

                    "isolation_forest_score":
                        observation.get(
                            "isolation_forest_score"
                        ),

                    "autoencoder_score":
                        observation.get(
                            "autoencoder_score"
                        ),

                    "dual_ai_consensus_score":
                        observation.get(
                            "dual_ai_consensus_score"
                        ),

                    "delta_seconds":
                        observation.get(
                            "delta_seconds"
                        ),

                    "identity_source":
                        identity_source,
                },
            )
        )

        # ========================================================
        # PERIODIC CLEANUP
        # ========================================================

        self.cleanup_temporal_state_if_needed(
            current_time
        )

        # ========================================================
        # VALIDATE BUFFER RESPONSE
        # ========================================================

        if not isinstance(
            buffer_result,
            dict,
        ):

            return {

                "available":
                    False,

                "state":
                    "TEMPORAL_BUFFER_ERROR",

                "error":
                    "Temporal buffer returned "
                    "an invalid result.",
            }

        # ========================================================
        # COLLECTING HISTORY
        # ========================================================

        if not buffer_result.get(
            "ready",
            False,
        ):

            depth = (
                buffer_result.get(
                    "depth",
                    0,
                )
            )

            logger.debug(
                "TEMPORAL BUFFER | "
                "PID=%s | "
                "Process=%s | "
                "Depth=%s/%s",

                pid,

                process_name,

                depth,

                TEMPORAL_SEQUENCE_LENGTH,
            )

            return {

                "available":
                    True,

                "state":
                    "COLLECTING_HISTORY",

                "pid":
                    pid,

                "process_name":
                    process_name,

                "create_time":
                    create_time,

                "identity_source":
                    identity_source,

                "feature_record_id":
                    feature_record_id,

                "depth":
                    depth,

                "required_depth":
                    TEMPORAL_SEQUENCE_LENGTH,

                "ready":
                    False,

                "buffer":
                    buffer_result,

                "observation":
                    observation,

                "dual_ai_consensus":
                    consensus_result,
            }

        # ========================================================
        # GET TEMPORAL SEQUENCE
        # ========================================================

        sequence = (
            self.temporal_buffer
            .get_sequence(
                pid=
                    pid,

                create_time=
                    create_time,
            )
        )

        if sequence is None:

            return {

                "available":
                    False,

                "state":
                    "SEQUENCE_READ_FAILED",

                "pid":
                    pid,

                "process_name":
                    process_name,

                "create_time":
                    create_time,
            }

        # ========================================================
        # TEMPORAL TRANSFORMER INFERENCE
        # ========================================================

        temporal_result = (
            self.temporal_predictor
            .predict(
                sequence,
                input_is_normalized=False,
            )
        )

        if not isinstance(
            temporal_result,
            dict,
        ):

            return {

                "available":
                    False,

                "state":
                    "TEMPORAL_INFERENCE_FAILED",

                "pid":
                    pid,

                "process_name":
                    process_name,

                "error":
                    "Predictor returned "
                    "invalid result.",
            }

        if not temporal_result.get(
            "available",
            False,
        ):

            logger.warning(
                "Temporal Transformer inference failed | "
                "PID=%s | "
                "Process=%s | "
                "Error=%s",

                pid,

                process_name,

                temporal_result.get(
                    "error"
                ),
            )

            return {

                "available":
                    False,

                "state":
                    "TEMPORAL_INFERENCE_FAILED",

                "pid":
                    pid,

                "process_name":
                    process_name,

                "create_time":
                    create_time,

                "error":
                    temporal_result.get(
                        "error"
                    ),

                "buffer":
                    buffer_result,
            }

        # ========================================================
        # SEQUENCE METADATA
        # ========================================================

        observation_metadata = (
            self.temporal_buffer
            .get_observation_metadata(
                pid=
                    pid,

                create_time=
                    create_time,
            )
        )

        feature_record_ids = (
            self.temporal_buffer
            .get_feature_record_ids(
                pid=
                    pid,

                create_time=
                    create_time,
            )
        )

        if not observation_metadata:

            raise RuntimeError(
                "Temporal sequence metadata "
                "is unavailable."
            )

        if not feature_record_ids:

            raise RuntimeError(
                "Temporal feature-record IDs "
                "are unavailable."
            )

        sequence_start_timestamp = (
            float(
                observation_metadata[
                    0
                ][
                    "timestamp"
                ]
            )
        )

        sequence_end_timestamp = (
            float(
                observation_metadata[
                    -1
                ][
                    "timestamp"
                ]
            )
        )

        # ========================================================
        # SEQUENCE GENERATION
        # ========================================================

        sequence_generation = (
            buffer_result.get(
                "sequence_generation",
                0,
            )
        )

        try:

            sequence_generation = (
                int(
                    sequence_generation
                )
            )

        except (
            TypeError,
            ValueError,
        ):

            sequence_generation = 0

        # ========================================================
        # PERSIST TEMPORAL RESULT
        # ========================================================

        temporal_result_id = (
            self.temporal_result_store
            .save_result(
                feature_record_id=
                    int(
                        feature_record_id
                    ),

                pid=
                    pid,

                process_name=
                    process_name,

                process_create_time=
                    create_time,

                sequence_generation=
                    sequence_generation,

                sequence_feature_record_ids=
                    feature_record_ids,

                sequence_start_timestamp=
                    sequence_start_timestamp,

                sequence_end_timestamp=
                    sequence_end_timestamp,

                temporal_result=
                    temporal_result,
            )
        )

        # ========================================================
        # TEMPORAL ALERT
        #
        # Temporal does NOT directly create another SOC incident.
        #
        # Fusion-v3 consumes temporal evidence later.
        # ========================================================

        temporal_alert_emitted = (
            False
        )

        if temporal_result.get(
            "should_alert",
            False,
        ):

            if self.temporal_alert_allowed(
                pid=
                    pid,

                create_time=
                    create_time,

                current_time=
                    current_time,
            ):

                self.mark_temporal_alert(
                    pid=
                        pid,

                    create_time=
                        create_time,

                    current_time=
                        current_time,
                )

                temporal_alert_emitted = (
                    True
                )

                anomaly_score = (
                    temporal_result.get(
                        "anomaly_score",
                        0.0,
                    )
                )

                raw_error = (
                    temporal_result.get(
                        "raw_temporal_reconstruction_error",
                        0.0,
                    )
                )

                try:

                    anomaly_score = float(
                        anomaly_score
                    )

                except (
                    TypeError,
                    ValueError,
                ):

                    anomaly_score = 0.0

                try:

                    raw_error = float(
                        raw_error
                    )

                except (
                    TypeError,
                    ValueError,
                ):

                    raw_error = 0.0

                logger.warning(
                    "TEMPORAL AI SIGNAL | "
                    "PID=%s | "
                    "Process=%s | "
                    "Score=%.2f | "
                    "Label=%s | "
                    "Severity=%s | "
                    "RawError=%.6f | "
                    "MostUnusualTimestep=%s",

                    pid,

                    process_name,

                    anomaly_score,

                    temporal_result.get(
                        "anomaly_label"
                    ),

                    temporal_result.get(
                        "severity"
                    ),

                    raw_error,

                    temporal_result.get(
                        "most_unusual_timestep"
                    ),
                )

        # ========================================================
        # NORMAL TEMPORAL INFERENCE LOG
        # ========================================================

        anomaly_score = (
            temporal_result.get(
                "anomaly_score",
                0.0,
            )
        )

        try:

            anomaly_score = float(
                anomaly_score
            )

        except (
            TypeError,
            ValueError,
        ):

            anomaly_score = 0.0

        logger.info(
            "TEMPORAL AI | "
            "PID=%s | "
            "Process=%s | "
            "Depth=%s | "
            "Score=%.2f | "
            "Label=%s | "
            "Embedding=%s | "
            "ResultID=%s",

            pid,

            process_name,

            buffer_result.get(
                "depth"
            ),

            anomaly_score,

            temporal_result.get(
                "anomaly_label"
            ),

            temporal_result.get(
                "temporal_embedding_dimension"
            ),

            temporal_result_id,
        )

        # ========================================================
        # COMPLETE RESULT
        # ========================================================

        return {

            "available":
                True,

            "state":
                "TEMPORAL_INFERENCE_COMPLETE",

            "pid":
                pid,

            "process_name":
                process_name,

            "create_time":
                create_time,

            "identity_source":
                identity_source,

            "feature_record_id":
                feature_record_id,

            "depth":
                buffer_result.get(
                    "depth"
                ),

            "ready":
                True,

            "buffer":
                buffer_result,

            "observation":
                observation,

            "dual_ai_consensus":
                consensus_result,

            "temporal_result":
                temporal_result,

            "temporal_result_id":
                temporal_result_id,

            "temporal_alert_emitted":
                temporal_alert_emitted,
        }

    # ============================================================
    # OVERRIDE PHASE-2 AI FEATURE COLLECTION
    #
    # Existing ProcessMonitor pipeline executes FIRST.
    #
    # Temporal AI runs only after the existing Phase-2 logic.
    #
    # Temporal failures must NOT break ProcessMonitor.
    # ============================================================

    def collect_ai_behavior_features(
        self,
        process_info: Dict[
            str,
            Any,
        ],
        context: Dict[
            str,
            Any,
        ],
    ) -> Dict[
        str,
        Any,
    ]:

        # ========================================================
        # EXISTING PHASE-2 PIPELINE
        # ========================================================

        phase2_result = (
            super()
            .collect_ai_behavior_features(
                process_info=
                    process_info,

                context=
                    context,
            )
        )

        # ========================================================
        # PRESERVE ORIGINAL RESULT
        # ========================================================

        if not isinstance(
            phase2_result,
            dict,
        ):

            return phase2_result

        # ========================================================
        # FEATURE RECORD ID
        # ========================================================

        record_id = (
            self
            .resolve_feature_record_id(
                phase2_result
            )
        )

        # ========================================================
        # ISOLATION FOREST RESULT
        # ========================================================

        isolation_result = (
            phase2_result.get(
                "isolation_forest"
            )
        )

        # ========================================================
        # AUTOENCODER RESULT
        # ========================================================

        autoencoder_result = (
            phase2_result.get(
                "autoencoder"
            )
        )

        # ========================================================
        # RECORD ID VALIDATION
        # ========================================================

        if record_id is None:

            phase2_result[
                "temporal"
            ] = {

                "available":
                    False,

                "state":
                    "MISSING_FEATURE_RECORD_ID",
            }

            return phase2_result

        # ========================================================
        # ISOLATION RESULT VALIDATION
        # ========================================================

        if not isinstance(
            isolation_result,
            dict,
        ):

            phase2_result[
                "temporal"
            ] = {

                "available":
                    False,

                "state":
                    "MISSING_ISOLATION_RESULT",
            }

            return phase2_result

        # ========================================================
        # AUTOENCODER RESULT VALIDATION
        # ========================================================

        if not isinstance(
            autoencoder_result,
            dict,
        ):

            phase2_result[
                "temporal"
            ] = {

                "available":
                    False,

                "state":
                    "MISSING_AUTOENCODER_RESULT",
            }

            return phase2_result

        # ========================================================
        # ISOLATION MODEL AVAILABILITY
        # ========================================================

        if isolation_result.get(
            "available"
        ) is False:

            phase2_result[
                "temporal"
            ] = {

                "available":
                    False,

                "state":
                    "ISOLATION_MODEL_UNAVAILABLE",
            }

            return phase2_result

        # ========================================================
        # AUTOENCODER AVAILABILITY
        # ========================================================

        if autoencoder_result.get(
            "available"
        ) is False:

            phase2_result[
                "temporal"
            ] = {

                "available":
                    False,

                "state":
                    "AUTOENCODER_UNAVAILABLE",
            }

            return phase2_result

        # ========================================================
        # FEATURE RECORD
        # ========================================================

        feature_record = (
            self
            .resolve_feature_record(
                phase2_result
            )
        )

        if feature_record is None:

            phase2_result[
                "temporal"
            ] = {

                "available":
                    False,

                "state":
                    "FEATURE_RECORD_UNAVAILABLE",
            }

            return phase2_result

        # ========================================================
        # TEMPORAL PIPELINE
        # ========================================================

        try:

            temporal_output = (
                self
                .process_temporal_sample(
                    process_info=
                        process_info,

                    feature_record=
                        feature_record,

                    feature_record_id=
                        record_id,

                    isolation_result=
                        isolation_result,

                    autoencoder_result=
                        autoencoder_result,
                )
            )

        except Exception as error:

            logger.exception(
                "Temporal integration failure | "
                "PID=%s | "
                "Process=%s",

                process_info.get(
                    "pid"
                ),

                process_info.get(
                    "name"
                ),
            )

            temporal_output = {

                "available":
                    False,

                "state":
                    "TEMPORAL_PIPELINE_EXCEPTION",

                "error":
                    str(
                        error
                    ),
            }

        # ========================================================
        # EXPOSE TEMPORAL OUTPUT
        # ========================================================

        phase2_result[
            "temporal"
        ] = temporal_output

        return phase2_result