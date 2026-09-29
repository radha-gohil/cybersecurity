from __future__ import annotations

import sqlite3
import time

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
# Extends the already-working ProcessMonitor.
#
# Existing Phase-2 behavior is preserved by:
#
#       result = super().collect_ai_behavior_features(...)
#
# Only AFTER Phase-2 completes successfully do we:
#
#       IF + AE
#           ↓
#       Dual-AI agreement
#           ↓
#       build 27D temporal observation
#           ↓
#       rolling 8-step buffer
#           ↓
#       Transformer
#           ↓
#       persistence
#
#
# This class does NOT modify Fusion v2 yet.
#
# Fusion v3 comes after temporal live inference is verified.
# ================================================================


class TemporalProcessMonitor(
    ProcessMonitor,
):

    def __init__(
        self,
        *args,
        temporal_database_path: Optional[
            str | Path
        ] = None,
        **kwargs,
    ):

        # ========================================================
        # EXISTING PHASE-2 MONITOR
        # ========================================================

        super().__init__(
            *args,
            **kwargs,
        )


        # ========================================================
        # TEMPORAL AI COMPONENTS
        # ========================================================

        self.temporal_observation_builder = (
            ProcessTemporalObservationBuilder()
        )


        self.temporal_buffer = (
            ProcessTemporalBuffer()
        )


        self.temporal_predictor = (
            ProcessTemporalPredictor(
                auto_load=True
            )
        )


        self.temporal_result_store = (
            ProcessTemporalResultStore(

                database_path=(
                    temporal_database_path

                    if temporal_database_path
                    is not None

                    else DEFAULT_DATABASE_PATH
                )
            )
        )


        self.temporal_ai_agreement = (
            DualAIAgreementEngine()
        )


        # ========================================================
        # TEMPORAL ALERT COOLDOWN
        # ========================================================

        self.temporal_alert_last_emitted = {}


        self.temporal_alert_cooldown_seconds = (
            TEMPORAL_ALERT_COOLDOWN_SECONDS
        )


        # ========================================================
        # CLEANUP
        # ========================================================

        self.last_temporal_cleanup_time = 0.0


        # ========================================================
        # STATUS
        # ========================================================

        temporal_status = (
            self.temporal_predictor.get_status()
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
                self.temporal_predictor.get_status(),

            "buffer":
                self.temporal_buffer.get_status(),

            "stored_results":
                self.temporal_result_store.count(),

            "stored_alert_candidates":
                self.temporal_result_store
                .count_alert_candidates(),
        }


    # ============================================================
    # LOAD FEATURE RECORD FROM SQLITE
    #
    # This fallback makes the wrapper robust even if the existing
    # ProcessMonitor returns only record_id instead of the complete
    # feature record.
    # ============================================================

    def load_feature_record_from_database(
        self,
        record_id: int,
    ) -> Optional[
        Dict[str, Any]
    ]:

        connection = sqlite3.connect(

            DEFAULT_DATABASE_PATH,

            timeout=30.0,
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
        phase2_result: Dict[str, Any],
    ) -> Optional[Any]:

        # --------------------------------------------------------
        # Support several possible result names without changing
        # the working Phase-2 monitor.
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
                self.load_feature_record_from_database(
                    int(
                        record_id
                    )
                )
            )


        except Exception as error:

            logger.warning(

                "Temporal feature-record reload failed | "
                "Record=%s | Error=%s",

                record_id,

                error,
            )


            return None


    # ============================================================
    # RESOLVE RECORD ID
    # ============================================================

    def resolve_feature_record_id(
        self,
        phase2_result: Dict[str, Any],
    ) -> Optional[int]:

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
    # RESOLVE PROCESS IDENTITY
    # ============================================================

    def resolve_process_identity(
        self,
        process_info: Dict[str, Any],
    ) -> Dict[str, Any]:

        pid = (
            process_info.get(
                "pid"
            )
        )


        create_time = (
            process_info.get(
                "create_time"
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


        try:

            pid = int(
                pid
            )


        except (
            TypeError,
            ValueError,
        ) as error:

            raise ValueError(

                "Temporal integration requires "
                "a valid process PID."
            ) from error


        try:

            create_time = float(
                create_time
            )


        except (
            TypeError,
            ValueError,
        ) as error:

            raise ValueError(

                "Temporal integration requires "
                "process create_time."
            ) from error


        return {
            "pid":
                pid,

            "create_time":
                create_time,

            "process_name":
                str(
                    process_name
                ),
        }


    # ============================================================
    # PREVIOUS OBSERVATION TIMESTAMP
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


        return float(

            observations[
                -1
            ][
                "timestamp"
            ]
        )


    # ============================================================
    # CALCULATE DUAL-AI CONSENSUS
    # ============================================================

    def calculate_temporal_ai_consensus(
        self,
        isolation_result: Dict[str, Any],
        autoencoder_result: Dict[str, Any],
    ) -> Dict[str, Any]:

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
            self.temporal_alert_last_emitted.get(
                key
            )
        )


        if previous is None:

            return True


        return (

            current_time
            - previous

            >= self.temporal_alert_cooldown_seconds
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
    # CLEAN STALE TEMPORAL STATE
    # ============================================================

    def cleanup_temporal_state_if_needed(
        self,
        current_time: float,
    ) -> None:

        if (

            current_time
            - self.last_temporal_cleanup_time

            < TEMPORAL_STALE_CLEANUP_INTERVAL_SECONDS

        ):

            return


        removed = (
            self.temporal_buffer.cleanup_stale(
                now=current_time
            )
        )


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
    #
    # This can also be called directly by E2E tests.
    # ============================================================

    def process_temporal_sample(
        self,
        *,
        process_info: Dict[str, Any],
        feature_record: Any,
        feature_record_id: int,
        isolation_result: Dict[str, Any],
        autoencoder_result: Dict[str, Any],
        timestamp: Optional[float] = None,
    ) -> Dict[str, Any]:

        current_time = (

            float(
                timestamp
            )

            if timestamp is not None

            else time.time()
        )


        # ========================================================
        # PREDICTOR AVAILABILITY
        # ========================================================

        if not self.temporal_predictor.available:

            return {
                "available":
                    False,

                "state":
                    "TEMPORAL_MODEL_UNAVAILABLE",

                "error":
                    self.temporal_predictor.load_error,
            }


        # ========================================================
        # PROCESS IDENTITY
        # ========================================================

        identity = (
            self.resolve_process_identity(
                process_info
            )
        )


        pid = (
            identity[
                "pid"
            ]
        )


        create_time = (
            identity[
                "create_time"
            ]
        )


        process_name = (
            identity[
                "process_name"
            ]
        )


        # ========================================================
        # PREVIOUS TIMESTAMP
        # ========================================================

        previous_timestamp = (
            self.get_previous_temporal_timestamp(

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
            self.calculate_temporal_ai_consensus(

                isolation_result=
                    isolation_result,

                autoencoder_result=
                    autoencoder_result,
            )
        )


        # ========================================================
        # BUILD EXACT 27D TRAINING-COMPATIBLE VECTOR
        # ========================================================

        observation = (
            self.temporal_observation_builder
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


        # ========================================================
        # ADD TO ROLLING BUFFER
        # ========================================================

        buffer_result = (
            self.temporal_buffer
            .add_observation(

                pid=
                    pid,

                create_time=
                    create_time,

                vector=
                    observation[
                        "vector"
                    ],

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
                        observation[
                            "isolation_forest_score"
                        ],

                    "autoencoder_score":
                        observation[
                            "autoencoder_score"
                        ],

                    "dual_ai_consensus_score":
                        observation[
                            "dual_ai_consensus_score"
                        ],

                    "delta_seconds":
                        observation[
                            "delta_seconds"
                        ],
                },
            )
        )


        # ========================================================
        # CLEANUP
        # ========================================================

        self.cleanup_temporal_state_if_needed(
            current_time
        )


        # ========================================================
        # NOT ENOUGH HISTORY YET
        # ========================================================

        if not buffer_result[
            "ready"
        ]:

            logger.debug(

                "TEMPORAL BUFFER | "
                "PID=%s | "
                "Process=%s | "
                "Depth=%s/%s",

                pid,

                process_name,

                buffer_result[
                    "depth"
                ],

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

                "feature_record_id":
                    feature_record_id,

                "depth":
                    buffer_result[
                        "depth"
                    ],

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
        # GET 8 × 27 SEQUENCE
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
            }


        # ========================================================
        # TEMPORAL TRANSFORMER
        # ========================================================

        temporal_result = (
            self.temporal_predictor.predict(

                sequence,

                input_is_normalized=False,
            )
        )


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

                "Temporal sequence metadata is unavailable."
            )


        if not feature_record_ids:

            raise RuntimeError(

                "Temporal feature-record IDs are unavailable."
            )


        sequence_start_timestamp = float(

            observation_metadata[
                0
            ][
                "timestamp"
            ]
        )


        sequence_end_timestamp = float(

            observation_metadata[
                -1
            ][
                "timestamp"
            ]
        )


        # ========================================================
        # PERSIST RESULT
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
                    int(
                        buffer_result[
                            "sequence_generation"
                        ]
                    ),

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
        # TEMPORAL ALERT COOLDOWN
        #
        # We only log the temporal alert here.
        #
        # We do NOT yet create another SOC incident because Fusion
        # v3 will combine temporal evidence with the other engines.
        # ========================================================

        temporal_alert_emitted = False


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


                temporal_alert_emitted = True


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

                    float(
                        temporal_result[
                            "anomaly_score"
                        ]
                    ),

                    temporal_result[
                        "anomaly_label"
                    ],

                    temporal_result[
                        "severity"
                    ],

                    float(
                        temporal_result[
                            "raw_temporal_reconstruction_error"
                        ]
                    ),

                    temporal_result[
                        "most_unusual_timestep"
                    ],
                )


        # ========================================================
        # NORMAL TEMPORAL LOG
        # ========================================================

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

            buffer_result[
                "depth"
            ],

            float(
                temporal_result[
                    "anomaly_score"
                ]
            ),

            temporal_result[
                "anomaly_label"
            ],

            temporal_result[
                "temporal_embedding_dimension"
            ],

            temporal_result_id,
        )


        return {
            "available":
                True,

            "state":
                "TEMPORAL_INFERENCE_COMPLETE",

            "pid":
                pid,

            "process_name":
                process_name,

            "feature_record_id":
                feature_record_id,

            "depth":
                buffer_result[
                    "depth"
                ],

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
    # OVERRIDE EXISTING PHASE-2 FEATURE COLLECTION
    #
    # Existing code executes FIRST.
    # ============================================================

    def collect_ai_behavior_features(
        self,
        process_info: Dict[str, Any],
        context: Dict[str, Any],
    ) -> Dict[str, Any]:

        # ========================================================
        # EXISTING WORKING PHASE-2 PIPELINE
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


        # Always preserve original result.

        if not isinstance(
            phase2_result,
            dict,
        ):

            return phase2_result


        # ========================================================
        # RESOLVE REQUIRED PHASE-2 OUTPUT
        # ========================================================

        record_id = (
            self.resolve_feature_record_id(
                phase2_result
            )
        )


        isolation_result = (
            phase2_result.get(
                "isolation_forest"
            )
        )


        autoencoder_result = (
            phase2_result.get(
                "autoencoder"
            )
        )


        # --------------------------------------------------------
        # Do not let temporal integration break Phase-2 execution.
        # --------------------------------------------------------

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


        feature_record = (
            self.resolve_feature_record(
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
                self.process_temporal_sample(

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
        # EXPOSE TEMPORAL RESULT TO CALLER
        # ========================================================

        phase2_result[
            "temporal"
        ] = temporal_output


        return phase2_result