from __future__ import annotations

from pathlib import Path

from typing import (
    Any,
    Dict,
    Optional,
)


# ================================================================
# EXISTING FUSION V3 SHADOW MONITOR
# ================================================================

from endpoint.collectors.fusion_v3_process_monitor import (
    FusionV3ProcessMonitor,
)


# ================================================================
# LOGGER
# ================================================================

from endpoint.utils.logger import (
    get_logger,
)


# ================================================================
# TEMPORAL V2 COMPONENTS
# ================================================================

from ai_detection.temporal.process_temporal_observation_builder_v2 import (
    ProcessTemporalObservationBuilderV2,
)

from ai_detection.temporal.process_temporal_predictor_v2 import (
    ProcessTemporalPredictorV2,
)

from ai_detection.temporal.process_temporal_buffer import (
    ProcessTemporalBuffer,
)


logger = get_logger(
    __name__
)


# ================================================================
# SENTINEL-X
# FUSION V3 + TEMPORAL AI V2 RUNTIME
#
#
# Inheritance:
#
#       ProcessMonitor
#             ↓
#       TemporalProcessMonitor
#             ↓
#       FusionV3ProcessMonitor
#             ↓
#       FusionV3ProcessMonitorV2
#
#
# We reuse all currently working:
#
#       Process collection
#       Rule detector
#       Statistical detector
#       Isolation Forest
#       Autoencoder
#       Dual-AI consensus
#       Temporal result persistence
#       Fusion v3
#       Fusion v3 persistence
#
#
# Only these runtime components change:
#
#       Temporal Observation Builder v1 → v2
#       Temporal Buffer 27D             → 26D
#       Temporal Predictor v1           → v2
#
#
# Fusion v3 remains:
#
#       SHADOW_VALIDATION
#
# until the live Windows baseline is healthy.
# ================================================================


TEMPORAL_V2_SEQUENCE_LENGTH = 8

TEMPORAL_V2_FEATURE_COUNT = 26


# ================================================================
# MONITOR
# ================================================================

class FusionV3ProcessMonitorV2(
    FusionV3ProcessMonitor,
):

    def __init__(
        self,
        *args,
        **kwargs,
    ):

        # ========================================================
        # BUILD EXISTING WORKING PIPELINE FIRST
        # ========================================================

        super().__init__(
            *args,
            **kwargs,
        )


        # ========================================================
        # REPLACE TEMPORAL V1 COMPONENTS WITH V2
        # ========================================================

        self.temporal_observation_builder = (
            ProcessTemporalObservationBuilderV2()
        )


        self.temporal_buffer = (
            ProcessTemporalBuffer(

                sequence_length=
                    TEMPORAL_V2_SEQUENCE_LENGTH,

                expected_feature_count=
                    TEMPORAL_V2_FEATURE_COUNT,
            )
        )


        self.temporal_predictor = (
            ProcessTemporalPredictorV2(
                auto_load=True
            )
        )


        # ========================================================
        # RESET TRANSIENT TEMPORAL STATE
        #
        # Do not mix any v1 sequence state with v2 state.
        # ========================================================

        self.temporal_alert_last_emitted = {}

        self.last_temporal_cleanup_time = 0.0


        # ========================================================
        # VERIFY
        # ========================================================

        status = (
            self.temporal_predictor
            .get_status()
        )


        if not status.get(
            "available",
            False,
        ):

            raise RuntimeError(

                "Temporal Predictor v2 failed to load: "
                f"{status.get('load_error')}"
            )


        if (

            int(
                status.get(
                    "feature_count",
                    -1,
                )
            )

            != TEMPORAL_V2_FEATURE_COUNT

        ):

            raise RuntimeError(

                "Temporal Predictor v2 feature count "
                "is not 26."
            )


        if (

            str(
                status.get(
                    "model_version"
                )
            )

            != "v2"

        ):

            raise RuntimeError(

                "Expected Temporal Transformer v2."
            )


        if (

            str(
                status.get(
                    "calibration_version"
                )
            )

            != "v2"

        ):

            raise RuntimeError(

                "Expected Temporal calibration v2."
            )


        logger.info(

            "Temporal AI Runtime Override | "
            "Model=%s | "
            "Predictor=%s | "
            "Calibration=%s | "
            "Sequence=%s | "
            "Features=%s | "
            "Embedding=%s | "
            "RemovedFeature=%s",

            status.get(
                "model_version"
            ),

            status.get(
                "predictor_version"
            ),

            status.get(
                "calibration_version"
            ),

            status.get(
                "sequence_length"
            ),

            status.get(
                "feature_count"
            ),

            status.get(
                "representation_dimension"
            ),

            status.get(
                "removed_feature"
            ),
        )


    # ============================================================
    # EXTENDED STATUS
    # ============================================================

    def get_temporal_v2_status(
        self,
    ) -> Dict[str, Any]:

        predictor_status = (
            self.temporal_predictor
            .get_status()
        )


        buffer_status = (
            self.temporal_buffer
            .get_status()
        )


        return {
            "runtime":
                "TEMPORAL_V2",

            "predictor":
                predictor_status,

            "buffer":
                buffer_status,

            "fusion_v3_mode":
                self.fusion_v3_operating_mode,

            "stored_temporal_results":
                self.temporal_result_store
                .count(),

            "stored_fusion_v3_results":
                self.fusion_v3_store
                .count(),
        }