from __future__ import annotations

from typing import (
    Any,
    Dict,
    Optional,
)


from endpoint.collectors.fusion_v3_evidence_bridge_monitor import (
    FusionV3EvidenceBridgeMonitor,
)


from endpoint.utils.logger import (
    get_logger,
)


logger = get_logger(
    __name__
)


# ================================================================
# SENTINEL-X
# FUSION V3 PRIMARY PROCESS MONITOR
#
#
# Previous state:
#
#       Fusion v2 = primary
#       Fusion v3 = SHADOW_VALIDATION
#
#
# New state:
#
#       Fusion v3 = PRIMARY
#       Fusion v2 = reference / rollback
#
#
# IMPORTANT:
#
# Existing ProcessMonitor.handle_process_start() expects the
# legacy Fusion-v2 result structure.
#
# Therefore this class produces:
#
#       Fusion-v3 decision
#             +
#       Fusion-v2 compatibility fields
#
#
# This allows:
#
#       existing telemetry
#       existing process-start handling
#       existing alert logic
#
# to continue working while Fusion v3 becomes authoritative.
# ================================================================


PRIMARY_MODE = (
    "PRODUCTION_PRIMARY"
)


PRIMARY_ENGINE = (
    "process_threat_fusion_v3"
)


PRIMARY_VERSION = "v3"


class FusionV3PrimaryProcessMonitor(
    FusionV3EvidenceBridgeMonitor,
):

    def __init__(
        self,
        *args,
        **kwargs,
    ):

        super().__init__(
            *args,
            **kwargs,
        )


        # ========================================================
        # PROMOTE V3
        # ========================================================

        self.fusion_v3_operating_mode = (
            PRIMARY_MODE
        )


        logger.warning(
            "=" * 78
        )


        logger.warning(
            "SENTINEL-X FUSION V3 PRIMARY MODE ENABLED"
        )


        logger.warning(
            "Fusion v3 : PRIMARY"
        )


        logger.warning(
            "Fusion v2 : REFERENCE / ROLLBACK"
        )


        logger.warning(
            "Temporal  : Transformer v2 / 8x26"
        )


        logger.warning(
            "=" * 78
        )


    # ============================================================
    # BUILD LEGACY-COMPATIBLE PRIMARY RESULT
    # ============================================================

    def build_primary_result(
        self,
        *,
        fusion_v2_result: Dict[str, Any],
        fusion_v3_result: Dict[str, Any],
    ) -> Dict[str, Any]:

        # --------------------------------------------------------
        # Begin with v2 so existing consumers still see:
        #
        #       ai_consensus
        #       behavior indicators
        #       statistical indicators
        #       IF / AE supporting metadata
        #
        # --------------------------------------------------------

        result = dict(
            fusion_v2_result
        )


        v3_scores = (
            fusion_v3_result.get(
                "scores"
            )

            or {}
        )


        v3_categories = (
            fusion_v3_result.get(
                "categories"
            )

            or {}
        )


        behavioral_category = (
            v3_categories.get(
                "behavioral_ai"
            )

            or {}
        )


        # ========================================================
        # IDENTITY
        # ========================================================

        result[
            "fusion_name"
        ] = (
            PRIMARY_ENGINE
        )


        result[
            "fusion_version"
        ] = (
            PRIMARY_VERSION
        )


        result[
            "primary_engine"
        ] = (
            PRIMARY_ENGINE
        )


        result[
            "operating_mode"
        ] = (
            PRIMARY_MODE
        )


        result[
            "primary_decision"
        ] = True


        result[
            "promoted_to_primary"
        ] = True


        # ========================================================
        # PRIMARY V3 SCORE
        # ========================================================

        result[
            "fusion_score"
        ] = (
            fusion_v3_result.get(
                "fusion_score",
                0.0,
            )
        )


        result[
            "severity"
        ] = (
            fusion_v3_result.get(
                "severity",
                "INFO",
            )
        )


        result[
            "evidence_confidence"
        ] = (
            fusion_v3_result.get(
                "evidence_confidence",
                "LOW",
            )
        )


        # ========================================================
        # PRIMARY DECISION FLAGS
        # ========================================================

        result[
            "should_alert"
        ] = bool(

            fusion_v3_result.get(
                "should_alert",
                False,
            )
        )


        result[
            "suspicious"
        ] = bool(

            fusion_v3_result.get(
                "suspicious",
                False,
            )

            or

            fusion_v3_result.get(
                "should_alert",
                False,
            )
        )


        result[
            "critical_allowed"
        ] = bool(

            fusion_v3_result.get(
                "critical_allowed",
                False,
            )
        )


        # ========================================================
        # CATEGORY SCORES
        #
        # Preserve names expected by existing ProcessMonitor code.
        # ========================================================

        result[
            "rule_score"
        ] = (
            v3_scores.get(
                "rules"
            )
        )


        result[
            "statistical_score"
        ] = (
            v3_scores.get(
                "statistical"
            )
        )


        result[
            "ai_consensus_score"
        ] = (
            v3_scores.get(
                "behavioral_ai_consensus"
            )
        )


        result[
            "temporal_ai_score"
        ] = (
            v3_scores.get(
                "temporal_ai"
            )
        )


        # ========================================================
        # EXISTING AI CONSENSUS COMPATIBILITY
        #
        # Keep the richer original Fusion-v2 AI consensus object.
        # ========================================================

        if not isinstance(
            result.get(
                "ai_consensus"
            ),
            dict,
        ):

            result[
                "ai_consensus"
            ] = {}


        result[
            "ai_consensus"
        ][
            "fusion_v3_category_score"
        ] = (
            behavioral_category.get(
                "score"
            )
        )


        # ========================================================
        # V3 EVIDENCE INFORMATION
        # ========================================================

        result[
            "active_signal_count"
        ] = int(

            fusion_v3_result.get(
                "active_signal_count",
                0,
            )
        )


        result[
            "strong_signal_count"
        ] = int(

            fusion_v3_result.get(
                "strong_signal_count",
                0,
            )
        )


        result[
            "active_signals"
        ] = list(

            fusion_v3_result.get(
                "active_categories",
                [],
            )
        )


        result[
            "strong_signals"
        ] = list(

            fusion_v3_result.get(
                "strong_categories",
                [],
            )
        )


        result[
            "active_categories"
        ] = list(

            fusion_v3_result.get(
                "active_categories",
                [],
            )
        )


        result[
            "strong_categories"
        ] = list(

            fusion_v3_result.get(
                "strong_categories",
                [],
            )
        )


        result[
            "reasons"
        ] = list(

            fusion_v3_result.get(
                "reasons",
                [],
            )
        )


        # ========================================================
        # TEMPORAL
        # ========================================================

        result[
            "temporal_ai_available"
        ] = bool(

            fusion_v3_result.get(
                "temporal_ai_available",
                False,
            )
        )


        result[
            "ai_temporal_disagreement"
        ] = bool(

            fusion_v3_result.get(
                "ai_temporal_disagreement",
                False,
            )
        )


        result[
            "ai_temporal_score_difference"
        ] = (
            fusion_v3_result.get(
                "ai_temporal_score_difference"
            )
        )


        # ========================================================
        # FULL V3 RESULT
        #
        # Keep the complete native v3 object so API/dashboard and
        # later investigation logic can inspect it.
        # ========================================================

        result[
            "fusion_v3"
        ] = (
            fusion_v3_result
        )


        # ========================================================
        # V2 REFERENCE
        # ========================================================

        result[
            "fusion_v2_reference"
        ] = (
            fusion_v2_result
        )


        result[
            "rollback_engine"
        ] = (
            "process_threat_fusion_v2"
        )


        result[
            "rollback_available"
        ] = True


        # ========================================================
        # COMPARISON
        # ========================================================

        result[
            "fusion_v2_comparison"
        ] = (
            fusion_v3_result.get(
                "fusion_v2_comparison",
                {}
            )
        )


        return result


    # ============================================================
    # CALCULATE PRIMARY FUSION
    #
    # Evidence Bridge does:
    #
    #   1. calculate v2
    #   2. calculate v3
    #   3. persist v3
    #   4. attach v2/v3 to ai_result
    #
    # It currently returns v2.
    #
    # Here we capture the shared ai_result reference BEFORE the
    # bridge consumes/clears its pending package.
    #
    # Then we convert the authoritative v3 decision into the
    # legacy-compatible return structure.
    # ============================================================

    def calculate_fusion(
        self,
        behavior_result: dict,
        anomaly_result: dict,
        isolation_result: dict | None,
        autoencoder_result: dict | None,
    ) -> dict:

        # ========================================================
        # CAPTURE CURRENT PACKAGE
        # ========================================================

        package = (
            self._fusion_v3_pending_package
        )


        ai_result = None


        if isinstance(
            package,
            dict,
        ):

            possible_ai_result = (
                package.get(
                    "ai_result"
                )
            )


            if isinstance(
                possible_ai_result,
                dict,
            ):

                ai_result = (
                    possible_ai_result
                )


        # ========================================================
        # RUN EXISTING EVIDENCE BRIDGE
        # ========================================================

        fusion_v2_result = (
            super().calculate_fusion(

                behavior_result=
                    behavior_result,

                anomaly_result=
                    anomaly_result,

                isolation_result=
                    isolation_result,

                autoencoder_result=
                    autoencoder_result,
            )
        )


        if not isinstance(
            fusion_v2_result,
            dict,
        ):

            raise RuntimeError(

                "Fusion v2 reference result is invalid."
            )


        # ========================================================
        # NO AI PACKAGE
        #
        # Defensive fallback:
        #
        # Never break process monitoring if v3 failed to execute.
        # ========================================================

        if ai_result is None:

            logger.error(

                "Fusion v3 primary promotion fallback | "
                "AI package unavailable | "
                "using Fusion v2 reference decision"
            )


            fallback = dict(
                fusion_v2_result
            )


            fallback[
                "primary_engine"
            ] = (
                "process_threat_fusion_v2"
            )


            fallback[
                "primary_decision"
            ] = True


            fallback[
                "promoted_to_primary"
            ] = False


            fallback[
                "fallback_reason"
            ] = (
                "fusion_v3_ai_package_unavailable"
            )


            return fallback


        # ========================================================
        # GET V3
        # ========================================================

        fusion_v3_result = (
            ai_result.get(
                "fusion_v3"
            )
        )


        if not isinstance(
            fusion_v3_result,
            dict,
        ):

            logger.error(

                "Fusion v3 primary promotion fallback | "
                "Fusion v3 result unavailable"
            )


            fallback = dict(
                fusion_v2_result
            )


            fallback[
                "primary_engine"
            ] = (
                "process_threat_fusion_v2"
            )


            fallback[
                "primary_decision"
            ] = True


            fallback[
                "promoted_to_primary"
            ] = False


            fallback[
                "fallback_reason"
            ] = (
                "fusion_v3_result_unavailable"
            )


            return fallback


        # ========================================================
        # BRIDGE MUST BE COMPLETE
        # ========================================================

        if not fusion_v3_result.get(
            "evidence_bridge_complete",
            False,
        ):

            logger.error(

                "Fusion v3 primary promotion fallback | "
                "Evidence bridge incomplete"
            )


            fallback = dict(
                fusion_v2_result
            )


            fallback[
                "primary_engine"
            ] = (
                "process_threat_fusion_v2"
            )


            fallback[
                "primary_decision"
            ] = True


            fallback[
                "promoted_to_primary"
            ] = False


            fallback[
                "fallback_reason"
            ] = (
                "fusion_v3_bridge_incomplete"
            )


            return fallback


        # ========================================================
        # BUILD AUTHORITATIVE PRIMARY RESULT
        # ========================================================

        primary_result = (
            self.build_primary_result(

                fusion_v2_result=
                    fusion_v2_result,

                fusion_v3_result=
                    fusion_v3_result,
            )
        )


        # ========================================================
        # UPDATE AI RESULT
        # ========================================================

        ai_result[
            "primary_decision_candidate"
        ] = {
            "engine":
                PRIMARY_ENGINE,

            "mode":
                PRIMARY_MODE,

            "promoted_to_primary":
                True,

            "fusion_score":
                primary_result.get(
                    "fusion_score"
                ),

            "severity":
                primary_result.get(
                    "severity"
                ),

            "should_alert":
                primary_result.get(
                    "should_alert"
                ),

            "rollback_engine":
                "process_threat_fusion_v2",
        }


        ai_result[
            "primary_fusion"
        ] = (
            primary_result
        )


        # ========================================================
        # LOG
        # ========================================================

        logger.info(

            "FUSION V3 PRIMARY DECISION | "
            "Score=%s | "
            "Severity=%s | "
            "Alert=%s | "
            "Active=%s | "
            "Strong=%s | "
            "Temporal=%s | "
            "RollbackV2=%s",

            primary_result.get(
                "fusion_score"
            ),

            primary_result.get(
                "severity"
            ),

            primary_result.get(
                "should_alert"
            ),

            primary_result.get(
                "active_signal_count"
            ),

            primary_result.get(
                "strong_signal_count"
            ),

            primary_result.get(
                "temporal_ai_score"
            ),

            fusion_v2_result.get(
                "fusion_score"
            ),
        )


        return primary_result


    # ============================================================
    # STATUS
    # ============================================================

    def get_primary_fusion_status(
        self,
    ) -> Dict[str, Any]:

        bridge = (
            self.get_evidence_bridge_status()
        )


        return {
            "primary_engine":
                PRIMARY_ENGINE,

            "primary_version":
                PRIMARY_VERSION,

            "operating_mode":
                PRIMARY_MODE,

            "promoted_to_primary":
                True,

            "fallback_engine":
                "process_threat_fusion_v2",

            "fallback_available":
                True,

            "temporal_runtime":
                bridge.get(
                    "temporal_runtime"
                ),

            "bridge_version":
                bridge.get(
                    "bridge_version"
                ),

            "bridge_statistics":
                bridge.get(
                    "statistics"
                ),
        }