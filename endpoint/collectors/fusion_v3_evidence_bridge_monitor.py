from __future__ import annotations

import time

from typing import (
    Any,
    Dict,
    Optional,
)


# ================================================================
# EXISTING TEMPORAL V2 + FUSION V3 RUNTIME
# ================================================================

from endpoint.collectors.fusion_v3_process_monitor_v2 import (
    FusionV3ProcessMonitorV2,
)


# ================================================================
# IMPORTANT
#
# We intentionally call TemporalProcessMonitor's collection method
# directly so that:
#
#       IF
#       Autoencoder
#       Temporal v2
#
# run normally,
#
# but the old FusionV3ProcessMonitor.collect_ai_behavior_features()
# does NOT calculate Fusion v3 prematurely before Rule and
# Statistical evidence exist.
# ================================================================

from endpoint.collectors.temporal_process_monitor import (
    TemporalProcessMonitor,
)


# ================================================================
# ORIGINAL PROCESS MONITOR
#
# Used for the already-working Fusion-v2 calculation.
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


logger = get_logger(
    __name__
)


# ================================================================
# SENTINEL-X FUSION V3 EVIDENCE BRIDGE
#
#
# REAL EXISTING ORDER:
#
#       behavior_detector.analyze()
#              ↓
#          Rule Result
#
#       anomaly_detector.analyze()
#              ↓
#       Statistical Result
#
#       collect_ai_behavior_features()
#              ↓
#       IF + AE + Temporal v2
#
#       calculate_fusion()
#              ↓
#         Fusion v2
#
#
# NEW BRIDGE:
#
#       Rule Result ────────────────┐
#       Statistical Result ─────────┤
#       IF ─────────────────────────┤
#       Autoencoder ────────────────┤
#       Temporal v2 ────────────────┤
#                                   ↓
#                              Fusion v3
#
#
# Fusion v2 remains unchanged.
#
# Fusion v3 remains SHADOW_VALIDATION.
# ================================================================


BRIDGE_NAME = (
    "sentinelx_fusion_v3_evidence_bridge"
)


BRIDGE_VERSION = "v1"


PENDING_MAX_AGE_SECONDS = 30.0


# ================================================================
# MONITOR
# ================================================================

class FusionV3EvidenceBridgeMonitor(
    FusionV3ProcessMonitorV2,
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
        # PENDING AI RESULT
        #
        # handle_process_start() is synchronous:
        #
        #       collect AI
        #          ↓
        #       calculate fusion
        #
        # Therefore we cache exactly one pending AI package for
        # the subsequent calculate_fusion() call.
        # ========================================================

        self._fusion_v3_pending_package = None


        self._fusion_v3_bridge_statistics = {
            "ai_packages_created":
                0,

            "bridge_calculations":
                0,

            "bridge_success":
                0,

            "bridge_missing_package":
                0,

            "bridge_stale_package":
                0,

            "bridge_exceptions":
                0,
        }


        logger.info(

            "Fusion V3 Evidence Bridge | "
            "Version=%s | "
            "Mode=%s | "
            "Temporal=v2",

            BRIDGE_VERSION,

            self.fusion_v3_operating_mode,
        )


    # ============================================================
    # TEMPORAL RESULT
    # ============================================================

    def extract_bridge_temporal_result(
        self,
        ai_result: Dict[str, Any],
    ) -> Optional[
        Dict[str, Any]
    ]:

        temporal_wrapper = (
            ai_result.get(
                "temporal"
            )
        )


        if not isinstance(
            temporal_wrapper,
            dict,
        ):

            return None


        if (

            temporal_wrapper.get(
                "state"
            )

            != "TEMPORAL_INFERENCE_COMPLETE"

        ):

            return None


        temporal_result = (
            temporal_wrapper.get(
                "temporal_result"
            )
        )


        if not isinstance(
            temporal_result,
            dict,
        ):

            return None


        if not temporal_result.get(
            "available",
            False,
        ):

            return None


        return temporal_result


    # ============================================================
    # CREATE PENDING PACKAGE
    # ============================================================

    def create_pending_package(
        self,
        *,
        process_info: Dict[str, Any],
        context: Dict[str, Any],
        ai_result: Dict[str, Any],
    ) -> None:

        self._fusion_v3_pending_package = {
            "created_at":
                time.time(),

            "process_info":
                dict(
                    process_info
                ),

            "context":
                dict(
                    context

                    if isinstance(
                        context,
                        dict,
                    )

                    else {}
                ),

            # ----------------------------------------------------
            # IMPORTANT:
            #
            # Do NOT copy this dictionary.
            #
            # handle_process_start() holds a reference to the same
            # ai_result object. Later, calculate_fusion() adds:
            #
            #       fusion_v2
            #       fusion_v3
            #
            # to this same object.
            # ----------------------------------------------------

            "ai_result":
                ai_result,
        }


        self._fusion_v3_bridge_statistics[
            "ai_packages_created"
        ] += 1


    # ============================================================
    # GET PENDING PACKAGE
    # ============================================================

    def get_pending_package(
        self,
    ) -> Optional[
        Dict[str, Any]
    ]:

        package = (
            self._fusion_v3_pending_package
        )


        if package is None:

            self._fusion_v3_bridge_statistics[
                "bridge_missing_package"
            ] += 1


            return None


        try:

            age = (

                time.time()

                - float(
                    package[
                        "created_at"
                    ]
                )
            )


        except (
            TypeError,
            ValueError,
            KeyError,
        ):

            age = (
                PENDING_MAX_AGE_SECONDS
                + 1.0
            )


        if age > PENDING_MAX_AGE_SECONDS:

            self._fusion_v3_bridge_statistics[
                "bridge_stale_package"
            ] += 1


            self._fusion_v3_pending_package = None


            return None


        return package


    # ============================================================
    # CLEAR PACKAGE
    # ============================================================

    def clear_pending_package(
        self,
    ) -> None:

        self._fusion_v3_pending_package = None


    # ============================================================
    # AI COLLECTION
    #
    # CRITICAL DESIGN:
    #
    # Bypass:
    #
    #       FusionV3ProcessMonitor.collect_ai_behavior_features()
    #
    # because it calculates Fusion v3 before Rule/Statistical
    # evidence exists.
    #
    # Instead call:
    #
    #       TemporalProcessMonitor.collect_ai_behavior_features()
    #
    # directly.
    #
    # Because this object already has:
    #
    #       Builder v2
    #       Buffer 26D
    #       Predictor v2
    #
    # polymorphism still uses the corrected Temporal-v2 objects.
    # ============================================================

    def collect_ai_behavior_features(
        self,
        process_info: Dict[str, Any],
        context: Dict[str, Any],
    ) -> Dict[str, Any]:

        ai_result = (
            TemporalProcessMonitor
            .collect_ai_behavior_features(

                self,

                process_info=
                    process_info,

                context=
                    context,
            )
        )


        if not isinstance(
            ai_result,
            dict,
        ):

            return ai_result


        # ========================================================
        # CACHE RESULT FOR calculate_fusion()
        # ========================================================

        self.create_pending_package(

            process_info=
                process_info,

            context=
                context,

            ai_result=
                ai_result,
        )


        # ========================================================
        # DO NOT CLAIM V3 HAS RUN YET
        # ========================================================

        ai_result[
            "fusion_v3"
        ] = {
            "available":
                False,

            "state":
                "WAITING_FOR_RULE_STATISTICAL_BRIDGE",

            "operating_mode":
                self.fusion_v3_operating_mode,

            "bridge_name":
                BRIDGE_NAME,

            "bridge_version":
                BRIDGE_VERSION,
        }


        ai_result[
            "primary_decision_candidate"
        ] = {
            "engine":
                "fusion_v3",

            "mode":
                self.fusion_v3_operating_mode,

            "promoted_to_primary":
                False,

            "state":
                "WAITING_FOR_COMPLETE_EVIDENCE",
        }


        return ai_result


    # ============================================================
    # CALCULATE FUSION
    #
    # This method is already called by handle_process_start()
    #
    # Inputs:
    #
    #       behavior_result       = Rules
    #       anomaly_result        = Statistical
    #       isolation_result      = IF
    #       autoencoder_result    = AE
    #
    #
    # First:
    #
    #       calculate Fusion v2 exactly as before
    #
    # Then:
    #
    #       use same evidence + Temporal v2 for Fusion v3
    #
    # Finally:
    #
    #       return Fusion v2 unchanged
    #
    # Therefore existing production behavior is preserved.
    # ============================================================

    def calculate_fusion(
        self,
        behavior_result: dict,
        anomaly_result: dict,
        isolation_result: dict | None,
        autoencoder_result: dict | None,
    ) -> dict:

        self._fusion_v3_bridge_statistics[
            "bridge_calculations"
        ] += 1


        # ========================================================
        # 1. EXISTING FUSION V2
        # ========================================================

        fusion_v2_result = (
            ProcessMonitor
            .calculate_fusion(

                self,

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


        # ========================================================
        # 2. GET AI PACKAGE
        # ========================================================

        package = (
            self.get_pending_package()
        )


        if package is None:

            logger.warning(

                "Fusion-v3 evidence bridge | "
                "No matching pending AI package. "
                "Returning Fusion v2 only."
            )


            return fusion_v2_result


        ai_result = (
            package[
                "ai_result"
            ]
        )


        process_info = (
            package[
                "process_info"
            ]
        )


        # ========================================================
        # 3. FEATURE RECORD ID
        # ========================================================

        feature_record_id = (
            self.resolve_feature_record_id(
                ai_result
            )
        )


        if feature_record_id is None:

            ai_result[
                "fusion_v2"
            ] = fusion_v2_result


            ai_result[
                "fusion_v3"
            ] = {
                "available":
                    False,

                "state":
                    "MISSING_FEATURE_RECORD_ID",

                "operating_mode":
                    self.fusion_v3_operating_mode,
            }


            self.clear_pending_package()


            return fusion_v2_result


        # ========================================================
        # 4. TEMPORAL V2
        #
        # It is perfectly valid for this to be None while:
        #
        #       depth < 8
        #
        # Fusion v3 will then use:
        #
        #       Rules
        #       Statistical
        #       Behavioral AI
        #
        # only.
        # ========================================================

        temporal_result = (
            self.extract_bridge_temporal_result(
                ai_result
            )
        )


        # ========================================================
        # 5. CALCULATE FUSION V3 WITH COMPLETE EVIDENCE
        # ========================================================

        try:

            fusion_v3_result = (
                self.calculate_and_persist_fusion_v3(

                    process_info=
                        process_info,

                    feature_record_id=
                        feature_record_id,

                    # --------------------------------------------
                    # EXACT ALREADY-COMPUTED RULE RESULT
                    # --------------------------------------------

                    rule_result=
                        behavior_result,

                    # --------------------------------------------
                    # EXACT ALREADY-COMPUTED STATISTICAL RESULT
                    # --------------------------------------------

                    statistical_result=
                        anomaly_result,

                    isolation_result=
                        isolation_result,

                    autoencoder_result=
                        autoencoder_result,

                    temporal_result=
                        temporal_result,
                )
            )


            fusion_v3_result[
                "bridge_name"
            ] = (
                BRIDGE_NAME
            )


            fusion_v3_result[
                "bridge_version"
            ] = (
                BRIDGE_VERSION
            )


            fusion_v3_result[
                "evidence_bridge_complete"
            ] = True


            # ====================================================
            # ADD COMPARISON DATA
            # ====================================================

            fusion_v3_result[
                "fusion_v2_comparison"
            ] = {
                "available":
                    True,

                "fusion_v2_score":
                    fusion_v2_result.get(
                        "fusion_score"
                    ),

                "fusion_v2_severity":
                    fusion_v2_result.get(
                        "severity"
                    ),

                "fusion_v2_rule_score":
                    fusion_v2_result.get(
                        "rule_score"
                    ),

                "fusion_v2_statistical_score":
                    fusion_v2_result.get(
                        "statistical_score"
                    ),

                "fusion_v2_ai_consensus_score":
                    fusion_v2_result.get(
                        "ai_consensus_score"
                    ),
            }


            try:

                v2_score = float(

                    fusion_v2_result.get(
                        "fusion_score",
                        0.0,
                    )
                )


                v3_score = float(

                    fusion_v3_result.get(
                        "fusion_score",
                        0.0,
                    )
                )


                fusion_v3_result[
                    "fusion_v2_comparison"
                ][
                    "score_delta_v3_minus_v2"
                ] = (

                    v3_score

                    - v2_score
                )


            except (
                TypeError,
                ValueError,
            ):

                fusion_v3_result[
                    "fusion_v2_comparison"
                ][
                    "score_delta_v3_minus_v2"
                ] = None


            # ====================================================
            # MUTATE THE SAME AI RESULT OBJECT HELD BY
            # handle_process_start()
            # ====================================================

            ai_result[
                "fusion_v2"
            ] = fusion_v2_result


            ai_result[
                "fusion_v3"
            ] = fusion_v3_result


            ai_result[
                "primary_decision_candidate"
            ] = {
                "engine":
                    "fusion_v3",

                "mode":
                    self.fusion_v3_operating_mode,

                "promoted_to_primary":
                    False,

                "state":
                    "COMPLETE_SHADOW_DECISION",
            }


            self._fusion_v3_bridge_statistics[
                "bridge_success"
            ] += 1


            # ====================================================
            # LOG
            # ====================================================

            categories = (
                fusion_v3_result.get(
                    "categories",
                    {}
                )
            )


            logger.info(

                "FUSION V3 EVIDENCE BRIDGE | "
                "PID=%s | "
                "Process=%s | "
                "Rule=%s | "
                "Stat=%s | "
                "BehaviorAI=%s | "
                "Temporal=%s | "
                "V2=%s | "
                "V3=%s | "
                "Severity=%s | "
                "Mode=%s",

                process_info.get(
                    "pid"
                ),

                process_info.get(
                    "name"
                ),

                (
                    categories
                    .get(
                        "rules",
                        {}
                    )
                    .get(
                        "score"
                    )
                ),

                (
                    categories
                    .get(
                        "statistical",
                        {}
                    )
                    .get(
                        "score"
                    )
                ),

                (
                    categories
                    .get(
                        "behavioral_ai",
                        {}
                    )
                    .get(
                        "score"
                    )
                ),

                (
                    categories
                    .get(
                        "temporal_ai",
                        {}
                    )
                    .get(
                        "score"
                    )
                ),

                fusion_v2_result.get(
                    "fusion_score"
                ),

                fusion_v3_result.get(
                    "fusion_score"
                ),

                fusion_v3_result.get(
                    "severity"
                ),

                self.fusion_v3_operating_mode,
            )


            if fusion_v3_result.get(
                "should_alert",
                False,
            ):

                logger.warning(

                    "FUSION V3 SHADOW ALERT CANDIDATE | "
                    "PID=%s | "
                    "Process=%s | "
                    "Score=%s | "
                    "Severity=%s | "
                    "Reasons=%s",

                    process_info.get(
                        "pid"
                    ),

                    process_info.get(
                        "name"
                    ),

                    fusion_v3_result.get(
                        "fusion_score"
                    ),

                    fusion_v3_result.get(
                        "severity"
                    ),

                    fusion_v3_result.get(
                        "reasons"
                    ),
                )


        except Exception as error:

            self._fusion_v3_bridge_statistics[
                "bridge_exceptions"
            ] += 1


            logger.exception(

                "Fusion-v3 evidence bridge failure | "
                "PID=%s | "
                "Process=%s",

                process_info.get(
                    "pid"
                ),

                process_info.get(
                    "name"
                ),
            )


            ai_result[
                "fusion_v2"
            ] = fusion_v2_result


            ai_result[
                "fusion_v3"
            ] = {
                "available":
                    False,

                "state":
                    "FUSION_V3_BRIDGE_EXCEPTION",

                "error":
                    str(
                        error
                    ),

                "operating_mode":
                    self.fusion_v3_operating_mode,
            }


        finally:

            # ----------------------------------------------------
            # Never reuse evidence for another process.
            # ----------------------------------------------------

            self.clear_pending_package()


        # ========================================================
        # EXISTING PRODUCTION CALLER EXPECTS FUSION V2
        # ========================================================

        return fusion_v2_result


    # ============================================================
    # BRIDGE STATUS
    # ============================================================

    def get_evidence_bridge_status(
        self,
    ) -> Dict[str, Any]:

        return {
            "bridge_name":
                BRIDGE_NAME,

            "bridge_version":
                BRIDGE_VERSION,

            "operating_mode":
                self.fusion_v3_operating_mode,

            "temporal_runtime":
                self.get_temporal_v2_status(),

            "statistics":
                dict(
                    self._fusion_v3_bridge_statistics
                ),

            "pending_package":
                (
                    self._fusion_v3_pending_package
                    is not None
                ),
        }