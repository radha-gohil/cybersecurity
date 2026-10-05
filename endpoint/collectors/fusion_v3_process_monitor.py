from __future__ import annotations

import math
import time
from pathlib import Path

from typing import (
    Any,
    Dict,
    Optional,
)


from endpoint.collectors.temporal_process_monitor import (
    TemporalProcessMonitor,
)


from endpoint.utils.logger import (
    get_logger,
)


from ai_detection.behavior.process_threat_fusion_v3 import (
    ProcessThreatFusionV3,
)


from ai_detection.behavior.process_fusion_v3_result_store import (
    ProcessFusionV3ResultStore,
)


logger = get_logger(
    __name__
)


# ================================================================
# PROJECT PATHS
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
# MODE
#
# Keep Fusion v2 untouched while Fusion v3 is validated against
# real live endpoint behavior.
# ================================================================

FUSION_V3_OPERATING_MODE = (
    "SHADOW_VALIDATION"
)


# ================================================================
# SENTINEL-X FUSION V3 PROCESS MONITOR
# ================================================================

class FusionV3ProcessMonitor(
    TemporalProcessMonitor,
):

    def __init__(
        self,
        *args,
        fusion_database_path: Optional[
            str | Path
        ] = None,
        **kwargs,
    ):

        # --------------------------------------------------------
        # If caller supplies a custom fusion database for testing,
        # use the same database for temporal results unless they
        # explicitly supplied another temporal database.
        # --------------------------------------------------------

        if (

            fusion_database_path
            is not None

            and

            "temporal_database_path"
            not in kwargs

        ):

            kwargs[
                "temporal_database_path"
            ] = fusion_database_path


        super().__init__(
            *args,
            **kwargs,
        )


        self.fusion_v3_engine = (
            ProcessThreatFusionV3()
        )


        self.fusion_v3_store = (
            ProcessFusionV3ResultStore(

                database_path=(

                    fusion_database_path

                    if fusion_database_path
                    is not None

                    else DEFAULT_DATABASE_PATH
                )
            )
        )


        self.fusion_v3_operating_mode = (
            FUSION_V3_OPERATING_MODE
        )


        logger.info(

            "Process Threat Fusion | "
            "Version=v3 | "
            "Mode=%s | "
            "TemporalAI=ENABLED",

            self.fusion_v3_operating_mode,
        )


    # ============================================================
    # GENERIC NESTED RESULT LOOKUP
    # ============================================================

    def find_result(
        self,
        source: Dict[str, Any],
        candidate_keys,
    ) -> Optional[
        Dict[str, Any]
    ]:

        if not isinstance(
            source,
            dict,
        ):

            return None


        for key in candidate_keys:

            value = (
                source.get(
                    key
                )
            )


            if isinstance(
                value,
                dict,
            ):

                return value


        return None


    # ============================================================
    # SCORE FROM OLD FUSION RESULT
    #
    # If Phase-2 does not expose the raw rule/statistical result,
    # recover the category score from Fusion v2.
    # ============================================================

    def recover_score_from_fusion_v2(
        self,
        phase2_result: Dict[str, Any],
        category_names,
    ) -> Optional[
        Dict[str, Any]
    ]:

        possible_fusion_keys = [

            "fusion",

            "fusion_v2",

            "threat_fusion",

            "fusion_result",

            "process_threat_fusion",
        ]


        for fusion_key in possible_fusion_keys:

            fusion = (
                phase2_result.get(
                    fusion_key
                )
            )


            if not isinstance(
                fusion,
                dict,
            ):

                continue


            # ====================================================
            # scores = {"rules": 50, ...}
            # ====================================================

            scores = (
                fusion.get(
                    "scores"
                )
            )


            if isinstance(
                scores,
                dict,
            ):

                for name in category_names:

                    if name in scores:

                        try:

                            return {
                                "available":
                                    True,

                                "score":
                                    float(
                                        scores[
                                            name
                                        ]
                                    ),

                                "recovered_from":
                                    "fusion_v2_scores",
                            }


                        except (
                            TypeError,
                            ValueError,
                        ):

                            pass


            # ====================================================
            # categories = {"rules": {"score": ...}}
            # ====================================================

            categories = (
                fusion.get(
                    "categories"
                )
            )


            if isinstance(
                categories,
                dict,
            ):

                for name in category_names:

                    category = (
                        categories.get(
                            name
                        )
                    )


                    if not isinstance(
                        category,
                        dict,
                    ):

                        continue


                    for score_key in [

                        "score",

                        "anomaly_score",

                        "risk_score",

                    ]:

                        if score_key not in category:

                            continue


                        try:

                            return {
                                "available":
                                    True,

                                "score":
                                    float(
                                        category[
                                            score_key
                                        ]
                                    ),

                                "recovered_from":
                                    "fusion_v2_categories",
                            }


                        except (
                            TypeError,
                            ValueError,
                        ):

                            pass


        return None


    # ============================================================
    # RULE RESULT
    # ============================================================

    def resolve_rule_result(
        self,
        phase2_result: Dict[str, Any],
    ) -> Optional[
        Dict[str, Any]
    ]:

        direct = (
            self.find_result(

                phase2_result,

                [
                    "rule_result",

                    "rule_detection",

                    "rule_based",

                    "rule_based_detection",

                    "behavior_rule",

                    "behavior_detection",

                    "rule",
                ],
            )
        )


        if direct is not None:

            return direct


        return (
            self.recover_score_from_fusion_v2(

                phase2_result,

                [
                    "rules",

                    "rule",

                    "rule_based",
                ],
            )
        )


    # ============================================================
    # STATISTICAL RESULT
    # ============================================================

    def resolve_statistical_result(
        self,
        phase2_result: Dict[str, Any],
    ) -> Optional[
        Dict[str, Any]
    ]:

        direct = (
            self.find_result(

                phase2_result,

                [
                    "statistical_result",

                    "statistical",

                    "statistical_anomaly",

                    "anomaly_result",

                    "process_anomaly",

                    "anomaly_detection",
                ],
            )
        )


        if direct is not None:

            return direct


        return (
            self.recover_score_from_fusion_v2(

                phase2_result,

                [
                    "statistical",

                    "statistics",

                    "statistical_anomaly",
                ],
            )
        )


    # ============================================================
    # TEMPORAL RESULT
    # ============================================================

    def resolve_temporal_result(
        self,
        phase2_result: Dict[str, Any],
    ) -> Optional[
        Dict[str, Any]
    ]:

        temporal_wrapper = (
            phase2_result.get(
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
    # PROCESS IDENTITY
    # ============================================================

    def safe_process_identity(
        self,
        process_info: Dict[str, Any],
    ) -> Dict[str, Any]:

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


        try:

            pid_value = int(
                pid
            )


        except (
            TypeError,
            ValueError,
        ):

            pid_value = -1


        try:

            create_time_value = (

                float(
                    create_time
                )

                if create_time
                is not None

                else None
            )


        except (
            TypeError,
            ValueError,
            OverflowError,
        ):

            create_time_value = None


        return {
            "pid":
                pid_value,

            "process_name":
                str(
                    process_name
                ),

            "create_time":
                create_time_value,
        }


    # ============================================================
    # CALCULATE + SAVE FUSION V3
    #
    # Public method also used by tests.
    # ============================================================

    def calculate_and_persist_fusion_v3(
        self,
        *,
        process_info: Dict[str, Any],
        feature_record_id: int,
        rule_result: Optional[
            Dict[str, Any]
        ],
        statistical_result: Optional[
            Dict[str, Any]
        ],
        isolation_result: Optional[
            Dict[str, Any]
        ],
        autoencoder_result: Optional[
            Dict[str, Any]
        ],
        temporal_result: Optional[
            Dict[str, Any]
        ],
    ) -> Dict[str, Any]:

        identity = (
            self.safe_process_identity(
                process_info
            )
        )


        # Defense in depth: a direct caller must not persist a Fusion
        # V3 AI verdict for Windows PID 0, PID 4 with epoch-zero
        # creation time, or any other invalid process identity.
        try:
            create_time = float(identity["create_time"])
            identity_valid = (
                identity["pid"] > 0
                and math.isfinite(create_time)
                and 0.0 < create_time <= time.time() + 60.0
            )
        except (TypeError, ValueError, OverflowError, KeyError):
            identity_valid = False

        if not identity_valid:
            return {
                "available": False,
                "state": "INVALID_PROCESS_FEATURE_IDENTITY",
                "operating_mode": self.fusion_v3_operating_mode,
                "should_alert": False,
                "result_id": None,
            }

        fusion_result = (
            self.fusion_v3_engine.calculate(

                rule_result=
                    rule_result,

                statistical_result=
                    statistical_result,

                isolation_result=
                    isolation_result,

                autoencoder_result=
                    autoencoder_result,

                temporal_result=
                    temporal_result,
            )
        )


        result_id = (
            self.fusion_v3_store.save_result(

                feature_record_id=
                    int(
                        feature_record_id
                    ),

                pid=
                    identity[
                        "pid"
                    ],

                process_name=
                    identity[
                        "process_name"
                    ],

                process_create_time=
                    identity[
                        "create_time"
                    ],

                fusion_result=
                    fusion_result,

                operating_mode=
                    self.fusion_v3_operating_mode,
            )
        )


        output = dict(
            fusion_result
        )


        output[
            "result_id"
        ] = result_id


        output[
            "operating_mode"
        ] = (
            self.fusion_v3_operating_mode
        )


        return output


    # ============================================================
    # STATUS
    # ============================================================

    def get_fusion_v3_status(
        self,
    ) -> Dict[str, Any]:

        return {
            "fusion_version":
                "v3",

            "operating_mode":
                self.fusion_v3_operating_mode,

            "stored_results":
                self.fusion_v3_store.count(),

            "stored_alert_candidates":
                self.fusion_v3_store.count_alerts(),

            "temporal":
                self.get_temporal_status(),
        }


    # ============================================================
    # EXISTING COLLECTION OVERRIDE
    # ============================================================

    def collect_ai_behavior_features(
        self,
        process_info: Dict[str, Any],
        context: Dict[str, Any],
    ) -> Dict[str, Any]:

        # --------------------------------------------------------
        # Existing Phase-2 + Temporal logic runs first.
        # --------------------------------------------------------

        phase2_result = (
            super()
            .collect_ai_behavior_features(

                process_info=
                    process_info,

                context=
                    context,
            )
        )


        if not isinstance(
            phase2_result,
            dict,
        ):

            return phase2_result


        feature_record_id = (
            self.resolve_feature_record_id(
                phase2_result
            )
        )


        if feature_record_id is None:

            phase2_result[
                "fusion_v3"
            ] = {
                "available":
                    False,

                "state":
                    "MISSING_FEATURE_RECORD_ID",

                "operating_mode":
                    self.fusion_v3_operating_mode,
            }


            return phase2_result


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


        rule_result = (
            self.resolve_rule_result(
                phase2_result
            )
        )


        statistical_result = (
            self.resolve_statistical_result(
                phase2_result
            )
        )


        temporal_result = (
            self.resolve_temporal_result(
                phase2_result
            )
        )


        # ========================================================
        # FUSION V3
        # ========================================================

        try:

            fusion_v3_result = (
                self.calculate_and_persist_fusion_v3(

                    process_info=
                        process_info,

                    feature_record_id=
                        feature_record_id,

                    rule_result=
                        rule_result,

                    statistical_result=
                        statistical_result,

                    isolation_result=
                        isolation_result,

                    autoencoder_result=
                        autoencoder_result,

                    temporal_result=
                        temporal_result,
                )
            )


            # ----------------------------------------------------
            # Shadow mode:
            #
            # Save + expose + log.
            #
            # Do NOT replace existing Fusion-v2 SOC emission yet.
            # ----------------------------------------------------

            logger.info(

                "FUSION V3 | "
                "PID=%s | "
                "Process=%s | "
                "Score=%.2f | "
                "Severity=%s | "
                "Active=%s | "
                "Strong=%s | "
                "Temporal=%s | "
                "Mode=%s",

                process_info.get(
                    "pid"
                ),

                process_info.get(
                    "name"
                ),

                float(
                    fusion_v3_result[
                        "fusion_score"
                    ]
                ),

                fusion_v3_result[
                    "severity"
                ],

                fusion_v3_result[
                    "active_signal_count"
                ],

                fusion_v3_result[
                    "strong_signal_count"
                ],

                fusion_v3_result[
                    "temporal_ai_available"
                ],

                self.fusion_v3_operating_mode,
            )


            if fusion_v3_result[
                "should_alert"
            ]:

                logger.warning(

                    "FUSION V3 ALERT CANDIDATE | "
                    "PID=%s | "
                    "Process=%s | "
                    "Score=%.2f | "
                    "Severity=%s | "
                    "Reasons=%s | "
                    "Mode=%s",

                    process_info.get(
                        "pid"
                    ),

                    process_info.get(
                        "name"
                    ),

                    float(
                        fusion_v3_result[
                            "fusion_score"
                        ]
                    ),

                    fusion_v3_result[
                        "severity"
                    ],

                    fusion_v3_result[
                        "reasons"
                    ],

                    self.fusion_v3_operating_mode,
                )


        except Exception as error:

            logger.exception(

                "Fusion v3 integration failure | "
                "PID=%s | Process=%s",

                process_info.get(
                    "pid"
                ),

                process_info.get(
                    "name"
                ),
            )


            fusion_v3_result = {
                "available":
                    False,

                "state":
                    "FUSION_V3_EXCEPTION",

                "error":
                    str(
                        error
                    ),

                "operating_mode":
                    self.fusion_v3_operating_mode,
            }


        # ========================================================
        # PRESERVE EVERYTHING
        # ========================================================

        phase2_result[
            "fusion_v3"
        ] = (
            fusion_v3_result
        )


        phase2_result[
            "primary_decision_candidate"
        ] = {
            "engine":
                "fusion_v3",

            "mode":
                self.fusion_v3_operating_mode,

            "promoted_to_primary":
                False,
        }


        return phase2_result