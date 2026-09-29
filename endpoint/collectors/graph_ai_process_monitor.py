from __future__ import annotations

from endpoint.collectors.fusion_v3_primary_process_monitor import (
    FusionV3PrimaryProcessMonitor,
)


from ai_detection.graph.process_graph_anomaly_predictor import (
    ProcessGraphAnomalyPredictor,
)


from ai_detection.graph.process_graph_result_store import (
    ProcessGraphResultStore,
)


from endpoint.utils.logger import (
    get_logger,
)


logger = get_logger(
    __name__
)


class GraphAIProcessMonitor(
    FusionV3PrimaryProcessMonitor
):

    GRAPH_AI_MODE = (
        "SHADOW_GRAPH_AI"
    )


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
        # GRAPH-AI RUNTIME
        # ========================================================

        self.graph_ai_predictor = (
            ProcessGraphAnomalyPredictor()
        )


        self.graph_ai_store = (
            ProcessGraphResultStore()
        )


        logger.info(
            "Graph AI Runtime | "
            "Predictor=v1 | "
            "Model=v1 | "
            "Mode=%s",
            self.GRAPH_AI_MODE,
        )


    # ============================================================
    # EXTRACT PROCESS IDENTITY
    # ============================================================

    def resolve_process_identity(
        self,
        process_info,
    ):

        process_info = (
            process_info
            or {}
        )


        pid = (
            process_info.get(
                "pid"
            )
        )


        process_name = (

            process_info.get(
                "name"
            )

            or

            process_info.get(
                "process_name"
            )
        )


        device_id = (

            process_info.get(
                "device_id"
            )

            or

            process_info.get(
                "hostname"
            )
        )


        return {
            "pid":
                pid,

            "process_name":
                process_name,

            "device_id":
                device_id,
        }


    # ============================================================
    # GRAPH-AI INFERENCE
    # ============================================================

    def run_graph_ai(
        self,
        *,
        process_info,
        event_id=None,
    ):

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


        if pid is None:

            return {
                "available":
                    False,

                "state":
                    "PID_UNAVAILABLE",

                "graph_anomaly_score":
                    None,

                "operating_mode":
                    self.GRAPH_AI_MODE,
            }


        try:

            result = (
                self.graph_ai_predictor
                .predict(

                    pid=
                        pid,

                    process_name=
                        identity[
                            "process_name"
                        ],

                    device_id=
                        identity[
                            "device_id"
                        ],
                )
            )


            # ====================================================
            # PERSIST ONLY COMPLETE INFERENCE
            # ====================================================

            if (
                result.get(
                    "available",
                    False,
                )

                and

                result.get(
                    "state"
                )
                ==
                "GRAPH_INFERENCE_COMPLETE"
            ):

                result_id = (
                    self.graph_ai_store
                    .save_result(

                        result,

                        event_id=
                            event_id,
                    )
                )


                result[
                    "result_id"
                ] = (
                    result_id
                )


                logger.info(
                    "Graph AI inference | "
                    "PID=%s | "
                    "Process=%s | "
                    "Score=%.2f | "
                    "Band=%s | "
                    "Nodes=%s | "
                    "Edges=%s | "
                    "Mode=%s",

                    result.get(
                        "pid"
                    ),

                    result.get(
                        "process_name"
                    ),

                    float(
                        result.get(
                            "graph_anomaly_score",
                            0.0,
                        )
                    ),

                    result.get(
                        "graph_anomaly_band"
                    ),

                    result.get(
                        "graph_node_count"
                    ),

                    result.get(
                        "graph_edge_count"
                    ),

                    self.GRAPH_AI_MODE,
                )


            return result


        except Exception as error:

            logger.exception(
                "Graph AI inference failed | "
                "PID=%s | "
                "Process=%s | "
                "Error=%s",

                pid,

                identity[
                    "process_name"
                ],

                error,
            )


            return {
                "available":
                    False,

                "state":
                    "GRAPH_INFERENCE_ERROR",

                "pid":
                    pid,

                "process_name":
                    identity[
                        "process_name"
                    ],

                "graph_anomaly_score":
                    None,

                "operating_mode":
                    self.GRAPH_AI_MODE,

                "error":
                    str(
                        error
                    ),
            }


    # ============================================================
    # COLLECT AI FEATURES
    #
    # Existing behavioral + temporal pipeline runs first.
    #
    # Then graph evidence is attached.
    # ============================================================

    def collect_ai_behavior_features(
        self,
        process_info,
        context,
    ):

        ai_result = (
            super()
            .collect_ai_behavior_features(

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

            ai_result = {}


        # ========================================================
        # GRAPH INFERENCE
        # ========================================================

        graph_result = (
            self.run_graph_ai(

                process_info=
                    process_info,

                event_id=
                    None,
            )
        )


        ai_result[
            "graph_ai"
        ] = (
            graph_result
        )


        # ========================================================
        # PRIMARY DECISION IS STILL FUSION-V3
        # ========================================================

        ai_result[
            "graph_ai_primary_influence"
        ] = False


        ai_result[
            "graph_ai_operating_mode"
        ] = (
            self.GRAPH_AI_MODE
        )


        return ai_result


    # ============================================================
    # STATUS
    # ============================================================

    def get_graph_ai_status(
        self,
    ):

        return {
            "available":
                True,

            "predictor":
                "process_graph_anomaly",

            "predictor_version":
                "v1",

            "model_version":
                self.graph_ai_predictor
                .checkpoint
                .get(
                    "model_version"
                ),

            "calibration_version":
                self.graph_ai_predictor
                .calibration
                .get(
                    "calibration_version"
                ),

            "calibration_quality":
                self.graph_ai_predictor
                .calibration
                .get(
                    "calibration_quality"
                ),

            "operating_mode":
                self.GRAPH_AI_MODE,

            "primary_influence":
                False,

            "authoritative_alert":
                False,

            "persisted_results":
                self.graph_ai_store
                .count(),

            "active_results":
                self.graph_ai_store
                .count_active(),

            "strong_results":
                self.graph_ai_store
                .count_strong(),
        }


    # ============================================================
    # STOP
    # ============================================================

    def stop(
        self,
    ):

        try:

            self.graph_ai_predictor.close()

        except Exception:

            logger.exception(
                "Unable to close Graph-AI predictor."
            )


        try:

            self.graph_ai_store.close()

        except Exception:

            logger.exception(
                "Unable to close Graph-AI result store."
            )


        return (
            super().stop()
        )