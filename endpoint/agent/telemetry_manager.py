from __future__ import annotations


from endpoint.models.security_event import (
    SecurityEvent,
)

from endpoint.storage.database import (
    save_event,
)

from endpoint.utils.logger import (
    get_logger,
)


from detection.fusion.correlation_manager import (
    CorrelationManager,
)


from ai_detection.graph.provenance_graph_builder import (
    ProvenanceGraphBuilder,
)


logger = get_logger(
    __name__
)


# ================================================================
# SHARED CORRELATION MANAGER
# ================================================================
#
# One correlation manager is shared by all TelemetryManager
# instances inside this Python process.
#
# This allows:
#
#   Process
#   File
#   Network
#   Registry
#
# events to contribute to the same evolving incident.
# ================================================================

shared_correlation_manager = (
    CorrelationManager(

        correlation_window_seconds=
            120,

        incident_threshold=
            35,
    )
)


# ================================================================
# SHARED PROVENANCE GRAPH BUILDER
#
# Lazy initialization is intentional.
#
# We do NOT create the graph database simply because this module
# was imported.
#
# The first TelemetryManager instance that needs the graph creates
# it.
#
# ProvenanceGraphStore uses short-lived SQLite connections, so this
# builder is safe to share between collector threads.
# ================================================================

_shared_provenance_graph_builder = None


def get_shared_provenance_graph_builder():

    global _shared_provenance_graph_builder


    if (
        _shared_provenance_graph_builder
        is None
    ):

        _shared_provenance_graph_builder = (
            ProvenanceGraphBuilder()
        )


        logger.info(
            "SENTINEL-X Provenance Graph initialized."
        )


    return (
        _shared_provenance_graph_builder
    )


# ================================================================
# TELEMETRY MANAGER
# ================================================================


class TelemetryManager:

    def __init__(
        self,
        device_id: str = "local-device",
        provenance_builder=None,
        correlation_manager=None,
    ):

        # ========================================================
        # DEVICE
        # ========================================================

        self.device_id = (
            device_id
        )


        # ========================================================
        # PROVENANCE GRAPH
        #
        # Tests can inject their own isolated builder.
        #
        # Production automatically receives the shared graph
        # builder.
        # ========================================================

        self.provenance_builder = (

            provenance_builder

            if provenance_builder
            is not None

            else
            get_shared_provenance_graph_builder()
        )


        # ========================================================
        # CORRELATION
        #
        # Tests can inject a controlled correlation manager.
        #
        # Production automatically uses the existing shared
        # CorrelationManager.
        # ========================================================

        self.correlation_manager = (

            correlation_manager

            if correlation_manager
            is not None

            else
            shared_correlation_manager
        )


    # ============================================================
    # EVENT CATEGORY
    # ============================================================

    def get_event_category(
        self,
        event_type: str,
    ) -> str:

        event_type = (
            event_type
            or ""
        ).lower()


        # ========================================================
        # PROCESS
        # ========================================================

        if event_type.startswith(
            "process"
        ):

            return "PROCESS"


        # ========================================================
        # FILE
        # ========================================================

        if event_type.startswith(
            "file"
        ):

            return "FILE"


        # ========================================================
        # NETWORK
        # ========================================================

        if event_type.startswith(
            "network"
        ):

            return "NETWORK"


        # ========================================================
        # REGISTRY
        # ========================================================

        if event_type.startswith(
            "registry"
        ):

            return "REGISTRY"


        # ========================================================
        # STARTUP
        # ========================================================

        if event_type.startswith(
            "startup"
        ):

            return "STARTUP"


        # ========================================================
        # SECURITY
        # ========================================================

        if event_type.startswith(
            "security"
        ):

            return "SECURITY"


        # ========================================================
        # RESPONSE
        # ========================================================

        if event_type.startswith(
            "response"
        ):

            return "RESPONSE"


        return "SYSTEM"


    # ============================================================
    # WRITE EVENT TO PROVENANCE GRAPH
    #
    # IMPORTANT:
    #
    # Provenance failure must NEVER stop:
    #
    #       raw telemetry
    #       detection
    #       correlation
    #       incident creation
    #
    # It is an additional intelligence layer.
    # ============================================================

    def write_provenance_graph(
        self,
        event,
    ):

        if (
            self.provenance_builder
            is None
        ):

            return None


        try:

            # SecurityEvent already provides to_dict().
            event_dict = (
                event.to_dict()
            )


            graph_result = (
                self.provenance_builder
                .build_from_event(
                    event_dict
                )
            )


            logger.info(
                "Provenance graph updated | "
                "EventID=%s | "
                "Category=%s | "
                "Nodes=%s | "
                "Edges=%s",

                event.event_id,

                graph_result.get(
                    "category"
                ),

                len(
                    graph_result.get(
                        "nodes",
                        {},
                    )
                ),

                graph_result.get(
                    "edge_count",
                    0,
                ),
            )


            return (
                graph_result
            )


        except Exception as error:

            # ----------------------------------------------------
            # Provenance processing is intentionally isolated.
            #
            # A graph problem must not interrupt endpoint
            # telemetry.
            # ----------------------------------------------------

            logger.exception(
                "Provenance graph processing failed | "
                "EventID=%s | %s",

                event.event_id,

                error,
            )


            return None


    # ============================================================
    # PROCESS CORRELATION
    # ============================================================

    def process_correlation(
        self,
        event,
    ):

        try:

            correlation_result = (
                self.correlation_manager
                .process_event(
                    event
                )
            )


            if not isinstance(
                correlation_result,
                dict,
            ):

                correlation_result = {}


            correlation = (
                correlation_result.get(
                    "correlation",
                    {},
                )
            )


            if not isinstance(
                correlation,
                dict,
            ):

                correlation = {}


            correlation_score = (
                correlation.get(
                    "correlation_score",
                    0,
                )
            )


            related_event_count = (
                correlation.get(
                    "related_event_count",
                    0,
                )
            )


            # ====================================================
            # CORRELATED EVENT
            # ====================================================

            if (
                correlation.get(
                    "correlated",
                    False,
                )
            ):

                logger.info(
                    "Event correlation detected | "
                    "EventID=%s | "
                    "Score=%s | "
                    "RelatedEvents=%s",

                    event.event_id,

                    correlation_score,

                    related_event_count,
                )


            # ====================================================
            # INCIDENT CREATED
            # ====================================================

            if correlation_result.get(
                "incident_created",
                False,
            ):

                incident = (
                    correlation_result.get(
                        "incident",
                        {},
                    )
                )


                if not isinstance(
                    incident,
                    dict,
                ):

                    incident = {}


                logger.warning(
                    "Incident created | "
                    "IncidentID=%s | "
                    "Title=%s | "
                    "Score=%s | "
                    "Severity=%s | "
                    "Events=%s",

                    incident.get(
                        "incident_id"
                    ),

                    incident.get(
                        "title"
                    ),

                    incident.get(
                        "correlation_score"
                    ),

                    incident.get(
                        "severity"
                    ),

                    incident.get(
                        "event_count"
                    ),
                )


            # ====================================================
            # INCIDENT UPDATED
            # ====================================================

            elif correlation_result.get(
                "incident_updated",
                False,
            ):

                incident = (
                    correlation_result.get(
                        "incident",
                        {},
                    )
                )


                if not isinstance(
                    incident,
                    dict,
                ):

                    incident = {}


                logger.warning(
                    "Incident updated | "
                    "IncidentID=%s | "
                    "Title=%s | "
                    "Score=%s | "
                    "Severity=%s | "
                    "Events=%s",

                    incident.get(
                        "incident_id"
                    ),

                    incident.get(
                        "title"
                    ),

                    incident.get(
                        "correlation_score"
                    ),

                    incident.get(
                        "severity"
                    ),

                    incident.get(
                        "event_count"
                    ),
                )


            return (
                correlation_result
            )


        except Exception as error:

            # ----------------------------------------------------
            # Correlation failure must NEVER stop telemetry
            # collection.
            # ----------------------------------------------------

            logger.exception(
                "Correlation processing failed | "
                "EventID=%s | %s",

                event.event_id,

                error,
            )


            return None


    # ============================================================
    # EMIT TELEMETRY EVENT
    #
    # FINAL PIPELINE
    #
    # Collector
    #     ↓
    # TelemetryManager.emit()
    #     ↓
    # SecurityEvent
    #     ↓
    # Raw event persistence
    #     ↓
    # Provenance graph
    #     ↓
    # Correlation
    #     ↓
    # Incident creation / update
    # ============================================================

    def emit(
        self,
        event_type: str,
        source: str,
        severity: str = "INFO",
        process: dict = None,
        file: dict = None,
        network: dict = None,
        registry: dict = None,
        metadata: dict = None,
    ):

        # ========================================================
        # NORMALIZE INPUT
        # ========================================================

        process = (
            process
            or {}
        )


        file = (
            file
            or {}
        )


        network = (
            network
            or {}
        )


        registry = (
            registry
            or {}
        )


        metadata = (
            metadata
            or {}
        )


        # ========================================================
        # CATEGORY
        # ========================================================

        category = (
            self.get_event_category(
                event_type
            )
        )


        # ========================================================
        # CENTRAL TELEMETRY METADATA
        # ========================================================

        metadata = dict(
            metadata
        )


        metadata.update(
            {
                "event_category":
                    category,

                "device_id":
                    self.device_id,
            }
        )


        # ========================================================
        # CREATE SECURITY EVENT
        # ========================================================

        event = (
            SecurityEvent(

                event_type=
                    event_type,

                source=
                    source,

                device_id=
                    self.device_id,

                severity=
                    severity,

                process=
                    process,

                file=
                    file,

                network=
                    network,

                registry=
                    registry,

                metadata=
                    metadata,
            )
        )


        # ========================================================
        # 1. SAVE RAW TELEMETRY
        # ========================================================

        save_event(
            event
        )


        logger.info(
            "Telemetry event emitted | "
            "Type=%s | "
            "Category=%s | "
            "EventID=%s",

            event_type,

            category,

            event.event_id,
        )


        # ========================================================
        # 2. PROVENANCE GRAPH
        #
        # Every SecurityEvent now automatically updates the graph.
        # ========================================================

        provenance_result = (
            self.write_provenance_graph(
                event
            )
        )


        # ========================================================
        # 3. CORRELATION
        # ========================================================

        correlation_result = (
            self.process_correlation(
                event
            )
        )


        # ========================================================
        # OPTIONAL RUNTIME METADATA
        #
        # This modifies only the returned in-memory SecurityEvent.
        # Raw event persistence already happened above.
        # ========================================================

        if isinstance(
            event.metadata,
            dict,
        ):

            event.metadata[
                "provenance_graph"
            ] = {
                "processed":
                    provenance_result
                    is not None,

                "node_count":
                    (
                        len(
                            provenance_result.get(
                                "nodes",
                                {},
                            )
                        )

                        if isinstance(
                            provenance_result,
                            dict,
                        )

                        else 0
                    ),

                "edge_count":
                    (
                        provenance_result.get(
                            "edge_count",
                            0,
                        )

                        if isinstance(
                            provenance_result,
                            dict,
                        )

                        else 0
                    ),
            }


            event.metadata[
                "correlation_processed"
            ] = (
                correlation_result
                is not None
            )


        # ========================================================
        # RETURN SECURITY EVENT
        # ========================================================

        return event