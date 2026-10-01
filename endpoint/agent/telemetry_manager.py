from __future__ import annotations

import threading
import time
from datetime import datetime, timezone


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
        correlation_window_seconds=120,
        incident_threshold=35,
    )
)


# ================================================================
# SHARED PROVENANCE GRAPH BUILDER
# ================================================================
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

_shared_provenance_graph_lock = (
    threading.RLock()
)


def get_shared_provenance_graph_builder():

    global _shared_provenance_graph_builder

    if (
        _shared_provenance_graph_builder
        is None
    ):

        with _shared_provenance_graph_lock:

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


        # ========================================================
        # LIVE TELEMETRY RUNTIME
        #
        # These values represent telemetry observed by THIS
        # running Sentinel-X process.
        #
        # They are different from the historical SQLite totals.
        # ========================================================

        self.runtime_lock = (
            threading.RLock()
        )

        self.runtime_started_at = (
            time.time()
        )

        self.runtime_event_count = 0


        # Total telemetry received since this runtime started.

        self.runtime_category_counts = {

            "PROCESS": 0,

            "FILE": 0,

            "NETWORK": 0,

            "REGISTRY": 0,

            "STARTUP": 0,

            "SECURITY": 0,

            "RESPONSE": 0,

            "SYSTEM": 0,
        }


        # Number of events received since the frontend/API
        # last consumed an interval snapshot.

        self.interval_category_counts = {

            "PROCESS": 0,

            "FILE": 0,

            "NETWORK": 0,

            "REGISTRY": 0,

            "STARTUP": 0,

            "SECURITY": 0,

            "RESPONSE": 0,

            "SYSTEM": 0,
        }


        # ========================================================
        # LATEST EVENT
        # ========================================================

        self.latest_event_timestamp = None

        self.latest_event_type = None

        self.latest_event_category = None

        self.latest_event_severity = None

        self.latest_event_id = None

        self.latest_event_source = None


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
    # RECORD LIVE TELEMETRY EVENT
    # ============================================================

    def record_runtime_event(
        self,
        *,
        event,
        category: str,
    ):

        category = (
            str(
                category
                or "SYSTEM"
            )
            .upper()
        )


        with self.runtime_lock:

            # ====================================================
            # TOTAL RUNTIME EVENTS
            # ====================================================

            self.runtime_event_count += 1


            # ====================================================
            # ENSURE CATEGORY EXISTS
            # ====================================================

            if (
                category
                not in self.runtime_category_counts
            ):

                self.runtime_category_counts[
                    category
                ] = 0


            if (
                category
                not in self.interval_category_counts
            ):

                self.interval_category_counts[
                    category
                ] = 0


            # ====================================================
            # RUNTIME TOTAL
            # ====================================================

            self.runtime_category_counts[
                category
            ] += 1


            # ====================================================
            # CURRENT FRONTEND INTERVAL
            # ====================================================

            self.interval_category_counts[
                category
            ] += 1


            # ====================================================
            # LATEST EVENT
            # ====================================================

            self.latest_event_timestamp = (
                getattr(
                    event,
                    "timestamp",
                    None,
                )
            )

            self.latest_event_type = (
                getattr(
                    event,
                    "event_type",
                    None,
                )
            )

            self.latest_event_category = (
                category
            )

            self.latest_event_severity = (
                getattr(
                    event,
                    "severity",
                    None,
                )
            )

            self.latest_event_id = (
                getattr(
                    event,
                    "event_id",
                    None,
                )
            )

            self.latest_event_source = (
                getattr(
                    event,
                    "source",
                    None,
                )
            )


    # ============================================================
    # LIVE TELEMETRY SNAPSHOT
    #
    # reset_interval=True:
    #
    #   return all events collected since previous API request,
    #   then reset only the interval counters.
    #
    # Runtime totals are NOT reset.
    # ============================================================

    def get_live_snapshot(
        self,
        reset_interval: bool = True,
    ) -> dict:

        with self.runtime_lock:

            runtime_counts = dict(
                self.runtime_category_counts
            )

            interval_counts = dict(
                self.interval_category_counts
            )


            runtime_event_count = (
                self.runtime_event_count
            )


            latest_event = {

                "event_id":
                    self.latest_event_id,

                "timestamp":
                    self.latest_event_timestamp,

                "event_type":
                    self.latest_event_type,

                "category":
                    self.latest_event_category,

                "severity":
                    self.latest_event_severity,

                "source":
                    self.latest_event_source,
            }


            if reset_interval:

                for category in (
                    self.interval_category_counts
                ):

                    self.interval_category_counts[
                        category
                    ] = 0


        uptime_seconds = max(
            0.0,
            time.time()
            -
            self.runtime_started_at,
        )


        return {

            "status":
                "ACTIVE",

            "running":
                True,

            "device_id":
                self.device_id,

            "timestamp":
                datetime.now(
                    timezone.utc
                ).isoformat(),

            "uptime_seconds":
                round(
                    uptime_seconds,
                    2,
                ),

            "runtime_event_count":
                runtime_event_count,


            # ====================================================
            # ALL EVENTS SEEN SINCE THIS BACKEND STARTED
            # ====================================================

            "runtime_counts": {

                "process":
                    runtime_counts.get(
                        "PROCESS",
                        0,
                    ),

                "file":
                    runtime_counts.get(
                        "FILE",
                        0,
                    ),

                "network":
                    runtime_counts.get(
                        "NETWORK",
                        0,
                    ),

                "registry":
                    runtime_counts.get(
                        "REGISTRY",
                        0,
                    ),

                "startup":
                    runtime_counts.get(
                        "STARTUP",
                        0,
                    ),

                "security":
                    runtime_counts.get(
                        "SECURITY",
                        0,
                    ),

                "response":
                    runtime_counts.get(
                        "RESPONSE",
                        0,
                    ),

                "system":
                    runtime_counts.get(
                        "SYSTEM",
                        0,
                    ),
            },


            # ====================================================
            # EVENTS SINCE PREVIOUS SNAPSHOT
            #
            # These values are intended for the Live Monitor graph.
            # ====================================================

            "recent": {

                "process":
                    interval_counts.get(
                        "PROCESS",
                        0,
                    ),

                "file":
                    interval_counts.get(
                        "FILE",
                        0,
                    ),

                "network":
                    interval_counts.get(
                        "NETWORK",
                        0,
                    ),

                "registry":
                    interval_counts.get(
                        "REGISTRY",
                        0,
                    ),

                "startup":
                    interval_counts.get(
                        "STARTUP",
                        0,
                    ),

                "security":
                    interval_counts.get(
                        "SECURITY",
                        0,
                    ),

                "response":
                    interval_counts.get(
                        "RESPONSE",
                        0,
                    ),

                "system":
                    interval_counts.get(
                        "SYSTEM",
                        0,
                    ),
            },


            # ====================================================
            # FRONTEND FRIENDLY VIEW
            # ====================================================

            "live_monitor": {

                "process_events":
                    interval_counts.get(
                        "PROCESS",
                        0,
                    ),

                "file_events":
                    interval_counts.get(
                        "FILE",
                        0,
                    ),

                "network_events":
                    interval_counts.get(
                        "NETWORK",
                        0,
                    ),

                "system_events":
                    (
                        interval_counts.get(
                            "REGISTRY",
                            0,
                        )
                        +
                        interval_counts.get(
                            "SYSTEM",
                            0,
                        )
                        +
                        interval_counts.get(
                            "STARTUP",
                            0,
                        )
                    ),
            },


            "latest_event":
                latest_event,
        }


    # ============================================================
    # NON-DESTRUCTIVE LIVE SNAPSHOT
    #
    # Useful for:
    #
    #   dashboard
    #   status endpoint
    #   debugging
    #
    # It does NOT clear recent counters.
    # ============================================================

    def peek_live_snapshot(
        self,
    ) -> dict:

        return self.get_live_snapshot(
            reset_interval=False
        )


    # ============================================================
    # RESET RUNTIME COUNTERS
    #
    # Intended primarily for controlled tests.
    # Do not normally call this from the frontend.
    # ============================================================

    def reset_runtime_counters(
        self,
    ):

        with self.runtime_lock:

            self.runtime_started_at = (
                time.time()
            )

            self.runtime_event_count = 0


            for category in (
                self.runtime_category_counts
            ):

                self.runtime_category_counts[
                    category
                ] = 0


            for category in (
                self.interval_category_counts
            ):

                self.interval_category_counts[
                    category
                ] = 0


            self.latest_event_timestamp = None

            self.latest_event_type = None

            self.latest_event_category = None

            self.latest_event_severity = None

            self.latest_event_id = None

            self.latest_event_source = None


        logger.info(
            "Telemetry runtime counters reset."
        )


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
    # Live telemetry runtime counters
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
        #
        # Preserve your existing behaviour:
        #
        # only count an event as live telemetry after the event
        # has successfully reached central persistence.
        # ========================================================

        save_event(
            event
        )


        # ========================================================
        # 2. RECORD LIVE RUNTIME EVENT
        #
        # Every successfully persisted telemetry event is recorded
        # exactly once here.
        #
        # This is what powers:
        #
        #     Process Events
        #     File Events
        #     Network Events
        #     System Events
        #
        # and the real-time line chart.
        # ========================================================

        self.record_runtime_event(
            event=event,
            category=category,
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
        # 3. PROVENANCE GRAPH
        #
        # Every SecurityEvent automatically updates the graph.
        # ========================================================

        provenance_result = (
            self.write_provenance_graph(
                event
            )
        )


        # ========================================================
        # 4. CORRELATION
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
        #
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


# ================================================================
# SHARED PRODUCTION TELEMETRY MANAGER
#
# IMPORTANT:
#
# All production collectors should use THIS SAME instance.
#
# Do NOT create:
#
#     TelemetryManager()
#
# separately inside every collector if you want the frontend
# runtime counters to represent all collector activity together.
# ================================================================

shared_telemetry_manager = (
    TelemetryManager(
        device_id="local-device"
    )
)