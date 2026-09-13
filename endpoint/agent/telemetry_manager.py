from endpoint.models.security_event import SecurityEvent
from endpoint.storage.database import save_event
from endpoint.utils.logger import get_logger

from detection.fusion.correlation_manager import (
    CorrelationManager,
)


logger = get_logger(__name__)


# ============================================================
# SHARED CORRELATION MANAGER
# ============================================================

# One shared manager for all telemetry events handled
# inside this Python process.
#
# This means file, process, network, and registry events
# can all contribute to the same evolving incident.
shared_correlation_manager = (
    CorrelationManager(
        correlation_window_seconds=120,
        incident_threshold=35,
    )
)


class TelemetryManager:

    def __init__(
        self,
        device_id: str = "local-device",
    ):

        self.device_id = device_id


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


        if event_type.startswith(
            "process"
        ):

            return "PROCESS"


        if event_type.startswith(
            "file"
        ):

            return "FILE"


        if event_type.startswith(
            "network"
        ):

            return "NETWORK"


        if event_type.startswith(
            "registry"
        ):

            return "REGISTRY"


        if event_type.startswith(
            "startup"
        ):

            return "STARTUP"


        if event_type.startswith(
            "security"
        ):

            return "SECURITY"


        if event_type.startswith(
            "response"
        ):

            return "RESPONSE"


        return "SYSTEM"


    # ============================================================
    # EMIT TELEMETRY EVENT
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

        # --------------------------------------------------------
        # NORMALIZE INPUT
        # --------------------------------------------------------

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


        # --------------------------------------------------------
        # CATEGORY
        # --------------------------------------------------------

        category = (
            self.get_event_category(
                event_type
            )
        )


        # --------------------------------------------------------
        # ADD CENTRAL TELEMETRY METADATA
        # --------------------------------------------------------

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


        # --------------------------------------------------------
        # CREATE SECURITY EVENT
        # --------------------------------------------------------

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


        # --------------------------------------------------------
        # SAVE RAW TELEMETRY
        # --------------------------------------------------------

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


        # --------------------------------------------------------
        # CORRELATION
        # --------------------------------------------------------

        try:

            correlation_result = (
                shared_correlation_manager.process_event(
                    event
                )
            )


            correlation = (
                correlation_result.get(
                    "correlation",
                    {}
                )
            )


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


            # ----------------------------------------------------
            # CORRELATION LOG
            # ----------------------------------------------------

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


            # ----------------------------------------------------
            # INCIDENT CREATED
            # ----------------------------------------------------

            if correlation_result.get(
                "incident_created",
                False,
            ):

                incident = (
                    correlation_result.get(
                        "incident",
                        {}
                    )
                )


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


            # ----------------------------------------------------
            # INCIDENT UPDATED
            # ----------------------------------------------------

            elif correlation_result.get(
                "incident_updated",
                False,
            ):

                incident = (
                    correlation_result.get(
                        "incident",
                        {}
                    )
                )


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


        except Exception as error:

            # ----------------------------------------------------
            # Correlation failure must NEVER stop telemetry
            # collection.
            # ----------------------------------------------------

            logger.error(
                "Correlation processing failed | "
                "EventID=%s | %s",

                event.event_id,

                error,
            )


        # --------------------------------------------------------
        # RETURN SECURITY EVENT
        # --------------------------------------------------------

        return event