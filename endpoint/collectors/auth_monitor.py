from detection.auth.auth_behavior_detector import (
    AuthBehaviorDetector,
)

from endpoint.agent.telemetry_manager import (
    TelemetryManager,
)

from endpoint.storage.database import (
    save_detection,
)

from endpoint.utils.logger import (
    get_logger,
)


logger = get_logger(__name__)


class AuthMonitor:
    """
    SENTINEL-X authentication-event processor.

    This component does NOT perform authentication attempts.

    It receives authentication metadata from a log source,
    detector test, API, or future Windows authentication collector.

    Current pipeline:

        Authentication metadata
                ↓
        AuthBehaviorDetector
                ↓
        SecurityEvent
                ↓
        Detection Database
                ↓
        Correlation
                ↓
        Incident
    """

    def __init__(
        self,
    ):

        # ========================================================
        # TELEMETRY
        # ========================================================

        self.telemetry = (
            TelemetryManager()
        )

        # ========================================================
        # AUTH BEHAVIOR DETECTOR
        # ========================================================

        self.behavior_detector = (
            AuthBehaviorDetector()
        )

    # ============================================================
    # SEVERITY ORDER
    # ============================================================

    def get_final_severity(
        self,
        detections,
    ) -> str:

        severity_order = {

            "INFO":
                0,

            "LOW":
                1,

            "MEDIUM":
                2,

            "HIGH":
                3,

            "CRITICAL":
                4,
        }

        severities = [
            "INFO"
        ]

        for detection in detections:

            severities.append(

                detection.get(
                    "severity",
                    "INFO",
                )
            )

        return max(

            severities,

            key=lambda value:
                severity_order.get(
                    value,
                    0,
                ),
        )

    # ============================================================
    # AUTH EVENT TYPE
    # ============================================================

    def get_security_event_type(
        self,
        auth_event: dict,
        detections,
    ) -> str:

        original_type = str(

            auth_event.get(
                "event_type",
                ""
            )

        ).lower()

        # --------------------------------------------------------
        # Detection generated
        # --------------------------------------------------------

        if detections:

            return (
                "security_auth_detection"
            )

        # --------------------------------------------------------
        # Successful authentication
        # --------------------------------------------------------

        if (
            "success"
            in original_type
        ):

            return (
                "security_auth_success"
            )

        result = str(

            auth_event.get(
                "result",
                ""
            )

        ).lower()

        if (
            result
            ==
            "success"
        ):

            return (
                "security_auth_success"
            )

        # --------------------------------------------------------
        # Failure
        # --------------------------------------------------------

        return (
            "security_auth_failure"
        )

    # ============================================================
    # BUILD NETWORK CONTEXT
    #
    # Authentication source IP is also placed in the network
    # section so SENTINEL-X entity correlation can associate
    # repeated events from the same remote source.
    # ============================================================

    def build_network_context(
        self,
        auth_event: dict,
    ) -> dict:

        source_ip = (

            auth_event.get(
                "source_ip"
            )

            or auth_event.get(
                "src_ip"
            )

            or auth_event.get(
                "remote_ip"
            )

            or auth_event.get(
                "ip_address"
            )
        )

        return {

            "remote_ip":
                source_ip,

            "remote_port":
                auth_event.get(
                    "source_port"
                ),

            "protocol":
                (
                    auth_event.get(
                        "protocol"
                    )
                    or "AUTH"
                ),

            "status":
                (
                    auth_event.get(
                        "result"
                    )
                    or auth_event.get(
                        "status"
                    )
                ),
        }

    # ============================================================
    # SAVE AUTH DETECTIONS
    # ============================================================

    def save_auth_detections(
        self,
        event,
        detections,
    ):

        for detection in detections:

            detection = dict(
                detection
            )

            if (
                "risk"
                not in detection
            ):

                detection[
                    "risk"
                ] = (
                    detection.get(
                        "risk_score",
                        0,
                    )
                )

            try:

                save_detection(

                    event.event_id,

                    detection,
                )

                logger.warning(
                    "AUTH DETECTION | "
                    "EventID=%s | "
                    "Type=%s | "
                    "Severity=%s | "
                    "Risk=%s | "
                    "Confidence=%s | "
                    "SourceIP=%s | "
                    "Reason=%s",

                    event.event_id,

                    detection.get(
                        "detection_type"
                    ),

                    detection.get(
                        "severity"
                    ),

                    detection.get(
                        "risk_score"
                    ),

                    detection.get(
                        "confidence"
                    ),

                    detection.get(
                        "source_ip"
                    ),

                    detection.get(
                        "reason"
                    ),
                )

            except Exception as error:

                logger.error(
                    "Failed to save auth detection | "
                    "EventID=%s | "
                    "Type=%s | %s",

                    event.event_id,

                    detection.get(
                        "detection_type"
                    ),

                    error,
                )

    # ============================================================
    # PROCESS AUTH EVENT
    # ============================================================

    def process_auth_event(
        self,
        auth_event: dict,
        current_time=None,
    ):

        # --------------------------------------------------------
        # ANALYZE
        # --------------------------------------------------------

        detections = (
            self.behavior_detector.analyze(

                auth_event,

                current_time=
                    current_time,
            )
        )

        # --------------------------------------------------------
        # EVENT SEVERITY
        # --------------------------------------------------------

        severity = (
            self.get_final_severity(
                detections
            )
        )

        # --------------------------------------------------------
        # SECURITY EVENT TYPE
        # --------------------------------------------------------

        security_event_type = (
            self.get_security_event_type(

                auth_event,

                detections,
            )
        )

        # --------------------------------------------------------
        # NETWORK / SOURCE CONTEXT
        # --------------------------------------------------------

        network_context = (
            self.build_network_context(
                auth_event
            )
        )

        # --------------------------------------------------------
        # AUTH METADATA
        # --------------------------------------------------------

        metadata = {

            "collector":
                "AuthMonitor",

            "auth_analysis":
                True,

            "original_event_type":
                auth_event.get(
                    "event_type"
                ),

            "username":
                (
                    auth_event.get(
                        "username"
                    )
                    or auth_event.get(
                        "user"
                    )
                    or auth_event.get(
                        "account"
                    )
                ),

            "source_ip":
                network_context.get(
                    "remote_ip"
                ),

            "result":
                (
                    auth_event.get(
                        "result"
                    )
                    or auth_event.get(
                        "status"
                    )
                ),

            "auth_detection_count":
                len(
                    detections
                ),

            "auth_detection_types":
                [

                    detection.get(
                        "detection_type"
                    )

                    for detection
                    in detections
                ],

            "synthetic_test":
                auth_event.get(
                    "synthetic_test",
                    False,
                ),
        }

        # --------------------------------------------------------
        # CREATE SECURITY EVENT
        #
        # TelemetryManager automatically:
        #
        #   saves the raw event
        #   runs correlation
        #   creates/updates incidents
        # --------------------------------------------------------

        event = (
            self.telemetry.emit(

                event_type=
                    security_event_type,

                source=
                    "auth_monitor",

                severity=
                    severity,

                network=
                    network_context,

                metadata=
                    metadata,
            )
        )

        # --------------------------------------------------------
        # SAVE DEDICATED DETECTIONS
        # --------------------------------------------------------

        if detections:

            self.save_auth_detections(

                event,

                detections,
            )

        # --------------------------------------------------------
        # LOG
        # --------------------------------------------------------

        logger.info(
            "AUTH EVENT | "
            "User=%s | "
            "SourceIP=%s | "
            "Result=%s | "
            "Detections=%s | "
            "Severity=%s | "
            "EventID=%s",

            metadata.get(
                "username"
            ),

            metadata.get(
                "source_ip"
            ),

            metadata.get(
                "result"
            ),

            len(
                detections
            ),

            severity,

            event.event_id,
        )

        return {

            "event":
                event,

            "detections":
                detections,
        }