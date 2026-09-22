from detection.anomaly.generic_behavior_anomaly_detector import (
    GenericBehaviorAnomalyDetector,
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


class GenericAnomalyMonitor:
    """
    SENTINEL-X Generic Behavior Anomaly Monitor.

    Metadata-only analysis.

    This component does NOT:

        - generate network traffic
        - open connections
        - read files
        - execute processes
        - contact external systems
    """

    def __init__(
        self,
        detector=None,
    ):

        self.telemetry = (
            TelemetryManager()
        )

        self.detector = (
            detector
            or GenericBehaviorAnomalyDetector()
        )

    # ============================================================
    # SEVERITY
    # ============================================================

    def get_final_severity(
        self,
        detections,
    ) -> str:

        severity_order = {
            "INFO": 0,
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4,
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
    # EVENT TYPE
    # ============================================================

    def get_event_type(
        self,
        detections,
    ) -> str:

        if detections:

            return (
                "network_unknown_anomaly_detection"
            )

        return (
            "network_behavior_observation"
        )

    # ============================================================
    # NETWORK CONTEXT
    # ============================================================

    def build_network_context(
        self,
        behavior_event,
    ) -> dict:

        return {

            # Important for correlation.
            "pid":
                behavior_event.get(
                    "pid"
                ),

            "process_name":
                behavior_event.get(
                    "process_name"
                ),

            "local_ip":
                behavior_event.get(
                    "local_ip"
                ),

            "local_port":
                behavior_event.get(
                    "local_port"
                ),

            "remote_ip":
                behavior_event.get(
                    "remote_ip"
                ),

            "remote_port":
                behavior_event.get(
                    "remote_port"
                ),

            "protocol":
                (
                    behavior_event.get(
                        "protocol"
                    )
                    or "UNKNOWN"
                ),

            "direction":
                behavior_event.get(
                    "direction"
                ),

            "bytes_sent":
                behavior_event.get(
                    "bytes_sent"
                ),

            "connection_count":
                behavior_event.get(
                    "connection_count"
                ),

            "destination_count":
                behavior_event.get(
                    "destination_count"
                ),
        }

    # ============================================================
    # SAVE DETECTIONS
    # ============================================================

    def save_anomaly_detections(
        self,
        event,
        detections,
    ):

        for detection in detections:

            detection = dict(
                detection
            )

            if "risk" not in detection:

                detection[
                    "risk"
                ] = (
                    detection.get(
                        "risk_score",
                        0,
                    )
                )

            save_detection(
                event.event_id,
                detection,
            )

            logger.warning(
                "GENERIC ANOMALY DETECTION | "
                "EventID=%s | "
                "Type=%s | "
                "Severity=%s | "
                "Risk=%s | "
                "Process=%s | "
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
                    "process_name"
                ),

                detection.get(
                    "reason"
                ),
            )

    # ============================================================
    # PROCESS BEHAVIOR
    # ============================================================

    def process_behavior(
        self,
        behavior_event: dict,
    ):

        # --------------------------------------------------------
        # ANALYZE
        # --------------------------------------------------------

        detections = (
            self.detector.analyze(
                behavior_event
            )
        )

        # --------------------------------------------------------
        # SEVERITY
        # --------------------------------------------------------

        severity = (
            self.get_final_severity(
                detections
            )
        )

        # --------------------------------------------------------
        # EVENT TYPE
        # --------------------------------------------------------

        event_type = (
            self.get_event_type(
                detections
            )
        )

        # --------------------------------------------------------
        # NETWORK CONTEXT
        # --------------------------------------------------------

        network_context = (
            self.build_network_context(
                behavior_event
            )
        )

        # --------------------------------------------------------
        # METADATA
        # --------------------------------------------------------

        metadata = {

            "collector":
                "GenericAnomalyMonitor",

            "generic_anomaly_analysis":
                True,

            "device_id":
                behavior_event.get(
                    "device_id"
                ),

            "pid":
                behavior_event.get(
                    "pid"
                ),

            "process_name":
                behavior_event.get(
                    "process_name"
                ),

            "remote_ip":
                behavior_event.get(
                    "remote_ip"
                ),

            "bytes_sent":
                behavior_event.get(
                    "bytes_sent"
                ),

            "connection_count":
                behavior_event.get(
                    "connection_count"
                ),

            "destination_count":
                behavior_event.get(
                    "destination_count"
                ),

            "anomaly_detection_count":
                len(
                    detections
                ),

            "anomaly_detection_types":
                [
                    detection.get(
                        "detection_type"
                    )

                    for detection
                    in detections
                ],

            "synthetic_test":
                behavior_event.get(
                    "synthetic_test",
                    False,
                ),
        }

        # --------------------------------------------------------
        # SECURITY EVENT
        # --------------------------------------------------------

        event = (
            self.telemetry.emit(

                event_type=
                    event_type,

                source=
                    "generic_anomaly_monitor",

                severity=
                    severity,

                network=
                    network_context,

                metadata=
                    metadata,
            )
        )

        # --------------------------------------------------------
        # DETECTION STORAGE
        # --------------------------------------------------------

        if detections:

            self.save_anomaly_detections(
                event,
                detections,
            )

        logger.info(
            "GENERIC ANOMALY EVENT | "
            "Process=%s | "
            "PID=%s | "
            "Detections=%s | "
            "Severity=%s | "
            "EventID=%s",

            behavior_event.get(
                "process_name"
            ),

            behavior_event.get(
                "pid"
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