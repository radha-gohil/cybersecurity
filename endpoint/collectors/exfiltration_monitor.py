from detection.exfiltration.exfiltration_detector import (
    ExfiltrationBehaviorDetector,
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


class ExfiltrationMonitor:
    """
    SENTINEL-X Exfiltration Metadata Monitor.

    This component only analyzes supplied network-transfer
    metadata.

    It DOES NOT:

        - create network connections
        - transfer files
        - upload data
        - read confidential files
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

            or ExfiltrationBehaviorDetector()
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
                "network_exfiltration_detection"
            )

        return (
            "network_transfer_observation"
        )

    # ============================================================
    # NETWORK CONTEXT
    # ============================================================

    def build_network_context(
        self,
        transfer_event,
    ) -> dict:

        return {

            "pid":
                transfer_event.get(
                    "pid"
                ),

            "process_name":
                transfer_event.get(
                    "process_name"
                ),

            "local_ip":
                transfer_event.get(
                    "local_ip"
                ),

            "local_port":
                transfer_event.get(
                    "local_port"
                ),

            "remote_ip":
                transfer_event.get(
                    "remote_ip"
                ),

            "remote_port":
                transfer_event.get(
                    "remote_port"
                ),

            "protocol":
                (
                    transfer_event.get(
                        "protocol"
                    )
                    or "TCP"
                ),

            "direction":
                transfer_event.get(
                    "direction"
                ),

            "bytes_sent":
                transfer_event.get(
                    "bytes_sent"
                ),

            "destination_scope":
                transfer_event.get(
                    "destination_scope"
                ),

            "approved_destination":
                transfer_event.get(
                    "approved_destination"
                ),
        }

    # ============================================================
    # SAVE DETECTIONS
    # ============================================================

    def save_exfiltration_detections(
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

            save_detection(

                event.event_id,

                detection,
            )

            logger.warning(
                "EXFILTRATION DETECTION | "
                "EventID=%s | "
                "Type=%s | "
                "Severity=%s | "
                "Risk=%s | "
                "RemoteIP=%s | "
                "BytesSent=%s | "
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
                    "remote_ip"
                ),

                detection.get(
                    "bytes_sent"
                ),

                detection.get(
                    "reason"
                ),
            )

    # ============================================================
    # PROCESS TRANSFER METADATA
    # ============================================================

    def process_transfer(
        self,
        transfer_event: dict,
        current_time=None,
    ):

        # --------------------------------------------------------
        # DETECTION
        # --------------------------------------------------------

        detections = (
            self.detector.analyze(

                transfer_event,

                current_time=
                    current_time,
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
                transfer_event
            )
        )

        # --------------------------------------------------------
        # METADATA
        # --------------------------------------------------------

        metadata = {

            "collector":
                "ExfiltrationMonitor",

            "exfiltration_analysis":
                True,

            "direction":
                transfer_event.get(
                    "direction"
                ),

            "process_name":
                transfer_event.get(
                    "process_name"
                ),

            "remote_ip":
                transfer_event.get(
                    "remote_ip"
                ),

            "bytes_sent":
                transfer_event.get(
                    "bytes_sent"
                ),

            "destination_scope":
                transfer_event.get(
                    "destination_scope"
                ),

            "approved_destination":
                transfer_event.get(
                    "approved_destination"
                ),

            "exfiltration_detection_count":
                len(
                    detections
                ),

            "exfiltration_detection_types":
                [

                    detection.get(
                        "detection_type"
                    )

                    for detection
                    in detections
                ],

            "synthetic_test":
                transfer_event.get(
                    "synthetic_test",
                    False,
                ),
        }

        # --------------------------------------------------------
        # TELEMETRY
        # --------------------------------------------------------

        event = (
            self.telemetry.emit(

                event_type=
                    event_type,

                source=
                    "exfiltration_monitor",

                severity=
                    severity,

                network=
                    network_context,

                metadata=
                    metadata,
            )
        )

        # --------------------------------------------------------
        # DETECTION DATABASE
        # --------------------------------------------------------

        if detections:

            self.save_exfiltration_detections(

                event,

                detections,
            )

        logger.info(
            "EXFILTRATION EVENT | "
            "Process=%s | "
            "RemoteIP=%s | "
            "BytesSent=%s | "
            "Detections=%s | "
            "Severity=%s | "
            "EventID=%s",

            transfer_event.get(
                "process_name"
            ),

            transfer_event.get(
                "remote_ip"
            ),

            transfer_event.get(
                "bytes_sent"
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