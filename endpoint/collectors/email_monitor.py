from detection.phishing.phishing_detector import (
    PhishingDetector,
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


class EmailMonitor:
    """
    SENTINEL-X Email / Phishing Metadata Monitor.

    This component performs metadata analysis only.

    It does NOT:

        - send emails
        - open URLs
        - download attachments
        - execute attachments
        - connect to mail servers
    """

    def __init__(
        self,
        phishing_detector=None,
    ):

        self.telemetry = (
            TelemetryManager()
        )

        self.phishing_detector = (

            phishing_detector

            or PhishingDetector()
        )

    # ============================================================
    # FINAL SEVERITY
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
                "security_email_detection"
            )

        return (
            "security_email_observation"
        )

    # ============================================================
    # EMAIL ADDRESS DOMAIN
    # ============================================================

    def get_sender_domain(
        self,
        email_event,
    ) -> str:

        sender = (

            email_event.get(
                "sender"
            )

            or email_event.get(
                "from"
            )

            or email_event.get(
                "from_address"
            )

            or ""
        )

        return (
            self.phishing_detector
            .extract_domain_from_email(
                sender
            )
        )

    # ============================================================
    # NETWORK CONTEXT
    #
    # Only use a source IP when the email metadata genuinely
    # contains one.
    # ============================================================

    def build_network_context(
        self,
        email_event,
    ) -> dict:

        source_ip = (

            email_event.get(
                "source_ip"
            )

            or email_event.get(
                "sender_ip"
            )

            or email_event.get(
                "originating_ip"
            )
        )

        if not source_ip:

            return {}

        return {

            "remote_ip":
                str(
                    source_ip
                ),

            "protocol":
                "EMAIL",

            "status":
                "RECEIVED",
        }

    # ============================================================
    # SAVE PHISHING DETECTIONS
    # ============================================================

    def save_phishing_detections(
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
                "PHISHING DETECTION | "
                "EventID=%s | "
                "Type=%s | "
                "Severity=%s | "
                "Risk=%s | "
                "SenderDomain=%s | "
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
                    "sender_domain"
                ),

                detection.get(
                    "reason"
                ),
            )

    # ============================================================
    # PROCESS EMAIL
    # ============================================================

    def process_email(
        self,
        email_event: dict,
    ):

        # --------------------------------------------------------
        # DETECT
        # --------------------------------------------------------

        detections = (
            self.phishing_detector
            .analyze(
                email_event
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
        # SENDER DOMAIN
        # --------------------------------------------------------

        sender_domain = (
            self.get_sender_domain(
                email_event
            )
        )

        # --------------------------------------------------------
        # NETWORK CONTEXT
        # --------------------------------------------------------

        network_context = (
            self.build_network_context(
                email_event
            )
        )

        # --------------------------------------------------------
        # METADATA
        # --------------------------------------------------------

        metadata = {

            "collector":
                "EmailMonitor",

            "email_analysis":
                True,

            "sender":
                (
                    email_event.get(
                        "sender"
                    )
                    or email_event.get(
                        "from"
                    )
                ),

            "display_name":
                email_event.get(
                    "display_name"
                ),

            "sender_domain":
                sender_domain,

            "subject":
                email_event.get(
                    "subject"
                ),

            "message_id":
                email_event.get(
                    "message_id"
                ),

            "source_ip":
                (
                    network_context.get(
                        "remote_ip"
                    )
                ),

            "attachment_count":
                len(
                    self.phishing_detector
                    .get_attachments(
                        email_event
                    )
                ),

            "url_count":
                len(
                    self.phishing_detector
                    .get_urls(
                        email_event
                    )
                ),

            "phishing_detection_count":
                len(
                    detections
                ),

            "phishing_detection_types":
                [

                    detection.get(
                        "detection_type"
                    )

                    for detection
                    in detections
                ],

            "synthetic_test":
                email_event.get(
                    "synthetic_test",
                    False,
                ),
        }

        # --------------------------------------------------------
        # SECURITY EVENT
        #
        # TelemetryManager:
        #
        #   - creates SecurityEvent
        #   - stores event
        #   - invokes correlation
        #
        # Correlation is not part of this test yet.
        # --------------------------------------------------------

        event = (
            self.telemetry.emit(

                event_type=
                    event_type,

                source=
                    "email_monitor",

                severity=
                    severity,

                network=
                    network_context,

                metadata=
                    metadata,
            )
        )

        # --------------------------------------------------------
        # SAVE DETECTIONS
        # --------------------------------------------------------

        if detections:

            self.save_phishing_detections(

                event,

                detections,
            )

        logger.info(
            "EMAIL EVENT | "
            "Sender=%s | "
            "Domain=%s | "
            "Detections=%s | "
            "Severity=%s | "
            "EventID=%s",

            metadata.get(
                "sender"
            ),

            sender_domain,

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