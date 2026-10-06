from __future__ import annotations

from config import (
    IS_VALIDATION_MODE,
)

from detection.auth.auth_behavior_detector import (
    AuthBehaviorDetector,
)

from endpoint.agent.telemetry_manager import (
    shared_telemetry_manager,
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

    Modes:

        OFF
            Collect authentication telemetry only.
            Do not run AuthBehaviorDetector.

        SHADOW
            Run the real AuthBehaviorDetector and return/log findings,
            but keep the emitted authentication event informational and
            do not persist detection rows.

        EMIT
            Run the detector, emit a detection-level SecurityEvent, and
            persist detection rows.

    Safety:
        During VALIDATION runtime, real endpoint authentication telemetry
        must not contaminate the synthetic validation SOC database.
        Therefore EMIT is automatically forced to SHADOW.
    """

    VALID_DETECTION_MODES = {
        "OFF",
        "SHADOW",
        "EMIT",
    }


    def __init__(
        self,
        auth_detection_mode: str = "SHADOW",
        telemetry_manager=None,
        behavior_detector=None,
    ):

        requested_mode = str(
            auth_detection_mode
        ).strip().upper()


        if requested_mode not in self.VALID_DETECTION_MODES:

            raise ValueError(
                "auth_detection_mode must be OFF, SHADOW, or EMIT"
            )


        if (
            IS_VALIDATION_MODE
            and requested_mode == "EMIT"
        ):

            logger.warning(
                "Auth EMIT requested during VALIDATION mode. "
                "Forcing authentication detection to SHADOW."
            )

            requested_mode = "SHADOW"


        self.auth_detection_mode = (
            requested_mode
        )


        # All endpoint collectors must use the shared manager so live
        # runtime counters represent one coherent endpoint runtime.
        self.telemetry = (
            telemetry_manager
            if telemetry_manager is not None
            else shared_telemetry_manager
        )


        self.behavior_detector = (
            behavior_detector
            if behavior_detector is not None
            else AuthBehaviorDetector()
        )


        logger.info(
            "AuthMonitor initialized | DetectionMode=%s | Validation=%s",
            self.auth_detection_mode,
            IS_VALIDATION_MODE,
        )


    # ============================================================
    # SEVERITY ORDER
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
                str(
                    detection.get(
                        "severity",
                        "INFO",
                    )
                ).upper()
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
    # ORIGINAL AUTH EVENT TYPE
    # ============================================================

    def get_base_security_event_type(
        self,
        auth_event: dict,
    ) -> str:

        original_type = str(
            auth_event.get(
                "event_type",
                "",
            )
        ).lower()


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
                "",
            )
        ).lower()


        if result == "success":

            return (
                "security_auth_success"
            )


        return (
            "security_auth_failure"
        )


    def get_security_event_type(
        self,
        auth_event: dict,
        detections,
    ) -> str:

        # Only EMIT mode is allowed to turn the raw authentication
        # telemetry event into an authoritative detection event.
        if (
            self.auth_detection_mode
            == "EMIT"
            and detections
        ):

            return (
                "security_auth_detection"
            )


        return (
            self.get_base_security_event_type(
                auth_event
            )
        )


    # ============================================================
    # NETWORK CONTEXT
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
    # DETECTION PERSISTENCE
    # ============================================================

    def save_auth_detections(
        self,
        event,
        detections,
    ) -> int:

        stored = 0


        for original in detections:

            detection = dict(
                original
            )


            detection_type = str(
                detection.get(
                    "detection_type",
                    "UNKNOWN_AUTH_BEHAVIOR",
                )
            )


            detection.update(
                {
                    "engine":
                        detection.get(
                            "engine",
                            "auth_behavior",
                        ),

                    "detected":
                        True,

                    "detection_type":
                        detection_type,

                    "threat_type":
                        detection.get(
                            "threat_type",
                            detection_type,
                        ),

                    "risk":
                        detection.get(
                            "risk",
                            detection.get(
                                "risk_score",
                                0,
                            ),
                        ),

                    "risk_score":
                        detection.get(
                            "risk_score",
                            detection.get(
                                "risk",
                                0,
                            ),
                        ),
                }
            )


            try:

                save_detection(
                    event.event_id,
                    detection,
                )

                stored += 1


                logger.warning(
                    "AUTH DETECTION SAVED | "
                    "EventID=%s | Type=%s | Severity=%s | "
                    "Risk=%s | Confidence=%s | SourceIP=%s",
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
                )


            except Exception:

                logger.exception(
                    "Failed to save auth detection | "
                    "EventID=%s | Type=%s",
                    event.event_id,
                    detection.get(
                        "detection_type"
                    ),
                )


        return stored


    # ============================================================
    # PROCESS AUTH EVENT
    # ============================================================

    def process_auth_event(
        self,
        auth_event: dict,
        current_time=None,
    ):

        if not isinstance(
            auth_event,
            dict,
        ):

            return None


        # --------------------------------------------------------
        # ANALYZE
        # --------------------------------------------------------

        if (
            self.auth_detection_mode
            == "OFF"
        ):

            detections = []


        else:

            detections = (
                self.behavior_detector.analyze(
                    auth_event,
                    current_time=current_time,
                )
            )


        # --------------------------------------------------------
        # EVENT TYPE / SEVERITY
        # --------------------------------------------------------

        security_event_type = (
            self.get_security_event_type(
                auth_event,
                detections,
            )
        )


        # SHADOW findings are evidence for logs/validation only.
        # They must not elevate the raw live authentication event.
        severity = "INFO"


        if (
            self.auth_detection_mode
            == "EMIT"
            and detections
        ):

            severity = (
                self.get_final_severity(
                    detections
                )
            )


        # --------------------------------------------------------
        # CONTEXT
        # --------------------------------------------------------

        network_context = (
            self.build_network_context(
                auth_event
            )
        )


        metadata = {
            "collector":
                "AuthMonitor",

            "auth_analysis":
                (
                    self.auth_detection_mode
                    != "OFF"
                ),

            "auth_detection_mode":
                self.auth_detection_mode,

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

            "shadow_detection_count":
                (
                    len(
                        detections
                    )
                    if self.auth_detection_mode
                    == "SHADOW"
                    else 0
                ),

            "synthetic_test":
                bool(
                    auth_event.get(
                        "synthetic_test",
                        False,
                    )
                ),

            "validation_runtime":
                bool(
                    IS_VALIDATION_MODE
                ),
        }


        # --------------------------------------------------------
        # LIVE AUTH TELEMETRY
        #
        # In VALIDATION mode the shared TelemetryManager's existing
        # isolation contract keeps real collector telemetry live-only.
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


        stored = 0


        # --------------------------------------------------------
        # AUTHORITATIVE DETECTION STORAGE
        # --------------------------------------------------------

        if (
            self.auth_detection_mode
            == "EMIT"
            and detections
            and not IS_VALIDATION_MODE
        ):

            stored = (
                self.save_auth_detections(
                    event,
                    detections,
                )
            )


        elif (
            detections
            and self.auth_detection_mode
            == "SHADOW"
        ):

            for detection in detections:

                logger.warning(
                    "AUTH SHADOW DETECTION | "
                    "Type=%s | Severity=%s | Risk=%s | "
                    "SourceIP=%s | User=%s | Reason=%s",
                    detection.get(
                        "detection_type"
                    ),
                    detection.get(
                        "severity"
                    ),
                    detection.get(
                        "risk_score",
                        detection.get(
                            "risk"
                        ),
                    ),
                    detection.get(
                        "source_ip"
                    ),
                    detection.get(
                        "username"
                    ),
                    detection.get(
                        "reason"
                    ),
                )


        logger.info(
            "AUTH EVENT | "
            "User=%s | SourceIP=%s | Result=%s | "
            "Findings=%s | Stored=%s | Severity=%s | Mode=%s | "
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
            stored,
            severity,
            self.auth_detection_mode,
            getattr(
                event,
                "event_id",
                None,
            ),
        )


        return {
            "event":
                event,

            "detections":
                detections,

            "stored_detection_count":
                stored,

            "detection_mode":
                self.auth_detection_mode,
        }
