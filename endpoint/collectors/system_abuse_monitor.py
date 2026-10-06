from __future__ import annotations

from config import (
    IS_VALIDATION_MODE,
)

from detection.system.system_abuse_detector import (
    SystemAbuseDetector,
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


class SystemAbuseMonitor:
    """
    SENTINEL-X system-abuse security-event processor.

    Consumes normalized Windows Security Event Log metadata for:
        4672 - special privileges assigned
        4720 - user account created
        4728 - member added to global security group
        4732 - member added to local security group
        4698 - scheduled task created
        1102 - Security log cleared
        4719 - audit policy changed

    Modes:
        OFF     -> telemetry only
        SHADOW  -> run detector, return/log findings, no detection persistence
        EMIT    -> authoritative detection persistence (outside VALIDATION only)

    No account, privilege, task, audit-policy, or log modification is performed.
    """

    VALID_DETECTION_MODES = {
        "OFF",
        "SHADOW",
        "EMIT",
    }


    EVENT_TYPE_BY_ID = {
        4672: "security_special_privilege_assignment",
        4720: "security_account_created",
        4728: "security_group_membership_change",
        4732: "security_group_membership_change",
        4698: "security_scheduled_task_created",
        1102: "security_log_cleared",
        4719: "security_audit_policy_change",
    }


    def __init__(
        self,
        system_detection_mode: str = "SHADOW",
        telemetry_manager=None,
        behavior_detector=None,
    ):

        requested_mode = str(
            system_detection_mode
        ).strip().upper()


        if requested_mode not in self.VALID_DETECTION_MODES:

            raise ValueError(
                "system_detection_mode must be OFF, SHADOW, or EMIT"
            )


        if (
            IS_VALIDATION_MODE
            and requested_mode == "EMIT"
        ):

            logger.warning(
                "System-abuse EMIT requested during VALIDATION mode. "
                "Forcing detector to SHADOW."
            )

            requested_mode = "SHADOW"


        self.system_detection_mode = (
            requested_mode
        )


        self.telemetry = (
            telemetry_manager
            if telemetry_manager is not None
            else shared_telemetry_manager
        )


        self.behavior_detector = (
            behavior_detector
            if behavior_detector is not None
            else SystemAbuseDetector()
        )


        logger.info(
            "SystemAbuseMonitor initialized | "
            "DetectionMode=%s | Validation=%s",
            self.system_detection_mode,
            IS_VALIDATION_MODE,
        )


    # ============================================================
    # EVENT TYPE
    # ============================================================

    def get_security_event_type(
        self,
        system_event: dict,
        detections,
    ) -> str:

        event_id = (
            system_event.get(
                "windows_event_id"
            )
            or system_event.get(
                "event_id"
            )
        )


        try:

            event_id = int(
                event_id
            )

        except (
            TypeError,
            ValueError,
        ):

            event_id = None


        if (
            self.system_detection_mode == "EMIT"
            and detections
        ):

            return (
                "security_system_abuse_detection"
            )


        return self.EVENT_TYPE_BY_ID.get(
            event_id,
            "security_system_event",
        )


    # ============================================================
    # SEVERITY
    # ============================================================

    @staticmethod
    def get_final_severity(
        detections,
    ) -> str:

        order = {
            "INFO": 0,
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4,
        }

        result = "INFO"


        for detection in detections:

            severity = str(
                detection.get(
                    "severity",
                    "INFO",
                )
            ).upper()


            if (
                order.get(
                    severity,
                    0,
                )
                > order[
                    result
                ]
            ):

                result = severity


        return result


    # ============================================================
    # DETECTION PERSISTENCE
    # ============================================================

    def save_system_detections(
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
                    "UNKNOWN_SYSTEM_ABUSE",
                )
            )


            detection.update(
                {
                    "engine":
                        detection.get(
                            "engine",
                            "system_abuse",
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
                    "SYSTEM ABUSE DETECTION SAVED | "
                    "EventID=%s | Type=%s | Severity=%s | Risk=%s",
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
                )


            except Exception:

                logger.exception(
                    "Failed to save system-abuse detection | "
                    "EventID=%s | Type=%s",
                    event.event_id,
                    detection.get(
                        "detection_type"
                    ),
                )


        return stored


    # ============================================================
    # PROCESS NORMALIZED SYSTEM EVENT
    # ============================================================

    def process_system_event(
        self,
        system_event: dict,
    ):

        if not isinstance(
            system_event,
            dict,
        ):

            return None


        if (
            self.system_detection_mode
            == "OFF"
        ):

            detections = []


        else:

            detections = (
                self.behavior_detector.analyze(
                    system_event
                )
            )


        event_type = (
            self.get_security_event_type(
                system_event,
                detections,
            )
        )


        # SHADOW evidence must not elevate raw endpoint telemetry.
        severity = "INFO"


        if (
            self.system_detection_mode == "EMIT"
            and detections
        ):

            severity = (
                self.get_final_severity(
                    detections
                )
            )


        metadata = {
            "collector":
                "SystemAbuseMonitor",

            "system_detection_mode":
                self.system_detection_mode,

            "windows_event_id":
                system_event.get(
                    "windows_event_id"
                ),

            "record_id":
                system_event.get(
                    "record_id"
                ),

            "username":
                system_event.get(
                    "username",
                    system_event.get(
                        "subject_username"
                    ),
                ),

            "target_username":
                system_event.get(
                    "target_username"
                ),

            "group_name":
                system_event.get(
                    "group_name"
                ),

            "member_name":
                system_event.get(
                    "member_name"
                ),

            "task_name":
                system_event.get(
                    "task_name"
                ),

            "task_command":
                system_event.get(
                    "task_command"
                ),

            "privilege_list":
                system_event.get(
                    "privilege_list",
                    system_event.get(
                        "privileges"
                    ),
                ),

            "subcategory":
                system_event.get(
                    "subcategory"
                ),

            "change":
                system_event.get(
                    "change"
                ),

            "system_detection_count":
                len(
                    detections
                ),

            "system_detection_types":
                [
                    item.get(
                        "detection_type"
                    )
                    for item
                    in detections
                ],

            "shadow_detection_count":
                (
                    len(
                        detections
                    )
                    if self.system_detection_mode == "SHADOW"
                    else 0
                ),

            "validation_runtime":
                bool(
                    IS_VALIDATION_MODE
                ),
        }


        event = (
            self.telemetry.emit(
                event_type=
                    event_type,

                source=
                    "windows_system_security_log",

                severity=
                    severity,

                metadata=
                    metadata,
            )
        )


        stored = 0


        if (
            self.system_detection_mode == "EMIT"
            and detections
            and not IS_VALIDATION_MODE
        ):

            stored = (
                self.save_system_detections(
                    event,
                    detections,
                )
            )


        elif (
            self.system_detection_mode == "SHADOW"
            and detections
        ):

            for detection in detections:

                logger.warning(
                    "SYSTEM ABUSE SHADOW DETECTION | "
                    "Type=%s | Severity=%s | Risk=%s | Reason=%s",
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
                        "reason"
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
                self.system_detection_mode,
        }
