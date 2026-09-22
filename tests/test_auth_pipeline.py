import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:

    sys.path.insert(
        0,
        str(PROJECT_ROOT),
    )


import endpoint.collectors.auth_monitor as auth_monitor_module


from detection.auth.auth_behavior_detector import (
    AuthBehaviorDetector,
)

from endpoint.collectors.auth_monitor import (
    AuthMonitor,
)

from endpoint.agent.telemetry_manager import (
    shared_correlation_manager,
)


def separator():

    print(
        "\n"
        + "=" * 72
    )


def main():

    separator()

    print(
        "SENTINEL-X AUTHENTICATION FULL PIPELINE TEST"
    )

    separator()

    print(
        "\nNo authentication attempts are performed."
    )

    print(
        "Only synthetic authentication metadata is used."
    )

    # ============================================================
    # AUTH MONITOR
    # ============================================================

    monitor = (
        AuthMonitor()
    )

    # ------------------------------------------------------------
    # TEST THRESHOLDS
    # ------------------------------------------------------------

    monitor.behavior_detector = (
        AuthBehaviorDetector(

            failure_window_seconds=60,

            repeated_failure_threshold=5,

            multi_account_threshold=3,

            brute_force_score_threshold=70,

            alert_cooldown_seconds=0,
        )
    )

    # ============================================================
    # CAPTURE EVENTS
    # ============================================================

    captured_events = []

    original_emit = (
        monitor.telemetry.emit
    )

    def capture_emit(
        *args,
        **kwargs,
    ):

        event = original_emit(
            *args,
            **kwargs,
        )

        captured_events.append(
            event
        )

        return event

    monitor.telemetry.emit = (
        capture_emit
    )

    # ============================================================
    # CAPTURE DETECTIONS
    # ============================================================

    captured_detections = []

    original_save_detection = (
        auth_monitor_module.save_detection
    )

    def capture_save_detection(
        event_id,
        detection,
    ):

        captured_detections.append(
            {
                "event_id":
                    event_id,

                "detection":
                    dict(
                        detection
                    ),
            }
        )

        return original_save_detection(
            event_id,
            detection,
        )

    auth_monitor_module.save_detection = (
        capture_save_detection
    )

    # ============================================================
    # INCIDENT STATE BEFORE
    # ============================================================

    incidents_before = set(
        shared_correlation_manager
        .incidents
        .keys()
    )

    detected_types = set()

    try:

        # ========================================================
        # SYNTHETIC AUTH EVENTS
        # ========================================================

        usernames = [

            "synthetic_admin",

            "synthetic_user1",

            "synthetic_user2",

            "synthetic_admin",

            "synthetic_user1",

            "synthetic_user2",
        ]

        base_time = (
            1_700_400_000.0
        )

        source_ip = (
            "198.51.100.25"
        )

        for index, username in enumerate(
            usernames
        ):

            separator()

            print(
                "SYNTHETIC AUTH FAILURE",
                index + 1,
            )

            auth_event = {

                "event_type":
                    "login_failure",

                "source_ip":
                    source_ip,

                "username":
                    username,

                "result":
                    "failed",

                "protocol":
                    "AUTH",

                "device_id":
                    "synthetic-endpoint",

                "synthetic_test":
                    True,
            }

            result = (
                monitor.process_auth_event(

                    auth_event,

                    current_time=
                        base_time
                        + (
                            index
                            * 5
                        ),
                )
            )

            event = (
                result[
                    "event"
                ]
            )

            detections = (
                result[
                    "detections"
                ]
            )

            print(
                "\nSECURITY EVENT"
            )

            print(
                "Event ID:",
                event.event_id,
            )

            print(
                "Type:",
                event.event_type,
            )

            print(
                "Severity:",
                event.severity,
            )

            print(
                "Source:",
                event.source,
            )

            print(
                "Remote IP:",
                (
                    event.network
                    or {}
                ).get(
                    "remote_ip"
                ),
            )

            if not detections:

                print(
                    "\nNo auth detection yet."
                )

            for detection in detections:

                detection_type = (
                    detection.get(
                        "detection_type"
                    )
                )

                detected_types.add(
                    detection_type
                )

                print(
                    "\n>>> AUTH DETECTION"
                )

                print(
                    "Type:",
                    detection_type,
                )

                print(
                    "Severity:",
                    detection.get(
                        "severity"
                    ),
                )

                print(
                    "Risk:",
                    detection.get(
                        "risk_score"
                    ),
                )

                print(
                    "Confidence:",
                    detection.get(
                        "confidence"
                    ),
                )

                print(
                    "Failures:",
                    detection.get(
                        "failure_count"
                    ),
                )

                print(
                    "Accounts:",
                    detection.get(
                        "unique_account_count"
                    ),
                )

                print(
                    "Reason:",
                    detection.get(
                        "reason"
                    ),
                )

        # ========================================================
        # INCIDENT STATE AFTER
        # ========================================================

        incidents_after = set(
            shared_correlation_manager
            .incidents
            .keys()
        )

        new_incident_ids = (
            incidents_after
            - incidents_before
        )

        # ========================================================
        # SUMMARY
        # ========================================================

        separator()

        print(
            "AUTH PIPELINE SUMMARY"
        )

        print(
            "\nSecurityEvents created:",
            len(
                captured_events
            ),
        )

        print(
            "Auth detections stored:",
            len(
                captured_detections
            ),
        )

        print(
            "New incidents:",
            len(
                new_incident_ids
            ),
        )

        print(
            "\nDetected types:"
        )

        for item in sorted(
            detected_types
        ):

            print(
                " -",
                item,
            )

        # ========================================================
        # INCIDENT DETAILS
        # ========================================================

        if new_incident_ids:

            print(
                "\nINCIDENTS:"
            )

            for incident_id in (
                new_incident_ids
            ):

                incident = (
                    shared_correlation_manager
                    .incidents
                    .get(
                        incident_id,
                        {},
                    )
                )

                print(
                    "\nIncident ID:",
                    incident_id,
                )

                print(
                    "Title:",
                    incident.get(
                        "title"
                    ),
                )

                print(
                    "Severity:",
                    incident.get(
                        "severity"
                    ),
                )

                print(
                    "Correlation Score:",
                    incident.get(
                        "correlation_score"
                    ),
                )

                print(
                    "Events:",
                    incident.get(
                        "event_count"
                    ),
                )

        # ========================================================
        # VALIDATION
        # ========================================================

        separator()

        print(
            "VALIDATION"
        )

        if len(
            captured_events
        ) != 6:

            raise AssertionError(
                "Expected 6 authentication SecurityEvents."
            )

        print(
            "SecurityEvent creation: PASS"
        )

        required = {

            "REPEATED_LOGIN_FAILURES",

            "MULTI_ACCOUNT_LOGIN_FAILURES",

            "AUTH_BRUTE_FORCE_BEHAVIOR",
        }

        missing = (

            required
            - detected_types
        )

        if missing:

            raise AssertionError(
                "Missing auth detections: "
                + str(
                    sorted(
                        missing
                    )
                )
            )

        print(
            "Authentication behavior detection: PASS"
        )

        if not captured_detections:

            raise AssertionError(
                "No authentication detections "
                "were stored."
            )

        print(
            "Detection database integration: PASS"
        )

        if not new_incident_ids:

            raise AssertionError(
                "Authentication events were not "
                "correlated into an incident."
            )

        print(
            "Correlation: PASS"
        )

        print(
            "Incident creation: PASS"
        )

        separator()

        print(
            "AUTHENTICATION PIPELINE TEST "
            "COMPLETED SUCCESSFULLY"
        )

        separator()

        print(
            """
Verified path:

Synthetic Authentication Metadata
             |
             v
     AuthBehaviorDetector
             |
             v
         AuthMonitor
             |
             v
        SecurityEvent
             |
             v
       Event Database
             |
             v
      Auth Detection DB
             |
             v
         Correlation
             |
             v
          Incident
"""
        )

    finally:

        # ========================================================
        # RESTORE
        # ========================================================

        monitor.telemetry.emit = (
            original_emit
        )

        auth_monitor_module.save_detection = (
            original_save_detection
        )


if __name__ == "__main__":

    main()