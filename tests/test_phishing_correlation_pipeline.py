import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:

    sys.path.insert(
        0,
        str(PROJECT_ROOT),
    )


import endpoint.collectors.email_monitor as email_monitor_module


from detection.phishing.phishing_detector import (
    PhishingDetector,
)

from endpoint.collectors.email_monitor import (
    EmailMonitor,
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
        "SENTINEL-X PHISHING FULL CORRELATION PIPELINE TEST"
    )

    separator()

    print(
        "\nOffline metadata-only test."
    )

    print(
        "No email is sent."
    )

    print(
        "No URL is opened."
    )

    print(
        "No attachment is downloaded or executed."
    )

    # ============================================================
    # DETECTOR
    # ============================================================

    detector = (
        PhishingDetector(

            phishing_score_threshold=60,

            protected_brand_domains={

                "examplecorp": {
                    "examplecorp.test"
                },
            },
        )
    )

    # ============================================================
    # MONITOR
    # ============================================================

    monitor = (
        EmailMonitor(
            phishing_detector=
                detector
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
        email_monitor_module.save_detection
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

    email_monitor_module.save_detection = (
        capture_save_detection
    )

    # ============================================================
    # INCIDENTS BEFORE
    # ============================================================

    incidents_before = set(
        shared_correlation_manager
        .incidents
        .keys()
    )

    detected_types = set()

    try:

        # ========================================================
        # THREE SYNTHETIC EMAILS
        #
        # Same synthetic sender infrastructure IP is used so
        # SENTINEL-X has explicit correlation evidence.
        #
        # Nothing is transmitted over the network.
        # ========================================================

        for index in range(
            1,
            4,
        ):

            separator()

            print(
                "SYNTHETIC PHISHING EMAIL",
                index,
            )

            email_event = {

                "sender":
                    (
                        "ExampleCorp Security "
                        "<alert@xn--examplecorp-9za.test>"
                    ),

                "display_name":
                    "ExampleCorp Security",

                "subject":
                    (
                        "URGENT: Action required - "
                        "verify your account immediately"
                    ),

                "body":
                    (
                        "Security alert. "
                        "Your account will be suspended "
                        "within 24 hours. "
                        "Verify your account immediately."
                    ),

                # ------------------------------------------------
                # Documentation/test-only address.
                # ------------------------------------------------

                "source_ip":
                    "198.51.100.90",

                # ------------------------------------------------
                # This is text only.
                # The test does not request/open this URL.
                # ------------------------------------------------

                "urls": [

                    (
                        "http://secure-login.example.test"
                        "@198.51.100.77/"
                        "verify-account"
                    )
                ],

                "attachments": [
                    "security_update.js"
                ],

                "message_id":
                    (
                        f"synthetic-phishing-{index:03d}"
                    ),

                "synthetic_test":
                    True,
            }

            result = (
                monitor.process_email(
                    email_event
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
                "Event Type:",
                event.event_type,
            )

            print(
                "Severity:",
                event.severity,
            )

            print(
                "Category:",
                (
                    event.metadata
                    or {}
                ).get(
                    "event_category"
                ),
            )

            print(
                "Source IP:",
                (
                    event.network
                    or {}
                ).get(
                    "remote_ip"
                ),
            )

            print(
                "Message ID:",
                (
                    event.metadata
                    or {}
                ).get(
                    "message_id"
                ),
            )

            print(
                "Detections:",
                len(
                    detections
                ),
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
                    "  -",
                    detection_type,
                    "|",
                    detection.get(
                        "severity"
                    ),
                    "| Risk:",
                    detection.get(
                        "risk_score"
                    ),
                )

        # ========================================================
        # INCIDENTS AFTER
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
            "PHISHING CORRELATION PIPELINE SUMMARY"
        )

        print(
            "\nSecurityEvents created:",
            len(
                captured_events
            ),
        )

        print(
            "Detections stored:",
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

        for detection_type in sorted(
            detected_types
        ):

            print(
                " -",
                detection_type,
            )

        # ========================================================
        # INCIDENT DETAILS
        # ========================================================

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
                "Event Count:",
                incident.get(
                    "event_count"
                ),
            )

            print(
                "Categories:",
                incident.get(
                    "categories"
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
        ) != 3:

            raise AssertionError(
                "Expected 3 email SecurityEvents."
            )

        print(
            "SecurityEvent creation: PASS"
        )

        for event in captured_events:

            if (
                event.event_type
                !=
                "security_email_detection"
            ):

                raise AssertionError(
                    "Unexpected email event type."
                )

        print(
            "EmailMonitor integration: PASS"
        )

        for event in captured_events:

            if (
                event.severity
                !=
                "CRITICAL"
            ):

                raise AssertionError(
                    "Expected CRITICAL phishing events."
                )

        print(
            "Severity propagation: PASS"
        )

        required = {

            "SUSPICIOUS_SENDER_DOMAIN",

            "DISPLAY_NAME_DOMAIN_MISMATCH",

            "SUSPICIOUS_URL",

            "URGENCY_LANGUAGE",

            "SUSPICIOUS_ATTACHMENT",

            "PHISHING_SUSPICION",
        }

        missing = (
            required
            - detected_types
        )

        if missing:

            raise AssertionError(
                "Missing phishing detections: "
                + str(
                    sorted(
                        missing
                    )
                )
            )

        print(
            "Phishing behavior detection: PASS"
        )

        if not captured_detections:

            raise AssertionError(
                "No phishing detections were stored."
            )

        print(
            "Detection database integration: PASS"
        )

        if not new_incident_ids:

            raise AssertionError(
                "Phishing events were not "
                "correlated into an incident."
            )

        print(
            "Correlation: PASS"
        )

        print(
            "Incident creation: PASS"
        )

        incident_has_multiple_events = False

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

            if (
                incident.get(
                    "event_count",
                    0,
                )
                >= 3
            ):

                incident_has_multiple_events = (
                    True
                )

        if not incident_has_multiple_events:

            raise AssertionError(
                "Incident was not updated with "
                "the repeated phishing events."
            )

        print(
            "Incident update: PASS"
        )

        separator()

        print(
            "PHISHING CORRELATION PIPELINE "
            "TEST COMPLETED SUCCESSFULLY"
        )

        separator()

        print(
            """
Verified path:

Synthetic Email Metadata
          |
          v
     PhishingDetector
          |
          v
       EmailMonitor
          |
          v
      SecurityEvent
          |
          v
      Event Database
          |
          v
 Phishing Detection DB
          |
          v
       Correlation
          |
          v
        Incident
"""
        )

    finally:

        monitor.telemetry.emit = (
            original_emit
        )

        email_monitor_module.save_detection = (
            original_save_detection
        )


if __name__ == "__main__":

    main()