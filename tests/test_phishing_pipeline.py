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


def separator():

    print(
        "\n"
        + "=" * 72
    )


def main():

    separator()

    print(
        "SENTINEL-X PHISHING PIPELINE TEST"
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
        "No attachment is executed."
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
    # EMAIL MONITOR
    # ============================================================

    monitor = (
        EmailMonitor(
            phishing_detector=
                detector
        )
    )

    # ============================================================
    # CAPTURE SECURITY EVENTS
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
    # CAPTURE DB DETECTIONS
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

    try:

        # ========================================================
        # SYNTHETIC PHISHING-LIKE EMAIL
        # ========================================================

        suspicious_email = {

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

            # ----------------------------------------------------
            # Documentation-only source IP.
            # ----------------------------------------------------

            "source_ip":
                "198.51.100.90",

            # ----------------------------------------------------
            # URL is analyzed as text only.
            # ----------------------------------------------------

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
                "synthetic-phishing-001",

            "synthetic_test":
                True,
        }

        separator()

        print(
            "PROCESSING SYNTHETIC EMAIL"
        )

        result = (
            monitor.process_email(
                suspicious_email
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

        # ========================================================
        # EVENT
        # ========================================================

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
            "Source:",
            event.source,
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
            "Sender Domain:",
            (
                event.metadata
                or {}
            ).get(
                "sender_domain"
            ),
        )

        # ========================================================
        # DETECTIONS
        # ========================================================

        detected_types = set()

        print(
            "\nDETECTIONS:"
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
                "\n>>> PHISHING DETECTION"
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

        # ========================================================
        # SUMMARY
        # ========================================================

        separator()

        print(
            "PHISHING PIPELINE SUMMARY"
        )

        print(
            "\nSecurityEvents created:",
            len(
                captured_events
            ),
        )

        print(
            "Detector outputs:",
            len(
                detections
            ),
        )

        print(
            "DB detections stored:",
            len(
                captured_detections
            ),
        )

        print(
            "\nDetected Types:"
        )

        for item in sorted(
            detected_types
        ):

            print(
                " -",
                item
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
        ) != 1:

            raise AssertionError(
                "Expected exactly one "
                "SecurityEvent."
            )

        print(
            "SecurityEvent creation: PASS"
        )

        if (
            event.event_type
            !=
            "security_email_detection"
        ):

            raise AssertionError(
                "Unexpected email SecurityEvent type."
            )

        print(
            "EmailMonitor integration: PASS"
        )

        if (
            event.severity
            !=
            "CRITICAL"
        ):

            raise AssertionError(
                "Expected CRITICAL email severity."
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
            "Phishing detections: PASS"
        )

        if (
            len(
                captured_detections
            )
            !=
            len(
                detections
            )
        ):

            raise AssertionError(
                "Not all phishing detections "
                "were saved."
            )

        print(
            "Detection database integration: PASS"
        )

        engines = {

            item[
                "detection"
            ].get(
                "engine"
            )

            for item
            in captured_detections
        }

        if engines != {
            "phishing_behavior"
        }:

            raise AssertionError(
                "Unexpected phishing "
                "detection engine."
            )

        print(
            "Detection engine: PASS"
        )

        separator()

        print(
            "PHISHING PIPELINE STORAGE TEST "
            "COMPLETED SUCCESSFULLY"
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