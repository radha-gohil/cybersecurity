import sys
from pathlib import Path


# ================================================================
# PROJECT ROOT
# ================================================================

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(
        0,
        str(PROJECT_ROOT),
    )


# ================================================================
# IMPORTS
# ================================================================

import endpoint.collectors.exfiltration_monitor as exfiltration_monitor_module

from detection.exfiltration.exfiltration_detector import (
    ExfiltrationBehaviorDetector,
)

from endpoint.collectors.exfiltration_monitor import (
    ExfiltrationMonitor,
)


# ================================================================
# SEPARATOR
# ================================================================

def separator():
    print(
        "\n"
        + "=" * 72
    )


# ================================================================
# MAIN TEST
# ================================================================

def main():

    separator()

    print(
        "SENTINEL-X EXFILTRATION FULL PIPELINE STORAGE TEST"
    )

    separator()

    print(
        "\nSynthetic metadata only."
    )

    print(
        "No files are read."
    )

    print(
        "No data is uploaded."
    )

    print(
        "No network connection is created."
    )

    print(
        "No external system is contacted."
    )

    # ============================================================
    # CREATE DETECTOR
    # ============================================================

    detector = (
        ExfiltrationBehaviorDetector(

            transfer_window_seconds=60,

            large_transfer_threshold_bytes=
                50 * 1024 * 1024,

            repeated_upload_threshold=5,

            cumulative_transfer_threshold_bytes=
                100 * 1024 * 1024,

            exfiltration_score_threshold=70,
        )
    )

    # ============================================================
    # CREATE MONITOR
    # ============================================================

    monitor = (
        ExfiltrationMonitor(
            detector=
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

        event = (
            original_emit(
                *args,
                **kwargs,
            )
        )

        captured_events.append(
            event
        )

        return event

    monitor.telemetry.emit = (
        capture_emit
    )

    # ============================================================
    # CAPTURE DATABASE DETECTIONS
    # ============================================================

    captured_detections = []

    original_save_detection = (
        exfiltration_monitor_module
        .save_detection
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

        return (
            original_save_detection(
                event_id,
                detection,
            )
        )

    exfiltration_monitor_module.save_detection = (
        capture_save_detection
    )

    # ============================================================
    # TRACK DETECTION TYPES
    # ============================================================

    detected_types = set()

    try:

        # ========================================================
        # TEST 1 — BENIGN CONTROL
        # ========================================================

        separator()

        print(
            "TEST 1 - BENIGN TRANSFER CONTROL"
        )

        benign_event = {

            "event_type":
                "network_transfer",

            "direction":
                "outbound",

            "device_id":
                "synthetic-endpoint",

            "pid":
                1111,

            "process_name":
                "synthetic_backup.exe",

            "local_ip":
                "192.0.2.10",

            "local_port":
                50001,

            "remote_ip":
                "203.0.113.20",

            "remote_port":
                443,

            "protocol":
                "TCP",

            "bytes_sent":
                1 * 1024 * 1024,

            "destination_scope":
                "external",

            "approved_destination":
                True,

            "synthetic_test":
                True,
        }

        benign_result = (
            monitor.process_transfer(

                benign_event,

                current_time=
                    1_700_600_000.0,
            )
        )

        benign_security_event = (
            benign_result[
                "event"
            ]
        )

        benign_detections = (
            benign_result[
                "detections"
            ]
        )

        print(
            "\nSECURITY EVENT"
        )

        print(
            "Event ID:",
            benign_security_event.event_id,
        )

        print(
            "Event Type:",
            benign_security_event.event_type,
        )

        print(
            "Severity:",
            benign_security_event.severity,
        )

        print(
            "Detections:",
            len(
                benign_detections
            ),
        )

        if benign_detections:

            raise AssertionError(
                "Benign transfer generated "
                "exfiltration detections."
            )

        print(
            "BENIGN CONTROL: PASS"
        )

        # ========================================================
        # TEST 2 — REPEATED SYNTHETIC TRANSFERS
        # ========================================================

        separator()

        print(
            "TEST 2 - SYNTHETIC EXFILTRATION-LIKE PATTERN"
        )

        # --------------------------------------------------------
        # New detector prevents the benign control from affecting
        # the repeated-transfer history.
        # --------------------------------------------------------

        detector = (
            ExfiltrationBehaviorDetector(

                transfer_window_seconds=60,

                large_transfer_threshold_bytes=
                    50 * 1024 * 1024,

                repeated_upload_threshold=5,

                cumulative_transfer_threshold_bytes=
                    100 * 1024 * 1024,

                exfiltration_score_threshold=70,
            )
        )

        monitor.detector = (
            detector
        )

        base_time = (
            1_700_601_000.0
        )

        # --------------------------------------------------------
        # Six synthetic 25 MB transfer metadata records.
        #
        # 25 MB x 4 = 100 MB
        #
        # Therefore:
        #
        # transfer 4:
        # HIGH_VOLUME_OUTBOUND_ACTIVITY
        #
        # transfer 5:
        # REPEATED_OUTBOUND_UPLOADS
        # HIGH_VOLUME_OUTBOUND_ACTIVITY
        # UNAPPROVED_EXTERNAL_DESTINATION
        # POSSIBLE_DATA_EXFILTRATION
        # --------------------------------------------------------

        for index in range(
            6
        ):

            separator()

            print(
                "SYNTHETIC TRANSFER",
                index + 1,
            )

            transfer_event = {

                "event_type":
                    "network_transfer",

                "direction":
                    "outbound",

                "device_id":
                    "synthetic-endpoint",

                "pid":
                    4242,

                "process_name":
                    "synthetic_transfer.exe",

                "local_ip":
                    "192.0.2.10",

                "local_port":
                    50010 + index,

                "remote_ip":
                    "203.0.113.45",

                "remote_port":
                    443,

                "protocol":
                    "TCP",

                # ------------------------------------------------
                # Metadata value only.
                # No actual bytes are transferred.
                # ------------------------------------------------

                "bytes_sent":
                    25 * 1024 * 1024,

                "destination_scope":
                    "external",

                "approved_destination":
                    False,

                "synthetic_test":
                    True,
            }

            result = (
                monitor.process_transfer(

                    transfer_event,

                    current_time=
                        (
                            base_time
                            +
                            (
                                index
                                * 5
                            )
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
                "Event Type:",
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
                "Remote IP:",
                (
                    event.network
                    or {}
                ).get(
                    "remote_ip"
                ),
            )

            print(
                "Bytes Sent:",
                (
                    event.network
                    or {}
                ).get(
                    "bytes_sent"
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
                    "\n>>> EXFILTRATION DETECTION"
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
                    "Transfer Count:",
                    detection.get(
                        "transfer_count"
                    ),
                )

                print(
                    "Cumulative Bytes:",
                    detection.get(
                        "cumulative_bytes"
                    ),
                )

                print(
                    "Reason:",
                    detection.get(
                        "reason"
                    ),
                )

        # ========================================================
        # TEST 3 — LARGE SINGLE TRANSFER
        # ========================================================

        separator()

        print(
            "TEST 3 - LARGE SYNTHETIC OUTBOUND TRANSFER"
        )

        # --------------------------------------------------------
        # Separate detector isolates this test from previous
        # repeated-transfer state.
        # --------------------------------------------------------

        large_detector = (
            ExfiltrationBehaviorDetector(

                transfer_window_seconds=60,

                large_transfer_threshold_bytes=
                    50 * 1024 * 1024,

                repeated_upload_threshold=5,

                cumulative_transfer_threshold_bytes=
                    100 * 1024 * 1024,

                exfiltration_score_threshold=70,
            )
        )

        monitor.detector = (
            large_detector
        )

        large_transfer_event = {

            "event_type":
                "network_transfer",

            "direction":
                "outbound",

            "device_id":
                "synthetic-endpoint",

            "pid":
                5252,

            "process_name":
                "synthetic_large_transfer.exe",

            "local_ip":
                "192.0.2.10",

            "local_port":
                51000,

            "remote_ip":
                "203.0.113.60",

            "remote_port":
                443,

            "protocol":
                "TCP",

            "bytes_sent":
                60 * 1024 * 1024,

            "destination_scope":
                "external",

            "approved_destination":
                True,

            "synthetic_test":
                True,
        }

        large_result = (
            monitor.process_transfer(

                large_transfer_event,

                current_time=
                    1_700_602_000.0,
            )
        )

        large_security_event = (
            large_result[
                "event"
            ]
        )

        large_detections = (
            large_result[
                "detections"
            ]
        )

        print(
            "\nSECURITY EVENT"
        )

        print(
            "Event ID:",
            large_security_event.event_id,
        )

        print(
            "Event Type:",
            large_security_event.event_type,
        )

        print(
            "Severity:",
            large_security_event.severity,
        )

        print(
            "Remote IP:",
            (
                large_security_event.network
                or {}
            ).get(
                "remote_ip"
            ),
        )

        print(
            "Bytes Sent:",
            (
                large_security_event.network
                or {}
            ).get(
                "bytes_sent"
            ),
        )

        for detection in (
            large_detections
        ):

            detection_type = (
                detection.get(
                    "detection_type"
                )
            )

            detected_types.add(
                detection_type
            )

            print(
                "\n>>> EXFILTRATION DETECTION"
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
                "Reason:",
                detection.get(
                    "reason"
                ),
            )

        # ========================================================
        # PIPELINE SUMMARY
        # ========================================================

        separator()

        print(
            "EXFILTRATION PIPELINE SUMMARY"
        )

        print(
            "\nSecurityEvents created:",
            len(
                captured_events
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

        for detection_type in sorted(
            detected_types
        ):

            print(
                " -",
                detection_type,
            )

        # ========================================================
        # VALIDATION
        # ========================================================

        separator()

        print(
            "VALIDATION"
        )

        # --------------------------------------------------------
        # 1 benign
        # + 6 repeated suspicious transfers
        # + 1 large transfer
        #
        # Total = 8 SecurityEvents
        # --------------------------------------------------------

        if len(
            captured_events
        ) != 8:

            raise AssertionError(
                (
                    "Expected exactly 8 SecurityEvents, "
                    f"got {len(captured_events)}."
                )
            )

        print(
            "SecurityEvent creation: PASS"
        )

        # ========================================================
        # VERIFY BENIGN EVENT TYPE
        # ========================================================

        if (
            benign_security_event.event_type
            !=
            "network_transfer_observation"
        ):

            raise AssertionError(
                "Benign event should be "
                "network_transfer_observation."
            )

        if (
            benign_security_event.severity
            !=
            "INFO"
        ):

            raise AssertionError(
                "Benign event should have "
                "INFO severity."
            )

        print(
            "Benign transfer observation: PASS"
        )

        # ========================================================
        # REQUIRED DETECTION TYPES
        # ========================================================

        required = {

            "LARGE_OUTBOUND_TRANSFER",

            "REPEATED_OUTBOUND_UPLOADS",

            "HIGH_VOLUME_OUTBOUND_ACTIVITY",

            "UNAPPROVED_EXTERNAL_DESTINATION",

            "POSSIBLE_DATA_EXFILTRATION",
        }

        missing = (
            required
            - detected_types
        )

        if missing:

            raise AssertionError(
                (
                    "Missing exfiltration detections: "
                    + str(
                        sorted(
                            missing
                        )
                    )
                )
            )

        print(
            "Exfiltration behavior detection: PASS"
        )

        # ========================================================
        # DETECTION DATABASE
        # ========================================================

        if not captured_detections:

            raise AssertionError(
                "No exfiltration detections "
                "were saved to the database."
            )

        print(
            "Detection database integration: PASS"
        )

        # ========================================================
        # ENGINE VALIDATION
        # ========================================================

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
            "exfiltration_behavior"
        }:

            raise AssertionError(
                (
                    "Unexpected detection engines: "
                    + str(
                        engines
                    )
                )
            )

        print(
            "Detection engine: PASS"
        )

        # ========================================================
        # VERIFY COMBINED DETECTION
        # ========================================================

        combined_detections = [

            item

            for item
            in captured_detections

            if (
                item[
                    "detection"
                ].get(
                    "detection_type"
                )
                ==
                "POSSIBLE_DATA_EXFILTRATION"
            )
        ]

        if not combined_detections:

            raise AssertionError(
                "POSSIBLE_DATA_EXFILTRATION "
                "was not saved."
            )

        print(
            "Combined exfiltration detection: PASS"
        )

        # ========================================================
        # VERIFY LARGE TRANSFER
        # ========================================================

        large_transfer_found = any(

            item[
                "detection"
            ].get(
                "detection_type"
            )
            ==
            "LARGE_OUTBOUND_TRANSFER"

            for item
            in captured_detections
        )

        if not large_transfer_found:

            raise AssertionError(
                "LARGE_OUTBOUND_TRANSFER "
                "was not saved."
            )

        print(
            "Large outbound transfer storage: PASS"
        )

        # ========================================================
        # VERIFY HIGH VOLUME
        # ========================================================

        high_volume_found = any(

            item[
                "detection"
            ].get(
                "detection_type"
            )
            ==
            "HIGH_VOLUME_OUTBOUND_ACTIVITY"

            for item
            in captured_detections
        )

        if not high_volume_found:

            raise AssertionError(
                "HIGH_VOLUME_OUTBOUND_ACTIVITY "
                "was not saved."
            )

        print(
            "High-volume detection storage: PASS"
        )

        # ========================================================
        # VERIFY REPEATED UPLOAD
        # ========================================================

        repeated_found = any(

            item[
                "detection"
            ].get(
                "detection_type"
            )
            ==
            "REPEATED_OUTBOUND_UPLOADS"

            for item
            in captured_detections
        )

        if not repeated_found:

            raise AssertionError(
                "REPEATED_OUTBOUND_UPLOADS "
                "was not saved."
            )

        print(
            "Repeated-upload detection storage: PASS"
        )

        # ========================================================
        # VERIFY UNAPPROVED DESTINATION
        # ========================================================

        unapproved_found = any(

            item[
                "detection"
            ].get(
                "detection_type"
            )
            ==
            "UNAPPROVED_EXTERNAL_DESTINATION"

            for item
            in captured_detections
        )

        if not unapproved_found:

            raise AssertionError(
                "UNAPPROVED_EXTERNAL_DESTINATION "
                "was not saved."
            )

        print(
            "Unapproved-destination storage: PASS"
        )

        # ========================================================
        # VERIFY NETWORK CONTEXT
        # ========================================================

        suspicious_event_found = False

        for event in (
            captured_events
        ):

            network = (
                event.network
                or {}
            )

            if (
                network.get(
                    "remote_ip"
                )
                ==
                "203.0.113.45"
            ):

                suspicious_event_found = True

                if (
                    network.get(
                        "direction"
                    )
                    !=
                    "outbound"
                ):

                    raise AssertionError(
                        "Network direction was "
                        "not preserved."
                    )

                if (
                    network.get(
                        "bytes_sent"
                    )
                    !=
                    25 * 1024 * 1024
                ):

                    raise AssertionError(
                        "bytes_sent was not "
                        "preserved."
                    )

        if not suspicious_event_found:

            raise AssertionError(
                "Synthetic exfiltration "
                "SecurityEvent not found."
            )

        print(
            "Network metadata propagation: PASS"
        )

        # ========================================================
        # FINAL RESULT
        # ========================================================

        separator()

        print(
            "EXFILTRATION PIPELINE STORAGE TEST "
            "COMPLETED SUCCESSFULLY"
        )

        separator()

        print(
            """
Verified path:

Synthetic Transfer Metadata
           |
           v
ExfiltrationBehaviorDetector
           |
           v
   ExfiltrationMonitor
           |
           v
      SecurityEvent
           |
           v
      Event Database
           |
           v
Exfiltration Detection DB
"""
        )

    # ============================================================
    # RESTORE PATCHED METHODS
    # ============================================================

    finally:

        monitor.telemetry.emit = (
            original_emit
        )

        exfiltration_monitor_module.save_detection = (
            original_save_detection
        )


# ================================================================
# RUN
# ================================================================

if __name__ == "__main__":

    main()