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

from endpoint.agent.telemetry_manager import (
    shared_correlation_manager,
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
# MAIN
# ================================================================

def main():

    separator()

    print(
        "SENTINEL-X EXFILTRATION FULL CORRELATION PIPELINE TEST"
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
    # DETECTOR
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
    # MONITOR
    # ============================================================

    monitor = (
        ExfiltrationMonitor(
            detector=
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
    # CAPTURE DETECTIONS
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
        # SIX SYNTHETIC TRANSFER RECORDS
        # ========================================================

        base_time = (
            1_700_700_000.0
        )

        for index in range(
            6
        ):

            separator()

            print(
                "SYNTHETIC EXFILTRATION TRANSFER",
                index + 1,
            )

            transfer_event = {

                "event_type":
                    "network_transfer",

                "direction":
                    "outbound",

                "device_id":
                    "synthetic-endpoint",

                # ------------------------------------------------
                # Same synthetic PID gives explicit entity
                # correlation evidence.
                # ------------------------------------------------

                "pid":
                    4242,

                "process_name":
                    "synthetic_transfer.exe",

                "local_ip":
                    "192.0.2.10",

                "local_port":
                    50000 + index,

                "remote_ip":
                    "203.0.113.45",

                "remote_port":
                    443,

                "protocol":
                    "TCP",

                # ------------------------------------------------
                # Metadata value only.
                # No bytes are actually sent.
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
                "PID:",
                (
                    event.network
                    or {}
                ).get(
                    "pid"
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
                "Detection Count:",
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
            "EXFILTRATION CORRELATION PIPELINE SUMMARY"
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

        # --------------------------------------------------------
        # SECURITY EVENTS
        # --------------------------------------------------------

        if len(
            captured_events
        ) != 6:

            raise AssertionError(
                (
                    "Expected 6 SecurityEvents, "
                    f"got {len(captured_events)}."
                )
            )

        print(
            "SecurityEvent creation: PASS"
        )

        # --------------------------------------------------------
        # EVENT TYPES
        # --------------------------------------------------------

        for event in captured_events:

            if (
                event.event_type
                !=
                "network_exfiltration_detection"
            ):

                raise AssertionError(
                    (
                        "Unexpected event type: "
                        + str(
                            event.event_type
                        )
                    )
                )

        print(
            "ExfiltrationMonitor integration: PASS"
        )

        # --------------------------------------------------------
        # REQUIRED DETECTIONS
        # --------------------------------------------------------

        required = {

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

        # --------------------------------------------------------
        # DATABASE
        # --------------------------------------------------------

        if not captured_detections:

            raise AssertionError(
                "No exfiltration detections "
                "were stored."
            )

        print(
            "Detection database integration: PASS"
        )

        # --------------------------------------------------------
        # DETECTION ENGINE
        # --------------------------------------------------------

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
                    "Unexpected engines: "
                    + str(
                        engines
                    )
                )
            )

        print(
            "Detection engine: PASS"
        )

        # --------------------------------------------------------
        # COMBINED SIGNAL
        # --------------------------------------------------------

        combined_found = any(

            item[
                "detection"
            ].get(
                "detection_type"
            )
            ==
            "POSSIBLE_DATA_EXFILTRATION"

            for item
            in captured_detections
        )

        if not combined_found:

            raise AssertionError(
                "POSSIBLE_DATA_EXFILTRATION "
                "was not stored."
            )

        print(
            "Combined exfiltration behavior: PASS"
        )

        # --------------------------------------------------------
        # INCIDENT CREATED
        # --------------------------------------------------------

        if not new_incident_ids:

            raise AssertionError(
                "Exfiltration events were not "
                "correlated into an incident."
            )

        print(
            "Correlation: PASS"
        )

        print(
            "Incident creation: PASS"
        )

        # --------------------------------------------------------
        # INCIDENT UPDATE
        # --------------------------------------------------------

        incident_updated = False

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
                >= 6
            ):

                incident_updated = True

        if not incident_updated:

            raise AssertionError(
                "The incident was not updated "
                "with all repeated transfer events."
            )

        print(
            "Incident update: PASS"
        )

        # --------------------------------------------------------
        # CATEGORY
        # --------------------------------------------------------

        network_category_found = False

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

            categories = (
                incident.get(
                    "categories"
                )
                or []
            )

            if (
                "NETWORK"
                in categories
            ):

                network_category_found = True

        if not network_category_found:

            raise AssertionError(
                "NETWORK incident category "
                "was not preserved."
            )

        print(
            "Incident category: PASS"
        )

        # --------------------------------------------------------
        # NETWORK METADATA
        # --------------------------------------------------------

        for event in captured_events:

            network = (
                event.network
                or {}
            )

            if (
                network.get(
                    "remote_ip"
                )
                !=
                "203.0.113.45"
            ):

                raise AssertionError(
                    "Unexpected remote IP."
                )

            if (
                network.get(
                    "pid"
                )
                !=
                4242
            ):

                raise AssertionError(
                    "Synthetic PID was not preserved."
                )

        print(
            "Network entity propagation: PASS"
        )

        # ========================================================
        # FINAL
        # ========================================================

        separator()

        print(
            "EXFILTRATION CORRELATION PIPELINE "
            "TEST COMPLETED SUCCESSFULLY"
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
            |
            v
        Correlation
            |
            v
         Incident
"""
        )

    # ============================================================
    # RESTORE PATCHES
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