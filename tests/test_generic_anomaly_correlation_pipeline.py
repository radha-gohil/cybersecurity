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

import endpoint.collectors.generic_anomaly_monitor as generic_anomaly_monitor_module

from detection.anomaly.generic_behavior_anomaly_detector import (
    GenericBehaviorAnomalyDetector,
)

from endpoint.collectors.generic_anomaly_monitor import (
    GenericAnomalyMonitor,
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
        "SENTINEL-X GENERIC ANOMALY FULL CORRELATION PIPELINE TEST"
    )

    separator()

    print(
        "\nSynthetic metadata only."
    )

    print(
        "No network traffic is generated."
    )

    print(
        "No files are accessed."
    )

    print(
        "No process is executed."
    )

    print(
        "No external system is contacted."
    )

    # ============================================================
    # DETECTOR
    # ============================================================

    detector = (
        GenericBehaviorAnomalyDetector(

            history_size=30,

            min_history=5,

            anomaly_z_threshold=3.0,

            combined_score_threshold=60,
        )
    )

    # ============================================================
    # BUILD BASELINE DIRECTLY
    #
    # Baseline samples are supplied only to the detector so they
    # do not create SecurityEvents or affect correlation.
    # ============================================================

    separator()

    print(
        "BUILDING SYNTHETIC NORMAL BASELINE"
    )

    normal_samples = [

        {
            "bytes_sent": 1_000_000,
            "connection_count": 10,
            "destination_count": 2,
        },

        {
            "bytes_sent": 1_050_000,
            "connection_count": 11,
            "destination_count": 2,
        },

        {
            "bytes_sent": 980_000,
            "connection_count": 9,
            "destination_count": 2,
        },

        {
            "bytes_sent": 1_020_000,
            "connection_count": 10,
            "destination_count": 3,
        },

        {
            "bytes_sent": 990_000,
            "connection_count": 10,
            "destination_count": 2,
        },
    ]

    for index, sample in enumerate(
        normal_samples,
        start=1,
    ):

        baseline_event = {

            "device_id":
                "synthetic-endpoint",

            "process_name":
                "synthetic_service.exe",

            "bytes_sent":
                sample[
                    "bytes_sent"
                ],

            "connection_count":
                sample[
                    "connection_count"
                ],

            "destination_count":
                sample[
                    "destination_count"
                ],

            "synthetic_test":
                True,
        }

        detections = (
            detector.analyze(
                baseline_event
            )
        )

        print(
            "Baseline sample",
            index,
            "| Detections:",
            len(
                detections
            ),
        )

        if detections:

            raise AssertionError(
                "Baseline sample generated "
                "an anomaly."
            )

    print(
        "BASELINE BUILD: PASS"
    )

    # ============================================================
    # MONITOR
    # ============================================================

    monitor = (
        GenericAnomalyMonitor(
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
        generic_anomaly_monitor_module
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

    generic_anomaly_monitor_module.save_detection = (
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
        # THREE REPEATED UNKNOWN ANOMALIES
        #
        # Same synthetic PID and remote IP are intentionally used
        # to provide explicit correlation evidence.
        # ========================================================

        for index in range(
            1,
            4,
        ):

            separator()

            print(
                "SYNTHETIC UNKNOWN ANOMALY",
                index,
            )

            anomalous_event = {

                "device_id":
                    "synthetic-endpoint",

                "pid":
                    6060,

                "process_name":
                    "synthetic_service.exe",

                "local_ip":
                    "192.0.2.10",

                "local_port":
                    52000 + index,

                "remote_ip":
                    "203.0.113.99",

                "remote_port":
                    443,

                "protocol":
                    "TCP",

                "direction":
                    "outbound",

                "bytes_sent":
                    25_000_000,

                "connection_count":
                    80,

                "destination_count":
                    25,

                "synthetic_test":
                    True,
            }

            result = (
                monitor.process_behavior(
                    anomalous_event
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
            "GENERIC ANOMALY CORRELATION PIPELINE SUMMARY"
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
        # EVENTS
        # --------------------------------------------------------

        if len(
            captured_events
        ) != 3:

            raise AssertionError(
                (
                    "Expected 3 SecurityEvents, "
                    f"got {len(captured_events)}."
                )
            )

        print(
            "SecurityEvent creation: PASS"
        )

        # --------------------------------------------------------
        # EVENT TYPE + SEVERITY
        # --------------------------------------------------------

        for event in captured_events:

            if (
                event.event_type
                !=
                "network_unknown_anomaly_detection"
            ):

                raise AssertionError(
                    (
                        "Unexpected event type: "
                        + str(
                            event.event_type
                        )
                    )
                )

            if (
                event.severity
                !=
                "CRITICAL"
            ):

                raise AssertionError(
                    "Expected CRITICAL anomaly event."
                )

        print(
            "GenericAnomalyMonitor integration: PASS"
        )

        print(
            "Severity propagation: PASS"
        )

        # --------------------------------------------------------
        # DETECTION TYPES
        # --------------------------------------------------------

        required = {

            "UNUSUAL_TRANSFER_VOLUME",

            "UNUSUAL_CONNECTION_COUNT",

            "UNUSUAL_DESTINATION_COUNT",

            "UNKNOWN_BEHAVIOR_ANOMALY",
        }

        missing = (
            required
            - detected_types
        )

        if missing:

            raise AssertionError(
                (
                    "Missing anomaly detections: "
                    + str(
                        sorted(
                            missing
                        )
                    )
                )
            )

        print(
            "Generic anomaly detection: PASS"
        )

        # --------------------------------------------------------
        # DATABASE
        # --------------------------------------------------------

        if len(
            captured_detections
        ) != 12:

            raise AssertionError(
                (
                    "Expected 12 stored detections, "
                    f"got {len(captured_detections)}."
                )
            )

        print(
            "Detection database integration: PASS"
        )

        # --------------------------------------------------------
        # ENGINE
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
            "generic_behavior_anomaly"
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
        # CORRELATION
        # --------------------------------------------------------

        if not new_incident_ids:

            raise AssertionError(
                "Repeated unknown anomalies "
                "did not create an incident."
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
                >= 3
            ):

                incident_updated = True

        if not incident_updated:

            raise AssertionError(
                "Incident was not updated with "
                "all anomaly events."
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
                "NETWORK category not found."
            )

        print(
            "Incident category: PASS"
        )

        # --------------------------------------------------------
        # ENTITY PROPAGATION
        # --------------------------------------------------------

        for event in captured_events:

            network = (
                event.network
                or {}
            )

            if (
                network.get(
                    "pid"
                )
                !=
                6060
            ):

                raise AssertionError(
                    "Synthetic PID was not preserved."
                )

            if (
                network.get(
                    "remote_ip"
                )
                !=
                "203.0.113.99"
            ):

                raise AssertionError(
                    "Synthetic remote IP was not preserved."
                )

        print(
            "Correlation entity propagation: PASS"
        )

        # --------------------------------------------------------
        # BASELINE PROTECTION
        #
        # Only the five baseline samples should remain.
        # All three anomalies must be excluded.
        # --------------------------------------------------------

        entity_key = (
            detector.build_entity_key(
                {
                    "device_id":
                        "synthetic-endpoint",

                    "process_name":
                        "synthetic_service.exe",
                }
            )
        )

        baseline_size = len(
            detector.history[
                entity_key
            ][
                "bytes_sent"
            ]
        )

        if baseline_size != 5:

            raise AssertionError(
                (
                    "Anomalies contaminated baseline. "
                    f"Expected 5 samples, got "
                    f"{baseline_size}."
                )
            )

        print(
            "Baseline contamination protection: PASS"
        )

        # ========================================================
        # FINAL
        # ========================================================

        separator()

        print(
            "GENERIC ANOMALY CORRELATION PIPELINE "
            "TEST COMPLETED SUCCESSFULLY"
        )

        separator()

        print(
            """
Verified path:

Synthetic Behavior Metadata
            |
            v
GenericBehaviorAnomalyDetector
            |
            v
    GenericAnomalyMonitor
            |
            v
       SecurityEvent
            |
            v
       Event Database
            |
            v
 Generic Anomaly Detection DB
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

        generic_anomaly_monitor_module.save_detection = (
            original_save_detection
        )


if __name__ == "__main__":

    main()