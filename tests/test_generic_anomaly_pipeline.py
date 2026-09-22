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
        "SENTINEL-X GENERIC ANOMALY PIPELINE TEST"
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
    # MONITOR
    # ============================================================

    monitor = (
        GenericAnomalyMonitor(
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

    detected_types = set()

    try:

        # ========================================================
        # TEST 1 — BUILD BASELINE
        # ========================================================

        separator()

        print(
            "TEST 1 - BUILD NORMAL BASELINE"
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

            behavior_event = {

                "device_id":
                    "synthetic-endpoint",

                "process_name":
                    "synthetic_service.exe",

                "remote_ip":
                    None,

                "protocol":
                    "TCP",

                "direction":
                    "outbound",

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

            result = (
                monitor.process_behavior(
                    behavior_event
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
                "\nBaseline sample:",
                index,
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
                "Detections:",
                len(
                    detections
                ),
            )

            if detections:

                raise AssertionError(
                    "Baseline sample generated "
                    "an anomaly detection."
                )

        print(
            "BASELINE BUILD: PASS"
        )

        # ========================================================
        # TEST 2 — NORMAL CONTROL
        # ========================================================

        separator()

        print(
            "TEST 2 - NORMAL BEHAVIOR CONTROL"
        )

        normal_event = {

            "device_id":
                "synthetic-endpoint",

            "process_name":
                "synthetic_service.exe",

            "remote_ip":
                None,

            "protocol":
                "TCP",

            "direction":
                "outbound",

            "bytes_sent":
                1_010_000,

            "connection_count":
                10,

            "destination_count":
                2,

            "synthetic_test":
                True,
        }

        normal_result = (
            monitor.process_behavior(
                normal_event
            )
        )

        normal_security_event = (
            normal_result[
                "event"
            ]
        )

        normal_detections = (
            normal_result[
                "detections"
            ]
        )

        print(
            "\nEvent Type:",
            normal_security_event.event_type,
        )

        print(
            "Severity:",
            normal_security_event.severity,
        )

        print(
            "Detections:",
            len(
                normal_detections
            ),
        )

        if normal_detections:

            raise AssertionError(
                "Normal control generated "
                "an anomaly detection."
            )

        print(
            "NORMAL CONTROL: PASS"
        )

        # ========================================================
        # TEST 3 — UNKNOWN ANOMALOUS BEHAVIOR
        # ========================================================

        separator()

        print(
            "TEST 3 - UNKNOWN ANOMALOUS BEHAVIOR"
        )

        anomalous_event = {

            "device_id":
                "synthetic-endpoint",

            "process_name":
                "synthetic_service.exe",

            "remote_ip":
                "203.0.113.99",

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

        anomaly_result = (
            monitor.process_behavior(
                anomalous_event
            )
        )

        anomaly_security_event = (
            anomaly_result[
                "event"
            ]
        )

        anomaly_detections = (
            anomaly_result[
                "detections"
            ]
        )

        print(
            "\nSECURITY EVENT"
        )

        print(
            "Event ID:",
            anomaly_security_event.event_id,
        )

        print(
            "Event Type:",
            anomaly_security_event.event_type,
        )

        print(
            "Source:",
            anomaly_security_event.source,
        )

        print(
            "Severity:",
            anomaly_security_event.severity,
        )

        print(
            "Category:",
            (
                anomaly_security_event.metadata
                or {}
            ).get(
                "event_category"
            ),
        )

        print(
            "Remote IP:",
            (
                anomaly_security_event.network
                or {}
            ).get(
                "remote_ip"
            ),
        )

        print(
            "Detections:",
            len(
                anomaly_detections
            ),
        )

        for detection in anomaly_detections:

            detection_type = (
                detection.get(
                    "detection_type"
                )
            )

            detected_types.add(
                detection_type
            )

            print(
                "\n>>> GENERIC ANOMALY DETECTION"
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

            if (
                "z_score"
                in detection
            ):

                print(
                    "Z Score:",
                    detection.get(
                        "z_score"
                    ),
                )

            print(
                "Reason:",
                detection.get(
                    "reason"
                ),
            )

        # ========================================================
        # SUMMARY
        # ========================================================

        separator()

        print(
            "GENERIC ANOMALY PIPELINE SUMMARY"
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
        # 5 baseline + 1 normal + 1 anomaly = 7
        # --------------------------------------------------------

        if len(
            captured_events
        ) != 7:

            raise AssertionError(
                (
                    "Expected 7 SecurityEvents, "
                    f"got {len(captured_events)}."
                )
            )

        print(
            "SecurityEvent creation: PASS"
        )

        # --------------------------------------------------------
        # NORMAL EVENT
        # --------------------------------------------------------

        if (
            normal_security_event.event_type
            !=
            "network_behavior_observation"
        ):

            raise AssertionError(
                "Normal behavior should produce "
                "network_behavior_observation."
            )

        if (
            normal_security_event.severity
            !=
            "INFO"
        ):

            raise AssertionError(
                "Normal behavior should remain INFO."
            )

        print(
            "Normal behavior observation: PASS"
        )

        # --------------------------------------------------------
        # ANOMALY EVENT
        # --------------------------------------------------------

        if (
            anomaly_security_event.event_type
            !=
            "network_unknown_anomaly_detection"
        ):

            raise AssertionError(
                "Unexpected anomaly event type."
            )

        print(
            "GenericAnomalyMonitor integration: PASS"
        )

        if (
            anomaly_security_event.severity
            !=
            "CRITICAL"
        ):

            raise AssertionError(
                "Combined anomaly should propagate "
                "CRITICAL severity."
            )

        print(
            "Severity propagation: PASS"
        )

        # --------------------------------------------------------
        # REQUIRED DETECTIONS
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
            "Generic anomaly behavior detection: PASS"
        )

        # --------------------------------------------------------
        # DATABASE
        # --------------------------------------------------------

        if (
            len(
                captured_detections
            )
            != 4
        ):

            raise AssertionError(
                (
                    "Expected 4 stored anomaly detections, "
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
                    "Unexpected detection engines: "
                    + str(
                        engines
                    )
                )
            )

        print(
            "Detection engine: PASS"
        )

        # --------------------------------------------------------
        # UNKNOWN COMBINED SIGNAL
        # --------------------------------------------------------

        combined_found = any(

            item[
                "detection"
            ].get(
                "detection_type"
            )
            ==
            "UNKNOWN_BEHAVIOR_ANOMALY"

            for item
            in captured_detections
        )

        if not combined_found:

            raise AssertionError(
                "UNKNOWN_BEHAVIOR_ANOMALY "
                "was not stored."
            )

        print(
            "Combined unknown anomaly storage: PASS"
        )

        # --------------------------------------------------------
        # NETWORK METADATA
        # --------------------------------------------------------

        network = (
            anomaly_security_event.network
            or {}
        )

        if (
            network.get(
                "remote_ip"
            )
            !=
            "203.0.113.99"
        ):

            raise AssertionError(
                "Remote IP was not preserved."
            )

        if (
            network.get(
                "bytes_sent"
            )
            !=
            25_000_000
        ):

            raise AssertionError(
                "bytes_sent was not preserved."
            )

        if (
            network.get(
                "connection_count"
            )
            !=
            80
        ):

            raise AssertionError(
                "connection_count was not preserved."
            )

        if (
            network.get(
                "destination_count"
            )
            !=
            25
        ):

            raise AssertionError(
                "destination_count was not preserved."
            )

        print(
            "Behavior metadata propagation: PASS"
        )

        # --------------------------------------------------------
        # BASELINE CONTAMINATION
        # --------------------------------------------------------

        entity_key = (
            detector.build_entity_key(
                anomalous_event
            )
        )

        baseline_size = len(
            detector.history[
                entity_key
            ][
                "bytes_sent"
            ]
        )

        if baseline_size != 6:

            raise AssertionError(
                (
                    "Anomaly polluted baseline. "
                    f"Expected size 6, got "
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
            "GENERIC ANOMALY PIPELINE STORAGE TEST "
            "COMPLETED SUCCESSFULLY"
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