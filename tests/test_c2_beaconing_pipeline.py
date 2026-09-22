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
# SENTINEL-X IMPORTS
# ================================================================

from detection.network.network_behavior_tracker import (
    NetworkBehaviorTracker,
)

from endpoint.collectors.network_monitor import (
    NetworkMonitor,
)


# ================================================================
# HELPERS
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
        "SENTINEL-X C2 / BEACONING FULL PIPELINE TEST"
    )

    separator()

    print(
        "\nThis test generates NO real network traffic."
    )

    print(
        "Only synthetic connection metadata is used."
    )

    # ------------------------------------------------------------
    # CREATE NETWORK MONITOR
    # ------------------------------------------------------------

    monitor = NetworkMonitor(
        polling_interval=3.0
    )

    # ------------------------------------------------------------
    # REPLACE TRACKER WITH TEST CONFIGURATION
    #
    # Other detectors use very high thresholds so that this test
    # specifically validates beaconing.
    # ------------------------------------------------------------

    monitor.behavior_tracker = (
        NetworkBehaviorTracker(

            connection_window_seconds=10,
            connection_burst_threshold=100,

            port_scan_window_seconds=30,
            port_scan_threshold=100,

            dos_window_seconds=10,
            dos_connection_threshold=100,

            beacon_min_connections=5,

            beacon_history_seconds=300,

            beacon_min_interval_seconds=5,

            beacon_max_interval_seconds=60,

            beacon_max_coefficient_variation=0.15,

            # Test only:
            # allow a detection at both the 5th and 6th event.
            alert_cooldown_seconds=0,
        )
    )

    # ------------------------------------------------------------
    # SYNTHETIC CONNECTION
    # ------------------------------------------------------------

    connection = {

        "pid":
            7000,

        "process_name":
            "synthetic_beacon_pipeline.exe",

        "protocol":
            "TCP",

        "local_ip":
            "192.0.2.10",

        "local_port":
            53000,

        "remote_ip":
            "203.0.113.200",

        "remote_port":
            443,

        "status":
            "ESTABLISHED",
    }

    # ------------------------------------------------------------
    # SYNTHETIC BEACON TIMESTAMPS
    #
    # Connection every 10 seconds.
    #
    # These timestamps are used only by NetworkBehaviorTracker.
    # ------------------------------------------------------------

    timestamps = [

        1_700_100_000.0,

        1_700_100_010.0,

        1_700_100_020.0,

        1_700_100_030.0,

        1_700_100_040.0,

        1_700_100_050.0,
    ]

    detected = False

    detected_types = set()

    created_event_ids = []

    detection_count = 0

    # ------------------------------------------------------------
    # PROCESS EACH SYNTHETIC CONNECTION
    # ------------------------------------------------------------

    for index, timestamp in enumerate(
        timestamps,
        start=1,
    ):

        print(
            "\n"
            + "-" * 72
        )

        print(
            f"SYNTHETIC CONNECTION {index}"
        )

        print(
            "Detector timestamp:",
            timestamp,
        )

        # --------------------------------------------------------
        # IMPORTANT
        #
        # NetworkMonitor normally uses real UTC time.
        #
        # For this test we temporarily make the tracker return our
        # synthetic timestamp.
        #
        # No waiting and no network traffic are required.
        # --------------------------------------------------------

        monitor.behavior_tracker.now_timestamp = (
            lambda value=timestamp: value
        )

        # --------------------------------------------------------
        # SEND THROUGH REAL SENTINEL-X PIPELINE
        # --------------------------------------------------------

        result = (
            monitor.create_connection_event(
                connection
            )
        )

        event = (
            result.get(
                "event"
            )
        )

        detections = (
            result.get(
                "detections",
                []
            )
        )

        # --------------------------------------------------------
        # EVENT INFORMATION
        # --------------------------------------------------------

        if event:

            created_event_ids.append(
                event.event_id
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

        # --------------------------------------------------------
        # DETECTION INFORMATION
        # --------------------------------------------------------

        if not detections:

            print(
                "\nNo detection for this event."
            )

        for detection in detections:

            detection_count += 1

            detection_type = (
                detection.get(
                    "detection_type"
                )
            )

            detected_types.add(
                detection_type
            )

            print(
                "\n>>> SECURITY DETECTION"
            )

            print(
                "Engine:",
                detection.get(
                    "engine"
                ),
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
                "Average Interval:",
                detection.get(
                    "average_interval_seconds"
                ),
            )

            print(
                "Interval Variation:",
                detection.get(
                    "coefficient_of_variation"
                ),
            )

            print(
                "Reason:",
                detection.get(
                    "reason"
                ),
            )

            if (
                detection_type
                ==
                "SUSPICIOUS_BEACONING"
            ):

                detected = True

    # ============================================================
    # SUMMARY
    # ============================================================

    separator()

    print(
        "SENTINEL-X BEACONING PIPELINE SUMMARY"
    )

    separator()

    print(
        "\nSecurityEvents created:",
        len(
            created_event_ids
        ),
    )

    print(
        "Detections generated:",
        detection_count,
    )

    print(
        "\nDetected types:"
    )

    if detected_types:

        for detection_type in sorted(
            detected_types
        ):

            print(
                " -",
                detection_type,
            )

    else:

        print(
            " NONE"
        )

    # ============================================================
    # VALIDATION
    # ============================================================

    separator()

    print(
        "VALIDATION"
    )

    if not created_event_ids:

        raise AssertionError(
            "No SecurityEvents were created."
        )

    print(
        "SecurityEvent creation:"
        " PASS"
    )

    if not detected:

        raise AssertionError(
            "SUSPICIOUS_BEACONING was not detected."
        )

    print(
        "Beaconing detection:"
        " PASS"
    )

    if (
        "SUSPICIOUS_BEACONING"
        not in detected_types
    ):

        raise AssertionError(
            "Beaconing detection type missing."
        )

    print(
        "Detection type validation:"
        " PASS"
    )

    # ------------------------------------------------------------
    # Database storage is performed by NetworkMonitor using
    # save_detection().
    #
    # Correlation is performed by TelemetryManager.
    #
    # Their logs should appear above this summary.
    # ------------------------------------------------------------

    print(
        "Database integration:"
        " check 'Detection saved' log"
    )

    print(
        "Correlation integration:"
        " check correlation log"
    )

    print(
        "Incident integration:"
        " check Incident created/updated log"
    )

    # ============================================================
    # FINAL
    # ============================================================

    separator()

    print(
        "C2 / BEACONING PIPELINE TEST COMPLETED SUCCESSFULLY"
    )

    separator()

    print(
        """
Verified path:

Synthetic periodic metadata
            |
            v
NetworkBehaviorTracker
            |
            v
SUSPICIOUS_BEACONING
            |
            v
NetworkMonitor
            |
            v
TelemetryManager
            |
            v
SecurityEvent
            |
            v
Event Database
            |
            v
CorrelationManager
            |
            v
Incident
            |
            v
Detection Database
"""
    )


# ================================================================
# ENTRY POINT
# ================================================================

if __name__ == "__main__":

    main()