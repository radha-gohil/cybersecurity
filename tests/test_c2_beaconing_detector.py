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


from detection.network.network_behavior_tracker import (
    NetworkBehaviorTracker,
)


def separator():

    print(
        "\n"
        + "=" * 70
    )


def main():

    separator()

    print(
        "SENTINEL-X SUSPICIOUS BEACONING DETECTION TEST"
    )

    separator()

    # ------------------------------------------------------------
    # CREATE DETECTOR
    #
    # High thresholds are used for other detectors so this test
    # focuses only on beaconing behavior.
    # ------------------------------------------------------------

    tracker = NetworkBehaviorTracker(

        connection_burst_threshold=100,

        port_scan_threshold=100,

        dos_connection_threshold=100,

        beacon_min_connections=5,

        beacon_history_seconds=300,

        beacon_min_interval_seconds=5,

        beacon_max_interval_seconds=60,

        beacon_max_coefficient_variation=0.15,

        alert_cooldown_seconds=0,
    )

    # ------------------------------------------------------------
    # SYNTHETIC CONNECTION
    # ------------------------------------------------------------

    connection = {

        "pid":
            7000,

        "process_name":
            "synthetic_beacon_test.exe",

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
    # SYNTHETIC TIMESTAMPS
    #
    # Regular connection every 10 seconds.
    #
    # No real waiting and no real network traffic.
    # ------------------------------------------------------------

    timestamps = [

        1_700_000_000.0,

        1_700_000_010.0,

        1_700_000_020.0,

        1_700_000_030.0,

        1_700_000_040.0,

        1_700_000_050.0,
    ]

    detected = False

    print(
        "\nFeeding regular synthetic timestamps..."
    )

    for timestamp in timestamps:

        detections = (
            tracker.analyze(
                connection,
                current_time=timestamp,
            )
        )

        print(
            "\nTimestamp:",
            timestamp,
        )

        if not detections:

            print(
                "No detection."
            )

        for detection in detections:

            print(
                "\n>>> DETECTION"
            )

            print(
                "Type:",
                detection.get(
                    "detection_type"
                ),
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
                detection.get(
                    "detection_type"
                )
                ==
                "SUSPICIOUS_BEACONING"
            ):

                detected = True

    separator()

    if not detected:

        raise AssertionError(
            "SUSPICIOUS_BEACONING "
            "was not detected."
        )

    print(
        "SUSPICIOUS BEACONING TEST: PASS"
    )

    separator()

    # ============================================================
    # IRREGULAR TRAFFIC TEST
    #
    # This should NOT be classified as regular beaconing.
    # ============================================================

    print(
        "\nTesting irregular traffic..."
    )

    tracker_irregular = (
        NetworkBehaviorTracker(

            connection_burst_threshold=100,

            port_scan_threshold=100,

            dos_connection_threshold=100,

            beacon_min_connections=5,

            beacon_history_seconds=300,

            beacon_min_interval_seconds=5,

            beacon_max_interval_seconds=60,

            beacon_max_coefficient_variation=0.15,

            alert_cooldown_seconds=0,
        )
    )

    irregular_timestamps = [

        1_700_001_000.0,

        1_700_001_006.0,

        1_700_001_025.0,

        1_700_001_034.0,

        1_700_001_072.0,

        1_700_001_083.0,
    ]

    false_positive = False

    for timestamp in irregular_timestamps:

        detections = (
            tracker_irregular.analyze(
                connection,
                current_time=timestamp,
            )
        )

        for detection in detections:

            if (
                detection.get(
                    "detection_type"
                )
                ==
                "SUSPICIOUS_BEACONING"
            ):

                false_positive = True

    if false_positive:

        raise AssertionError(
            "Irregular traffic was incorrectly "
            "classified as beaconing."
        )

    print(
        "IRREGULAR TRAFFIC TEST: PASS"
    )

    separator()

    print(
        "ALL BEACONING TESTS PASSED"
    )

    separator()


if __name__ == "__main__":

    main()