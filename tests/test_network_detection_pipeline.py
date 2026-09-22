import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(
        0,
        str(PROJECT_ROOT),
    )
from detection.network.network_behavior_tracker import (
    NetworkBehaviorTracker,
)

from endpoint.collectors.network_monitor import (
    NetworkMonitor,
)


def print_separator():
    print(
        "\n"
        + "=" * 70
    )


def main():

    print_separator()

    print(
        "SENTINEL-X NETWORK DETECTION "
        "PIPELINE TEST"
    )

    print_separator()

    # ------------------------------------------------------------
    # CREATE NETWORK MONITOR
    # ------------------------------------------------------------

    monitor = NetworkMonitor(
        polling_interval=3.0
    )

    # ------------------------------------------------------------
    # USE LOW THRESHOLDS ONLY FOR THIS SYNTHETIC TEST
    #
    # We are NOT generating real network traffic.
    # We are feeding synthetic connection metadata.
    # ------------------------------------------------------------

    monitor.behavior_tracker = (
        NetworkBehaviorTracker(

            connection_window_seconds=10,

            connection_burst_threshold=5,

            port_scan_window_seconds=30,

            port_scan_threshold=5,

            dos_window_seconds=10,

            dos_connection_threshold=5,

            alert_cooldown_seconds=0,
        )
    )

    # ------------------------------------------------------------
    # SYNTHETIC PORT SCAN-LIKE METADATA
    # ------------------------------------------------------------

    ports = [
        21,
        22,
        23,
        80,
        443,
        445,
    ]

    detected_types = set()

    latest_event_id = None

    print(
        "\nFeeding synthetic "
        "network metadata..."
    )

    for index, port in enumerate(
        ports,
        start=1,
    ):

        connection = {

            "pid":
                4321,

            "process_name":
                "synthetic_network_test.exe",

            "protocol":
                "TCP",

            "local_ip":
                "192.0.2.10",

            "local_port":
                50000 + index,

            "remote_ip":
                "203.0.113.25",

            "remote_port":
                port,

            "status":
                "ESTABLISHED",
        }

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

        if event:

            latest_event_id = (
                event.event_id
            )

            print(
                "\nEVENT CREATED"
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
                "\n>>> DETECTION GENERATED"
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
                "Reason:",
                detection.get(
                    "reason"
                ),
            )

    # ------------------------------------------------------------
    # RESULT
    # ------------------------------------------------------------

    print_separator()

    print(
        "DETECTED TYPES:"
    )

    for detection_type in sorted(
        detected_types
    ):

        print(
            " -",
            detection_type,
        )

    print()

    if (
        "PORT_SCAN_BEHAVIOR"
        not in detected_types
    ):

        raise AssertionError(
            "PORT_SCAN_BEHAVIOR "
            "was not detected."
        )

    if latest_event_id is None:

        raise AssertionError(
            "No SecurityEvent "
            "was created."
        )

    print(
        "NETWORK DETECTION:"
        " PASS"
    )

    print(
        "SECURITY EVENT:"
        " PASS"
    )

    print(
        "DATABASE SAVE:"
        " Check logs for "
        "'NETWORK DETECTION'"
    )

    print(
        "CORRELATION:"
        " Check telemetry/"
        "correlation logs"
    )

    print_separator()

    print(
        "NETWORK PIPELINE TEST "
        "COMPLETED SUCCESSFULLY"
    )

    print_separator()


if __name__ == "__main__":

    main()