from detection.network.network_behavior_tracker import (
    NetworkBehaviorTracker,
)


def print_detections(
    detections,
):

    for detection in detections:

        print(
            "\n--------------------------------"
        )

        print(
            "DETECTION:",
            detection.get(
                "detection_type"
            ),
        )

        print(
            "SEVERITY:",
            detection.get(
                "severity"
            ),
        )

        print(
            "RISK:",
            detection.get(
                "risk_score"
            ),
        )

        print(
            "CONFIDENCE:",
            detection.get(
                "confidence"
            ),
        )

        print(
            "REASON:",
            detection.get(
                "reason"
            ),
        )


def test_port_scan():

    print(
        "\n=== PORT SCAN BEHAVIOR TEST ==="
    )

    tracker = NetworkBehaviorTracker(

        connection_burst_threshold=50,

        port_scan_threshold=5,

        dos_connection_threshold=50,

        alert_cooldown_seconds=0,
    )

    found = False

    for port in [
        21,
        22,
        23,
        80,
        443,
        445,
    ]:

        connection = {

            "pid":
                4321,

            "process_name":
                "synthetic_test.exe",

            "protocol":
                "TCP",

            "local_ip":
                "192.0.2.10",

            "local_port":
                50000,

            "remote_ip":
                "203.0.113.25",

            "remote_port":
                port,

            "status":
                "ESTABLISHED",
        }

        detections = (
            tracker.analyze(
                connection
            )
        )

        for detection in detections:

            if (
                detection.get(
                    "detection_type"
                )
                ==
                "PORT_SCAN_BEHAVIOR"
            ):

                found = True

        print_detections(
            detections
        )

    assert found is True

    print(
        "\nPORT SCAN TEST: PASS"
    )


def test_connection_burst():

    print(
        "\n=== CONNECTION BURST TEST ==="
    )

    tracker = NetworkBehaviorTracker(

        connection_burst_threshold=5,

        port_scan_threshold=100,

        dos_connection_threshold=100,

        alert_cooldown_seconds=0,
    )

    found = False

    for index in range(
        6
    ):

        connection = {

            "pid":
                5000,

            "process_name":
                "synthetic_burst_test.exe",

            "protocol":
                "TCP",

            "local_ip":
                "192.0.2.10",

            "local_port":
                51000 + index,

            "remote_ip":
                "203.0.113.50",

            "remote_port":
                443,

            "status":
                "ESTABLISHED",
        }

        detections = (
            tracker.analyze(
                connection
            )
        )

        for detection in detections:

            if (
                detection.get(
                    "detection_type"
                )
                ==
                "CONNECTION_BURST"
            ):

                found = True

        print_detections(
            detections
        )

    assert found is True

    print(
        "\nCONNECTION BURST TEST: PASS"
    )


def test_possible_dos():

    print(
        "\n=== POSSIBLE DOS TEST ==="
    )

    tracker = NetworkBehaviorTracker(

        connection_burst_threshold=100,

        port_scan_threshold=100,

        dos_connection_threshold=5,

        alert_cooldown_seconds=0,
    )

    found = False

    for index in range(
        6
    ):

        connection = {

            "pid":
                6000,

            "process_name":
                "synthetic_dos_test.exe",

            "protocol":
                "TCP",

            "local_ip":
                "192.0.2.10",

            "local_port":
                52000 + index,

            "remote_ip":
                "203.0.113.100",

            "remote_port":
                443,

            "status":
                "ESTABLISHED",
        }

        detections = (
            tracker.analyze(
                connection
            )
        )

        for detection in detections:

            if (
                detection.get(
                    "detection_type"
                )
                ==
                "POSSIBLE_DOS_BEHAVIOR"
            ):

                found = True

        print_detections(
            detections
        )

    assert found is True

    print(
        "\nPOSSIBLE DOS TEST: PASS"
    )


if __name__ == "__main__":

    print(
        "======================================="
    )

    print(
        "SENTINEL-X NETWORK DETECTION TEST"
    )

    print(
        "======================================="
    )

    test_port_scan()

    test_connection_burst()

    test_possible_dos()

    print(
        "\n======================================="
    )

    print(
        "ALL NETWORK BEHAVIOR TESTS PASSED"
    )

    print(
        "======================================="
    )