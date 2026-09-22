import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:

    sys.path.insert(
        0,
        str(PROJECT_ROOT),
    )


from detection.exfiltration.exfiltration_detector import (
    ExfiltrationBehaviorDetector,
)


def separator():

    print(
        "\n"
        + "=" * 72
    )


def main():

    separator()

    print(
        "SENTINEL-X EXFILTRATION BEHAVIOR TEST"
    )

    separator()

    print(
        "\nSynthetic metadata only."
    )

    print(
        "No data is uploaded."
    )

    print(
        "No network connection is created."
    )

    print(
        "No files are read or transferred."
    )

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
    # TEST 1 — BENIGN CONTROL
    # ============================================================

    separator()

    print(
        "TEST 1 - BENIGN OUTBOUND TRANSFER"
    )

    benign_event = {

        "event_type":
            "network_transfer",

        "direction":
            "outbound",

        "device_id":
            "synthetic-endpoint",

        "process_name":
            "synthetic_backup.exe",

        "remote_ip":
            "203.0.113.20",

        "remote_port":
            443,

        "bytes_sent":
            1024 * 1024,

        "destination_scope":
            "external",

        "approved_destination":
            True,

        "synthetic_test":
            True,
    }

    benign_detections = (
        detector.analyze(

            benign_event,

            current_time=
                1_700_500_000.0,
        )
    )

    if benign_detections:

        raise AssertionError(
            "Benign transfer generated "
            "an exfiltration detection."
        )

    print(
        "BENIGN CONTROL: PASS"
    )

    # ============================================================
    # TEST 2 — SYNTHETIC EXFILTRATION-LIKE PATTERN
    # ============================================================

    separator()

    print(
        "TEST 2 - SYNTHETIC EXFILTRATION-LIKE PATTERN"
    )

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

    detected_types = set()

    base_time = (
        1_700_501_000.0
    )

    for index in range(
        6
    ):

        event = {

            "event_type":
                "network_transfer",

            "direction":
                "outbound",

            "device_id":
                "synthetic-endpoint",

            "process_name":
                "synthetic_transfer.exe",

            "remote_ip":
                "203.0.113.45",

            "remote_port":
                443,

            # 25 MB metadata value per event.
            "bytes_sent":
                25 * 1024 * 1024,

            "destination_scope":
                "external",

            "approved_destination":
                False,

            "synthetic_test":
                True,
        }

        detections = (
            detector.analyze(

                event,

                current_time=
                    base_time
                    + (
                        index
                        * 5
                    ),
            )
        )

        print(
            "\nTransfer:",
            index + 1,
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
                " -",
                detection_type,
                "| Severity:",
                detection.get(
                    "severity"
                ),
                "| Risk:",
                detection.get(
                    "risk_score"
                ),
            )

    # ============================================================
    # TEST 3 — LARGE SINGLE TRANSFER
    # ============================================================

    separator()

    print(
        "TEST 3 - LARGE SYNTHETIC TRANSFER"
    )

    large_detector = (
        ExfiltrationBehaviorDetector()
    )

    large_event = {

        "event_type":
            "network_transfer",

        "direction":
            "outbound",

        "device_id":
            "synthetic-endpoint",

        "process_name":
            "synthetic_large_transfer.exe",

        "remote_ip":
            "203.0.113.60",

        "remote_port":
            443,

        "bytes_sent":
            60 * 1024 * 1024,

        "destination_scope":
            "external",

        "approved_destination":
            True,

        "synthetic_test":
            True,
    }

    large_detections = (
        large_detector.analyze(

            large_event,

            current_time=
                1_700_502_000.0,
        )
    )

    for detection in large_detections:

        detected_types.add(
            detection.get(
                "detection_type"
            )
        )

        print(
            " -",
            detection.get(
                "detection_type"
            ),
            "| Risk:",
            detection.get(
                "risk_score"
            ),
        )

    # ============================================================
    # VALIDATION
    # ============================================================

    separator()

    print(
        "DETECTED TYPES"
    )

    for item in sorted(
        detected_types
    ):

        print(
            " -",
            item,
        )

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
            "Missing exfiltration detections: "
            + str(
                sorted(
                    missing
                )
            )
        )

    separator()

    print(
        "Large outbound transfer: PASS"
    )

    print(
        "Repeated outbound uploads: PASS"
    )

    print(
        "High-volume outbound activity: PASS"
    )

    print(
        "Unapproved external destination: PASS"
    )

    print(
        "Possible data exfiltration: PASS"
    )

    print(
        "Benign transfer control: PASS"
    )

    separator()

    print(
        "ALL EXFILTRATION BEHAVIOR TESTS PASSED"
    )

    separator()


if __name__ == "__main__":

    main()