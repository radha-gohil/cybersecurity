import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:

    sys.path.insert(
        0,
        str(PROJECT_ROOT),
    )


from detection.behavior.ransomware_behavior_detector import (
    RansomwareBehaviorDetector,
)

from endpoint.collectors.file_monitor import (
    SentinelFileEventHandler,
)


def separator():

    print(
        "\n"
        + "=" * 72
    )


def print_detections(
    detections,
):

    for detection in detections:

        print(
            "\n>>> RANSOMWARE BEHAVIOR DETECTION"
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
            "Reason:",
            detection.get(
                "reason"
            ),
        )


def main():

    separator()

    print(
        "SENTINEL-X RANSOMWARE FULL PIPELINE TEST"
    )

    separator()

    print(
        "\nNO files are created, renamed, encrypted, or modified."
    )

    print(
        "Only synthetic filesystem-event metadata is used."
    )

    handler = (
        SentinelFileEventHandler()
    )

    # ------------------------------------------------------------
    # LOWER THRESHOLDS FOR TESTING ONLY
    # ------------------------------------------------------------

    handler.ransomware_detector = (
        RansomwareBehaviorDetector(

            modification_window_seconds=30,

            modification_threshold=5,

            rename_window_seconds=30,

            rename_threshold=5,

            extension_window_seconds=30,

            extension_change_threshold=5,

            ransomware_score_threshold=70,

            alert_cooldown_seconds=0,
        )
    )

    detected_types = set()

    event_count = 0

    detection_count = 0

    # ============================================================
    # MODIFICATION-BURST EVENTS
    # ============================================================

    print(
        "\nTesting synthetic file modification burst..."
    )

    for index in range(
        6
    ):

        result = (
            handler.save_file_event(

                event_type=
                    "file_modify",

                file_path=
                    (
                        "C:/synthetic/"
                        f"document_{index}.txt"
                    ),

                extra_metadata={

                    "synthetic_test":
                        True,

                    "process_id":
                        8000,
                    "pid":
                        8000,

                    "process_name":
                        "synthetic_ransomware_test.exe",
                },
            )
        )

        event = (
            result[
                "event"
            ]
        )

        detections = (
            result[
                "ransomware_detections"
            ]
        )

        event_count += 1

        print(
            "\nEVENT:",
            event.event_id,
            event.event_type,
            event.severity,
        )

        for detection in detections:

            detection_count += 1

            detected_types.add(

                detection.get(
                    "detection_type"
                )
            )

        print_detections(
            detections
        )

    # ============================================================
    # RENAME + EXTENSION CHANGE EVENTS
    # ============================================================

    print(
        "\nTesting synthetic rename/extension activity..."
    )

    for index in range(
        6
    ):

        old_path = (
            "C:/synthetic/"
            f"report_{index}.docx"
        )

        new_path = (
            "C:/synthetic/"
            f"report_{index}.changed"
        )

        result = (
            handler.save_file_event(

                event_type=
                    "file_rename",

                file_path=
                    new_path,

                extra_metadata={

                    "source_path":
                        old_path,

                    "destination_path":
                        new_path,

                    "synthetic_test":
                        True,

                    "process_id":
                        8000,
                    "pid":
                        8000,

                    "process_name":
                        "synthetic_ransomware_test.exe",
                },
            )
        )

        event = (
            result[
                "event"
            ]
        )

        detections = (
            result[
                "ransomware_detections"
            ]
        )

        event_count += 1

        print(
            "\nEVENT:",
            event.event_id,
            event.event_type,
            event.severity,
        )

        for detection in detections:

            detection_count += 1

            detected_types.add(

                detection.get(
                    "detection_type"
                )
            )

        print_detections(
            detections
        )

    # ============================================================
    # SUMMARY
    # ============================================================

    separator()

    print(
        "PIPELINE SUMMARY"
    )

    print(
        "\nSecurityEvents created:",
        event_count,
    )

    print(
        "Ransomware detections:",
        detection_count,
    )

    print(
        "\nDetected types:"
    )

    for item in sorted(
        detected_types
    ):

        print(
            " -",
            item,
        )

    # ============================================================
    # VALIDATION
    # ============================================================

    required = {

        "FILE_MODIFICATION_BURST",

        "MASS_FILE_RENAME",

        "EXTENSION_CHANGE_BURST",

        "POSSIBLE_RANSOMWARE_BEHAVIOR",
    }

    missing = (
        required
        - detected_types
    )

    if missing:

        raise AssertionError(
            "Missing pipeline detections: "
            + str(
                sorted(
                    missing
                )
            )
        )

    separator()

    print(
        "SecurityEvent integration: PASS"
    )

    print(
        "Modification detection: PASS"
    )

    print(
        "Mass rename detection: PASS"
    )

    print(
        "Extension-change detection: PASS"
    )

    print(
        "Ransomware heuristic detection: PASS"
    )

    print(
        "Database integration: check "
        "'Detection saved' logs"
    )

    print(
        "Correlation integration: check "
        "'Event correlation detected' logs"
    )

    print(
        "Incident integration: check "
        "'Incident created/updated' logs"
    )

    separator()

    print(
        "RANSOMWARE PIPELINE TEST COMPLETED"
    )

    separator()


if __name__ == "__main__":

    main()