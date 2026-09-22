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


def separator():

    print(
        "\n"
        + "=" * 72
    )


def main():

    separator()

    print(
        "SENTINEL-X RANSOMWARE BEHAVIOR TEST"
    )

    separator()

    print(
        "\nNo files are modified by this test."
    )

    print(
        "Only synthetic metadata is analyzed."
    )

    detector = (
        RansomwareBehaviorDetector(

            modification_threshold=5,

            rename_threshold=5,

            extension_change_threshold=5,

            ransomware_score_threshold=70,

            alert_cooldown_seconds=0,
        )
    )

    base_time = (
        1_700_200_000.0
    )

    detected_types = set()

    # ============================================================
    # FILE MODIFICATION BURST
    # ============================================================

    print(
        "\nTesting rapid file modifications..."
    )

    for index in range(
        6
    ):

        event = {

            "event_type":
                "file_modify",

            "process_id":
                8000,

            "process_name":
                "synthetic_file_test.exe",

            "file_path":
                f"C:/synthetic/document_{index}.txt",
        }

        detections = (
            detector.analyze(
                event,
                current_time=
                    base_time
                    + index,
            )
        )

        for detection in detections:

            detected_types.add(
                detection[
                    "detection_type"
                ]
            )

            print(
                "\nDETECTION:",
                detection[
                    "detection_type"
                ],
            )

            print(
                "Severity:",
                detection[
                    "severity"
                ],
            )

            print(
                "Risk:",
                detection[
                    "risk_score"
                ],
            )

            print(
                "Reason:",
                detection[
                    "reason"
                ],
            )

    # ============================================================
    # MASS RENAMES + EXTENSION CHANGES
    # ============================================================

    print(
        "\nTesting synthetic rename activity..."
    )

    rename_base = (
        base_time
        + 50
    )

    for index in range(
        6
    ):

        event = {

            "event_type":
                "file_rename",

            "process_id":
                8000,

            "process_name":
                "synthetic_file_test.exe",

            "old_path":
                f"C:/synthetic/report_{index}.docx",

            "new_path":
                f"C:/synthetic/report_{index}.changed",
        }

        detections = (
            detector.analyze(
                event,
                current_time=
                    rename_base
                    + index,
            )
        )

        for detection in detections:

            detected_types.add(
                detection[
                    "detection_type"
                ]
            )

            print(
                "\nDETECTION:",
                detection[
                    "detection_type"
                ],
            )

            print(
                "Severity:",
                detection[
                    "severity"
                ],
            )

            print(
                "Risk:",
                detection[
                    "risk_score"
                ],
            )

            print(
                "Confidence:",
                detection[
                    "confidence"
                ],
            )

            print(
                "Reason:",
                detection[
                    "reason"
                ],
            )

    # ============================================================
    # VALIDATION
    # ============================================================

    separator()

    print(
        "Detected types:"
    )

    for item in sorted(
        detected_types
    ):

        print(
            " -",
            item,
        )

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
            "Missing detections: "
            + str(
                sorted(
                    missing
                )
            )
        )

    separator()

    print(
        "FILE MODIFICATION BURST: PASS"
    )

    print(
        "MASS FILE RENAME: PASS"
    )

    print(
        "EXTENSION CHANGE BURST: PASS"
    )

    print(
        "POSSIBLE RANSOMWARE BEHAVIOR: PASS"
    )

    separator()

    print(
        "ALL RANSOMWARE BEHAVIOR TESTS PASSED"
    )

    separator()


if __name__ == "__main__":

    main()