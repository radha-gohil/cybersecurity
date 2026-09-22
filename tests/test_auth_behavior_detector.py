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


from detection.auth.auth_behavior_detector import (
    AuthBehaviorDetector,
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
            "\n>>> AUTH DETECTION"
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
            "Source IP:",
            detection.get(
                "source_ip"
            ),
        )

        print(
            "Failures:",
            detection.get(
                "failure_count"
            ),
        )

        print(
            "Accounts:",
            detection.get(
                "unique_account_count"
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
        "SENTINEL-X AUTHENTICATION BEHAVIOR TEST"
    )

    separator()

    print(
        "\nNo real login attempts are performed."
    )

    print(
        "Only synthetic authentication metadata is analyzed."
    )

    detector = (
        AuthBehaviorDetector(

            failure_window_seconds=60,

            repeated_failure_threshold=5,

            multi_account_threshold=3,

            brute_force_score_threshold=70,

            # Test only:
            alert_cooldown_seconds=0,
        )
    )

    detected_types = set()

    # ============================================================
    # TEST 1 — SMALL NUMBER OF FAILURES
    #
    # This should not trigger our thresholds.
    # ============================================================

    print(
        "\nTesting low-volume authentication failures..."
    )

    low_volume_detector = (
        AuthBehaviorDetector(

            failure_window_seconds=60,

            repeated_failure_threshold=5,

            multi_account_threshold=3,

            brute_force_score_threshold=70,

            alert_cooldown_seconds=0,
        )
    )

    low_volume_events = [

        {
            "event_type":
                "login_failure",

            "source_ip":
                "198.51.100.10",

            "username":
                "synthetic_user_a",
        },

        {
            "event_type":
                "login_failure",

            "source_ip":
                "198.51.100.10",

            "username":
                "synthetic_user_b",
        },
    ]

    for index, event in enumerate(
        low_volume_events
    ):

        detections = (
            low_volume_detector.analyze(

                event,

                current_time=
                    1_700_300_000.0
                    + index,
            )
        )

        if detections:

            raise AssertionError(
                "Low-volume authentication failures "
                "incorrectly triggered a detection."
            )

    print(
        "LOW-VOLUME CONTROL: PASS"
    )

    # ============================================================
    # TEST 2 — SYNTHETIC BRUTE-FORCE-LIKE PATTERN
    # ============================================================

    separator()

    print(
        "Testing synthetic brute-force-like authentication pattern..."
    )

    source_ip = (
        "198.51.100.25"
    )

    usernames = [

        "synthetic_admin",

        "synthetic_user1",

        "synthetic_user2",

        "synthetic_admin",

        "synthetic_user1",

        "synthetic_user2",
    ]

    base_time = (
        1_700_301_000.0
    )

    for index, username in enumerate(
        usernames
    ):

        event = {

            "event_type":
                "login_failure",

            "source_ip":
                source_ip,

            "username":
                username,

            "device_id":
                "synthetic-endpoint",

            "result":
                "failed",

            "synthetic_test":
                True,
        }

        timestamp = (
            base_time
            + (
                index
                * 5
            )
        )

        detections = (
            detector.analyze(

                event,

                current_time=
                    timestamp,
            )
        )

        print(
            "\n"
            + "-" * 72
        )

        print(
            "Synthetic failure:",
            index + 1,
        )

        print(
            "Username:",
            username,
        )

        print(
            "Timestamp:",
            timestamp,
        )

        if not detections:

            print(
                "No detection yet."
            )

        for detection in detections:

            detected_types.add(

                detection.get(
                    "detection_type"
                )
            )

        print_detections(
            detections
        )

    # ============================================================
    # TEST 3 — SUCCESS EVENT SHOULD NOT INCREASE FAILURE HISTORY
    # ============================================================

    separator()

    print(
        "Testing successful login metadata..."
    )

    success_event = {

        "event_type":
            "login_success",

        "source_ip":
            source_ip,

        "username":
            "synthetic_admin",

        "result":
            "success",

        "synthetic_test":
            True,
    }

    success_detections = (
        detector.analyze(

            success_event,

            current_time=
                base_time
                + 40,
        )
    )

    if success_detections:

        raise AssertionError(
            "Successful authentication incorrectly "
            "generated a brute-force detection."
        )

    print(
        "SUCCESS EVENT CONTROL: PASS"
    )

    # ============================================================
    # VALIDATION
    # ============================================================

    separator()

    print(
        "DETECTED TYPES"
    )

    for detection_type in sorted(
        detected_types
    ):

        print(
            " -",
            detection_type,
        )

    required = {

        "REPEATED_LOGIN_FAILURES",

        "MULTI_ACCOUNT_LOGIN_FAILURES",

        "AUTH_BRUTE_FORCE_BEHAVIOR",
    }

    missing = (
        required
        - detected_types
    )

    if missing:

        raise AssertionError(
            "Missing authentication detections: "
            + str(
                sorted(
                    missing
                )
            )
        )

    separator()

    print(
        "REPEATED LOGIN FAILURES: PASS"
    )

    print(
        "MULTI-ACCOUNT FAILURES: PASS"
    )

    print(
        "AUTH BRUTE-FORCE BEHAVIOR: PASS"
    )

    print(
        "SUCCESSFUL LOGIN CONTROL: PASS"
    )

    separator()

    print(
        "ALL AUTHENTICATION BEHAVIOR TESTS PASSED"
    )

    separator()


if __name__ == "__main__":

    main()