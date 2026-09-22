import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:

    sys.path.insert(
        0,
        str(PROJECT_ROOT),
    )


from detection.anomaly.generic_behavior_anomaly_detector import (
    GenericBehaviorAnomalyDetector,
)


def separator():

    print(
        "\n"
        + "=" * 72
    )


def main():

    separator()

    print(
        "SENTINEL-X GENERIC BEHAVIOR ANOMALY TEST"
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
    # BASELINE
    # ============================================================

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

        event = {

            "device_id":
                "synthetic-endpoint",

            "process_name":
                "synthetic_service.exe",

            "remote_ip":
                "203.0.113.10",

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
                event
            )
        )

        print(
            f"Baseline sample {index}:",
            len(
                detections
            ),
            "detections",
        )

        if detections:

            raise AssertionError(
                "Baseline sample generated "
                "an anomaly detection."
            )

    print(
        "BASELINE BUILD: PASS"
    )

    # ============================================================
    # NORMAL CONTROL AFTER BASELINE
    # ============================================================

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
            "203.0.113.10",

        "bytes_sent":
            1_010_000,

        "connection_count":
            10,

        "destination_count":
            2,

        "synthetic_test":
            True,
    }

    normal_detections = (
        detector.analyze(
            normal_event
        )
    )

    print(
        "Detections:",
        len(
            normal_detections
        ),
    )

    if normal_detections:

        raise AssertionError(
            "Normal behavior generated "
            "an anomaly."
        )

    print(
        "NORMAL CONTROL: PASS"
    )

    # ============================================================
    # UNKNOWN ANOMALOUS BEHAVIOR
    # ============================================================

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

        "bytes_sent":
            25_000_000,

        "connection_count":
            80,

        "destination_count":
            25,

        "synthetic_test":
            True,
    }

    detections = (
        detector.analyze(
            anomalous_event
        )
    )

    detected_types = set()

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
            "\n>>> ANOMALY DETECTION"
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

    # ============================================================
    # VALIDATION
    # ============================================================

    separator()

    print(
        "VALIDATION"
    )

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
            "Missing anomaly detections: "
            + str(
                sorted(
                    missing
                )
            )
        )

    print(
        "Unusual transfer volume: PASS"
    )

    print(
        "Unusual connection count: PASS"
    )

    print(
        "Unusual destination count: PASS"
    )

    print(
        "Combined unknown anomaly: PASS"
    )

    print(
        "Normal baseline control: PASS"
    )

    # ============================================================
    # VERIFY ANOMALY DID NOT POLLUTE BASELINE
    # ============================================================

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

    # Five initial baseline samples
    # + one normal control
    # = 6
    #
    # Anomalous sample should NOT be added.

    if baseline_size != 6:

        raise AssertionError(
            (
                "Anomalous sample polluted baseline. "
                f"Expected baseline size 6, got "
                f"{baseline_size}."
            )
        )

    print(
        "Baseline contamination protection: PASS"
    )

    separator()

    print(
        "ALL GENERIC ANOMALY DETECTOR TESTS PASSED"
    )

    separator()


if __name__ == "__main__":

    main()