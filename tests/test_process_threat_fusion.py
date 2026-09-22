import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:

    sys.path.insert(
        0,
        str(PROJECT_ROOT),
    )

from detection.behavior.process_behavior_detector import (
    ProcessBehaviorDetector,
)

from detection.anomaly.process_anomaly_detector import (
    ProcessAnomalyDetector,
)


def score_to_severity(
    score: int,
) -> str:

    if score >= 80:
        return "CRITICAL"

    if score >= 60:
        return "HIGH"

    if score >= 35:
        return "MEDIUM"

    if score >= 15:
        return "LOW"

    return "INFO"


def calculate_combined_score(
    behavior_result: dict,
    anomaly_result: dict,
) -> int:

    behavior_score = (
        behavior_result.get(
            "behavior_score",
            0,
        )
    )

    anomaly_score = (
        anomaly_result.get(
            "anomaly_score",
            0,
        )
    )

    primary_score = max(
        behavior_score,
        anomaly_score,
    )

    secondary_score = min(
        behavior_score,
        anomaly_score,
    )

    combined_score = (
        primary_score
        + (
            secondary_score
            * 0.25
        )
    )

    return min(
        int(
            round(
                combined_score
            )
        ),
        100,
    )


def main():

    behavior_detector = (
        ProcessBehaviorDetector()
    )

    anomaly_detector = (
        ProcessAnomalyDetector(
            minimum_history=5,
        )
    )

    print()
    print("=" * 70)
    print("SENTINEL-X PROCESS THREAT FUSION TEST")
    print("=" * 70)


    # ============================================================
    # BUILD NORMAL BASELINE
    # ============================================================

    baseline_samples = [
        {
            "name": "powershell.exe",
            "cpu_percent": 5,
            "memory_percent": 2,
            "num_threads": 7,
        },
        {
            "name": "powershell.exe",
            "cpu_percent": 6,
            "memory_percent": 2.1,
            "num_threads": 7,
        },
        {
            "name": "powershell.exe",
            "cpu_percent": 5.5,
            "memory_percent": 2,
            "num_threads": 8,
        },
        {
            "name": "powershell.exe",
            "cpu_percent": 4.8,
            "memory_percent": 2.2,
            "num_threads": 7,
        },
        {
            "name": "powershell.exe",
            "cpu_percent": 5.2,
            "memory_percent": 2.1,
            "num_threads": 7,
        },
    ]


    for sample in baseline_samples:

        anomaly_detector.analyze(
            sample
        )


    # ============================================================
    # SAFE SYNTHETIC SUSPICIOUS PROCESS METADATA
    #
    # This does NOT execute PowerShell or Word.
    # ============================================================

    test_process = {

        "pid":
            99999,

        "ppid":
            88888,

        "name":
            "powershell.exe",

        "exe":
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",

        "cmdline":
            "powershell.exe -EncodedCommand TEST_DATA_ONLY",

        "parent_name":
            "winword.exe",

        "cpu_percent":
            95,

        "memory_percent":
            60,

        "num_threads":
            40,
    }


    # ============================================================
    # BEHAVIOR ANALYSIS
    # ============================================================

    behavior_result = (
        behavior_detector.analyze(
            test_process
        )
    )


    # ============================================================
    # ANOMALY ANALYSIS
    # ============================================================

    anomaly_result = (
        anomaly_detector.analyze(
            test_process
        )
    )


    # ============================================================
    # FUSION
    # ============================================================

    combined_score = (
        calculate_combined_score(
            behavior_result,
            anomaly_result,
        )
    )


    severity = (
        score_to_severity(
            combined_score
        )
    )


    suspicious = (
        behavior_result.get(
            "suspicious",
            False,
        )
        or
        anomaly_result.get(
            "anomalous",
            False,
        )
        or
        combined_score >= 35
    )


    # ============================================================
    # OUTPUT
    # ============================================================

    print(
        "Process:",
        test_process["name"],
    )

    print(
        "Parent:",
        test_process["parent_name"],
    )

    print()

    print(
        "Behavior Score:",
        behavior_result[
            "behavior_score"
        ],
    )

    print(
        "Behavior Suspicious:",
        behavior_result[
            "suspicious"
        ],
    )

    print(
        "Behavior Indicators:",
        behavior_result[
            "indicators"
        ],
    )

    print()

    print(
        "Anomaly Score:",
        anomaly_result[
            "anomaly_score"
        ],
    )

    print(
        "Anomaly Detected:",
        anomaly_result[
            "anomalous"
        ],
    )

    print(
        "Anomaly Indicators:",
        anomaly_result[
            "indicators"
        ],
    )

    print()

    print(
        "Combined Threat Score:",
        combined_score,
    )

    print(
        "Final Severity:",
        severity,
    )

    print(
        "Final Suspicious:",
        suspicious,
    )

    print()
    print("=" * 70)


if __name__ == "__main__":

    main()