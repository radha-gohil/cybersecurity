import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:

    sys.path.insert(
        0,
        str(PROJECT_ROOT),
    )

from detection.anomaly.process_anomaly_detector import (
    ProcessAnomalyDetector,
)


def main():

    detector = ProcessAnomalyDetector(
        minimum_history=5,
    )


    print()
    print("=" * 70)
    print("SENTINEL-X PROCESS ANOMALY DETECTOR TEST")
    print("=" * 70)


    # ============================================================
    # BUILD NORMAL BASELINE
    # ============================================================

    normal_samples = [
        {
            "name": "demo_process.exe",
            "cpu_percent": 10,
            "memory_percent": 5,
            "num_threads": 8,
        },
        {
            "name": "demo_process.exe",
            "cpu_percent": 11,
            "memory_percent": 5.2,
            "num_threads": 8,
        },
        {
            "name": "demo_process.exe",
            "cpu_percent": 9,
            "memory_percent": 4.9,
            "num_threads": 9,
        },
        {
            "name": "demo_process.exe",
            "cpu_percent": 10.5,
            "memory_percent": 5.1,
            "num_threads": 8,
        },
        {
            "name": "demo_process.exe",
            "cpu_percent": 10.2,
            "memory_percent": 5.0,
            "num_threads": 8,
        },
    ]


    for sample in normal_samples:

        detector.analyze(
            sample
        )


    # ============================================================
    # SAFE SYNTHETIC ANOMALOUS SAMPLE
    # ============================================================

    anomalous_sample = {
        "name": "demo_process.exe",
        "cpu_percent": 95,
        "memory_percent": 60,
        "num_threads": 40,
    }


    result = detector.analyze(
        anomalous_sample
    )


    print(
        "Process:",
        result["process_name"],
    )

    print(
        "Anomaly Score:",
        result["anomaly_score"],
    )

    print(
        "Severity:",
        result["severity"],
    )

    print(
        "Anomalous:",
        result["anomalous"],
    )

    print(
        "CPU Z-Score:",
        result["cpu_z_score"],
    )

    print(
        "Memory Z-Score:",
        result["memory_z_score"],
    )

    print(
        "Thread Z-Score:",
        result["thread_z_score"],
    )

    print(
        "Indicators:",
        result["indicators"],
    )

    print(
        "Reasons:",
        result["reasons"],
    )


if __name__ == "__main__":

    main()