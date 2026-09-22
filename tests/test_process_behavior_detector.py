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


def main():

    detector = ProcessBehaviorDetector()

    benign_process = {
        "name": "notepad.exe",
        "exe": r"C:\Windows\System32\notepad.exe",
        "cmdline": [
            "notepad.exe"
        ],
        "parent_name": "explorer.exe",
    }

    result = detector.analyze(
        benign_process
    )

    print()
    print("=" * 70)
    print("SENTINEL-X PROCESS BEHAVIOR DETECTOR TEST")
    print("=" * 70)

    print(
        "Process:",
        result["process_name"],
    )

    print(
        "Behavior Score:",
        result["behavior_score"],
    )

    print(
        "Severity:",
        result["severity"],
    )

    print(
        "Suspicious:",
        result["suspicious"],
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