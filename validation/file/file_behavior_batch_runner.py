from __future__ import annotations

import csv
import json
import shutil
from pathlib import Path

from detection.behavior.ransomware_behavior_detector import (
    RansomwareBehaviorDetector,
)
from detection.malware.static_file_analyzer import (
    StaticFileAnalyzer,
)
from detection.behavior.suspicious_file_creation_detector import (
    SuspiciousFileCreationDetector,
)


# ================================================================
# PATHS
# ================================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

REPORT_DIR = PROJECT_ROOT / "validation" / "reports"
TMP_DIR = PROJECT_ROOT / "validation" / "tmp" / "file_behavior_phase3"

REPORT_DIR.mkdir(parents=True, exist_ok=True)
TMP_DIR.mkdir(parents=True, exist_ok=True)

CSV_PATH = REPORT_DIR / "file_behavior_validation.csv"
JSON_PATH = REPORT_DIR / "file_behavior_validation.json"


# ================================================================
# HELPERS
# ================================================================

def detection_types(items):
    return sorted(
        {
            str(item.get("detection_type"))
            for item in (items or [])
            if isinstance(item, dict)
            and item.get("detection_type")
        }
    )


def fresh_ransomware_detector():
    # These are the exact thresholds currently used by FileMonitor.
    return RansomwareBehaviorDetector(
        modification_window_seconds=20,
        modification_threshold=15,
        rename_window_seconds=30,
        rename_threshold=8,
        extension_window_seconds=30,
        extension_change_threshold=6,
        ransomware_score_threshold=70,
        alert_cooldown_seconds=30,
    )


def add_result(
    results,
    scenario_id,
    family,
    scenario_name,
    sample_count,
    detections,
    expected,
    passed,
    failure_layers="",
    static_risk=None,
    static_severity=None,
    notes="",
):
    results.append(
        {
            "scenario_id": scenario_id,
            "family": family,
            "scenario_name": scenario_name,
            "sample_count": sample_count,
            "detections": ",".join(detections),
            "expected": expected,
            "static_risk": static_risk,
            "static_severity": static_severity,
            "failure_layers": failure_layers,
            "passed": bool(passed),
            "notes": notes,
        }
    )


def make_event(
    event_type,
    file_path,
    pid,
    process_name,
    **extra,
):
    event = {
        "event_type": event_type,
        "file_path": file_path,
        "process_id": pid,
        "process_name": process_name,
    }
    event.update(extra)
    return event


# ================================================================
# F1 — SUSPICIOUS EXECUTABLE CREATION / STATIC BASELINE
# ================================================================

def run_f1(results):
    analyzer = StaticFileAnalyzer()

    # ------------------------------------------------------------
    # F1-01 — BENIGN TEXT FILE
    # ------------------------------------------------------------
    path = TMP_DIR / "notes.txt"
    path.write_text(
        "Sentinel-X benign validation text.\n",
        encoding="utf-8",
    )

    analysis = analyzer.analyze(str(path))

    add_result(
        results=results,
        scenario_id="F1-01",
        family="FILE_CREATE",
        scenario_name="Benign text file creation",
        sample_count=1,
        detections=[],
        expected="NO_ALERT",
        passed=(
            analysis.get("risk_score") == 0
            and analysis.get("severity") == "INFO"
        ),
        failure_layers=(
            ""
            if analysis.get("risk_score") == 0
            and analysis.get("severity") == "INFO"
            else "STATIC_ANALYZER"
        ),
        static_risk=analysis.get("risk_score"),
        static_severity=analysis.get("severity"),
        notes="False-positive control.",
    )

    # ------------------------------------------------------------
    # F1-02 — PE-LIKE LOW-ENTROPY EXECUTABLE
    #
    # This file is inert validation data. It is never executed.
    # StaticFileAnalyzer only checks the leading MZ signature.
    # ------------------------------------------------------------
    path = TMP_DIR / "benign_like.exe"
    path.write_bytes(
        b"MZ" + (b"\x00" * 8190)
    )

    analysis = analyzer.analyze(str(path))

    passed = (
        analysis.get("is_pe") is True
        and (analysis.get("risk_score") or 0) <= 20
        and analysis.get("severity") in {"INFO", "LOW"}
    )

    add_result(
        results=results,
        scenario_id="F1-02",
        family="FILE_CREATE",
        scenario_name="Low-entropy PE-like executable",
        sample_count=1,
        detections=[],
        expected="NO_HIGH_ALERT",
        passed=passed,
        failure_layers="" if passed else "STATIC_ANALYZER",
        static_risk=analysis.get("risk_score"),
        static_severity=analysis.get("severity"),
        notes=(
            "Benign-looking executable must not become HIGH/CRITICAL "
            "from extension/MZ signature alone."
        ),
    )

    # ------------------------------------------------------------
    # F1-03 — HIGH-ENTROPY PE-LIKE EXECUTABLE
    #
    # Current production code performs static scoring, but there is
    # no dedicated persisted F1 suspicious-executable detector yet.
    #
    # This scenario is expected to expose that gap.
    # ------------------------------------------------------------
    path = TMP_DIR / "packed_like.exe"

    deterministic_high_entropy = (
        b"MZ"
        + bytes(range(256)) * 32
    )

    path.write_bytes(
        deterministic_high_entropy
    )

    analysis = analyzer.analyze(str(path))

    static_signal_present = (
        analysis.get("is_pe") is True
        and (analysis.get("entropy") or 0) >= 7.2
        and (analysis.get("risk_score") or 0) >= 30
    )

    detector = SuspiciousFileCreationDetector(
        static_risk_threshold=30,
    )

    detection = detector.analyze(
        event_type="file_create",
        file_path=str(path),
        static_analysis=analysis,
    )

    f1_types = detection_types(
        [detection] if detection else []
    )

    actual_detection_present = (
        "SUSPICIOUS_EXECUTABLE_CREATION"
        in f1_types
    )

    passed = (
        static_signal_present
        and actual_detection_present
    )

    add_result(
        results=results,
        scenario_id="F1-03",
        family="FILE_CREATE",
        scenario_name="High-entropy PE-like executable creation",
        sample_count=1,
        detections=f1_types,
        expected="SUSPICIOUS_EXECUTABLE_CREATION",
        passed=passed,
        failure_layers="" if passed else "FILE_DETECTOR",
        static_risk=analysis.get("risk_score"),
        static_severity=analysis.get("severity"),
        notes=(
            "Static evidence is promoted to the dedicated F1 detector without "
            "claiming malware classification."
        ),
    )


# ================================================================
# F2 — MASS MODIFICATION / RENAME
# ================================================================

def run_f2(results):
    # ------------------------------------------------------------
    # F2-01 — 14 MODIFICATIONS, BELOW THRESHOLD
    # ------------------------------------------------------------
    detector = fresh_ransomware_detector()
    seen = []

    for index in range(14):
        seen.extend(
            detector.analyze(
                make_event(
                    "file_modify",
                    f"C:/validation/doc_{index}.txt",
                    7301,
                    "validation_writer.exe",
                ),
                current_time=1000.0 + index,
            )
        )

    types = detection_types(seen)
    passed = "FILE_MODIFICATION_BURST" not in types

    add_result(
        results,
        "F2-01",
        "MASS_MODIFICATION",
        "Fourteen distinct modifications",
        14,
        types,
        "NO_FILE_MODIFICATION_BURST",
        passed,
        "" if passed else "RANSOMWARE_BEHAVIOR",
        notes="Boundary test below threshold 15.",
    )

    # ------------------------------------------------------------
    # F2-02 — 15 MODIFICATIONS, EXACT THRESHOLD
    # ------------------------------------------------------------
    detector = fresh_ransomware_detector()
    seen = []

    for index in range(15):
        seen.extend(
            detector.analyze(
                make_event(
                    "file_modify",
                    f"C:/validation/report_{index}.docx",
                    7302,
                    "validation_writer.exe",
                ),
                current_time=2000.0 + index,
            )
        )

    types = detection_types(seen)
    passed = "FILE_MODIFICATION_BURST" in types

    add_result(
        results,
        "F2-02",
        "MASS_MODIFICATION",
        "Fifteen distinct modifications",
        15,
        types,
        "FILE_MODIFICATION_BURST",
        passed,
        "" if passed else "RANSOMWARE_BEHAVIOR",
        notes="Exact modification threshold.",
    )

    # ------------------------------------------------------------
    # F2-03 — 7 RENAMES, BELOW THRESHOLD
    # ------------------------------------------------------------
    detector = fresh_ransomware_detector()
    seen = []

    for index in range(7):
        old_path = f"C:/validation/file_{index}.txt"
        new_path = f"C:/validation/file_{index}_renamed.txt"

        seen.extend(
            detector.analyze(
                make_event(
                    "file_rename",
                    new_path,
                    7303,
                    "validation_renamer.exe",
                    old_path=old_path,
                    new_path=new_path,
                ),
                current_time=3000.0 + index,
            )
        )

    types = detection_types(seen)
    passed = "MASS_FILE_RENAME" not in types

    add_result(
        results,
        "F2-03",
        "MASS_RENAME",
        "Seven same-extension renames",
        7,
        types,
        "NO_MASS_FILE_RENAME",
        passed,
        "" if passed else "RANSOMWARE_BEHAVIOR",
        notes="Boundary test below rename threshold 8.",
    )

    # ------------------------------------------------------------
    # F2-04 — 8 RENAMES, EXACT THRESHOLD
    # ------------------------------------------------------------
    detector = fresh_ransomware_detector()
    seen = []

    for index in range(8):
        old_path = f"C:/validation/photo_{index}.jpg"
        new_path = f"C:/validation/photo_{index}_renamed.jpg"

        seen.extend(
            detector.analyze(
                make_event(
                    "file_rename",
                    new_path,
                    7304,
                    "validation_renamer.exe",
                    old_path=old_path,
                    new_path=new_path,
                ),
                current_time=4000.0 + index,
            )
        )

    types = detection_types(seen)
    passed = "MASS_FILE_RENAME" in types

    add_result(
        results,
        "F2-04",
        "MASS_RENAME",
        "Eight same-extension renames",
        8,
        types,
        "MASS_FILE_RENAME",
        passed,
        "" if passed else "RANSOMWARE_BEHAVIOR",
        notes="Exact rename threshold.",
    )


# ================================================================
# F3 — RANSOMWARE-LIKE BEHAVIOR
# ================================================================

def run_f3(results):
    # ------------------------------------------------------------
    # F3-01 — 5 EXTENSION CHANGES, BELOW THRESHOLD
    # ------------------------------------------------------------
    detector = fresh_ransomware_detector()
    seen = []

    for index in range(5):
        old_path = f"C:/validation/data_{index}.txt"
        new_path = f"C:/validation/data_{index}.locked"

        seen.extend(
            detector.analyze(
                make_event(
                    "file_rename",
                    new_path,
                    7401,
                    "validation_transformer.exe",
                    old_path=old_path,
                    new_path=new_path,
                ),
                current_time=5000.0 + index,
            )
        )

    types = detection_types(seen)
    passed = "EXTENSION_CHANGE_BURST" not in types

    add_result(
        results,
        "F3-01",
        "RANSOMWARE_BEHAVIOR",
        "Five extension changes",
        5,
        types,
        "NO_EXTENSION_CHANGE_BURST",
        passed,
        "" if passed else "RANSOMWARE_BEHAVIOR",
        notes="Below extension threshold 6.",
    )

    # ------------------------------------------------------------
    # F3-02 — 6 EXTENSION CHANGES, EXACT THRESHOLD
    # ------------------------------------------------------------
    detector = fresh_ransomware_detector()
    seen = []

    for index in range(6):
        old_path = f"C:/validation/data_{index}.txt"
        new_path = f"C:/validation/data_{index}.locked"

        seen.extend(
            detector.analyze(
                make_event(
                    "file_rename",
                    new_path,
                    7402,
                    "validation_transformer.exe",
                    old_path=old_path,
                    new_path=new_path,
                ),
                current_time=6000.0 + index,
            )
        )

    types = detection_types(seen)
    passed = "EXTENSION_CHANGE_BURST" in types

    add_result(
        results,
        "F3-02",
        "RANSOMWARE_BEHAVIOR",
        "Six extension changes",
        6,
        types,
        "EXTENSION_CHANGE_BURST",
        passed,
        "" if passed else "RANSOMWARE_BEHAVIOR",
        notes="Exact extension-change threshold.",
    )

    # ------------------------------------------------------------
    # F3-03 — 8 RAPID RENAMES + EXTENSION CHANGES
    #
    # Desired result:
    #   MASS_FILE_RENAME
    #   EXTENSION_CHANGE_BURST
    #   POSSIBLE_RANSOMWARE_BEHAVIOR
    #
    # With the current detector, EXTENSION_CHANGE_BURST is emitted
    # at event 6 and then suppressed by the 30-second cooldown.
    # MASS_FILE_RENAME appears at event 8. build_combined_detection()
    # only sees signals emitted on the current event, so the combined
    # ransomware signal is expected to be missing.
    # ------------------------------------------------------------
    detector = fresh_ransomware_detector()
    seen = []

    for index in range(8):
        old_path = f"C:/validation/victim_{index}.docx"
        new_path = f"C:/validation/victim_{index}.encrypted"

        seen.extend(
            detector.analyze(
                make_event(
                    "file_rename",
                    new_path,
                    7403,
                    "validation_transformer.exe",
                    old_path=old_path,
                    new_path=new_path,
                ),
                current_time=7000.0 + index,
            )
        )

    types = detection_types(seen)

    expected_required = {
        "MASS_FILE_RENAME",
        "EXTENSION_CHANGE_BURST",
        "POSSIBLE_RANSOMWARE_BEHAVIOR",
    }

    passed = expected_required.issubset(
        set(types)
    )

    add_result(
        results,
        "F3-03",
        "RANSOMWARE_BEHAVIOR",
        "Eight rapid extension-changing renames",
        8,
        types,
        "POSSIBLE_RANSOMWARE_BEHAVIOR",
        passed,
        "" if passed else "RANSOMWARE_COMBINATION_LOGIC",
        notes=(
            "Combined ransomware scoring must use active recent signals, "
            "not only alerts emitted on the current event."
        ),
    )


# ================================================================
# REPORTING
# ================================================================

def save_reports(results):
    fields = [
        "scenario_id",
        "family",
        "scenario_name",
        "sample_count",
        "detections",
        "expected",
        "static_risk",
        "static_severity",
        "failure_layers",
        "passed",
        "notes",
    ]

    with CSV_PATH.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=fields,
        )
        writer.writeheader()
        writer.writerows(results)

    with JSON_PATH.open(
        "w",
        encoding="utf-8",
    ) as handle:
        json.dump(
            {
                "suite": "SENTINEL-X PHASE 3 FILE BEHAVIOR VALIDATION",
                "scenario_count": len(results),
                "passed": sum(1 for row in results if row["passed"]),
                "failed": sum(1 for row in results if not row["passed"]),
                "results": results,
            },
            handle,
            indent=2,
        )


def print_matrix(results):
    print()
    print("=" * 100)
    print("SENTINEL-X PHASE 3 — FILE BEHAVIOR VALIDATION")
    print("=" * 100)

    for row in results:
        state = "PASS" if row["passed"] else "FAIL"

        print(
            f"{row['scenario_id']:<7} "
            f"{state:<5} "
            f"{row['scenario_name']:<44} "
            f"Observed={row['detections'] or 'NONE'} "
            f"Expected={row['expected']}"
        )

    passed = sum(
        1
        for row in results
        if row["passed"]
    )

    print("-" * 100)
    print(f"RESULT: {passed}/{len(results)} PASS")
    print(f"CSV   : {CSV_PATH}")
    print(f"JSON  : {JSON_PATH}")
    print("=" * 100)


# ================================================================
# MAIN
# ================================================================

def main():
    # Start clean; only this deterministic validation directory is touched.
    if TMP_DIR.exists():
        shutil.rmtree(TMP_DIR)

    TMP_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    results = []

    run_f1(results)
    run_f2(results)
    run_f3(results)

    save_reports(results)
    print_matrix(results)


if __name__ == "__main__":
    main()
