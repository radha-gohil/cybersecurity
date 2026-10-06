from __future__ import annotations

import csv
import json
from pathlib import Path

from detection.registry.registry_behavior_detector import (
    RegistryBehaviorDetector,
)


PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[2]
)

REPORT_DIR = (
    PROJECT_ROOT
    / "validation"
    / "reports"
)

REPORT_DIR.mkdir(
    parents=True,
    exist_ok=True,
)

CSV_PATH = (
    REPORT_DIR
    / "registry_validation.csv"
)

JSON_PATH = (
    REPORT_DIR
    / "registry_validation.json"
)


def make_event(
    registry_path,
    name,
    value,
    event_type="registry_modify",
):
    return {
        "event_type":
            event_type,

        "registry_path":
            registry_path,

        "name":
            name,

        "value":
            value,
    }


def types(
    findings,
):
    return sorted(
        {
            finding.get(
                "detection_type"
            )
            for finding
            in findings
            if finding.get(
                "detection_type"
            )
        }
    )


def run_case(
    detector,
    scenario_id,
    family,
    scenario_name,
    event,
    expected_present=None,
    expected_absent=None,
):
    findings = (
        detector.analyze(
            event
        )
    )

    observed = types(
        findings
    )

    expected_present = set(
        expected_present
        or []
    )

    expected_absent = set(
        expected_absent
        or []
    )

    passed = (
        expected_present.issubset(
            set(
                observed
            )
        )
        and not (
            expected_absent
            & set(
                observed
            )
        )
    )

    return {
        "scenario_id":
            scenario_id,

        "family":
            family,

        "scenario_name":
            scenario_name,

        "detections":
            ",".join(
                observed
            ),

        "expected":
            ",".join(
                sorted(
                    expected_present
                )
            )
            or "NO_ALERT",

        "failure_layers":
            ""
            if passed
            else "REGISTRY_DETECTOR",

        "passed":
            passed,
    }


def main():

    detector = (
        RegistryBehaviorDetector()
    )

    results = []


    # ============================================================
    # R1 — RUN / RUNONCE
    # ============================================================

    results.append(
        run_case(
            detector,
            "R1-01",
            "RUN_PERSISTENCE",
            "Unrelated benign registry preference",
            make_event(
                r"HKEY_CURRENT_USER\Software\ExampleApp",
                "Theme",
                "Dark",
            ),
            expected_absent=[
                "REGISTRY_AUTORUN_PERSISTENCE",
                "SUSPICIOUS_RUN_KEY_PERSISTENCE",
            ],
        )
    )


    results.append(
        run_case(
            detector,
            "R1-02",
            "RUN_PERSISTENCE",
            "Benign-looking Run key application",
            make_event(
                r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",
                "OneDrive",
                r"C:\Program Files\Microsoft OneDrive\OneDrive.exe",
                "registry_create",
            ),
            expected_present=[
                "REGISTRY_AUTORUN_PERSISTENCE",
            ],
            expected_absent=[
                "SUSPICIOUS_RUN_KEY_PERSISTENCE",
            ],
        )
    )


    results.append(
        run_case(
            detector,
            "R1-03",
            "RUN_PERSISTENCE",
            "Suspicious Run key PowerShell payload",
            make_event(
                r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",
                "Updater",
                r"powershell.exe -WindowStyle Hidden -File C:\Users\Public\update.ps1",
                "registry_create",
            ),
            expected_present=[
                "SUSPICIOUS_RUN_KEY_PERSISTENCE",
            ],
        )
    )


    results.append(
        run_case(
            detector,
            "R1-04",
            "RUN_PERSISTENCE",
            "Run key deletion",
            make_event(
                r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",
                "OldUpdater",
                r"C:\Program Files\Example\example.exe",
                "registry_delete",
            ),
            expected_absent=[
                "REGISTRY_AUTORUN_PERSISTENCE",
                "SUSPICIOUS_RUN_KEY_PERSISTENCE",
            ],
        )
    )


    # ============================================================
    # R2 — SERVICE / WINLOGON
    # ============================================================

    results.append(
        run_case(
            detector,
            "R2-01",
            "SERVICE_PERSISTENCE",
            "Normal service image path",
            make_event(
                r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ExampleSvc",
                "ImagePath",
                r"C:\Program Files\Example\service.exe",
                "registry_modify",
            ),
            expected_present=[
                "SERVICE_PERSISTENCE_CHANGE",
            ],
            expected_absent=[
                "SUSPICIOUS_SERVICE_PERSISTENCE",
            ],
        )
    )


    results.append(
        run_case(
            detector,
            "R2-02",
            "SERVICE_PERSISTENCE",
            "Suspicious service image path",
            make_event(
                r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UpdaterSvc",
                "ImagePath",
                r"cmd.exe /c C:\Users\Public\update.cmd",
                "registry_modify",
            ),
            expected_present=[
                "SUSPICIOUS_SERVICE_PERSISTENCE",
            ],
        )
    )


    results.append(
        run_case(
            detector,
            "R2-03",
            "WINLOGON_PERSISTENCE",
            "Standard Winlogon shell",
            make_event(
                r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
                "Shell",
                "explorer.exe",
                "registry_modify",
            ),
            expected_absent=[
                "WINLOGON_PERSISTENCE_CHANGE",
            ],
        )
    )


    results.append(
        run_case(
            detector,
            "R2-04",
            "WINLOGON_PERSISTENCE",
            "Nonstandard Winlogon shell",
            make_event(
                r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
                "Shell",
                r"explorer.exe, C:\Users\Public\helper.exe",
                "registry_modify",
            ),
            expected_present=[
                "WINLOGON_PERSISTENCE_CHANGE",
            ],
        )
    )


    # ============================================================
    # R3 — SECURITY TAMPERING
    # ============================================================

    results.append(
        run_case(
            detector,
            "R3-01",
            "SECURITY_TAMPERING",
            "Defender realtime monitoring disabled",
            make_event(
                r"HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Real-Time Protection",
                "DisableRealtimeMonitoring",
                "1",
                "registry_modify",
            ),
            expected_present=[
                "SECURITY_DEFENDER_TAMPERING",
            ],
        )
    )


    results.append(
        run_case(
            detector,
            "R3-02",
            "SECURITY_TAMPERING",
            "Incomplete registry event",
            {
                "event_type":
                    "registry_modify",

                "registry_path":
                    None,

                "name":
                    None,

                "value":
                    None,
            },
            expected_absent=[
                "REGISTRY_AUTORUN_PERSISTENCE",
                "SUSPICIOUS_RUN_KEY_PERSISTENCE",
                "SERVICE_PERSISTENCE_CHANGE",
                "SUSPICIOUS_SERVICE_PERSISTENCE",
                "WINLOGON_PERSISTENCE_CHANGE",
                "SECURITY_DEFENDER_TAMPERING",
                "SECURITY_POLICY_TAMPERING",
            ],
        )
    )


    save_reports(
        results
    )

    print_matrix(
        results
    )


def save_reports(
    results,
):

    fields = [
        "scenario_id",
        "family",
        "scenario_name",
        "detections",
        "expected",
        "failure_layers",
        "passed",
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
        writer.writerows(
            results
        )


    with JSON_PATH.open(
        "w",
        encoding="utf-8",
    ) as handle:

        json.dump(
            {
                "suite":
                    "SENTINEL-X PHASE 4 REGISTRY VALIDATION",

                "passed":
                    sum(
                        1
                        for row
                        in results
                        if row[
                            "passed"
                        ]
                    ),

                "failed":
                    sum(
                        1
                        for row
                        in results
                        if not row[
                            "passed"
                        ]
                    ),

                "results":
                    results,
            },
            handle,
            indent=2,
        )


def print_matrix(
    results,
):

    print()
    print(
        "=" * 96
    )

    print(
        "SENTINEL-X PHASE 4 — REGISTRY VALIDATION"
    )

    print(
        "=" * 96
    )


    for row in results:

        state = (
            "PASS"
            if row[
                "passed"
            ]
            else "FAIL"
        )

        print(
            f"{row['scenario_id']:<7} "
            f"{state:<5} "
            f"{row['scenario_name']:<42} "
            f"Observed={row['detections'] or 'NONE'} "
            f"Expected={row['expected']}"
        )


    passed = sum(
        1
        for row
        in results
        if row[
            "passed"
        ]
    )


    print(
        "-" * 96
    )

    print(
        f"RESULT: {passed}/{len(results)} PASS"
    )

    print(
        f"CSV   : {CSV_PATH}"
    )

    print(
        f"JSON  : {JSON_PATH}"
    )

    print(
        "=" * 96
    )


if __name__ == "__main__":

    main()
