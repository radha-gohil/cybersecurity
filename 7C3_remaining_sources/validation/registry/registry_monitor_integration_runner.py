from __future__ import annotations

import csv
import json
from pathlib import Path

from endpoint.collectors.registry_monitor import (
    RegistryMonitor,
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
    / "registry_monitor_integration.csv"
)

JSON_PATH = (
    REPORT_DIR
    / "registry_monitor_integration.json"
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


def case(
    monitor,
    scenario_id,
    name,
    event,
    expected_present=None,
    expected_absent=None,
):

    findings = (
        monitor.analyze_registry_change(
            event
        )
    )

    observed = set(
        types(
            findings
        )
    )

    required = set(
        expected_present
        or []
    )

    forbidden = set(
        expected_absent
        or []
    )

    passed = (
        required.issubset(
            observed
        )
        and not (
            forbidden
            & observed
        )
    )


    return {
        "scenario_id":
            scenario_id,

        "scenario_name":
            name,

        "mode":
            monitor.registry_detection_mode,

        "detections":
            ",".join(
                sorted(
                    observed
                )
            ),

        "expected":
            ",".join(
                sorted(
                    required
                )
            )
            or "NO_ALERT",

        "failure_layers":
            ""
            if passed
            else "REGISTRY_MONITOR_INTEGRATION",

        "passed":
            passed,
    }


def main():

    monitor = (
        RegistryMonitor(
            polling_interval=10.0,
            registry_detection_mode="SHADOW",
        )
    )


    results = []


    # ------------------------------------------------------------
    # Coverage contract
    # ------------------------------------------------------------

    scope_ids = {
        scope[
            "id"
        ]
        for scope
        in monitor.registry_scopes
    }

    required_scopes = {
        "hkcu_run",
        "hkcu_runonce",
        "hklm_run",
        "hklm_runonce",
        "services",
        "winlogon",
        "defender_policy",
        "defender_realtime_policy",
        "lsa_policy",
        "uac_policy",
    }

    coverage_pass = (
        required_scopes.issubset(
            scope_ids
        )
    )

    results.append(
        {
            "scenario_id":
                "RI-01",

            "scenario_name":
                "Registry collector coverage contract",

            "mode":
                monitor.registry_detection_mode,

            "detections":
                ",".join(
                    sorted(
                        scope_ids
                    )
                ),

            "expected":
                "R1_R2_R3_SCOPES_PRESENT",

            "failure_layers":
                ""
                if coverage_pass
                else "REGISTRY_COLLECTION_COVERAGE",

            "passed":
                coverage_pass,
        }
    )


    # ------------------------------------------------------------
    # R1
    # ------------------------------------------------------------

    results.append(
        case(
            monitor,
            "RI-02",
            "Run key benign persistence signal",
            make_event(
                r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",
                "OneDrive",
                r"C:\Program Files\Microsoft OneDrive\OneDrive.exe",
                "registry_create",
            ),
            expected_present=[
                "REGISTRY_AUTORUN_PERSISTENCE",
            ],
        )
    )


    results.append(
        case(
            monitor,
            "RI-03",
            "Run key suspicious PowerShell persistence",
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


    # ------------------------------------------------------------
    # R2
    # ------------------------------------------------------------

    results.append(
        case(
            monitor,
            "RI-04",
            "Suspicious service persistence",
            make_event(
                r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UpdaterSvc",
                "ImagePath",
                r"cmd.exe /c C:\Users\Public\update.cmd",
            ),
            expected_present=[
                "SUSPICIOUS_SERVICE_PERSISTENCE",
            ],
        )
    )


    results.append(
        case(
            monitor,
            "RI-05",
            "Standard Winlogon shell remains quiet",
            make_event(
                r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
                "Shell",
                "explorer.exe",
            ),
            expected_absent=[
                "WINLOGON_PERSISTENCE_CHANGE",
            ],
        )
    )


    results.append(
        case(
            monitor,
            "RI-06",
            "Nonstandard Winlogon shell",
            make_event(
                r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
                "Shell",
                r"explorer.exe, C:\Users\Public\helper.exe",
            ),
            expected_present=[
                "WINLOGON_PERSISTENCE_CHANGE",
            ],
        )
    )


    # ------------------------------------------------------------
    # R3
    # ------------------------------------------------------------

    results.append(
        case(
            monitor,
            "RI-07",
            "Defender realtime protection disabled",
            make_event(
                r"HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Real-Time Protection",
                "DisableRealtimeMonitoring",
                "1",
            ),
            expected_present=[
                "SECURITY_DEFENDER_TAMPERING",
            ],
        )
    )


    results.append(
        case(
            monitor,
            "RI-08",
            "Unrelated registry value remains quiet",
            make_event(
                r"HKEY_CURRENT_USER\Software\ExampleApp",
                "Theme",
                "Dark",
            ),
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


    # ------------------------------------------------------------
    # Mode contract
    # ------------------------------------------------------------

    shadow_pass = (
        monitor.registry_detection_mode
        == "SHADOW"
    )

    results.append(
        {
            "scenario_id":
                "RI-09",

            "scenario_name":
                "Registry detector defaults to SHADOW",

            "mode":
                monitor.registry_detection_mode,

            "detections":
                "",

            "expected":
                "SHADOW",

            "failure_layers":
                ""
                if shadow_pass
                else "REGISTRY_MODE",

            "passed":
                shadow_pass,
        }
    )


    results.append(
        case(
            monitor,
            "RI-10",
            "Incomplete registry evidence fails quiet",
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


    save(
        results
    )

    print_matrix(
        results
    )


def save(
    results,
):

    fields = [
        "scenario_id",
        "scenario_name",
        "mode",
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
                    "SENTINEL-X REGISTRY MONITOR INTEGRATION",

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
        "SENTINEL-X PHASE 4 — REGISTRY MONITOR INTEGRATION"
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
            f"{row['scenario_name']:<46} "
            f"Observed={row['detections'] or row['mode']}"
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
