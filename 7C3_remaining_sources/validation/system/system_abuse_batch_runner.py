from __future__ import annotations

import csv
import json
from pathlib import Path

from detection.system.system_abuse_detector import (
    SystemAbuseDetector,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
REPORT_DIR = PROJECT_ROOT / "validation" / "reports"
REPORT_DIR.mkdir(parents=True, exist_ok=True)

CSV_PATH = REPORT_DIR / "system_abuse_validation.csv"
JSON_PATH = REPORT_DIR / "system_abuse_validation.json"


def types(findings):
    return sorted(
        {
            finding.get("detection_type")
            for finding in findings
            if isinstance(finding, dict)
            and finding.get("detection_type")
        }
    )


def run_case(
    detector,
    scenario_id,
    scenario_name,
    event,
    expected_present=None,
    expected_absent=None,
):
    findings = detector.analyze(
        event
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

        "family":
            "SYSTEM_ABUSE",

        "scenario_name":
            scenario_name,

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
            else "SYSTEM_ABUSE_DETECTOR",

        "passed":
            passed,
    }


def main():
    detector = SystemAbuseDetector()
    results = []


    # S1-01 — incomplete/unknown
    results.append(
        run_case(
            detector,
            "S1-01",
            "Unknown system event remains quiet",
            {
                "windows_event_id": 9999,
            },
            expected_absent=[
                "SENSITIVE_PRIVILEGE_ASSIGNMENT",
                "LOCAL_ACCOUNT_CREATED",
                "PRIVILEGED_GROUP_MEMBERSHIP_CHANGE",
                "SCHEDULED_TASK_PERSISTENCE",
                "SUSPICIOUS_SCHEDULED_TASK_PERSISTENCE",
                "SECURITY_LOG_CLEARED",
                "AUDIT_POLICY_CHANGE",
            ],
        )
    )


    # S1-02 — SYSTEM 4672 is expected/noisy and should stay quiet
    results.append(
        run_case(
            detector,
            "S1-02",
            "SYSTEM special privileges remain quiet",
            {
                "windows_event_id": 4672,
                "username": "SYSTEM",
                "privilege_list": [
                    "SeDebugPrivilege",
                    "SeImpersonatePrivilege",
                ],
            },
            expected_absent=[
                "SENSITIVE_PRIVILEGE_ASSIGNMENT",
            ],
        )
    )


    # S1-03 — non-system sensitive privilege assignment
    results.append(
        run_case(
            detector,
            "S1-03",
            "User receives sensitive privileges",
            {
                "windows_event_id": 4672,
                "username": "operator1",
                "privilege_list": [
                    "SeDebugPrivilege",
                    "SeImpersonatePrivilege",
                ],
            },
            expected_present=[
                "SENSITIVE_PRIVILEGE_ASSIGNMENT",
            ],
        )
    )


    # S1-04 — account creation
    results.append(
        run_case(
            detector,
            "S1-04",
            "Local account creation",
            {
                "windows_event_id": 4720,
                "username": "administrator",
                "target_username": "new_local_user",
            },
            expected_present=[
                "LOCAL_ACCOUNT_CREATED",
            ],
        )
    )


    # S1-05 — ordinary group membership should not be privileged alert
    results.append(
        run_case(
            detector,
            "S1-05",
            "Ordinary Users group membership stays quiet",
            {
                "windows_event_id": 4732,
                "group_name": "Users",
                "member_name": "normal_user",
            },
            expected_absent=[
                "PRIVILEGED_GROUP_MEMBERSHIP_CHANGE",
            ],
        )
    )


    # S1-06 — administrators membership
    results.append(
        run_case(
            detector,
            "S1-06",
            "Account added to Administrators",
            {
                "windows_event_id": 4732,
                "group_name": "Administrators",
                "member_name": "operator1",
            },
            expected_present=[
                "PRIVILEGED_GROUP_MEMBERSHIP_CHANGE",
            ],
        )
    )


    # S1-07 — benign-looking scheduled task
    results.append(
        run_case(
            detector,
            "S1-07",
            "Scheduled task persistence signal",
            {
                "windows_event_id": 4698,
                "task_name": r"\Microsoft\Example\Maintenance",
                "task_command": r"C:\Program Files\Example\maintenance.exe",
            },
            expected_present=[
                "SCHEDULED_TASK_PERSISTENCE",
            ],
            expected_absent=[
                "SUSPICIOUS_SCHEDULED_TASK_PERSISTENCE",
            ],
        )
    )


    # S1-08 — suspicious scheduled task payload
    results.append(
        run_case(
            detector,
            "S1-08",
            "Suspicious PowerShell scheduled task",
            {
                "windows_event_id": 4698,
                "task_name": r"\Updater",
                "task_command": (
                    r"powershell.exe -WindowStyle Hidden "
                    r"-File C:\Users\Public\update.ps1"
                ),
            },
            expected_present=[
                "SUSPICIOUS_SCHEDULED_TASK_PERSISTENCE",
            ],
        )
    )


    # S1-09 — audit log clear
    results.append(
        run_case(
            detector,
            "S1-09",
            "Windows Security log cleared",
            {
                "windows_event_id": 1102,
                "username": "operator1",
            },
            expected_present=[
                "SECURITY_LOG_CLEARED",
            ],
        )
    )


    # S1-10 — audit policy change
    results.append(
        run_case(
            detector,
            "S1-10",
            "Windows audit policy changed",
            {
                "windows_event_id": 4719,
                "username": "operator1",
                "subcategory": "Process Creation",
                "change": "Success removed",
            },
            expected_present=[
                "AUDIT_POLICY_CHANGE",
            ],
        )
    )


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
                    "SENTINEL-X PHASE 5 S1 SYSTEM ABUSE VALIDATION",

                "passed":
                    sum(
                        1
                        for row
                        in results
                        if row["passed"]
                    ),

                "failed":
                    sum(
                        1
                        for row
                        in results
                        if not row["passed"]
                    ),

                "results":
                    results,
            },
            handle,
            indent=2,
        )


    print()
    print("=" * 100)
    print("SENTINEL-X PHASE 5 — S1 SYSTEM ABUSE VALIDATION")
    print("=" * 100)


    for row in results:

        state = (
            "PASS"
            if row["passed"]
            else "FAIL"
        )

        print(
            f"{row['scenario_id']:<7} "
            f"{state:<5} "
            f"{row['scenario_name']:<48} "
            f"Observed={row['detections'] or 'NONE'} "
            f"Expected={row['expected']}"
        )


    passed_count = sum(
        1
        for row
        in results
        if row["passed"]
    )

    print("-" * 100)
    print(
        f"RESULT: {passed_count}/{len(results)} PASS"
    )
    print(
        f"CSV   : {CSV_PATH}"
    )
    print(
        f"JSON  : {JSON_PATH}"
    )
    print("=" * 100)


if __name__ == "__main__":
    main()
