from __future__ import annotations

import csv
import json
from pathlib import Path
from types import SimpleNamespace

from config import (
    IS_VALIDATION_MODE,
)

from endpoint.agent.telemetry_manager import (
    shared_telemetry_manager,
)

from endpoint.collectors.system_abuse_monitor import (
    SystemAbuseMonitor,
)

from endpoint.collectors.windows_system_collector import (
    WindowsSystemCollector,
)


# ================================================================
# PATHS
# ================================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

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
    / "system_abuse_integration_validation.csv"
)

JSON_PATH = (
    REPORT_DIR
    / "system_abuse_integration_validation.json"
)


# ================================================================
# STUB TELEMETRY
# ================================================================

class StubTelemetry:

    def __init__(self):

        self.calls = []


    def emit(
        self,
        **kwargs,
    ):

        self.calls.append(
            dict(kwargs)
        )

        return SimpleNamespace(
            event_id=(
                f"stub-system-{len(self.calls)}"
            )
        )


# ================================================================
# STATIC DETECTOR
# ================================================================

class StaticDetector:

    def __init__(
        self,
        findings,
    ):

        self.findings = findings


    def analyze(
        self,
        event,
    ):

        return [
            dict(finding)
            for finding
            in self.findings
        ]


# ================================================================
# COUNTING MONITOR
# ================================================================

class CountingSystemMonitor(
    SystemAbuseMonitor,
):

    def __init__(
        self,
        **kwargs,
    ):

        super().__init__(
            **kwargs
        )

        self.persistence_calls = 0


    def save_system_detections(
        self,
        event,
        detections,
    ):

        self.persistence_calls += 1

        return len(
            detections
        )


# ================================================================
# SAMPLE FINDING
# ================================================================

def finding():

    return {
        "engine":
            "system_abuse",

        "detection_type":
            "PRIVILEGED_GROUP_MEMBERSHIP_CHANGE",

        "severity":
            "HIGH",

        "risk_score":
            86,

        "confidence":
            0.90,

        "reason":
            "Synthetic integration finding.",
    }


# ================================================================
# RESULT HELPER
# ================================================================

def add(
    results,
    scenario_id,
    scenario_name,
    observed,
    expected,
    passed,
    failure="",
):

    results.append(
        {
            "scenario_id":
                scenario_id,

            "scenario_name":
                scenario_name,

            "observed":
                observed,

            "expected":
                expected,

            "failure_layers":
                failure,

            "passed":
                bool(passed),
        }
    )


# ================================================================
# SYNTHETIC WINDOWS EVENT XML
# ================================================================

def xml_event(
    event_id,
    record_id,
    fields,
):

    data = "".join(
        (
            f'<Data Name="{name}">'
            f'{value}'
            f'</Data>'
        )
        for name, value
        in fields.items()
    )

    return (
        '<Event xmlns="http://schemas.microsoft.com/'
        'win/2004/08/events/event">'

        '<System>'

        f'<EventID>{event_id}</EventID>'

        f'<EventRecordID>'
        f'{record_id}'
        f'</EventRecordID>'

        '<TimeCreated '
        'SystemTime="2026-10-06T12:00:00.0000000Z" />'

        '</System>'

        '<EventData>'

        f'{data}'

        '</EventData>'

        '</Event>'
    )


# ================================================================
# MAIN
# ================================================================

def main():

    results = []


    # ============================================================
    # SI-01
    # SHARED TELEMETRY MANAGER
    # ============================================================

    monitor = (
        SystemAbuseMonitor()
    )


    passed = (
        monitor.telemetry
        is shared_telemetry_manager
    )


    add(
        results,

        "SI-01",

        (
            "SystemAbuseMonitor uses "
            "shared telemetry manager"
        ),

        str(passed),

        "True",

        passed,

        (
            ""
            if passed
            else "SYSTEM_TELEMETRY_MANAGER"
        ),
    )


    # ============================================================
    # SI-02
    # DEFAULT SHADOW MODE
    # ============================================================

    passed = (
        monitor.system_detection_mode
        == "SHADOW"
    )


    add(
        results,

        "SI-02",

        (
            "SystemAbuseMonitor "
            "defaults to SHADOW"
        ),

        monitor.system_detection_mode,

        "SHADOW",

        passed,

        (
            ""
            if passed
            else "SYSTEM_MODE"
        ),
    )


    # ============================================================
    # SI-03
    # SHADOW MUST NOT PERSIST
    # ============================================================

    telemetry = (
        StubTelemetry()
    )


    shadow = (
        CountingSystemMonitor(
            system_detection_mode=
                "SHADOW",

            telemetry_manager=
                telemetry,

            behavior_detector=
                StaticDetector(
                    [
                        finding()
                    ]
                ),
        )
    )


    result = (
        shadow.process_system_event(
            {
                "windows_event_id":
                    4732,

                "username":
                    "administrator",

                "group_name":
                    "Administrators",

                "member_name":
                    "operator1",
            }
        )
    )


    emitted = (
        telemetry.calls[
            0
        ]
    )


    passed = (
        emitted.get(
            "event_type"
        )
        == "security_group_membership_change"

        and

        emitted.get(
            "severity"
        )
        == "INFO"

        and

        result.get(
            "stored_detection_count"
        )
        == 0

        and

        shadow.persistence_calls
        == 0

        and

        len(
            result.get(
                "detections"
            )
            or []
        )
        == 1
    )


    add(
        results,

        "SI-03",

        (
            "SHADOW returns system finding "
            "without persistence"
        ),

        (
            f"type={emitted.get('event_type')};"
            f"severity={emitted.get('severity')};"
            f"stored={result.get('stored_detection_count')};"
            f"findings="
            f"{len(result.get('detections') or [])}"
        ),

        (
            "group-change/INFO/"
            "stored0/findings1"
        ),

        passed,

        (
            ""
            if passed
            else "SYSTEM_SHADOW_ISOLATION"
        ),
    )


    # ============================================================
    # SI-04
    # VALIDATION MUST BLOCK EMIT
    # ============================================================

    requested = (
        SystemAbuseMonitor(
            system_detection_mode=
                "EMIT",

            telemetry_manager=
                StubTelemetry(),

            behavior_detector=
                StaticDetector(
                    []
                ),
        )
    )


    expected_mode = (
        "SHADOW"
        if IS_VALIDATION_MODE
        else "EMIT"
    )


    passed = (
        requested.system_detection_mode
        == expected_mode
    )


    add(
        results,

        "SI-04",

        (
            "Runtime mode enforces safe "
            "system detection mode"
        ),

        requested.system_detection_mode,

        expected_mode,

        passed,

        (
            ""
            if passed
            else "SYSTEM_VALIDATION_ISOLATION"
        ),
    )


    # ============================================================
    # SI-05
    # WINDOWS EVENT ID COVERAGE
    # ============================================================

    collector = (
        WindowsSystemCollector()
    )


    expected_ids = {
        4672,
        4720,
        4728,
        4732,
        4698,
        1102,
        4719,
    }


    passed = (
        set(
            collector.SYSTEM_EVENT_IDS
        )
        == expected_ids
    )


    add(
        results,

        "SI-05",

        (
            "Windows system collector "
            "covers all S1 event IDs"
        ),

        ",".join(
            str(value)
            for value
            in sorted(
                collector.SYSTEM_EVENT_IDS
            )
        ),

        ",".join(
            str(value)
            for value
            in sorted(
                expected_ids
            )
        ),

        passed,

        (
            ""
            if passed
            else "SYSTEM_EVENT_COVERAGE"
        ),
    )


    # ============================================================
    # SI-06
    # EVENT 4672
    # ============================================================

    parsed = (
        collector.parse_event_xml(
            xml_event(
                4672,

                6101,

                {
                    "SubjectUserName":
                        "operator1",

                    "PrivilegeList":
                        (
                            "SeDebugPrivilege "
                            "SeImpersonatePrivilege"
                        ),
                },
            )
        )
    )


    passed = (
        parsed.get(
            "windows_event_id"
        )
        == 4672

        and

        parsed.get(
            "username"
        )
        == "operator1"

        and

        "SeDebugPrivilege"
        in parsed.get(
            "privilege_list",
            "",
        )
    )


    add(
        results,

        "SI-06",

        (
            "Event 4672 parses "
            "privilege evidence"
        ),

        json.dumps(
            parsed,
            default=str,
        ),

        "4672/operator1/privileges",

        passed,

        (
            ""
            if passed
            else "SYSTEM_XML_PARSER"
        ),
    )


    # ============================================================
    # SI-07
    # EVENT 4720
    # ============================================================

    parsed = (
        collector.parse_event_xml(
            xml_event(
                4720,

                6201,

                {
                    "SubjectUserName":
                        "administrator",

                    "TargetUserName":
                        "new_local_user",
                },
            )
        )
    )


    passed = (
        parsed.get(
            "windows_event_id"
        )
        == 4720

        and

        parsed.get(
            "target_username"
        )
        == "new_local_user"
    )


    add(
        results,

        "SI-07",

        (
            "Event 4720 parses "
            "created account"
        ),

        json.dumps(
            parsed,
            default=str,
        ),

        "4720/new_local_user",

        passed,

        (
            ""
            if passed
            else "SYSTEM_XML_PARSER"
        ),
    )


    # ============================================================
    # SI-08
    # EVENT 4732
    # ============================================================

    parsed = (
        collector.parse_event_xml(
            xml_event(
                4732,

                6301,

                {
                    "SubjectUserName":
                        "administrator",

                    "TargetUserName":
                        "Administrators",

                    "MemberName":
                        "operator1",
                },
            )
        )
    )


    passed = (
        parsed.get(
            "group_name"
        )
        == "Administrators"

        and

        parsed.get(
            "member_name"
        )
        == "operator1"
    )


    add(
        results,

        "SI-08",

        (
            "Event 4732 parses "
            "privileged group membership"
        ),

        json.dumps(
            parsed,
            default=str,
        ),

        "Administrators/operator1",

        passed,

        (
            ""
            if passed
            else "SYSTEM_XML_PARSER"
        ),
    )


    # ============================================================
    # SI-09
    # EVENT 4698
    #
    # FIX:
    # Use ONE literal Windows task-root backslash.
    # ============================================================

    parsed = (
        collector.parse_event_xml(
            xml_event(
                4698,

                6401,

                {
                    "SubjectUserName":
                        "operator1",

                    "TaskName":
                        r"\Updater",

                    "TaskContent":
                        (
                            r"powershell.exe "
                            r"-WindowStyle Hidden "
                            r"-File "
                            r"C:\Users\Public\update.ps1"
                        ),
                },
            )
        )
    )


    passed = (
        parsed.get(
            "task_name"
        )
        == r"\Updater"

        and

        "powershell.exe"
        in parsed.get(
            "task_command",
            "",
        )
    )


    add(
        results,

        "SI-09",

        (
            "Event 4698 parses "
            "scheduled-task evidence"
        ),

        json.dumps(
            parsed,
            default=str,
        ),

        (
            r"\Updater + task command"
        ),

        passed,

        (
            ""
            if passed
            else "SYSTEM_XML_PARSER"
        ),
    )


    # ============================================================
    # SI-10
    # EVENT 1102 + 4719
    # ============================================================

    cleared = (
        collector.parse_event_xml(
            xml_event(
                1102,

                6501,

                {
                    "SubjectUserName":
                        "operator1",
                },
            )
        )
    )


    policy = (
        collector.parse_event_xml(
            xml_event(
                4719,

                6502,

                {
                    "SubjectUserName":
                        "operator1",

                    "SubcategoryGuid":
                        "{TEST-GUID}",

                    "AuditPolicyChanges":
                        "Success removed",
                },
            )
        )
    )


    passed = (
        cleared.get(
            "windows_event_id"
        )
        == 1102

        and

        policy.get(
            "windows_event_id"
        )
        == 4719

        and

        policy.get(
            "change"
        )
        == "Success removed"
    )


    add(
        results,

        "SI-10",

        (
            "Events 1102 and 4719 "
            "parse audit-tampering evidence"
        ),

        json.dumps(
            {
                "1102":
                    cleared,

                "4719":
                    policy,
            },
            default=str,
        ),

        "1102+4719",

        passed,

        (
            ""
            if passed
            else "SYSTEM_XML_PARSER"
        ),
    )


    # ============================================================
    # SAVE CSV
    # ============================================================

    fields = [
        "scenario_id",
        "scenario_name",
        "observed",
        "expected",
        "failure_layers",
        "passed",
    ]


    with CSV_PATH.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as handle:

        writer = (
            csv.DictWriter(
                handle,
                fieldnames=fields,
            )
        )

        writer.writeheader()

        writer.writerows(
            results
        )


    # ============================================================
    # SAVE JSON
    # ============================================================

    with JSON_PATH.open(
        "w",
        encoding="utf-8",
    ) as handle:

        json.dump(
            {
                "suite":
                    (
                        "SENTINEL-X S1 "
                        "SYSTEM ABUSE INTEGRATION"
                    ),

                "validation_runtime":
                    bool(
                        IS_VALIDATION_MODE
                    ),

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


    # ============================================================
    # PRINT MATRIX
    # ============================================================

    print()

    print(
        "=" * 100
    )

    print(
        (
            "SENTINEL-X PHASE 5 — "
            "S1 SYSTEM ABUSE INTEGRATION"
        )
    )

    print(
        "=" * 100
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
            f"{row['scenario_name']:<60} "
            f"Observed={row['observed']}"
        )


    passed_count = sum(
        1
        for row
        in results
        if row[
            "passed"
        ]
    )


    print(
        "-" * 100
    )


    print(
        f"RESULT: "
        f"{passed_count}/{len(results)} PASS"
    )


    print(
        f"CSV   : {CSV_PATH}"
    )


    print(
        f"JSON  : {JSON_PATH}"
    )


    print(
        "=" * 100
    )


# ================================================================
# ENTRY POINT
# ================================================================

if __name__ == "__main__":

    main()