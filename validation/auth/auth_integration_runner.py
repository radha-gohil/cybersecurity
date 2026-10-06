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

from endpoint.collectors.auth_monitor import (
    AuthMonitor,
)

from endpoint.collectors.windows_auth_collector import (
    WindowsAuthCollector,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]

REPORT_DIR = PROJECT_ROOT / "validation" / "reports"
REPORT_DIR.mkdir(parents=True, exist_ok=True)

CSV_PATH = REPORT_DIR / "auth_integration_validation.csv"
JSON_PATH = REPORT_DIR / "auth_integration_validation.json"


class StubTelemetry:

    def __init__(self):
        self.calls = []

    def emit(
        self,
        **kwargs,
    ):
        self.calls.append(
            dict(
                kwargs
            )
        )

        return SimpleNamespace(
            event_id=
                f"stub-event-{len(self.calls)}",
            metadata=
                kwargs.get(
                    "metadata"
                )
                or {},
        )


class StaticDetector:

    def __init__(
        self,
        findings,
    ):
        self.findings = list(
            findings
        )

    def analyze(
        self,
        event,
        current_time=None,
    ):
        return [
            dict(
                item
            )
            for item
            in self.findings
        ]


class CountingAuthMonitor(
    AuthMonitor,
):

    def __init__(
        self,
        **kwargs,
    ):
        super().__init__(
            **kwargs
        )

        self.persistence_calls = 0

    def save_auth_detections(
        self,
        event,
        detections,
    ):
        self.persistence_calls += 1

        return len(
            detections
        )


class CountingProcessor:

    def __init__(self):
        self.calls = 0
        self.auth_detection_mode = "SHADOW"

    def process_auth_event(
        self,
        auth_event,
    ):
        self.calls += 1

        return {
            "processed":
                True,
        }


def add(
    results,
    scenario_id,
    scenario_name,
    observed,
    expected,
    passed,
    failure_layers="",
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
                failure_layers,

            "passed":
                bool(
                    passed
                ),
        }
    )


def sample_finding():
    return {
        "engine":
            "auth_behavior",

        "detection_type":
            "REPEATED_LOGIN_FAILURES",

        "severity":
            "MEDIUM",

        "risk_score":
            60,

        "confidence":
            0.5,

        "source_ip":
            "198.51.100.25",

        "username":
            "user1",

        "reason":
            "Synthetic integration finding.",
    }


def event(
    *,
    event_type="login_failure",
    result="failed",
):
    return {
        "event_type":
            event_type,

        "username":
            "user1",

        "source_ip":
            "198.51.100.25",

        "result":
            result,

        "synthetic_test":
            True,
    }


def xml_event(
    *,
    event_id,
    record_id,
    username,
    source_ip,
):
    return f"""<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System>
<EventID>{event_id}</EventID>
<EventRecordID>{record_id}</EventRecordID>
<TimeCreated SystemTime="2026-10-06T12:00:00.0000000Z" />
</System>
<EventData>
<Data Name="TargetUserName">{username}</Data>
<Data Name="TargetDomainName">TEST</Data>
<Data Name="IpAddress">{source_ip}</Data>
<Data Name="IpPort">51515</Data>
<Data Name="WorkstationName">TESTHOST</Data>
<Data Name="LogonType">3</Data>
<Data Name="ProcessName">C:\\Windows\\System32\\svchost.exe</Data>
<Data Name="Status">0xC000006D</Data>
<Data Name="SubStatus">0xC000006A</Data>
</EventData>
</Event>"""


def main():

    results = []


    # ============================================================
    # AI-01 — SHARED TELEMETRY MANAGER
    # ============================================================

    monitor = (
        AuthMonitor()
    )

    passed = (
        monitor.telemetry
        is shared_telemetry_manager
    )

    add(
        results,
        "AI-01",
        "AuthMonitor uses shared runtime telemetry manager",
        str(
            passed
        ),
        "True",
        passed,
        ""
        if passed
        else "AUTH_TELEMETRY_MANAGER",
    )


    # ============================================================
    # AI-02 — DEFAULT SHADOW MODE
    # ============================================================

    passed = (
        monitor.auth_detection_mode
        == "SHADOW"
    )

    add(
        results,
        "AI-02",
        "AuthMonitor defaults to SHADOW",
        monitor.auth_detection_mode,
        "SHADOW",
        passed,
        ""
        if passed
        else "AUTH_MODE",
    )


    # ============================================================
    # AI-03 — SHADOW FINDING DOES NOT BECOME AUTHORITATIVE EVENT
    # ============================================================

    telemetry = (
        StubTelemetry()
    )

    shadow = (
        CountingAuthMonitor(
            auth_detection_mode="SHADOW",
            telemetry_manager=telemetry,
            behavior_detector=
                StaticDetector(
                    [
                        sample_finding()
                    ]
                ),
        )
    )

    result = (
        shadow.process_auth_event(
            event(),
            current_time=1000.0,
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
        == "security_auth_failure"
        and emitted.get(
            "severity"
        )
        == "INFO"
        and result.get(
            "stored_detection_count"
        )
        == 0
        and shadow.persistence_calls
        == 0
        and len(
            result.get(
                "detections"
            )
            or []
        )
        == 1
    )

    add(
        results,
        "AI-03",
        "SHADOW returns findings without authoritative persistence",
        (
            f"type={emitted.get('event_type')};"
            f"severity={emitted.get('severity')};"
            f"stored={result.get('stored_detection_count')};"
            f"findings={len(result.get('detections') or [])}"
        ),
        "failure/INFO/stored0/findings1",
        passed,
        ""
        if passed
        else "AUTH_SHADOW_ISOLATION",
    )


    # ============================================================
    # AI-04 — VALIDATION RUNTIME BLOCKS EMIT
    # ============================================================

    requested_emit = (
        AuthMonitor(
            auth_detection_mode="EMIT",
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
        requested_emit.auth_detection_mode
        == expected_mode
    )

    add(
        results,
        "AI-04",
        "Runtime mode enforces safe authentication detection mode",
        requested_emit.auth_detection_mode,
        expected_mode,
        passed,
        ""
        if passed
        else "AUTH_VALIDATION_ISOLATION",
    )


    # ============================================================
    # AI-05 — SUCCESS EVENT REMAINS SUCCESS
    # ============================================================

    telemetry = (
        StubTelemetry()
    )

    success_monitor = (
        CountingAuthMonitor(
            auth_detection_mode="SHADOW",
            telemetry_manager=telemetry,
            behavior_detector=
                StaticDetector(
                    []
                ),
        )
    )

    success_monitor.process_auth_event(
        event(
            event_type="login_success",
            result="success",
        ),
        current_time=2000.0,
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
        == "security_auth_success"
        and emitted.get(
            "severity"
        )
        == "INFO"
    )

    add(
        results,
        "AI-05",
        "Successful authentication keeps success telemetry type",
        (
            f"{emitted.get('event_type')}/"
            f"{emitted.get('severity')}"
        ),
        "security_auth_success/INFO",
        passed,
        ""
        if passed
        else "AUTH_EVENT_MAPPING",
    )


    # ============================================================
    # AI-06 — COLLECTOR DEFAULTS TO SHADOW
    # ============================================================

    collector = (
        WindowsAuthCollector()
    )

    observed_mode = getattr(
        collector.auth_monitor,
        "auth_detection_mode",
        None,
    )

    passed = (
        observed_mode
        == "SHADOW"
    )

    add(
        results,
        "AI-06",
        "WindowsAuthCollector defaults to SHADOW",
        str(
            observed_mode
        ),
        "SHADOW",
        passed,
        ""
        if passed
        else "AUTH_COLLECTOR_MODE",
    )


    # ============================================================
    # AI-07 — 4625 PARSING
    # ============================================================

    parsed = (
        collector.parse_event_xml(
            xml_event(
                event_id=4625,
                record_id=7001,
                username="target_user",
                source_ip="198.51.100.77",
            )
        )
    )

    passed = (
        isinstance(
            parsed,
            dict,
        )
        and parsed.get(
            "event_type"
        )
        == "login_failure"
        and parsed.get(
            "result"
        )
        == "failed"
        and parsed.get(
            "record_id"
        )
        == 7001
        and parsed.get(
            "username"
        )
        == "target_user"
        and parsed.get(
            "source_ip"
        )
        == "198.51.100.77"
        and parsed.get(
            "synthetic_test"
        )
        is False
    )

    add(
        results,
        "AI-07",
        "Windows Event 4625 parses to normalized failure",
        json.dumps(
            parsed,
            default=str,
        ),
        "normalized login_failure",
        passed,
        ""
        if passed
        else "AUTH_XML_PARSER",
    )


    # ============================================================
    # AI-08 — 4624 PARSING
    # ============================================================

    parsed = (
        collector.parse_event_xml(
            xml_event(
                event_id=4624,
                record_id=8001,
                username="normal_user",
                source_ip="127.0.0.1",
            )
        )
    )

    passed = (
        isinstance(
            parsed,
            dict,
        )
        and parsed.get(
            "event_type"
        )
        == "login_success"
        and parsed.get(
            "result"
        )
        == "success"
        and parsed.get(
            "source_ip"
        )
        == "local"
    )

    add(
        results,
        "AI-08",
        "Windows Event 4624 parses to normalized success",
        json.dumps(
            parsed,
            default=str,
        ),
        "normalized login_success",
        passed,
        ""
        if passed
        else "AUTH_XML_PARSER",
    )


    # ============================================================
    # AI-09 — EVENT RECORD DEDUP
    # ============================================================

    processor = (
        CountingProcessor()
    )

    collector = (
        WindowsAuthCollector(
            auth_monitor=
                processor
        )
    )

    normalized = {
        "event_type":
            "login_failure",

        "record_id":
            9001,

        "username":
            "duplicate_user",

        "source_ip":
            "198.51.100.90",

        "result":
            "failed",
    }

    first = (
        collector.process_normalized_event(
            dict(
                normalized
            )
        )
    )

    second = (
        collector.process_normalized_event(
            dict(
                normalized
            )
        )
    )

    passed = (
        first is not None
        and second is None
        and processor.calls == 1
    )

    add(
        results,
        "AI-09",
        "Windows EventRecordID is idempotent",
        f"calls={processor.calls}",
        "calls=1",
        passed,
        ""
        if passed
        else "AUTH_EVENT_DEDUP",
    )


    # ============================================================
    # AI-10 — MISSING USERNAME FAILS QUIET
    # ============================================================

    processor = (
        CountingProcessor()
    )

    collector = (
        WindowsAuthCollector(
            auth_monitor=
                processor
        )
    )

    result = (
        collector.process_normalized_event(
            {
                "event_type":
                    "login_failure",

                "record_id":
                    10001,

                "username":
                    "",

                "source_ip":
                    "198.51.100.100",

                "result":
                    "failed",
            }
        )
    )

    passed = (
        result is None
        and processor.calls == 0
        and 10001 not in collector.processed_record_ids
    )

    add(
        results,
        "AI-10",
        "Missing username is ignored without consuming EventRecordID",
        (
            f"result={result};"
            f"calls={processor.calls};"
            f"record_consumed={10001 in collector.processed_record_ids}"
        ),
        "ignored/calls0/not-consumed",
        passed,
        ""
        if passed
        else "AUTH_MISSING_DATA",
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
                    "SENTINEL-X PHASE 5 AUTH INTEGRATION VALIDATION",

                "validation_runtime":
                    bool(
                        IS_VALIDATION_MODE
                    ),

                "passed":
                    sum(
                        1
                        for row in results
                        if row[
                            "passed"
                        ]
                    ),

                "failed":
                    sum(
                        1
                        for row in results
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
        "=" * 100
    )

    print(
        "SENTINEL-X PHASE 5 — AUTH COLLECTOR / ISOLATION INTEGRATION"
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
            f"{row['scenario_name']:<62} "
            f"Observed={row['observed']}"
        )


    passed = sum(
        1
        for row in results
        if row[
            "passed"
        ]
    )


    print(
        "-" * 100
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
        "=" * 100
    )


if __name__ == "__main__":

    main()
