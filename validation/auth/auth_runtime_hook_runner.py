from __future__ import annotations

import csv
import json
from pathlib import Path

from endpoint.collectors.windows_auth_collector import (
    WindowsAuthCollector,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
REPORT_DIR = PROJECT_ROOT / "validation" / "reports"
REPORT_DIR.mkdir(parents=True, exist_ok=True)

CSV_PATH = REPORT_DIR / "auth_runtime_hook_validation.csv"
JSON_PATH = REPORT_DIR / "auth_runtime_hook_validation.json"


def add(results, scenario_id, scenario_name, observed, expected, passed, failure=""):
    results.append(
        {
            "scenario_id": scenario_id,
            "scenario_name": scenario_name,
            "observed": observed,
            "expected": expected,
            "failure_layers": failure,
            "passed": bool(passed),
        }
    )


def main():
    results = []

    agent_path = PROJECT_ROOT / "endpoint" / "agent" / "sentinel_agent.py"
    api_path = PROJECT_ROOT / "api" / "main.py"

    agent_text = agent_path.read_text(encoding="utf-8")
    api_text = api_path.read_text(encoding="utf-8")

    passed = (
        "WindowsAuthCollector" in agent_text
        and "windows_auth_collector" in agent_text
    )
    add(
        results,
        "AH-01",
        "SentinelAgent imports WindowsAuthCollector",
        str(passed),
        "True",
        passed,
        "" if passed else "AGENT_IMPORT",
    )

    passed = (
        "self.auth_monitor" in agent_text
        and 'auth_detection_mode="SHADOW"' in agent_text
    )
    add(
        results,
        "AH-02",
        "SentinelAgent constructs auth collector in SHADOW",
        str(passed),
        "True",
        passed,
        "" if passed else "AGENT_AUTH_CONSTRUCTION",
    )

    start = agent_text.find("self.collectors = {")
    end = agent_text.find(
        "# ========================================================\n        # THREAD STORAGE",
        start,
    )
    collector_block = agent_text[start:end]

    passed = (
        '"auth"' in collector_block
        and "self.auth_monitor" in collector_block
    )
    add(
        results,
        "AH-03",
        "Authentication collector is registered in generic collector lifecycle",
        str(passed),
        "True",
        passed,
        "" if passed else "AGENT_COLLECTOR_REGISTRY",
    )

    collector = WindowsAuthCollector()
    mode = getattr(
        collector.auth_monitor,
        "auth_detection_mode",
        None,
    )

    passed = mode == "SHADOW"
    add(
        results,
        "AH-04",
        "Runtime WindowsAuthCollector remains SHADOW",
        str(mode),
        "SHADOW",
        passed,
        "" if passed else "AUTH_RUNTIME_MODE",
    )

    backend_available = bool(
        collector.is_backend_available()
    )
    add(
        results,
        "AH-05",
        "Windows Event Log backend dependency is available",
        str(backend_available),
        "True",
        backend_available,
        "" if backend_available else "PYWIN32_DEPENDENCY",
    )

    passed = '"auth": False' in api_text
    add(
        results,
        "AH-06",
        "/telemetry/live exposes auth collector",
        str(passed),
        "True",
        passed,
        "" if passed else "API_LIVE_COLLECTOR_MAP",
    )

    passed = (
        "healthy_count == len(collectors)" in api_text
        and '"expected_collector_count": len(collectors)' in api_text
    )
    add(
        results,
        "AH-07",
        "Live collector health count includes all registered collector types",
        str(passed),
        "True",
        passed,
        "" if passed else "API_COLLECTOR_HEALTH",
    )

    overview_idx = api_text.find(
        "collector_states = {"
    )
    overview_text = (
        api_text[overview_idx:overview_idx + 700]
        if overview_idx >= 0
        else ""
    )

    passed = '"auth": "OFFLINE"' in overview_text
    add(
        results,
        "AH-08",
        "/endpoint/overview exposes auth collector state",
        str(passed),
        "True",
        passed,
        "" if passed else "API_ENDPOINT_OVERVIEW",
    )

    collector_source = (
        PROJECT_ROOT
        / "endpoint"
        / "collectors"
        / "windows_auth_collector.py"
    ).read_text(encoding="utf-8")

    passed = (
        "SECURITY_LOG_NAME" in collector_source
        and "EventID=4624 or EventID=4625" in collector_source
        and "EvtQuery" in collector_source
        and "EvtRender" in collector_source
    )
    add(
        results,
        "AH-09",
        "Authentication collector uses read-only Security Event Log query path",
        str(passed),
        "True",
        passed,
        "" if passed else "AUTH_READ_ONLY_CONTRACT",
    )

    xml = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System>
<EventID>4625</EventID>
<EventRecordID>12345</EventRecordID>
<TimeCreated SystemTime="2026-10-06T12:00:00.0000000Z" />
</System>
<EventData>
<Data Name="TargetUserName">test_user</Data>
<Data Name="TargetDomainName">TEST</Data>
<Data Name="IpAddress">198.51.100.125</Data>
<Data Name="IpPort">51515</Data>
<Data Name="WorkstationName">TESTHOST</Data>
<Data Name="LogonType">3</Data>
<Data Name="ProcessName">C:\\Windows\\System32\\svchost.exe</Data>
<Data Name="Status">0xC000006D</Data>
<Data Name="SubStatus">0xC000006A</Data>
</EventData>
</Event>"""

    parsed = collector.parse_event_xml(xml)

    passed = (
        isinstance(parsed, dict)
        and parsed.get("event_type") == "login_failure"
        and parsed.get("record_id") == 12345
        and parsed.get("username") == "test_user"
    )
    add(
        results,
        "AH-10",
        "Auth parser remains functional after runtime hookup",
        json.dumps(parsed, default=str),
        "normalized 4625",
        passed,
        "" if passed else "AUTH_RUNTIME_PARSER",
    )

    fields = [
        "scenario_id",
        "scenario_name",
        "observed",
        "expected",
        "failure_layers",
        "passed",
    ]

    with CSV_PATH.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(results)

    with JSON_PATH.open("w", encoding="utf-8") as handle:
        json.dump(
            {
                "suite": "SENTINEL-X AUTH RUNTIME HOOK VALIDATION",
                "passed": sum(1 for row in results if row["passed"]),
                "failed": sum(1 for row in results if not row["passed"]),
                "results": results,
            },
            handle,
            indent=2,
        )

    print()
    print("=" * 100)
    print("SENTINEL-X PHASE 5 — AUTH RUNTIME HOOK")
    print("=" * 100)

    for row in results:
        state = "PASS" if row["passed"] else "FAIL"
        print(
            f"{row['scenario_id']:<7} "
            f"{state:<5} "
            f"{row['scenario_name']:<66} "
            f"Observed={row['observed']}"
        )

    passed_count = sum(1 for row in results if row["passed"])

    print("-" * 100)
    print(f"RESULT: {passed_count}/{len(results)} PASS")
    print(f"CSV   : {CSV_PATH}")
    print(f"JSON  : {JSON_PATH}")
    print("=" * 100)


if __name__ == "__main__":
    main()
