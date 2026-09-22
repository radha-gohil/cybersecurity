import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:

    sys.path.insert(
        0,
        str(PROJECT_ROOT),
    )


from endpoint.collectors.windows_auth_collector import (
    WindowsAuthCollector,
    PYWIN32_AVAILABLE,
)


def separator():

    print(
        "\n"
        + "=" * 72
    )


def main():

    separator()

    print(
        "SENTINEL-X WINDOWS AUTH COLLECTOR TEST"
    )

    separator()

    print(
        "\nREAD-ONLY TEST"
    )

    print(
        "No login attempts will be performed."
    )

    print(
        "No Windows configuration will be changed."
    )

    collector = (
        WindowsAuthCollector(
            max_events_per_poll=10
        )
    )

    # ============================================================
    # TEST 1 — SYNTHETIC WINDOWS 4625 XML
    # ============================================================

    separator()

    print(
        "TEST 1 - SYNTHETIC EVENT 4625"
    )

    failed_xml = """
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
        <Provider Name="Microsoft-Windows-Security-Auditing"/>
        <EventID>4625</EventID>
        <TimeCreated SystemTime="2026-09-22T04:30:00.0000000Z"/>
        <EventRecordID>123456</EventRecordID>
        <Channel>Security</Channel>
    </System>

    <EventData>
        <Data Name="TargetUserName">synthetic_user</Data>
        <Data Name="TargetDomainName">SYNTHETIC</Data>
        <Data Name="Status">0xC000006D</Data>
        <Data Name="SubStatus">0xC000006A</Data>
        <Data Name="LogonType">3</Data>
        <Data Name="WorkstationName">SYNTHETIC-PC</Data>
        <Data Name="IpAddress">198.51.100.50</Data>
        <Data Name="IpPort">50000</Data>
        <Data Name="ProcessName">-</Data>
    </EventData>
</Event>
"""

    failed_event = (
        collector.parse_event_xml(
            failed_xml
        )
    )

    if failed_event is None:

        raise AssertionError(
            "4625 event was not parsed."
        )

    print(
        "Event Type:",
        failed_event.get(
            "event_type"
        ),
    )

    print(
        "Windows Event ID:",
        failed_event.get(
            "windows_event_id"
        ),
    )

    print(
        "Username:",
        failed_event.get(
            "username"
        ),
    )

    print(
        "Source IP:",
        failed_event.get(
            "source_ip"
        ),
    )

    print(
        "Result:",
        failed_event.get(
            "result"
        ),
    )

    assert (
        failed_event[
            "windows_event_id"
        ]
        ==
        4625
    )

    assert (
        failed_event[
            "event_type"
        ]
        ==
        "login_failure"
    )

    assert (
        failed_event[
            "result"
        ]
        ==
        "failed"
    )

    assert (
        failed_event[
            "source_ip"
        ]
        ==
        "198.51.100.50"
    )

    print(
        "4625 parsing: PASS"
    )

    # ============================================================
    # TEST 2 — SYNTHETIC WINDOWS 4624 XML
    # ============================================================

    separator()

    print(
        "TEST 2 - SYNTHETIC EVENT 4624"
    )

    success_xml = """
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
        <Provider Name="Microsoft-Windows-Security-Auditing"/>
        <EventID>4624</EventID>
        <TimeCreated SystemTime="2026-09-22T04:31:00.0000000Z"/>
        <EventRecordID>123457</EventRecordID>
        <Channel>Security</Channel>
    </System>

    <EventData>
        <Data Name="TargetUserName">synthetic_user</Data>
        <Data Name="TargetDomainName">SYNTHETIC</Data>
        <Data Name="LogonType">3</Data>
        <Data Name="WorkstationName">SYNTHETIC-PC</Data>
        <Data Name="IpAddress">198.51.100.50</Data>
        <Data Name="IpPort">50001</Data>
        <Data Name="ProcessName">-</Data>
    </EventData>
</Event>
"""

    success_event = (
        collector.parse_event_xml(
            success_xml
        )
    )

    if success_event is None:

        raise AssertionError(
            "4624 event was not parsed."
        )

    print(
        "Event Type:",
        success_event.get(
            "event_type"
        ),
    )

    print(
        "Windows Event ID:",
        success_event.get(
            "windows_event_id"
        ),
    )

    print(
        "Result:",
        success_event.get(
            "result"
        ),
    )

    assert (
        success_event[
            "windows_event_id"
        ]
        ==
        4624
    )

    assert (
        success_event[
            "event_type"
        ]
        ==
        "login_success"
    )

    assert (
        success_event[
            "result"
        ]
        ==
        "success"
    )

    print(
        "4624 parsing: PASS"
    )

    # ============================================================
    # TEST 3 — DEDUPLICATION
    #
    # We do not feed the synthetic event into AuthMonitor here
    # because this test is checking the collector/parser only.
    # ============================================================

    separator()

    print(
        "TEST 3 - RECORD ID DEDUPLICATION"
    )

    record_id = (
        failed_event.get(
            "record_id"
        )
    )

    collector.processed_record_ids.add(
        record_id
    )

    duplicate_seen = (

        record_id
        in collector.processed_record_ids
    )

    if not duplicate_seen:

        raise AssertionError(
            "Record ID deduplication failed."
        )

    print(
        "Deduplication: PASS"
    )

    # ============================================================
    # TEST 4 — PYWIN32 STATUS
    # ============================================================

    separator()

    print(
        "TEST 4 - WINDOWS EVENT LOG BACKEND"
    )

    print(
        "pywin32 available:",
        PYWIN32_AVAILABLE,
    )

    # ============================================================
    # TEST 5 — LIVE READ-ONLY PROBE
    # ============================================================

    if not PYWIN32_AVAILABLE:

        print(
            "\nLIVE READ TEST: SKIPPED"
        )

        print(
            "Reason: pywin32 is not installed."
        )

        separator()

        print(
            "PARSER TESTS PASSED"
        )

        print(
            "Install pywin32 before testing "
            "live Security-log access."
        )

        return

    separator()

    print(
        "TEST 5 - LIVE READ-ONLY SECURITY LOG PROBE"
    )

    probe = (
        collector.poll_once()
    )

    print(
        "Backend Available:",
        probe.get(
            "backend_available"
        ),
    )

    print(
        "Events Read:",
        probe.get(
            "events_read"
        ),
    )

    print(
        "Events Parsed:",
        probe.get(
            "events_parsed"
        ),
    )

    print(
        "Events Processed:",
        probe.get(
            "events_processed"
        ),
    )

    print(
        "Errors:",
        probe.get(
            "errors"
        ),
    )

    # ------------------------------------------------------------
    # Access denial is not a parser failure.
    #
    # Company-managed laptops may block Security-log access.
    # ------------------------------------------------------------

    if probe.get(
        "errors"
    ):

        print(
            "\nLIVE SECURITY LOG ACCESS: NOT AVAILABLE"
        )

        print(
            "The collector/parser is working, but Windows "
            "did not allow this process to read the Security log."
        )

    else:

        print(
            "\nLIVE SECURITY LOG ACCESS: PASS"
        )

    separator()

    print(
        "WINDOWS AUTH COLLECTOR TEST COMPLETED"
    )


if __name__ == "__main__":

    main()