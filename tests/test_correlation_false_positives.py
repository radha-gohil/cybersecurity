from detection.fusion.event_correlator import (
    EventCorrelator,
)


def print_result(
    title,
    result,
):

    print()
    print("-" * 72)
    print(title)
    print("-" * 72)

    print(
        "Correlated:",
        result.get(
            "correlated"
        ),
    )

    print(
        "Score:",
        result.get(
            "correlation_score"
        ),
    )

    print(
        "Severity:",
        result.get(
            "severity"
        ),
    )

    print(
        "Related Events:",
        result.get(
            "related_event_count"
        ),
    )

    print(
        "Entity Links:",
        result.get(
            "entity_links"
        ),
    )


def main():

    print()
    print("=" * 72)
    print(
        "SENTINEL-X FALSE-POSITIVE CORRELATION TEST"
    )
    print("=" * 72)


    # ============================================================
    # TEST 1
    # Completely unrelated events close in time.
    #
    # EXPECTED:
    # No correlation.
    # ============================================================

    correlator = EventCorrelator(
        correlation_window_seconds=120,
        entity_link_threshold=40,
    )


    process_event = {

        "event_id":
            "fp-process-001",

        "event_type":
            "process_start",

        "source":
            "process_monitor",

        "severity":
            "INFO",

        "timestamp_unix":
            1000,

        "process": {

            "pid":
                1001,

            "name":
                "notepad.exe",

            "exe":
                r"C:\Windows\System32\notepad.exe",
        },

        "file": {},

        "network": {},

        "registry": {},

        "metadata": {},
    }


    file_event = {

        "event_id":
            "fp-file-001",

        "event_type":
            "file_modify",

        "source":
            "file_monitor",

        "severity":
            "LOW",

        "timestamp_unix":
            1005,

        "process": {},

        "file": {

            "name":
                "report.txt",

            "path":
                r"C:\Users\Test\Documents\report.txt",

            "sha256":
                "UNRELATED_HASH_001",
        },

        "network": {},

        "registry": {},

        "metadata": {},
    }


    correlator.add_event(
        process_event
    )


    result = (
        correlator.add_event(
            file_event
        )
    )


    print_result(
        "TEST 1 - UNRELATED PROCESS + FILE",
        result,
    )


    test1_pass = (
        result.get(
            "correlated"
        )
        is False
        and result.get(
            "related_event_count"
        )
        == 0
    )


    # ============================================================
    # TEST 2
    # Same filename but DIFFERENT executable path.
    #
    # Filename alone should NOT create a link.
    #
    # EXPECTED:
    # No correlation.
    # ============================================================

    correlator = EventCorrelator(
        correlation_window_seconds=120,
        entity_link_threshold=40,
    )


    process_event = {

        "event_id":
            "fp-process-002",

        "event_type":
            "process_start",

        "source":
            "process_monitor",

        "severity":
            "INFO",

        "timestamp_unix":
            2000,

        "process": {

            "pid":
                2002,

            "name":
                "setup.exe",

            "exe":
                r"C:\Program Files\VendorA\setup.exe",
        },

        "file": {},

        "network": {},

        "registry": {},

        "metadata": {},
    }


    file_event = {

        "event_id":
            "fp-file-002",

        "event_type":
            "file_create",

        "source":
            "file_monitor",

        "severity":
            "LOW",

        "timestamp_unix":
            2005,

        "process": {},

        "file": {

            "name":
                "setup.exe",

            "path":
                r"C:\Users\Test\Downloads\setup.exe",

            "sha256":
                "DIFFERENT_SETUP_HASH",
        },

        "network": {},

        "registry": {},

        "metadata": {},
    }


    correlator.add_event(
        process_event
    )


    result = (
        correlator.add_event(
            file_event
        )
    )


    print_result(
        "TEST 2 - SAME NAME, DIFFERENT PATH",
        result,
    )


    test2_pass = (
        result.get(
            "correlated"
        )
        is False
        and result.get(
            "related_event_count"
        )
        == 0
    )


    # ============================================================
    # TEST 3
    # Exact executable path should still correlate.
    #
    # EXPECTED:
    # Strong correlation.
    # ============================================================

    correlator = EventCorrelator(
        correlation_window_seconds=120,
        entity_link_threshold=40,
    )


    process_event = {

        "event_id":
            "fp-process-003",

        "event_type":
            "process_start",

        "source":
            "process_monitor",

        "severity":
            "MEDIUM",

        "timestamp_unix":
            3000,

        "process": {

            "pid":
                3003,

            "name":
                "demo.exe",

            "exe":
                r"C:\Temp\demo.exe",
        },

        "file": {},

        "network": {},

        "registry": {},

        "metadata": {},
    }


    file_event = {

        "event_id":
            "fp-file-003",

        "event_type":
            "file_modify",

        "source":
            "file_monitor",

        "severity":
            "HIGH",

        "timestamp_unix":
            3010,

        "process": {},

        "file": {

            "name":
                "demo.exe",

            "path":
                r"C:\Temp\demo.exe",

            "sha256":
                "EXACT_PATH_HASH",
        },

        "network": {},

        "registry": {},

        "metadata": {},
    }


    correlator.add_event(
        process_event
    )


    result = (
        correlator.add_event(
            file_event
        )
    )


    print_result(
        "TEST 3 - EXACT PROCESS/FILE PATH",
        result,
    )


    test3_pass = (
        result.get(
            "correlated"
        )
        is True
        and result.get(
            "related_event_count"
        )
        >= 1
    )


    # ============================================================
    # TEST 4
    # Same PID process/network relationship.
    #
    # EXPECTED:
    # Correlation.
    # ============================================================

    correlator = EventCorrelator(
        correlation_window_seconds=120,
        entity_link_threshold=40,
    )


    process_event = {

        "event_id":
            "fp-process-004",

        "event_type":
            "process_start",

        "source":
            "process_monitor",

        "severity":
            "MEDIUM",

        "timestamp_unix":
            4000,

        "process": {

            "pid":
                4004,

            "name":
                "browser.exe",

            "exe":
                r"C:\Program Files\Browser\browser.exe",
        },

        "file": {},

        "network": {},

        "registry": {},

        "metadata": {},
    }


    network_event = {

        "event_id":
            "fp-network-004",

        "event_type":
            "network_connect",

        "source":
            "network_monitor",

        "severity":
            "HIGH",

        "timestamp_unix":
            4010,

        "process": {},

        "file": {},

        "network": {

            "pid":
                4004,

            "process_name":
                "browser.exe",

            "remote_ip":
                "203.0.113.80",

            "remote_port":
                443,
        },

        "registry": {},

        "metadata": {},
    }


    correlator.add_event(
        process_event
    )


    result = (
        correlator.add_event(
            network_event
        )
    )


    print_result(
        "TEST 4 - PROCESS + NETWORK SAME PID",
        result,
    )


    test4_pass = (
        result.get(
            "correlated"
        )
        is True
        and result.get(
            "related_event_count"
        )
        >= 1
    )


    # ============================================================
    # TEST 5
    # Registry event references unrelated executable.
    #
    # EXPECTED:
    # No correlation.
    # ============================================================

    correlator = EventCorrelator(
        correlation_window_seconds=120,
        entity_link_threshold=40,
    )


    process_event = {

        "event_id":
            "fp-process-005",

        "event_type":
            "process_start",

        "source":
            "process_monitor",

        "severity":
            "INFO",

        "timestamp_unix":
            5000,

        "process": {

            "pid":
                5005,

            "name":
                "notepad.exe",

            "exe":
                r"C:\Windows\System32\notepad.exe",
        },

        "file": {},

        "network": {},

        "registry": {},

        "metadata": {},
    }


    registry_event = {

        "event_id":
            "fp-registry-005",

        "event_type":
            "registry_change",

        "source":
            "registry_monitor",

        "severity":
            "LOW",

        "timestamp_unix":
            5010,

        "process": {},

        "file": {},

        "network": {},

        "registry": {

            "key":
                r"HKCU\Software\Example",

            "value_name":
                "Example",

            "value_data":
                r"C:\Program Files\OtherApp\other.exe",
        },

        "metadata": {},
    }


    correlator.add_event(
        process_event
    )


    result = (
        correlator.add_event(
            registry_event
        )
    )


    print_result(
        "TEST 5 - UNRELATED REGISTRY EVENT",
        result,
    )


    test5_pass = (
        result.get(
            "correlated"
        )
        is False
        and result.get(
            "related_event_count"
        )
        == 0
    )


    # ============================================================
    # FINAL VALIDATION
    # ============================================================

    print()
    print("=" * 72)
    print(
        "FINAL FALSE-POSITIVE VALIDATION"
    )
    print("=" * 72)


    print(
        "Unrelated timing-only events:",
        "PASS"
        if test1_pass
        else "FAIL",
    )


    print(
        "Filename-only relationship:",
        "PASS"
        if test2_pass
        else "FAIL",
    )


    print(
        "Exact executable path:",
        "PASS"
        if test3_pass
        else "FAIL",
    )


    print(
        "Process/network PID:",
        "PASS"
        if test4_pass
        else "FAIL",
    )


    print(
        "Unrelated registry:",
        "PASS"
        if test5_pass
        else "FAIL",
    )


    all_passed = all(
        [
            test1_pass,
            test2_pass,
            test3_pass,
            test4_pass,
            test5_pass,
        ]
    )


    print()
    print(
        "OVERALL:",
        "PASS"
        if all_passed
        else "FAIL",
    )


    print("=" * 72)


if __name__ == "__main__":

    main()