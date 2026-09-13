from detection.fusion.event_correlator import (
    EventCorrelator,
)


def show_result(
    name,
    result,
):

    print()
    print("-" * 70)
    print(name)
    print("-" * 70)

    print(
        "Correlated:",
        result.get(
            "correlated"
        ),
    )

    print(
        "Correlation Score:",
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

    correlator = EventCorrelator(
        correlation_window_seconds=120,
        entity_link_threshold=40,
    )


    print()
    print("=" * 70)
    print(
        "SENTINEL-X ENTITY CORRELATION INTEGRATION TEST"
    )
    print("=" * 70)


    # ============================================================
    # PROCESS
    # ============================================================

    process_event = {

        "event_id":
            "entity-process-001",

        "event_type":
            "process_start",

        "source":
            "process_monitor",

        "severity":
            "MEDIUM",

        "timestamp_unix":
            1000,

        "process": {

            "pid":
                7000,

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


    result = (
        correlator.add_event(
            process_event
        )
    )


    show_result(
        "PROCESS EVENT",
        result,
    )


    # ============================================================
    # FILE WITHOUT PID
    # ============================================================

    file_event = {

        "event_id":
            "entity-file-001",

        "event_type":
            "file_modify",

        "source":
            "file_monitor",

        "severity":
            "HIGH",

        "timestamp_unix":
            1010,

        "process": {},

        "file": {

            "name":
                "demo.exe",

            "path":
                r"C:\Temp\demo.exe",

            "sha256":
                "ENTITY_TEST_HASH",
        },

        "network": {},

        "registry": {},

        "metadata": {},
    }


    result = (
        correlator.add_event(
            file_event
        )
    )


    show_result(
        "FILE EVENT WITHOUT PID",
        result,
    )


    # ============================================================
    # NETWORK WITH SAME PROCESS PID
    # ============================================================

    network_event = {

        "event_id":
            "entity-network-001",

        "event_type":
            "network_connect",

        "source":
            "network_monitor",

        "severity":
            "HIGH",

        "timestamp_unix":
            1020,

        "process": {},

        "file": {},

        "network": {

            "pid":
                7000,

            "process_name":
                "demo.exe",

            "remote_ip":
                "203.0.113.70",

            "remote_port":
                443,
        },

        "registry": {},

        "metadata": {},
    }


    result = (
        correlator.add_event(
            network_event
        )
    )


    show_result(
        "NETWORK EVENT",
        result,
    )


    # ============================================================
    # REGISTRY WITHOUT PID
    # ============================================================

    registry_event = {

        "event_id":
            "entity-registry-001",

        "event_type":
            "registry_change",

        "source":
            "registry_monitor",

        "severity":
            "HIGH",

        "timestamp_unix":
            1030,

        "process": {},

        "file": {},

        "network": {},

        "registry": {

            "key":
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",

            "value_name":
                "DemoApp",

            "value_data":
                r"C:\Temp\demo.exe",
        },

        "metadata": {},
    }


    result = (
        correlator.add_event(
            registry_event
        )
    )


    show_result(
        "REGISTRY EVENT WITHOUT PID",
        result,
    )


    print()
    print("=" * 70)
    print(
        "ENTITY CORRELATION TEST COMPLETE"
    )
    print("=" * 70)


if __name__ == "__main__":

    main()