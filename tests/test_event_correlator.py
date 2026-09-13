from detection.fusion.event_correlator import (
    EventCorrelator,
)


def main():

    correlator = EventCorrelator(
        correlation_window_seconds=120
    )


    print()
    print("=" * 70)
    print("SENTINEL-X EVENT CORRELATION TEST")
    print("=" * 70)


    # ============================================================
    # SYNTHETIC PROCESS EVENT
    # ============================================================

    process_event = {

        "event_id":
            "test-process-001",

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
                4321,

            "name":
                "demo.exe",
        },

        "file": {},

        "network": {},

        "registry": {},
    }


    result_1 = correlator.add_event(
        process_event
    )


    print()
    print("PROCESS EVENT")
    print(
        "Correlated:",
        result_1["correlated"],
    )

    print(
        "Score:",
        result_1["correlation_score"],
    )


    # ============================================================
    # SYNTHETIC FILE EVENT
    # ============================================================

    file_event = {

        "event_id":
            "test-file-001",

        "event_type":
            "file_modify",

        "source":
            "file_monitor",

        "severity":
            "HIGH",

        "timestamp_unix":
            1020,

        "process": {
            "pid":
                4321,
        },

        "file": {
            "path":
                r"C:\Temp\demo.exe",

            "sha256":
                "TEST_HASH_123",
        },

        "network": {},

        "registry": {},
    }


    result_2 = correlator.add_event(
        file_event
    )


    print()
    print("FILE EVENT")
    print(
        "Correlated:",
        result_2["correlated"],
    )

    print(
        "Score:",
        result_2["correlation_score"],
    )

    print(
        "Related Events:",
        result_2["related_event_count"],
    )


    # ============================================================
    # SYNTHETIC NETWORK EVENT
    # ============================================================

    network_event = {

        "event_id":
            "test-network-001",

        "event_type":
            "network_connect",

        "source":
            "network_monitor",

        "severity":
            "MEDIUM",

        "timestamp_unix":
            1040,

        "process": {
            "pid":
                4321,
        },

        "file": {},

        "network": {
            "remote_ip":
                "203.0.113.50",
        },

        "registry": {},
    }


    result_3 = correlator.add_event(
        network_event
    )


    print()
    print("NETWORK EVENT")
    print(
        "Correlated:",
        result_3["correlated"],
    )

    print(
        "Score:",
        result_3["correlation_score"],
    )

    print(
        "Severity:",
        result_3["severity"],
    )

    print(
        "Related Events:",
        result_3["related_event_count"],
    )


    print()
    print("=" * 70)


if __name__ == "__main__":

    main()