from detection.fusion.correlation_manager import (
    CorrelationManager,
)


def print_result(
    name,
    result,
):

    correlation = (
        result["correlation"]
    )

    print()
    print("-" * 70)
    print(name)
    print("-" * 70)

    print(
        "Correlation Score:",
        correlation.get(
            "correlation_score",
            0,
        ),
    )

    print(
        "Correlated:",
        correlation.get(
            "correlated",
            False,
        ),
    )

    print(
        "Related Events:",
        correlation.get(
            "related_event_count",
            0,
        ),
    )

    print(
        "Incident Created:",
        result.get(
            "incident_created",
            False,
        ),
    )

    print(
        "Incident Updated:",
        result.get(
            "incident_updated",
            False,
        ),
    )


    incident = (
        result.get(
            "incident"
        )
    )


    if incident:

        print()

        print(
            "Incident ID:",
            incident.get(
                "incident_id"
            ),
        )

        print(
            "Title:",
            incident.get(
                "title"
            ),
        )

        print(
            "Status:",
            incident.get(
                "status"
            ),
        )

        print(
            "Severity:",
            incident.get(
                "severity"
            ),
        )

        print(
            "Correlation Score:",
            incident.get(
                "correlation_score"
            ),
        )

        print(
            "Categories:",
            incident.get(
                "categories"
            ),
        )

        print(
            "Event Count:",
            incident.get(
                "event_count"
            ),
        )

        print(
            "Event IDs:",
            incident.get(
                "event_ids"
            ),
        )

        print(
            "Requires Investigation:",
            incident.get(
                "requires_investigation"
            ),
        )


def main():

    manager = (
        CorrelationManager(
            correlation_window_seconds=120,
            incident_threshold=35,
        )
    )


    print()
    print("=" * 70)
    print(
        "SENTINEL-X CORRELATION MANAGER + INCIDENT STORAGE TEST"
    )
    print("=" * 70)


    # ============================================================
    # 1. SYNTHETIC PROCESS EVENT
    # ============================================================

    process_event = {

        "event_id":
            "proc-001",

        "event_type":
            "process_start",

        "source":
            "process_monitor",

        "severity":
            "MEDIUM",

        "timestamp":
            "2026-09-11T10:00:00+00:00",

        "timestamp_unix":
            1000,

        "process": {

            "pid":
                5000,

            "name":
                "demo.exe",
        },

        "file":
            {},

        "network":
            {},

        "registry":
            {},

        "metadata":
            {},
    }


    result_process = (
        manager.process_event(
            process_event
        )
    )


    print_result(
        "PROCESS EVENT",
        result_process,
    )


    # ============================================================
    # 2. SYNTHETIC FILE EVENT
    # ============================================================

    file_event = {

        "event_id":
            "file-001",

        "event_type":
            "file_modify",

        "source":
            "file_monitor",

        "severity":
            "HIGH",

        "timestamp":
            "2026-09-11T10:00:15+00:00",

        "timestamp_unix":
            1015,

        "process": {

            "pid":
                5000,
        },

        "file": {

            "path":
                r"C:\Temp\demo.exe",

            "sha256":
                "TEST_HASH_5000",
        },

        "network":
            {},

        "registry":
            {},

        "metadata":
            {},
    }


    result_file = (
        manager.process_event(
            file_event
        )
    )


    print_result(
        "FILE EVENT",
        result_file,
    )


    # ============================================================
    # 3. SYNTHETIC NETWORK EVENT
    # ============================================================

    network_event = {

        "event_id":
            "network-001",

        "event_type":
            "network_connect",

        "source":
            "network_monitor",

        "severity":
            "HIGH",

        "timestamp":
            "2026-09-11T10:00:30+00:00",

        "timestamp_unix":
            1030,

        "process": {

            "pid":
                5000,
        },

        "file":
            {},

        "network": {

            "remote_ip":
                "203.0.113.55",

            "remote_port":
                443,
        },

        "registry":
            {},

        "metadata":
            {},
    }


    result_network = (
        manager.process_event(
            network_event
        )
    )


    print_result(
        "NETWORK EVENT",
        result_network,
    )


    # ============================================================
    # INCIDENTS CURRENTLY IN MEMORY
    # ============================================================

    print()
    print("=" * 70)
    print(
        "CURRENT IN-MEMORY INCIDENTS"
    )
    print("=" * 70)


    incidents = (
        manager.get_incidents()
    )


    print(
        "Total In-Memory Incidents:",
        len(
            incidents
        ),
    )


    for number, incident in enumerate(
        incidents,
        start=1,
    ):

        print()
        print(
            "-" * 70
        )

        print(
            f"INCIDENT {number}"
        )

        print(
            "-" * 70
        )

        print(
            "Incident ID:",
            incident.get(
                "incident_id"
            ),
        )

        print(
            "Title:",
            incident.get(
                "title"
            ),
        )

        print(
            "Status:",
            incident.get(
                "status"
            ),
        )

        print(
            "Correlation Score:",
            incident.get(
                "correlation_score"
            ),
        )

        print(
            "Severity:",
            incident.get(
                "severity"
            ),
        )

        print(
            "Categories:",
            incident.get(
                "categories"
            ),
        )

        print(
            "Event Count:",
            incident.get(
                "event_count"
            ),
        )

        print(
            "Event IDs:",
            incident.get(
                "event_ids"
            ),
        )

        print(
            "Requires Investigation:",
            incident.get(
                "requires_investigation"
            ),
        )

        print(
            "Created At:",
            incident.get(
                "created_at"
            ),
        )

        print(
            "Updated At:",
            incident.get(
                "updated_at"
            ),
        )


        # ========================================================
        # TIMELINE
        # ========================================================

        print()
        print(
            "Timeline:"
        )


        for timeline_event in (
            incident.get(
                "timeline",
                [],
            )
        ):

            print(
                "  ->",
                timeline_event.get(
                    "event_id"
                ),
                "|",
                timeline_event.get(
                    "event_type"
                ),
                "|",
                timeline_event.get(
                    "source"
                ),
                "|",
                timeline_event.get(
                    "severity"
                ),
            )


    # ============================================================
    # INCIDENTS PERSISTED IN SQLITE
    # ============================================================

    print()
    print("=" * 70)
    print(
        "PERSISTED INCIDENTS IN SQLITE"
    )
    print("=" * 70)


    persisted_incidents = (
        manager.get_persisted_incidents()
    )


    print(
        "Persisted Incident Count:",
        len(
            persisted_incidents
        ),
    )


    for number, incident in enumerate(
        persisted_incidents[:5],
        start=1,
    ):

        print()
        print(
            "-" * 70
        )

        print(
            f"PERSISTED INCIDENT {number}"
        )

        print(
            "-" * 70
        )

        print(
            "Incident ID:",
            incident.get(
                "incident_id"
            ),
        )

        print(
            "Title:",
            incident.get(
                "title"
            ),
        )

        print(
            "Status:",
            incident.get(
                "status"
            ),
        )

        print(
            "Correlation Score:",
            incident.get(
                "correlation_score"
            ),
        )

        print(
            "Severity:",
            incident.get(
                "severity"
            ),
        )

        print(
            "Categories:",
            incident.get(
                "categories"
            ),
        )

        print(
            "Event Count:",
            incident.get(
                "event_count"
            ),
        )

        print(
            "Event IDs:",
            incident.get(
                "event_ids"
            ),
        )

        print(
            "Requires Investigation:",
            incident.get(
                "requires_investigation"
            ),
        )

        print(
            "Created At:",
            incident.get(
                "created_at"
            ),
        )

        print(
            "Updated At:",
            incident.get(
                "updated_at"
            ),
        )


        print()
        print(
            "Persisted Timeline:"
        )


        for timeline_event in (
            incident.get(
                "timeline",
                [],
            )
        ):

            print(
                "  ->",
                timeline_event.get(
                    "event_id"
                ),
                "|",
                timeline_event.get(
                    "event_type"
                ),
                "|",
                timeline_event.get(
                    "source"
                ),
                "|",
                timeline_event.get(
                    "severity"
                ),
            )


    # ============================================================
    # FINAL VALIDATION
    # ============================================================

    print()
    print("=" * 70)
    print(
        "FINAL VALIDATION"
    )
    print("=" * 70)


    if len(
        incidents
    ) == 1:

        final_incident = (
            incidents[0]
        )


        print(
            "Incident merging:",
            "PASS",
        )


        if (
            final_incident.get(
                "event_count"
            )
            == 3
        ):

            print(
                "Event aggregation:",
                "PASS",
            )

        else:

            print(
                "Event aggregation:",
                "CHECK",
            )


        if (
            set(
                final_incident.get(
                    "categories",
                    [],
                )
            )
            == {
                "FILE",
                "NETWORK",
                "PROCESS",
            }
        ):

            print(
                "Category correlation:",
                "PASS",
            )

        else:

            print(
                "Category correlation:",
                "CHECK",
            )


        if (
            final_incident.get(
                "correlation_score",
                0,
            )
            >= 80
        ):

            print(
                "Risk escalation:",
                "PASS",
            )

        else:

            print(
                "Risk escalation:",
                "CHECK",
            )


    else:

        print(
            "Incident merging:",
            "CHECK",
        )


    # ============================================================
    # VERIFY CURRENT INCIDENT EXISTS IN DATABASE
    # ============================================================

    if incidents:

        current_incident_id = (
            incidents[0].get(
                "incident_id"
            )
        )


        persisted_current = (
            manager.incident_store.get_incident(
                current_incident_id
            )
        )


        if persisted_current:

            print(
                "SQLite persistence:",
                "PASS",
            )

            print(
                "Persisted Current Incident ID:",
                persisted_current.get(
                    "incident_id"
                ),
            )

        else:

            print(
                "SQLite persistence:",
                "CHECK",
            )


    print()
    print("=" * 70)
    print(
        "SENTINEL-X CORRELATION TEST COMPLETE"
    )
    print("=" * 70)


if __name__ == "__main__":

    main()