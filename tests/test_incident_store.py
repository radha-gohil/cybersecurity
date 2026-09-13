from detection.fusion.incident_store import (
    IncidentStore,
)


def main():

    store = IncidentStore()


    # ============================================================
    # SAFE SYNTHETIC INCIDENT
    # ============================================================

    incident = {

        "incident_id":
            "TEST-INCIDENT-001",

        "title":
            "Correlated FILE + NETWORK + PROCESS Activity",

        "status":
            "NEW",

        "correlation_score":
            80,

        "severity":
            "CRITICAL",

        "categories":
            [
                "FILE",
                "NETWORK",
                "PROCESS",
            ],

        "event_ids":
            [
                "proc-001",
                "file-001",
                "network-001",
            ],

        "event_count":
            3,

        "timeline":
            [
                {
                    "event_id":
                        "proc-001",

                    "event_type":
                        "process_start",

                    "timestamp_unix":
                        1000,
                },

                {
                    "event_id":
                        "file-001",

                    "event_type":
                        "file_modify",

                    "timestamp_unix":
                        1015,
                },

                {
                    "event_id":
                        "network-001",

                    "event_type":
                        "network_connect",

                    "timestamp_unix":
                        1030,
                },
            ],

        "source":
            "CorrelationManager",

        "requires_investigation":
            True,

        "created_at":
            "2026-09-11T10:00:00+00:00",

        "updated_at":
            "2026-09-11T10:01:00+00:00",
    }


    print()
    print("=" * 70)
    print(
        "SENTINEL-X INCIDENT STORAGE TEST"
    )
    print("=" * 70)


    # ============================================================
    # SAVE
    # ============================================================

    store.save_incident(
        incident
    )


    print()
    print(
        "Incident saved successfully."
    )


    # ============================================================
    # READ
    # ============================================================

    saved_incident = (
        store.get_incident(
            "TEST-INCIDENT-001"
        )
    )


    print()
    print(
        "Incident ID:",
        saved_incident[
            "incident_id"
        ],
    )

    print(
        "Title:",
        saved_incident[
            "title"
        ],
    )

    print(
        "Severity:",
        saved_incident[
            "severity"
        ],
    )

    print(
        "Correlation Score:",
        saved_incident[
            "correlation_score"
        ],
    )

    print(
        "Categories:",
        saved_incident[
            "categories"
        ],
    )

    print(
        "Event Count:",
        saved_incident[
            "event_count"
        ],
    )

    print(
        "Event IDs:",
        saved_incident[
            "event_ids"
        ],
    )

    print(
        "Requires Investigation:",
        saved_incident[
            "requires_investigation"
        ],
    )


    # ============================================================
    # UPDATE SAME INCIDENT
    # ============================================================

    incident[
        "correlation_score"
    ] = 90

    incident[
        "severity"
    ] = "CRITICAL"

    incident[
        "status"
    ] = "INVESTIGATING"

    incident[
        "updated_at"
    ] = "2026-09-11T10:05:00+00:00"


    store.save_incident(
        incident
    )


    updated_incident = (
        store.get_incident(
            "TEST-INCIDENT-001"
        )
    )


    print()
    print("-" * 70)
    print(
        "AFTER UPDATE"
    )
    print("-" * 70)


    print(
        "Status:",
        updated_incident[
            "status"
        ],
    )

    print(
        "Correlation Score:",
        updated_incident[
            "correlation_score"
        ],
    )

    print(
        "Severity:",
        updated_incident[
            "severity"
        ],
    )


    # ============================================================
    # COUNT
    # ============================================================

    print()
    print(
        "Total incidents in database:",
        store.count_incidents(),
    )


    print()
    print("=" * 70)
    print(
        "INCIDENT STORAGE TEST COMPLETE"
    )
    print("=" * 70)


if __name__ == "__main__":

    main()