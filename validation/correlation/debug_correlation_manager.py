from detection.fusion.correlation_manager import (
    CorrelationManager,
)


# ================================================================
# MEMORY STORE
# ================================================================

class MemoryIncidentStore:

    def __init__(self):
        self.saved = {}


    def save_incident(
        self,
        incident,
    ):

        incident_id = (
            incident.get(
                "incident_id"
            )
        )

        self.saved[
            incident_id
        ] = dict(
            incident
        )

        print(
            "\n[SAVE_INCIDENT]"
        )

        print(
            "Incident ID:",
            incident_id,
        )

        print(
            "Score:",
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
            "Event count:",
            incident.get(
                "event_count"
            ),
        )


# ================================================================
# EVENT
# ================================================================

def make_event(
    event_id,
    event_type,
    timestamp,
    severity="HIGH",
    process=None,
    file=None,
    network=None,
    registry=None,
):

    return {
        "event_id":
            event_id,

        "event_type":
            event_type,

        "timestamp_unix":
            float(
                timestamp
            ),

        "timestamp":
            str(
                timestamp
            ),

        "source":
            "correlation_debug",

        "severity":
            severity,

        "device_id":
            "debug-device",

        "process":
            process
            or {},

        "file":
            file
            or {},

        "network":
            network
            or {},

        "registry":
            registry
            or {},

        "metadata": {
            "synthetic_validation":
                True,
        },
    }


# ================================================================
# MAIN
# ================================================================

def main():

    manager = (
        CorrelationManager(
            correlation_window_seconds=
                120,

            incident_threshold=
                35,
        )
    )


    manager.incident_store = (
        MemoryIncidentStore()
    )


    pid = 42420

    path = (
        r"C:\Temp\sentinel_chain.exe"
    )


    events = [

        # --------------------------------------------------------
        # PROCESS
        # --------------------------------------------------------

        make_event(
            "debug-process",

            "process_start",

            8000,

            severity=
                "HIGH",

            process={
                "pid":
                    pid,

                "name":
                    "sentinel_chain.exe",

                "exe":
                    path,
            },
        ),


        # --------------------------------------------------------
        # FILE
        # --------------------------------------------------------

        make_event(
            "debug-file",

            "file_modify",

            8010,

            severity=
                "HIGH",

            process={
                "pid":
                    pid,

                "name":
                    "sentinel_chain.exe",

                "exe":
                    path,
            },

            file={
                "name":
                    "sentinel_chain.exe",

                "path":
                    path,

                "sha256":
                    "DEBUG_SHA256",
            },
        ),


        # --------------------------------------------------------
        # NETWORK
        # --------------------------------------------------------

        make_event(
            "debug-network",

            "network_connect",

            8020,

            severity=
                "CRITICAL",

            network={
                "pid":
                    pid,

                "remote_ip":
                    "198.51.100.200",

                "remote_port":
                    443,
            },
        ),


        # --------------------------------------------------------
        # REGISTRY
        # --------------------------------------------------------

        make_event(
            "debug-registry",

            "registry_modify",

            8030,

            severity=
                "CRITICAL",

            registry={
                "pid":
                    pid,

                "key":
                    (
                        r"HKCU\Software\Microsoft"
                        r"\Windows\CurrentVersion\Run"
                    ),

                "value_name":
                    "SentinelUpdater",

                "value_data":
                    path,
            },
        ),
    ]


    print(
        "=" * 90
    )

    print(
        "CORRELATION MANAGER DEBUG"
    )

    print(
        "=" * 90
    )


    for number, item in enumerate(
        events,
        start=1,
    ):

        print()

        print(
            "-" * 90
        )

        print(
            f"EVENT {number}: "
            f"{item['event_type']}"
        )

        print(
            "-" * 90
        )


        result = (
            manager.process_event(
                item
            )
        )


        correlation = (
            result.get(
                "correlation"
            )
            or {}
        )


        incident = (
            result.get(
                "incident"
            )
        )


        print(
            "Correlation score:",
            correlation.get(
                "correlation_score"
            ),
        )

        print(
            "Correlated:",
            correlation.get(
                "correlated"
            ),
        )

        print(
            "Related count:",
            correlation.get(
                "related_event_count"
            ),
        )

        print(
            "Severity:",
            correlation.get(
                "severity"
            ),
        )

        print(
            "Incident created:",
            result.get(
                "incident_created"
            ),
        )

        print(
            "Incident updated:",
            result.get(
                "incident_updated"
            ),
        )

        print(
            "Incident returned:",
            incident is not None,
        )


        if incident:

            print(
                "Incident ID:",
                incident.get(
                    "incident_id"
                ),
            )

            print(
                "Incident score:",
                incident.get(
                    "correlation_score"
                ),
            )

            print(
                "Incident categories:",
                incident.get(
                    "categories"
                ),
            )

            print(
                "Incident event count:",
                incident.get(
                    "event_count"
                ),
            )


        print(
            "Manager incident count:",
            len(
                manager.incidents
            ),
        )


    # ============================================================
    # FINAL INCIDENTS
    # ============================================================

    print()

    print(
        "=" * 90
    )

    print(
        "FINAL MANAGER INCIDENTS"
    )

    print(
        "=" * 90
    )


    print(
        "Total incidents:",
        len(
            manager.incidents
        ),
    )


    for incident_id, incident in (
        manager.incidents.items()
    ):

        print()

        print(
            "Incident ID:",
            incident_id,
        )

        print(
            "Score:",
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
            "Event IDs:",
            incident.get(
                "event_ids"
            ),
        )

        print(
            "Event count:",
            incident.get(
                "event_count"
            ),
        )


if __name__ == "__main__":

    main()