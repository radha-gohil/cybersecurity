from __future__ import annotations

import inspect

from detection.fusion.event_correlator import (
    EventCorrelator,
)

from detection.fusion.correlation_manager import (
    CorrelationManager,
)


# ================================================================
# MEMORY INCIDENT STORE
# ================================================================

class MemoryIncidentStore:

    def __init__(self):
        self.saved = {}


    def save_incident(
        self,
        incident,
    ):
        incident_id = incident.get(
            "incident_id"
        )

        if incident_id:
            self.saved[
                incident_id
            ] = dict(
                incident
            )

        return incident


    def get_incident(
        self,
        incident_id,
    ):
        return self.saved.get(
            incident_id
        )


    def get_incidents(
        self,
    ):
        return list(
            self.saved.values()
        )


# ================================================================
# EVENT FACTORY
# ================================================================

def make_process_event():

    return {
        "event_id":
            "bridge-process",

        "event_type":
            "process_start",

        "timestamp_unix":
            1000.0,

        "timestamp":
            "1000",

        "source":
            "bridge_debug",

        "severity":
            "HIGH",

        "device_id":
            "debug-device",

        "process": {
            "pid":
                4242,

            "name":
                "payload.exe",

            "exe":
                r"C:\Temp\payload.exe",
        },

        "file":
            {},

        "network":
            {},

        "registry":
            {},

        "metadata": {
            "synthetic_validation":
                True,
        },
    }


def make_file_event():

    return {
        "event_id":
            "bridge-file",

        "event_type":
            "file_modify",

        "timestamp_unix":
            1010.0,

        "timestamp":
            "1010",

        "source":
            "bridge_debug",

        "severity":
            "HIGH",

        "device_id":
            "debug-device",

        "process": {
            "pid":
                4242,

            "name":
                "payload.exe",

            "exe":
                r"C:\Temp\payload.exe",
        },

        "file": {
            "name":
                "payload.exe",

            "path":
                r"C:\Temp\payload.exe",

            "sha256":
                "BRIDGE_DEBUG_SHA256",
        },

        "network":
            {},

        "registry":
            {},

        "metadata": {
            "synthetic_validation":
                True,
        },
    }


# ================================================================
# RESULT PRINTER
# ================================================================

def show_result(
    label,
    result,
):

    print()

    print(
        "-" * 90
    )

    print(
        label
    )

    print(
        "-" * 90
    )

    if not isinstance(
        result,
        dict,
    ):

        print(
            "Result:",
            result,
        )

        return


    print(
        "Score:",
        result.get(
            "correlation_score"
        ),
    )

    print(
        "Correlated:",
        result.get(
            "correlated"
        ),
    )

    print(
        "Related count:",
        result.get(
            "related_event_count"
        ),
    )

    print(
        "Current event:",
        (
            result.get(
                "current_event"
            )
            or {}
        ).get(
            "event_id"
        ),
    )

    print(
        "Related IDs:",
        [
            item.get(
                "event_id"
            )
            for item
            in (
                result.get(
                    "related_events"
                )
                or []
            )
        ],
    )


# ================================================================
# MAIN
# ================================================================

def main():

    process_event = (
        make_process_event()
    )

    file_event = (
        make_file_event()
    )


    print(
        "=" * 90
    )

    print(
        "CORRELATION MANAGER BRIDGE DEBUG"
    )

    print(
        "=" * 90
    )


    # ============================================================
    # MODULE PATHS
    # ============================================================

    print()

    print(
        "EventCorrelator loaded from:"
    )

    print(
        inspect.getsourcefile(
            EventCorrelator
        )
    )


    print()

    print(
        "CorrelationManager loaded from:"
    )

    print(
        inspect.getsourcefile(
            CorrelationManager
        )
    )


    # ============================================================
    # DIRECT EVENT CORRELATOR
    # ============================================================

    print()

    print(
        "=" * 90
    )

    print(
        "TEST 1 — DIRECT EventCorrelator"
    )

    print(
        "=" * 90
    )


    direct = (
        EventCorrelator(
            correlation_window_seconds=
                120
        )
    )


    first_direct = (
        direct.add_event(
            process_event
        )
    )


    second_direct = (
        direct.add_event(
            file_event
        )
    )


    show_result(
        "DIRECT PROCESS RESULT",
        first_direct,
    )


    show_result(
        "DIRECT FILE RESULT",
        second_direct,
    )


    print()

    print(
        "Direct stored events:",
        len(
            direct.events
        ),
    )

    print(
        "Direct PID indexes:",
        list(
            direct.events_by_pid.keys()
        ),
    )


    print(
        "Direct PID 4242 count:",
        len(
            direct.events_by_pid.get(
                4242,
                [],
            )
        ),
    )


    # ============================================================
    # CORRELATION MANAGER
    # ============================================================

    print()

    print(
        "=" * 90
    )

    print(
        "TEST 2 — CorrelationManager"
    )

    print(
        "=" * 90
    )


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


    print()

    print(
        "Internal correlator class:"
    )

    print(
        manager.correlator.__class__
    )


    print(
        "Internal correlator source:"
    )

    print(
        inspect.getsourcefile(
            manager.correlator.__class__
        )
    )


    # ============================================================
    # NORMALIZATION CHECK
    # ============================================================

    normalized_process = (
        manager.normalize_event_input(
            process_event
        )
    )


    normalized_file = (
        manager.normalize_event_input(
            file_event
        )
    )


    print()

    print(
        "NORMALIZED PROCESS:"
    )

    print(
        normalized_process
    )


    print()

    print(
        "NORMALIZED FILE:"
    )

    print(
        normalized_file
    )


    print()

    print(
        "Normalized process PID:",
        (
            normalized_process
            .get(
                "process",
                {},
            )
            .get(
                "pid"
            )
        ),
    )


    print(
        "Normalized file process PID:",
        (
            normalized_file
            .get(
                "process",
                {},
            )
            .get(
                "pid"
            )
        ),
    )


    print(
        "Normalized process exe:",
        (
            normalized_process
            .get(
                "process",
                {},
            )
            .get(
                "exe"
            )
        ),
    )


    print(
        "Normalized file path:",
        (
            normalized_file
            .get(
                "file",
                {},
            )
            .get(
                "path"
            )
        ),
    )


    # ============================================================
    # FIRST MANAGER EVENT
    # ============================================================

    manager_first = (
        manager.process_event(
            process_event
        )
    )


    show_result(
        "MANAGER PROCESS CORRELATION",
        (
            manager_first.get(
                "correlation"
            )
            or {}
        ),
    )


    print()

    print(
        "After process event:"
    )


    print(
        "Internal events:",
        len(
            manager.correlator.events
        ),
    )


    print(
        "PID indexes:",
        list(
            manager
            .correlator
            .events_by_pid
            .keys()
        ),
    )


    print(
        "PID 4242 count:",
        len(
            manager
            .correlator
            .events_by_pid
            .get(
                4242,
                [],
            )
        ),
    )


    # ============================================================
    # SECOND MANAGER EVENT
    # ============================================================

    manager_second = (
        manager.process_event(
            file_event
        )
    )


    show_result(
        "MANAGER FILE CORRELATION",
        (
            manager_second.get(
                "correlation"
            )
            or {}
        ),
    )


    print()

    print(
        "After file event:"
    )


    print(
        "Internal events:",
        len(
            manager.correlator.events
        ),
    )


    print(
        "PID indexes:",
        list(
            manager
            .correlator
            .events_by_pid
            .keys()
        ),
    )


    print(
        "PID 4242 count:",
        len(
            manager
            .correlator
            .events_by_pid
            .get(
                4242,
                [],
            )
        ),
    )


    print(
        "File indexes:",
        list(
            manager
            .correlator
            .events_by_file
            .keys()
        ),
    )


    # ============================================================
    # CALL INTERNAL CORRELATOR DIRECTLY AFTER MANAGER STATE
    # ============================================================

    print()

    print(
        "=" * 90
    )

    print(
        "TEST 3 — Manager's internal correlator directly"
    )

    print(
        "=" * 90
    )


    test_file = (
        make_file_event()
    )


    test_file[
        "event_id"
    ] = "bridge-file-direct-internal"


    test_file[
        "timestamp_unix"
    ] = 1020.0


    internal_direct = (
        manager
        .correlator
        .add_event(
            test_file
        )
    )


    show_result(
        (
            "MANAGER INTERNAL "
            "CORRELATOR DIRECT CALL"
        ),

        internal_direct,
    )


    # ============================================================
    # FINAL MANAGER STATUS
    # ============================================================

    print()

    print(
        "=" * 90
    )

    print(
        "FINAL STATUS"
    )

    print(
        "=" * 90
    )


    print(
        "Manager incidents:",
        len(
            manager.incidents
        ),
    )


    for incident_id, incident in (
        manager.incidents.items()
    ):

        print()

        print(
            "Incident:",
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
            "Event IDs:",
            incident.get(
                "event_ids"
            ),
        )


if __name__ == "__main__":

    main()