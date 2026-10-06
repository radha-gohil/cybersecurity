from __future__ import annotations

import inspect

from config import (
    DATA_SOURCE_VALIDATION,
)

from detection.fusion.correlation_manager import (
    CorrelationManager,
)

from detection.fusion.event_correlator import (
    EventCorrelator,
)

from validation.correlation.cross_telemetry_batch_runner import (
    manager_event,
)


# ================================================================
# HELPERS
# ================================================================

def line():

    print(
        "=" * 100
    )


def section(
    title,
):

    print()

    line()

    print(
        title
    )

    line()


# ================================================================
# MAIN
# ================================================================

def main():

    section(
        "SENTINEL-X CORRELATION RELATED-EVENT DEBUG"
    )


    print(
        "DATA_SOURCE_VALIDATION =",
        repr(
            DATA_SOURCE_VALIDATION
        ),
    )


    print(
        "EventCorrelator file =",
        inspect.getsourcefile(
            EventCorrelator
        ),
    )


    print(
        "CorrelationManager file =",
        inspect.getsourcefile(
            CorrelationManager
        ),
    )


    # ============================================================
    # MANAGER
    # ============================================================

    manager = (
        CorrelationManager(
            correlation_window_seconds=
                120,

            incident_threshold=
                35,
        )
    )


    # ============================================================
    # EVENTS
    # ============================================================

    process_event = (
        manager_event(
            event_id=
                "debug-process",

            event_type=
                "process_start",

            timestamp=
                1000,

            severity=
                "HIGH",

            process={
                "pid":
                    4242,

                "name":
                    "payload.exe",

                "exe":
                    r"C:\Temp\payload.exe",
            },

            scenario_id=
                "DEBUG-CORRELATION",
        )
    )


    file_event = (
        manager_event(
            event_id=
                "debug-file",

            event_type=
                "file_modify",

            timestamp=
                1010,

            severity=
                "HIGH",

            process={
                "pid":
                    4242,

                "name":
                    "payload.exe",

                "exe":
                    r"C:\Temp\payload.exe",
            },

            file={
                "name":
                    "payload.exe",

                "path":
                    r"C:\Temp\payload.exe",

                "sha256":
                    "DEBUG_SHA256",
            },

            scenario_id=
                "DEBUG-CORRELATION",
        )
    )


    # ============================================================
    # PROCESS FIRST EVENT
    # ============================================================

    section(
        "STEP 1 — PROCESS EVENT"
    )


    process_result = (
        manager.process_event(
            process_event
        )
    )


    print(
        "Process result:"
    )

    print(
        process_result
    )


    print()

    print(
        "Internal event count:",
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
        "PID 4242 event IDs:",
        [
            item.get(
                "event_id"
            )
            for item
            in manager
            .correlator
            .events_by_pid
            .get(
                4242,
                [],
            )
        ],
    )


    # ============================================================
    # PROCESS FILE EVENT
    # ============================================================

    section(
        "STEP 2 — FILE EVENT"
    )


    file_result = (
        manager.process_event(
            file_event
        )
    )


    print(
        "File result:"
    )

    print(
        file_result
    )


    print()

    print(
        "Internal event count:",
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
        "PID 4242 event IDs:",
        [
            item.get(
                "event_id"
            )
            for item
            in manager
            .correlator
            .events_by_pid
            .get(
                4242,
                [],
            )
        ],
    )


    # ============================================================
    # STORED EVENTS
    # ============================================================

    section(
        "STEP 3 — STORED EVENT DETAILS"
    )


    for index, stored_event in enumerate(
        manager.correlator.events,
        start=1,
    ):

        print()

        print(
            "EVENT",
            index,
        )


        print(
            "event_id:",
            stored_event.get(
                "event_id"
            ),
        )


        print(
            "event_type:",
            stored_event.get(
                "event_type"
            ),
        )


        print(
            "timestamp_unix:",
            stored_event.get(
                "timestamp_unix"
            ),
        )


        print(
            "pid:",
            manager
            .correlator
            .extract_pid(
                stored_event
            ),
        )


        print(
            "file_path:",
            manager
            .correlator
            .extract_file_path(
                stored_event
            ),
        )


        print(
            "metadata:",
            stored_event.get(
                "metadata"
            ),
        )


    # ============================================================
    # CURRENT / CANDIDATE OBJECTS
    # ============================================================

    if (
        len(
            manager.correlator.events
        )
        < 2
    ):

        print(
            "ERROR: fewer than two events stored."
        )

        return


    candidate = (
        manager
        .correlator
        .events[
            0
        ]
    )


    current = (
        manager
        .correlator
        .events[
            1
        ]
    )


    # ============================================================
    # BASIC ENTITY CHECK
    # ============================================================

    section(
        "STEP 4 — BASIC ENTITY CHECK"
    )


    print(
        "Candidate ID:",
        candidate.get(
            "event_id"
        ),
    )


    print(
        "Current ID:",
        current.get(
            "event_id"
        ),
    )


    print(
        "Same object?:",
        candidate
        is current,
    )


    candidate_pid = (
        manager
        .correlator
        .extract_pid(
            candidate
        )
    )


    current_pid = (
        manager
        .correlator
        .extract_pid(
            current
        )
    )


    print(
        "Candidate PID:",
        candidate_pid,
    )


    print(
        "Current PID:",
        current_pid,
    )


    print(
        "PID equal:",
        candidate_pid
        == current_pid,
    )


    print(
        "Candidate timestamp:",
        candidate.get(
            "timestamp_unix"
        ),
    )


    print(
        "Current timestamp:",
        current.get(
            "timestamp_unix"
        ),
    )


    print(
        "Within correlation window:",
        manager
        .correlator
        .within_window(
            current,
            candidate,
        ),
    )


    # ============================================================
    # DIRECT CANDIDATE GROUPS
    # ============================================================

    section(
        "STEP 5 — DIRECT CANDIDATE GROUPS"
    )


    groups = (
        manager
        .correlator
        .get_direct_candidate_groups(
            current
        )
    )


    print(
        "Candidate group count:",
        len(
            groups
        ),
    )


    for group_index, group in enumerate(
        groups,
        start=1,
    ):

        print()

        print(
            f"GROUP {group_index}"
        )


        print(
            "Size:",
            len(
                group
            ),
        )


        print(
            "Event IDs:",
            [
                item.get(
                    "event_id"
                )
                for item
                in group
            ],
        )


    # ============================================================
    # MANUAL add_related_event
    # ============================================================

    section(
        "STEP 6 — MANUAL add_related_event"
    )


    manual_related = []

    manual_seen = set()


    manager.correlator.add_related_event(
        manual_related,
        manual_seen,
        current,
        candidate,
    )


    print(
        "Manual related IDs:",
        [
            item.get(
                "event_id"
            )
            for item
            in manual_related
        ],
    )


    print(
        "Manual seen IDs:",
        manual_seen,
    )


    # ============================================================
    # GET RELATED EVENTS
    # ============================================================

    section(
        "STEP 7 — get_related_events"
    )


    related = (
        manager
        .correlator
        .get_related_events(
            current
        )
    )


    print(
        "Related count:",
        len(
            related
        ),
    )


    print(
        "Related IDs:",
        [
            item.get(
                "event_id"
            )
            for item
            in related
        ],
    )


    # ============================================================
    # RE-CORRELATE CURRENT STORED EVENT
    # ============================================================

    section(
        "STEP 8 — correlate_event AGAIN"
    )


    recalculated = (
        manager
        .correlator
        .correlate_event(
            current
        )
    )


    print(
        "Recalculated result:"
    )


    print(
        recalculated
    )


    # ============================================================
    # ENTITY LINKER
    # ============================================================

    section(
        "STEP 9 — ENTITY LINKER"
    )


    link_result = (
        manager
        .correlator
        .entity_linker
        .score_pair(
            current,
            candidate,
        )
    )


    print(
        "Entity-link result:"
    )


    print(
        link_result
    )


    # ============================================================
    # EXACT RUNTIME METHOD SOURCE
    # ============================================================

    section(
        "STEP 10 — RUNTIME METHOD SOURCE"
    )


    print()

    print(
        "------ get_direct_candidate_groups ------"
    )


    print(
        inspect.getsource(
            EventCorrelator
            .get_direct_candidate_groups
        )
    )


    print()

    print(
        "------ add_related_event ------"
    )


    print(
        inspect.getsource(
            EventCorrelator
            .add_related_event
        )
    )


    print()

    print(
        "------ get_related_events ------"
    )


    print(
        inspect.getsource(
            EventCorrelator
            .get_related_events
        )
    )


    print()

    print(
        "------ within_window ------"
    )


    print(
        inspect.getsource(
            EventCorrelator
            .within_window
        )
    )


    # ============================================================
    # SUMMARY
    # ============================================================

    section(
        "DEBUG SUMMARY"
    )


    print(
        "Stored events:",
        len(
            manager.correlator.events
        ),
    )


    print(
        "Candidate PID:",
        candidate_pid,
    )


    print(
        "Current PID:",
        current_pid,
    )


    print(
        "Within window:",
        manager
        .correlator
        .within_window(
            current,
            candidate,
        ),
    )


    print(
        "Manual related count:",
        len(
            manual_related
        ),
    )


    print(
        "get_related_events count:",
        len(
            related
        ),
    )


    print(
        "Recalculated score:",
        recalculated.get(
            "correlation_score"
        ),
    )


    print(
        "Recalculated correlated:",
        recalculated.get(
            "correlated"
        ),
    )


    line()


if __name__ == "__main__":

    main()