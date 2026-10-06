from __future__ import annotations

import csv
import json
from pathlib import Path

from config import (
    DATA_SOURCE_VALIDATION,
)

from detection.fusion.event_correlator import (
    EventCorrelator,
)

from detection.fusion.correlation_manager import (
    CorrelationManager,
)


# ================================================================
# PATHS
# ================================================================

PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[2]
)

REPORT_DIR = (
    PROJECT_ROOT
    / "validation"
    / "reports"
)

REPORT_DIR.mkdir(
    parents=True,
    exist_ok=True,
)

CSV_PATH = (
    REPORT_DIR
    / "cross_telemetry_validation.csv"
)

JSON_PATH = (
    REPORT_DIR
    / "cross_telemetry_validation.json"
)


# ================================================================
# IN-MEMORY INCIDENT STORE
#
# Prevent validation from writing incidents into the actual DB.
# ================================================================

class MemoryIncidentStore:

    def __init__(
        self,
    ):

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
# NORMAL SYNTHETIC EVENT
#
# Used directly with EventCorrelator for C1 / C2 / C3 / C4-03.
# ================================================================

def event(
    event_id,
    event_type,
    timestamp,
    severity="HIGH",
    process=None,
    file=None,
    network=None,
    registry=None,
    metadata=None,
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
            "synthetic_cross_telemetry",

        "severity":
            severity,

        "device_id":
            "sentinelx-validation-device",

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

        "metadata":
            metadata
            or {
                "synthetic_validation":
                    True,
            },
    }

def manager_event(
    event_id,
    event_type,
    timestamp,
    severity="HIGH",
    process=None,
    file=None,
    network=None,
    registry=None,
    metadata=None,
    scenario_id="PHASE6-C4",
):

    item = event(
        event_id=
            event_id,

        event_type=
            event_type,

        timestamp=
            timestamp,

        severity=
            severity,

        process=
            process,

        file=
            file,

        network=
            network,

        registry=
            registry,

        metadata=
            metadata,
    )


    # ============================================================
    # OFFICIAL VALIDATION IDENTITY
    #
    # Synthetic validation evidence is allowed through the
    # CorrelationManager validation gate.
    #
    # IMPORTANT:
    # This is NOT simulation-only evidence.
    # Therefore simulation_mode must NOT be True.
    # ============================================================

    event_metadata = dict(
        item.get(
            "metadata"
        )
        or {}
    )


    event_metadata.update(
        {
            "data_source":
                DATA_SOURCE_VALIDATION,

            "synthetic":
                True,

            "synthetic_validation":
                True,

            "validation_mode":
                True,

            "sentinel_runtime_mode":
                "VALIDATION",

            "scenario_id":
                scenario_id,

            "validation_run_id":
                "PHASE6-CROSS-TELEMETRY",
        }
    )


    # ------------------------------------------------------------
    # Make absolutely sure simulation-only state is not inherited.
    # Correlation evidence intentionally excludes simulation_mode.
    # ------------------------------------------------------------

    event_metadata.pop(
        "simulation_mode",
        None,
    )


    item[
        "metadata"
    ] = event_metadata


    item.pop(
        "simulation_mode",
        None,
    )


    return item
# ================================================================
# CATEGORY HELPER
# ================================================================

def categories_from_result(
    correlator,
    result,
):

    items = [
        result.get(
            "current_event"
        )
        or {},

        *(
            result.get(
                "related_events"
            )
            or []
        ),
    ]


    categories = set()


    for item in items:

        category = (
            correlator
            .get_event_category(
                item
            )
        )


        if (
            category
            and category != "other"
        ):

            categories.add(
                category.upper()
            )


    return sorted(
        categories
    )


# ================================================================
# RESULT HELPER
# ================================================================

def add_result(
    results,
    scenario_id,
    family,
    scenario_name,
    score,
    correlated,
    categories,
    event_count,
    expected,
    passed,
    failure_layers="",
    notes="",
):

    results.append(
        {
            "scenario_id":
                scenario_id,

            "family":
                family,

            "scenario_name":
                scenario_name,

            "correlation_score":
                score,

            "correlated":
                correlated,

            "categories":
                ",".join(
                    categories
                ),

            "event_count":
                event_count,

            "expected":
                expected,

            "failure_layers":
                failure_layers,

            "passed":
                bool(
                    passed
                ),

            "notes":
                notes,
        }
    )


# ================================================================
# C1-01
# UNRELATED PROCESS + NETWORK
# ================================================================

def c1_01(
    results,
):

    correlator = (
        EventCorrelator()
    )


    correlator.add_event(
        event(
            "c1-01-process",
            "process_start",
            1000,

            severity=
                "INFO",

            process={
                "pid":
                    1001,

                "name":
                    "example.exe",

                "exe":
                    (
                        r"C:\Program Files"
                        r"\Example\example.exe"
                    ),
            },
        )
    )


    result = (
        correlator.add_event(
            event(
                "c1-01-network",
                "network_connect",
                1010,

                severity=
                    "INFO",

                network={
                    "pid":
                        2002,

                    "remote_ip":
                        "198.51.100.20",

                    "remote_port":
                        443,
                },
            )
        )
    )


    passed = (
        result.get(
            "correlated"
        )
        is False
    )


    add_result(
        results,
        "C1-01",
        "PROCESS_NETWORK",
        "Unrelated process and network activity",

        result.get(
            "correlation_score"
        ),

        result.get(
            "correlated"
        ),

        categories_from_result(
            correlator,
            result,
        ),

        (
            1
            + result.get(
                "related_event_count",
                0,
            )
        ),

        "NO_CORRELATION",

        passed,

        ""
        if passed
        else "CROSS_TELEMETRY_CORRELATION",
    )


# ================================================================
# C1-02
# PROCESS + NETWORK SAME PID
# ================================================================

def c1_02(
    results,
):

    correlator = (
        EventCorrelator()
    )


    correlator.add_event(
        event(
            "c1-02-process",
            "process_start",
            2000,

            severity=
                "HIGH",

            process={
                "pid":
                    4242,

                "name":
                    "demo.exe",

                "exe":
                    r"C:\Temp\demo.exe",
            },
        )
    )


    result = (
        correlator.add_event(
            event(
                "c1-02-network",
                "network_connect",
                2010,

                severity=
                    "HIGH",

                network={
                    "pid":
                        4242,

                    "remote_ip":
                        "198.51.100.42",

                    "remote_port":
                        443,
                },
            )
        )
    )


    cats = (
        categories_from_result(
            correlator,
            result,
        )
    )


    passed = (
        result.get(
            "correlated"
        )
        is True

        and

        {
            "PROCESS",
            "NETWORK",
        }.issubset(
            set(
                cats
            )
        )

        and

        result.get(
            "correlation_score",
            0,
        )
        >= 60
    )


    add_result(
        results,
        "C1-02",
        "PROCESS_NETWORK",
        "Process and network share exact PID",

        result.get(
            "correlation_score"
        ),

        result.get(
            "correlated"
        ),

        cats,

        (
            1
            + result.get(
                "related_event_count",
                0,
            )
        ),

        "PROCESS+NETWORK_CORRELATED",

        passed,

        ""
        if passed
        else "C1_PROCESS_NETWORK",
    )


# ================================================================
# C1-03
# SAME PID OUTSIDE CORRELATION WINDOW
# ================================================================

def c1_03(
    results,
):

    correlator = (
        EventCorrelator(
            correlation_window_seconds=
                120
        )
    )


    correlator.add_event(
        event(
            "c1-03-process",
            "process_start",
            3000,

            process={
                "pid":
                    5005,

                "name":
                    "late.exe",

                "exe":
                    r"C:\Temp\late.exe",
            },
        )
    )


    result = (
        correlator.add_event(
            event(
                "c1-03-network",
                "network_connect",
                3121,

                network={
                    "pid":
                        5005,

                    "remote_ip":
                        "198.51.100.50",

                    "remote_port":
                        443,
                },
            )
        )
    )


    passed = (
        result.get(
            "correlated"
        )
        is False

        and

        result.get(
            "related_event_count"
        )
        == 0
    )


    add_result(
        results,
        "C1-03",
        "PROCESS_NETWORK",
        "Same PID outside correlation window",

        result.get(
            "correlation_score"
        ),

        result.get(
            "correlated"
        ),

        categories_from_result(
            correlator,
            result,
        ),

        1,

        "NO_CORRELATION",

        passed,

        ""
        if passed
        else "CORRELATION_WINDOW",
    )


# ================================================================
# C2-01
# SAME NAME BUT DIFFERENT PATH
# ================================================================

def c2_01(
    results,
):

    correlator = (
        EventCorrelator()
    )


    correlator.add_event(
        event(
            "c2-01-process",
            "process_start",
            4000,

            severity=
                "INFO",

            process={
                "pid":
                    6001,

                "name":
                    "demo.exe",

                "exe":
                    (
                        r"C:\Program Files"
                        r"\AppA\demo.exe"
                    ),
            },
        )
    )


    result = (
        correlator.add_event(
            event(
                "c2-01-file",
                "file_modify",
                4010,

                severity=
                    "INFO",

                file={
                    "name":
                        "demo.exe",

                    "path":
                        r"C:\Temp\demo.exe",
                },
            )
        )
    )


    passed = (
        result.get(
            "correlated"
        )
        is False
    )


    add_result(
        results,
        "C2-01",
        "PROCESS_FILE",
        "Same filename but different file path",

        result.get(
            "correlation_score"
        ),

        result.get(
            "correlated"
        ),

        categories_from_result(
            correlator,
            result,
        ),

        (
            1
            + result.get(
                "related_event_count",
                0,
            )
        ),

        "NO_CORRELATION",

        passed,

        ""
        if passed
        else "C2_FALSE_POSITIVE",
    )


# ================================================================
# C2-02
# EXACT EXECUTABLE / FILE PATH
# ================================================================

def c2_02(
    results,
):

    correlator = (
        EventCorrelator()
    )


    path = (
        r"C:\Temp\payload.exe"
    )


    correlator.add_event(
        event(
            "c2-02-process",
            "process_start",
            5000,

            severity=
                "HIGH",

            process={
                "pid":
                    7007,

                "name":
                    "payload.exe",

                "exe":
                    path,
            },
        )
    )


    result = (
        correlator.add_event(
            event(
                "c2-02-file",
                "file_modify",
                5010,

                severity=
                    "HIGH",

                file={
                    "name":
                        "payload.exe",

                    "path":
                        path,

                    "sha256":
                        "SYNTHETIC_C2_SHA256",
                },
            )
        )
    )


    cats = (
        categories_from_result(
            correlator,
            result,
        )
    )


    passed = (
        result.get(
            "correlated"
        )
        is True

        and

        {
            "PROCESS",
            "FILE",
        }.issubset(
            set(
                cats
            )
        )

        and

        result.get(
            "correlation_score",
            0,
        )
        >= 60
    )


    add_result(
        results,
        "C2-02",
        "PROCESS_FILE",
        "Process executable exactly matches file path",

        result.get(
            "correlation_score"
        ),

        result.get(
            "correlated"
        ),

        cats,

        (
            1
            + result.get(
                "related_event_count",
                0,
            )
        ),

        "PROCESS+FILE_CORRELATED",

        passed,

        ""
        if passed
        else "C2_PROCESS_FILE",
    )


# ================================================================
# C3-01
# UNRELATED REGISTRY VALUE
# ================================================================

def c3_01(
    results,
):

    correlator = (
        EventCorrelator()
    )


    correlator.add_event(
        event(
            "c3-01-process",
            "process_start",
            6000,

            severity=
                "INFO",

            process={
                "pid":
                    8008,

                "name":
                    "demo.exe",

                "exe":
                    r"C:\Temp\demo.exe",
            },
        )
    )


    result = (
        correlator.add_event(
            event(
                "c3-01-registry",
                "registry_modify",
                6010,

                severity=
                    "INFO",

                registry={
                    "key":
                        (
                            r"HKCU\Software"
                            r"\Microsoft\Windows"
                            r"\CurrentVersion\Run"
                        ),

                    "value_name":
                        "Example",

                    "value_data":
                        (
                            r"C:\Program Files"
                            r"\Other\other.exe"
                        ),
                },
            )
        )
    )


    passed = (
        result.get(
            "correlated"
        )
        is False
    )


    add_result(
        results,
        "C3-01",
        "PROCESS_REGISTRY",
        "Registry value unrelated to process",

        result.get(
            "correlation_score"
        ),

        result.get(
            "correlated"
        ),

        categories_from_result(
            correlator,
            result,
        ),

        (
            1
            + result.get(
                "related_event_count",
                0,
            )
        ),

        "NO_CORRELATION",

        passed,

        ""
        if passed
        else "C3_FALSE_POSITIVE",
    )


# ================================================================
# C3-02
# REGISTRY VALUE REFERENCES PROCESS EXECUTABLE
# ================================================================

def c3_02(
    results,
):

    correlator = (
        EventCorrelator()
    )


    path = (
        r"C:\Users\Public\helper.exe"
    )


    correlator.add_event(
        event(
            "c3-02-process",
            "process_start",
            7000,

            severity=
                "HIGH",

            process={
                "pid":
                    9009,

                "name":
                    "helper.exe",

                "exe":
                    path,
            },
        )
    )


    result = (
        correlator.add_event(
            event(
                "c3-02-registry",
                "registry_modify",
                7010,

                severity=
                    "HIGH",

                registry={
                    "key":
                        (
                            r"HKCU\Software"
                            r"\Microsoft\Windows"
                            r"\CurrentVersion\Run"
                        ),

                    "value_name":
                        "Updater",

                    "value_data":
                        path,
                },
            )
        )
    )


    cats = (
        categories_from_result(
            correlator,
            result,
        )
    )


    passed = (
        result.get(
            "correlated"
        )
        is True

        and

        {
            "PROCESS",
            "REGISTRY",
        }.issubset(
            set(
                cats
            )
        )

        and

        result.get(
            "correlation_score",
            0,
        )
        >= 60
    )


    add_result(
        results,
        "C3-02",
        "PROCESS_REGISTRY",
        "Registry persistence references process executable",

        result.get(
            "correlation_score"
        ),

        result.get(
            "correlated"
        ),

        cats,

        (
            1
            + result.get(
                "related_event_count",
                0,
            )
        ),

        "PROCESS+REGISTRY_CORRELATED",

        passed,

        ""
        if passed
        else "C3_PROCESS_REGISTRY",
    )


# ================================================================
# C4-01 ATTACK CHAIN EVENTS
#
# IMPORTANT:
# Every event uses scenario_id="C4-01".
# ================================================================

def full_chain_events():

    pid = 42420

    path = (
        r"C:\Temp\sentinel_chain.exe"
    )


    scenario_id = (
        "C4-01"
    )


    return [

        # --------------------------------------------------------
        # PROCESS
        # --------------------------------------------------------

        manager_event(
            "c4-process",
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

            scenario_id=
                scenario_id,
        ),


        # --------------------------------------------------------
        # FILE
        # --------------------------------------------------------

        manager_event(
            "c4-file",
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
                    "SYNTHETIC_CHAIN_SHA256",
            },

            scenario_id=
                scenario_id,
        ),


        # --------------------------------------------------------
        # NETWORK
        # --------------------------------------------------------

        manager_event(
            "c4-network",
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

            scenario_id=
                scenario_id,
        ),


        # --------------------------------------------------------
        # REGISTRY
        # --------------------------------------------------------

        manager_event(
            "c4-registry",
            "registry_modify",
            8030,

            severity=
                "CRITICAL",

            registry={
                "pid":
                    pid,

                "key":
                    (
                        r"HKCU\Software"
                        r"\Microsoft\Windows"
                        r"\CurrentVersion\Run"
                    ),

                "value_name":
                    "SentinelUpdater",

                "value_data":
                    path,
            },

            scenario_id=
                scenario_id,
        ),
    ]


# ================================================================
# MEMORY CORRELATION MANAGER
# ================================================================

def memory_manager():

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


    return manager


# ================================================================
# C4-01
# FULL PROCESS + FILE + NETWORK + REGISTRY CHAIN
# ================================================================

def c4_01(
    results,
):

    manager = (
        memory_manager()
    )


    last_result = None


    for item in full_chain_events():

        last_result = (
            manager.process_event(
                item
            )
        )


    incident = (
        (
            last_result
            or {}
        ).get(
            "incident"
        )
        or {}
    )


    # ------------------------------------------------------------
    # If the manager updated the incident internally but the final
    # call did not return it, use the in-memory manager state.
    # ------------------------------------------------------------

    if (
        not incident
        and len(
            manager.incidents
        )
        == 1
    ):

        incident = next(
            iter(
                manager.incidents.values()
            )
        )


    categories = (
        incident.get(
            "categories"
        )
        or []
    )


    normalized_categories = {
        str(
            category
        ).upper()
        for category
        in categories
    }


    event_ids = (
        incident.get(
            "event_ids"
        )
        or []
    )


    event_count = (
        incident.get(
            "event_count"
        )
    )


    if event_count is None:

        event_count = len(
            event_ids
        )


    score = (
        incident.get(
            "correlation_score"
        )
    )


    passed = (
        len(
            manager.incidents
        )
        == 1

        and

        event_count
        == 4

        and

        {
            "PROCESS",
            "FILE",
            "NETWORK",
            "REGISTRY",
        }.issubset(
            normalized_categories
        )

        and

        (
            score
            is not None
            and score >= 80
        )

        and

        incident.get(
            "requires_investigation"
        )
        is True
    )


    add_result(
        results,
        "C4-01",
        "FULL_CHAIN",

        (
            "Process + file + network + "
            "registry attack chain"
        ),

        score,

        bool(
            incident
        ),

        sorted(
            normalized_categories
        ),

        event_count
        or 0,

        "ONE_CRITICAL_MULTI_CATEGORY_INCIDENT",

        passed,

        ""
        if passed
        else "C4_FULL_CHAIN",
    )


# ================================================================
# C4-02
# DUPLICATE / REPLAY IDEMPOTENCY
#
# Both events belong to scenario C4-02.
# ================================================================

def c4_02(
    results,
):

    manager = (
        memory_manager()
    )


    scenario_id = (
        "C4-02"
    )


    process_event = (
        manager_event(
            "c4-02-process",
            "process_start",
            9000,

            severity=
                "HIGH",

            process={
                "pid":
                    5151,

                "name":
                    "replay.exe",

                "exe":
                    r"C:\Temp\replay.exe",
            },

            scenario_id=
                scenario_id,
        )
    )


    network_event = (
        manager_event(
            "c4-02-network",
            "network_connect",
            9010,

            severity=
                "HIGH",

            network={
                "pid":
                    5151,

                "remote_ip":
                    "198.51.100.151",

                "remote_port":
                    443,
            },

            scenario_id=
                scenario_id,
        )
    )


    # ------------------------------------------------------------
    # PROCESS
    # ------------------------------------------------------------

    manager.process_event(
        process_event
    )


    # ------------------------------------------------------------
    # FIRST NETWORK EVENT
    # ------------------------------------------------------------

    original = (
        manager.process_event(
            network_event
        )
    )


    # ------------------------------------------------------------
    # EXACT REPLAY
    #
    # Same event ID and same scenario ID.
    # ------------------------------------------------------------

    replay = (
        manager.process_event(
            dict(
                network_event
            )
        )
    )


    incident = (
        (
            replay
            or {}
        ).get(
            "incident"
        )

        or

        (
            original
            or {}
        ).get(
            "incident"
        )

        or {}
    )


    if (
        not incident
        and len(
            manager.incidents
        )
        == 1
    ):

        incident = next(
            iter(
                manager.incidents.values()
            )
        )


    event_ids = (
        incident.get(
            "event_ids"
        )
        or []
    )


    event_count = (
        incident.get(
            "event_count"
        )
    )


    if event_count is None:

        event_count = len(
            event_ids
        )


    unique_event_ids = set(
        event_ids
    )


    categories = {
        str(
            category
        ).upper()
        for category
        in (
            incident.get(
                "categories"
            )
            or []
        )
    }


    passed = (
        len(
            manager.incidents
        )
        == 1

        and

        len(
            event_ids
        )
        == len(
            unique_event_ids
        )

        and

        event_count
        == 2

        and

        {
            "PROCESS",
            "NETWORK",
        }.issubset(
            categories
        )
    )


    add_result(
        results,
        "C4-02",
        "FULL_CHAIN",

        (
            "Duplicate network event does not "
            "duplicate incident evidence"
        ),

        incident.get(
            "correlation_score"
        ),

        bool(
            incident
        ),

        sorted(
            categories
        ),

        event_count
        or 0,

        "EVENT_COUNT_REMAINS_2",

        passed,

        ""
        if passed
        else "CORRELATION_IDEMPOTENCY",
    )


# ================================================================
# C4-03
# CRITICAL EVENTS WITHOUT ENTITY EVIDENCE
#
# Severity alone must NEVER create a relationship.
# ================================================================

def c4_03(
    results,
):

    correlator = (
        EventCorrelator()
    )


    correlator.add_event(
        event(
            "c4-03-process",
            "process_start",
            10000,

            severity=
                "CRITICAL",

            process={},
        )
    )


    result = (
        correlator.add_event(
            event(
                "c4-03-network",
                "network_connect",
                10010,

                severity=
                    "CRITICAL",

                network={},
            )
        )
    )


    passed = (
        result.get(
            "correlated"
        )
        is False

        and

        result.get(
            "related_event_count"
        )
        == 0
    )


    add_result(
        results,
        "C4-03",
        "FULL_CHAIN",

        (
            "Critical severity without entity "
            "evidence stays uncorrelated"
        ),

        result.get(
            "correlation_score"
        ),

        result.get(
            "correlated"
        ),

        categories_from_result(
            correlator,
            result,
        ),

        1,

        "NO_INVENTED_RELATIONSHIP",

        passed,

        ""
        if passed
        else "CORRELATION_MISSING_DATA",

        (
            "Severity alone must not create "
            "a cross-telemetry relationship."
        ),
    )


# ================================================================
# SAVE REPORTS
# ================================================================

def save_reports(
    results,
):

    fields = [
        "scenario_id",
        "family",
        "scenario_name",
        "correlation_score",
        "correlated",
        "categories",
        "event_count",
        "expected",
        "failure_layers",
        "passed",
        "notes",
    ]


    with CSV_PATH.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as handle:

        writer = (
            csv.DictWriter(
                handle,
                fieldnames=fields,
            )
        )


        writer.writeheader()


        writer.writerows(
            results
        )


    with JSON_PATH.open(
        "w",
        encoding="utf-8",
    ) as handle:

        json.dump(
            {
                "suite":
                    (
                        "SENTINEL-X PHASE 6 "
                        "CROSS-TELEMETRY VALIDATION"
                    ),

                "passed":
                    sum(
                        1
                        for row
                        in results
                        if row[
                            "passed"
                        ]
                    ),

                "failed":
                    sum(
                        1
                        for row
                        in results
                        if not row[
                            "passed"
                        ]
                    ),

                "results":
                    results,
            },

            handle,

            indent=2,
        )


# ================================================================
# PRINT MATRIX
# ================================================================

def print_matrix(
    results,
):

    print()

    print(
        "=" * 110
    )

    print(
        (
            "SENTINEL-X PHASE 6 — "
            "CROSS-TELEMETRY CORRELATION"
        )
    )

    print(
        "=" * 110
    )


    for row in results:

        state = (
            "PASS"
            if row[
                "passed"
            ]
            else "FAIL"
        )


        print(
            f"{row['scenario_id']:<7} "
            f"{state:<5} "
            f"{row['scenario_name']:<61} "
            f"Score={row['correlation_score']} "
            f"Categories="
            f"{row['categories'] or 'NONE'}"
        )


    passed_count = sum(
        1
        for row
        in results
        if row[
            "passed"
        ]
    )


    print(
        "-" * 110
    )


    print(
        f"RESULT: "
        f"{passed_count}/{len(results)} PASS"
    )


    print(
        f"CSV   : {CSV_PATH}"
    )


    print(
        f"JSON  : {JSON_PATH}"
    )


    print(
        "=" * 110
    )


# ================================================================
# MAIN
# ================================================================

def main():

    results = []


    # ============================================================
    # C1
    # PROCESS + NETWORK
    # ============================================================

    c1_01(
        results
    )

    c1_02(
        results
    )

    c1_03(
        results
    )


    # ============================================================
    # C2
    # PROCESS + FILE
    # ============================================================

    c2_01(
        results
    )

    c2_02(
        results
    )


    # ============================================================
    # C3
    # PROCESS + REGISTRY
    # ============================================================

    c3_01(
        results
    )

    c3_02(
        results
    )


    # ============================================================
    # C4
    # MANAGER / INCIDENT CHAIN
    # ============================================================

    c4_01(
        results
    )

    c4_02(
        results
    )

    c4_03(
        results
    )


    # ============================================================
    # REPORT
    # ============================================================

    save_reports(
        results
    )


    print_matrix(
        results
    )


# ================================================================
# ENTRY POINT
# ================================================================

if __name__ == "__main__":

    main()