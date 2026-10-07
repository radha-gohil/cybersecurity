from __future__ import annotations

import csv
import json
import time
import uuid

from pathlib import Path


from config import (
    IS_VALIDATION_MODE,
)

from endpoint.agent.telemetry_manager import (
    shared_telemetry_manager,
)

from endpoint.collectors.network_monitor import (
    NetworkMonitor,
)

from endpoint.storage.database import (
    initialize_database,
)

from detection.network.network_behavior_tracker import (
    NetworkBehaviorTracker,
)


# ================================================================
# CONFIG
# ================================================================

RUN_ID = (
    "NETWORK-BATCH-"
    + uuid.uuid4().hex[:8].upper()
)


REPORT_DIR = (
    Path(__file__)
    .resolve()
    .parents[1]
    / "reports"
)


REPORT_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


# ================================================================
# CONNECTION BUILDER
# ================================================================

def connection(
    *,
    pid: int,
    process_name: str = "validation.exe",
    remote_ip: str = "203.0.113.10",
    remote_port: int = 443,
    local_port: int = 50000,
):

    return {

        "pid":
            pid,

        "process_name":
            process_name,

        "protocol":
            "TCP",

        "local_ip":
            "192.0.2.10",

        "local_port":
            local_port,

        "remote_ip":
            remote_ip,

        "remote_port":
            remote_port,

        "status":
            "ESTABLISHED",
    }


# ================================================================
# RUN SEQUENCE THROUGH REAL TRACKER
# ================================================================

def run_sequence(
    samples,
):

    # ------------------------------------------------------------
    # Fresh tracker for every scenario.
    #
    # Prevents previous scenario history/cooldowns affecting
    # another test.
    # ------------------------------------------------------------

    tracker = (
        NetworkBehaviorTracker()
    )


    detections = []


    for (
        network_event,
        timestamp,
    ) in samples:

        findings = (
            tracker.analyze(

                connection=
                    network_event,

                current_time=
                    timestamp,
            )
        )


        for finding in findings:

            detections.append(
                finding
            )


    return detections


# ================================================================
# HELPER
# ================================================================

def detection_types(
    findings,
):

    return [

        finding.get(
            "detection_type"
        )

        for finding
        in findings
    ]


# ================================================================
# PERSIST ONE EXPECTED FINDING
# ================================================================

def persist_finding(
    *,
    scenario_id,
    scenario_name,
    finding,
    representative_connection,
):

    live_before = (
        shared_telemetry_manager
        .get_live_snapshot(
            reset_interval=False
        )
        .get(
            "runtime_event_count",
            0,
        )
    )


    event = (
        shared_telemetry_manager
        .emit_validation(

            scenario_id=
                scenario_id,

            validation_run_id=
                RUN_ID,

            event_type=
                "network_behavior_alert",

            source=
                "network_validation_suite",

            severity=
                finding.get(
                    "severity",
                    "INFO",
                ),

            network=dict(
                representative_connection
            ),

            metadata={

                "detector_family":
                    "NETWORK",

                "scenario_name":
                    scenario_name,

                "network_detection":
                    dict(
                        finding
                    ),
            },
        )
    )


    # Use the real NetworkMonitor persistence contract.
    monitor = (
        NetworkMonitor(
            polling_interval=3.0,
            network_detection_mode="SHADOW",
        )
    )


    saved = (
        monitor.persist_network_detection(

            event_id=
                event.event_id,

            finding=
                finding,
        )
    )


    live_after = (
        shared_telemetry_manager
        .get_live_snapshot(
            reset_interval=False
        )
        .get(
            "runtime_event_count",
            0,
        )
    )


    return {

        "event_id":
            event.event_id,

        "saved":
            bool(
                saved
            ),

        "live_isolation_ok":
            (
                live_before
                == live_after
            ),
    }


# ================================================================
# N1-01 — NORMAL SINGLE CONNECTION
# ================================================================

def scenario_normal_single():

    samples = [

        (
            connection(
                pid=994101,
            ),
            1000.0,
        )
    ]


    return {

        "id":
            "N1-01",

        "family":
            "BASELINE",

        "name":
            "Single normal outbound connection",

        "samples":
            samples,

        "expected_type":
            None,
    }


# ================================================================
# N1-02 — BELOW BURST THRESHOLD
# ================================================================

def scenario_burst_below():

    samples = []


    for index in range(
        19
    ):

        samples.append(
            (
                connection(

                    pid=
                        994102,

                    remote_ip=
                        f"198.51.100.{index + 1}",

                    remote_port=
                        443,

                    local_port=
                        51000 + index,
                ),

                2000.0
                + (
                    index
                    * 0.2
                ),
            )
        )


    return {

        "id":
            "N1-02",

        "family":
            "CONNECTION_BURST",

        "name":
            "Nineteen rapid connections",

        "samples":
            samples,

        "expected_type":
            None,
    }


# ================================================================
# N1-03 — CONNECTION BURST
# ================================================================

def scenario_connection_burst():

    samples = []


    for index in range(
        20
    ):

        samples.append(
            (
                connection(

                    pid=
                        994103,

                    remote_ip=
                        f"198.51.100.{index + 1}",

                    remote_port=
                        443,

                    local_port=
                        52000 + index,
                ),

                3000.0
                + (
                    index
                    * 0.2
                ),
            )
        )


    return {

        "id":
            "N1-03",

        "family":
            "CONNECTION_BURST",

        "name":
            "Twenty rapid connections",

        "samples":
            samples,

        "expected_type":
            "CONNECTION_BURST",
    }


# ================================================================
# N2-01 — PORT SCAN BELOW THRESHOLD
# ================================================================

def scenario_port_scan_below():

    samples = []


    for index in range(
        9
    ):

        samples.append(
            (
                connection(

                    pid=
                        994201,

                    remote_ip=
                        "203.0.113.50",

                    remote_port=
                        8000 + index,

                    local_port=
                        53000 + index,
                ),

                4000.0
                + index,
            )
        )


    return {

        "id":
            "N2-01",

        "family":
            "PORT_SCAN",

        "name":
            "Nine destination ports",

        "samples":
            samples,

        "expected_type":
            None,
    }


# ================================================================
# N2-02 — PORT SCAN
# ================================================================

def scenario_port_scan():

    samples = []


    for index in range(
        10
    ):

        samples.append(
            (
                connection(

                    pid=
                        994202,

                    remote_ip=
                        "203.0.113.51",

                    remote_port=
                        8100 + index,

                    local_port=
                        54000 + index,
                ),

                5000.0
                + index,
            )
        )


    return {

        "id":
            "N2-02",

        "family":
            "PORT_SCAN",

        "name":
            "Ten unique destination ports",

        "samples":
            samples,

        "expected_type":
            "PORT_SCAN_BEHAVIOR",
    }


# ================================================================
# N3-01 — DOS BELOW THRESHOLD
#
# Connection burst may legitimately occur after 20.
# We specifically assert that POSSIBLE_DOS is absent.
# ================================================================

def scenario_dos_below():

    samples = []


    for index in range(
        29
    ):

        samples.append(
            (
                connection(

                    pid=
                        994301,

                    remote_ip=
                        "203.0.113.70",

                    remote_port=
                        443,

                    local_port=
                        55000 + index,
                ),

                6000.0
                + (
                    index
                    * 0.2
                ),
            )
        )


    return {

        "id":
            "N3-01",

        "family":
            "DOS",

        "name":
            "Twenty-nine same-target connections",

        "samples":
            samples,

        "expected_type":
            None,

        "forbidden_type":
            "POSSIBLE_DOS_BEHAVIOR",

        # Other detector findings such as CONNECTION_BURST
        # are allowed.
        "allow_other_findings":
            True,
    }


# ================================================================
# N3-02 — DOS THRESHOLD
# ================================================================

def scenario_dos():

    samples = []


    for index in range(
        30
    ):

        samples.append(
            (
                connection(

                    pid=
                        994302,

                    remote_ip=
                        "203.0.113.71",

                    remote_port=
                        443,

                    local_port=
                        56000 + index,
                ),

                7000.0
                + (
                    index
                    * 0.2
                ),
            )
        )


    return {

        "id":
            "N3-02",

        "family":
            "DOS",

        "name":
            "Thirty same-target connections",

        "samples":
            samples,

        "expected_type":
            "POSSIBLE_DOS_BEHAVIOR",
    }


# ================================================================
# N4-01 — IRREGULAR TRAFFIC, NOT BEACONING
# ================================================================

def scenario_irregular_beacon():

    timestamps = [
        8000.0,
        8006.0,
        8023.0,
        8030.0,
        8060.0,
    ]


    samples = [

        (
            connection(

                pid=
                    994401,

                remote_ip=
                    "203.0.113.80",

                remote_port=
                    8443,

                local_port=
                    57000 + index,
            ),

            timestamp,
        )

        for index, timestamp
        in enumerate(
            timestamps
        )
    ]


    return {

        "id":
            "N4-01",

        "family":
            "BEACONING",

        "name":
            "Irregular repeated connections",

        "samples":
            samples,

        "expected_type":
            None,

        "forbidden_type":
            "SUSPICIOUS_BEACONING",

        "allow_other_findings":
            True,
    }


# ================================================================
# N4-02 — REGULAR BEACON
# ================================================================

def scenario_beacon():

    samples = []


    for index in range(
        5
    ):

        samples.append(
            (
                connection(

                    pid=
                        994402,

                    remote_ip=
                        "203.0.113.81",

                    remote_port=
                        8443,

                    local_port=
                        58000 + index,
                ),

                9000.0
                + (
                    index
                    * 10.0
                ),
            )
        )


    return {

        "id":
            "N4-02",

        "family":
            "BEACONING",

        "name":
            "Regular ten-second beacon",

        "samples":
            samples,

        "expected_type":
            "SUSPICIOUS_BEACONING",
    }


# ================================================================
# N5-01 — DISTRIBUTED DOS
#
# IMPORTANT:
#
# The current NetworkBehaviorTracker is process-attributed.
# It has no target-level multi-source DDoS aggregator.
#
# This case is EXPECTED to fail initially.
#
# That failure gives us the exact next implementation task.
# ================================================================

def scenario_ddos():

    samples = []


    timestamp = (
        10000.0
    )


    # 10 different processes.
    # 4 connections each.
    #
    # Total target traffic = 40.
    #
    # No single process reaches individual DoS threshold 30.
    for process_index in range(
        10
    ):

        for connection_index in range(
            4
        ):

            samples.append(
                (
                    connection(

                        pid=
                            (
                                994500
                                + process_index
                            ),

                        process_name=(
                            f"source{process_index}.exe"
                        ),

                        remote_ip=
                            "203.0.113.99",

                        remote_port=
                            443,

                        local_port=(
                            59000
                            + process_index * 10
                            + connection_index
                        ),
                    ),

                    timestamp
                    + (
                        connection_index
                        * 0.1
                    ),
                )
            )


    return {

        "id":
            "N5-01",

        "family":
            "DDOS",

        "name":
            "Multi-source distributed target flood",

        "samples":
            samples,

        "expected_type":
            "DISTRIBUTED_DOS_BEHAVIOR",
    }


# ================================================================
# SCENARIO LIST
# ================================================================

SCENARIOS = [

    scenario_normal_single(),
    scenario_burst_below(),
    scenario_connection_burst(),

    scenario_port_scan_below(),
    scenario_port_scan(),

    scenario_dos_below(),
    scenario_dos(),

    scenario_irregular_beacon(),
    scenario_beacon(),

    scenario_ddos(),
]


# ================================================================
# RUN SCENARIO
# ================================================================

def run_scenario(
    scenario,
):

    findings = (
        run_sequence(
            scenario[
                "samples"
            ]
        )
    )


    types = (
        detection_types(
            findings
        )
    )


    failures = []


    expected_type = (
        scenario.get(
            "expected_type"
        )
    )


    forbidden_type = (
        scenario.get(
            "forbidden_type"
        )
    )


    allow_other_findings = bool(
        scenario.get(
            "allow_other_findings",
            False,
        )
    )


    # ============================================================
    # EXPECTED DETECTION
    # ============================================================

    if expected_type:

        if (
            expected_type
            not in types
        ):

            failures.append(
                {
                    "layer":
                        "NETWORK_DETECTOR",

                    "reason":
                        "EXPECTED_DETECTION_MISSING",

                    "expected":
                        expected_type,

                    "actual":
                        types,
                }
            )


    # ============================================================
    # EXPECTED BENIGN
    # ============================================================

    elif (
        not allow_other_findings
        and findings
    ):

        failures.append(
            {
                "layer":
                    "NETWORK_DETECTOR",

                "reason":
                    "UNEXPECTED_NETWORK_DETECTION",

                "actual":
                    types,
            }
        )


    # ============================================================
    # FORBIDDEN SPECIFIC TYPE
    # ============================================================

    if (
        forbidden_type

        and

        forbidden_type
        in types
    ):

        failures.append(
            {
                "layer":
                    "NETWORK_DETECTOR",

                "reason":
                    "FORBIDDEN_DETECTION_PRESENT",

                "forbidden":
                    forbidden_type,
            }
        )


    # ============================================================
    # PERSIST EXPECTED FINDING
    # ============================================================

    persistence = None


    if (
        expected_type

        and

        expected_type
        in types
    ):

        finding = next(

            value

            for value
            in findings

            if value.get(
                "detection_type"
            )
            == expected_type
        )


        persistence = (
            persist_finding(

                scenario_id=
                    scenario[
                        "id"
                    ],

                scenario_name=
                    scenario[
                        "name"
                    ],

                finding=
                    finding,

                representative_connection=
                    scenario[
                        "samples"
                    ][
                        -1
                    ][
                        0
                    ],
            )
        )


        if not persistence.get(
            "saved",
            False,
        ):

            failures.append(
                {
                    "layer":
                        "PERSISTENCE",

                    "reason":
                        "NETWORK_DETECTION_NOT_SAVED",
                }
            )


        if not persistence.get(
            "live_isolation_ok",
            False,
        ):

            failures.append(
                {
                    "layer":
                        "ISOLATION",

                    "reason":
                        "SYNTHETIC_INCREMENTED_LIVE_COUNTER",
                }
            )


    return {

        "scenario_id":
            scenario[
                "id"
            ],

        "family":
            scenario[
                "family"
            ],

        "scenario_name":
            scenario[
                "name"
            ],

        "sample_count":
            len(
                scenario[
                    "samples"
                ]
            ),

        "detection_types":
            types,

        "expected_type":
            expected_type,

        "finding_count":
            len(
                findings
            ),

        "persistence":
            persistence,

        "failures":
            failures,

        "passed":
            (
                len(
                    failures
                )
                == 0
            ),
    }


# ================================================================
# REPORT
# ================================================================

def save_report(
    results,
):

    rows = []


    for result in results:

        persistence = (
            result.get(
                "persistence"
            )

            or {}
        )


        rows.append(
            {

                "scenario_id":
                    result[
                        "scenario_id"
                    ],

                "family":
                    result[
                        "family"
                    ],

                "scenario_name":
                    result[
                        "scenario_name"
                    ],

                "sample_count":
                    result[
                        "sample_count"
                    ],

                "detections":
                    ",".join(
                        result[
                            "detection_types"
                        ]
                    ),

                "expected":
                    result.get(
                        "expected_type"
                    ),

                "finding_count":
                    result[
                        "finding_count"
                    ],

                "stored":
                    persistence.get(
                        "saved",
                        False,
                    ),

                "failure_layers":
                    ",".join(
                        sorted(
                            {
                                failure[
                                    "layer"
                                ]

                                for failure
                                in result[
                                    "failures"
                                ]
                            }
                        )
                    ),

                "passed":
                    result[
                        "passed"
                    ],
            }
        )


    csv_path = (
        REPORT_DIR
        / "network_validation.csv"
    )


    json_path = (
        REPORT_DIR
        / "network_validation.json"
    )


    with open(
        csv_path,
        "w",
        newline="",
        encoding="utf-8",
    ) as handle:

        writer = csv.DictWriter(

            handle,

            fieldnames=list(
                rows[
                    0
                ].keys()
            ),
        )


        writer.writeheader()

        writer.writerows(
            rows
        )


    with open(
        json_path,
        "w",
        encoding="utf-8",
    ) as handle:

        json.dump(
            {
                "run_id":
                    RUN_ID,

                "results":
                    results,
            },
            handle,
            indent=2,
            default=str,
        )


    return (
        rows,
        csv_path,
        json_path,
    )


# ================================================================
# MAIN
# ================================================================

def main():

    if not IS_VALIDATION_MODE:

        raise RuntimeError(
            "Network validation requires VALIDATION mode."
        )


    initialize_database()


    print(
        "=" * 90
    )

    print(
        "SENTINEL-X NETWORK BATCH VALIDATION"
    )

    print(
        "Run:",
        RUN_ID
    )

    print(
        "=" * 90
    )


    results = []


    for scenario in SCENARIOS:

        print(
            "Running",
            scenario[
                "id"
            ],
            "-",
            scenario[
                "name"
            ],
        )


        results.append(
            run_scenario(
                scenario
            )
        )


    (
        rows,
        csv_path,
        json_path,
    ) = (
        save_report(
            results
        )
    )


    print()

    print(
        "=" * 120
    )

    print(
        "NETWORK VALIDATION MATRIX"
    )

    print(
        "=" * 120
    )


    for row in rows:

        print(
            f"{row['scenario_id']:<8}"
            f"{row['family']:<20}"
            f"{str(row['detections']):<45}"
            f"{('PASS' if row['passed'] else 'FAIL'):>8}"
        )


    print(
        "=" * 120
    )


    print()

    print(
        "FAILURE ANALYSIS"
    )

    print(
        "-" * 90
    )


    failed = [

        result

        for result
        in results

        if not result[
            "passed"
        ]
    ]


    if not failed:

        print(
            "No failures."
        )

    else:

        for result in failed:

            print(
                result[
                    "scenario_id"
                ],
                "-",
                result[
                    "scenario_name"
                ],
            )

            for failure in result[
                "failures"
            ]:

                print(
                    " ",
                    failure
                )


    passed = sum(

        1

        for result
        in results

        if result[
            "passed"
        ]
    )


    print()

    print(
        "=" * 90
    )

    print(
        "FINAL SUMMARY"
    )

    print(
        "=" * 90
    )

    print(
        "Passed:",
        passed,
        "/",
        len(
            results
        )
    )

    print(
        "Failed:",
        len(
            results
        )
        - passed,
    )

    print(
        "CSV:",
        csv_path
    )

    print(
        "JSON:",
        json_path
    )

    print(
        "=" * 90
    )


if __name__ == "__main__":

    main()