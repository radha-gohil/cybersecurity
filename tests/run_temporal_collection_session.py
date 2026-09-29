from __future__ import annotations

import os
import sys
import time

from collections import (
    Counter,
)

from pathlib import (
    Path,
)


# ================================================================
# PROJECT ROOT
# ================================================================

PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[1]
)


if str(PROJECT_ROOT) not in sys.path:

    sys.path.insert(
        0,
        str(PROJECT_ROOT),
    )


from endpoint.collectors.process_monitor import (
    ProcessMonitor,
)

from ai_detection.behavior.process_context_tracker import (
    shared_process_behavior_context,
)

from ai_detection.behavior.behavior_feature_store import (
    get_connection,
)


# ================================================================
# SENTINEL-X CONTROLLED TEMPORAL COLLECTION SESSION
#
# IMPORTANT:
#
# This is a DATA COLLECTION runner.
#
# It deliberately does NOT call:
#
#       ProcessMonitor.initialize()
#
# because initialize() scores every process on the machine and is
# unnecessarily expensive for building the temporal dataset.
#
#
# Instead:
#
#   1. Take one process snapshot.
#   2. Select stable long-running processes.
#   3. Keep the SAME PIDs.
#   4. Sample them repeatedly.
#   5. Run IF + Autoencoder v2.
#   6. Persist paired results normally.
#
# This gives us genuine temporal sequences.
# ================================================================


# ================================================================
# CONFIGURATION
# ================================================================

SAMPLE_INTERVAL_SECONDS = 15.0


# 16 processes provide reasonable diversity while preventing one
# complete machine-wide AI sweep from taking too long.

TARGET_PROCESS_COUNT = 16


# With:
#
# sequence length = 8
# stride          = 2
#
# 20 observations for one process create:
#
# (20 - 8) / 2 + 1 = 7 windows
#
# 16 processes can therefore create roughly 112 windows if they
# remain alive throughout collection.

TARGET_COLLECTION_CYCLES = 20


# Prefer processes already alive for at least this long.

MINIMUM_PROCESS_AGE_SECONDS = 120.0


# Ignore special Windows pseudo-processes.

EXCLUDED_PROCESS_NAMES = {

    "system idle process",

    "system",

    "registry",

    "unknown",
}


# ================================================================
# DATABASE
# ================================================================

def count_paired_records() -> int:

    connection = (
        get_connection()
    )


    try:

        row = (
            connection.execute(
                """
                SELECT COUNT(*) AS count_value

                FROM (

                    SELECT
                        feature_record_id

                    FROM behavior_model_results

                    WHERE model_family IN (
                        'isolation_forest',
                        'autoencoder'
                    )

                    GROUP BY feature_record_id

                    HAVING COUNT(
                        DISTINCT model_family
                    ) = 2
                )
                """
            )
            .fetchone()
        )


        return int(
            row[
                "count_value"
            ]
        )


    finally:

        connection.close()


# ================================================================
# MODEL RESULT HEALTH
# ================================================================

def valid_ai_result(
    result,
) -> bool:

    if not result:

        return False


    if not result.get(
        "available",
        False,
    ):

        return False


    if result.get(
        "prediction_failed",
        False,
    ):

        return False


    return True


# ================================================================
# STABLE PROCESS SELECTION
# ================================================================

def select_stable_processes(
    snapshot: dict,
    limit: int,
) -> dict:

    current_time = (
        time.time()
    )


    current_python_pid = (
        os.getpid()
    )


    candidates = []


    for (
        pid,
        process_info,
    ) in snapshot.items():

        if pid is None:

            continue


        if pid == current_python_pid:

            continue


        name = (

            str(

                process_info.get(
                    "name"
                )

                or "UNKNOWN"
            )
            .strip()
            .lower()
        )


        if name in EXCLUDED_PROCESS_NAMES:

            continue


        create_time = (
            process_info.get(
                "create_time"
            )
        )


        try:

            create_time = float(
                create_time
            )

        except (
            TypeError,
            ValueError,
        ):

            continue


        process_age = (

            current_time
            - create_time
        )


        if (

            process_age
            < MINIMUM_PROCESS_AGE_SECONDS

        ):

            continue


        candidates.append(
            {

                "pid":
                    int(
                        pid
                    ),

                "name":
                    name,

                "age":
                    process_age,

                "create_time":
                    create_time,

                "process_info":
                    process_info,
            }
        )


    # ------------------------------------------------------------
    # Oldest processes first.
    #
    # Long-running services/applications are less likely to exit
    # during sequence collection.
    # ------------------------------------------------------------

    candidates.sort(

        key=lambda item:
            item[
                "age"
            ],

        reverse=True,
    )


    selected = {}


    for item in candidates[
        :limit
    ]:

        selected[
            item[
                "pid"
            ]
        ] = {

            "name":
                item[
                    "name"
                ],

            "create_time":
                item[
                    "create_time"
                ],

            "initial_age":
                item[
                    "age"
                ],
        }


    return selected


# ================================================================
# REPLACE DEAD PROCESS
# ================================================================

def refill_selected_processes(

    selected: dict,

    snapshot: dict,

) -> None:

    if (

        len(
            selected
        )

        >= TARGET_PROCESS_COUNT

    ):

        return


    needed = (

        TARGET_PROCESS_COUNT

        - len(
            selected
        )
    )


    candidates = (
        select_stable_processes(

            snapshot,

            limit=
                TARGET_PROCESS_COUNT
                * 3,
        )
    )


    for (
        pid,
        metadata,
    ) in candidates.items():

        if pid in selected:

            continue


        selected[
            pid
        ] = metadata


        print(

            "Added replacement process | "
            f"PID={pid} | "
            f"Process={metadata['name']}"
        )


        needed -= 1


        if needed <= 0:

            break


# ================================================================
# PRINT SELECTED PROCESSES
# ================================================================

def print_selected_processes(
    selected,
):

    print()

    print(
        "=" * 90
    )

    print(
        "SELECTED TEMPORAL PROCESSES"
    )

    print(
        "=" * 90
    )


    print(

        f"{'PID':<10}"
        f"{'Process':<38}"
        f"{'Initial Age (s)':>18}"
    )


    print(
        "-" * 90
    )


    for (
        pid,
        metadata,
    ) in selected.items():

        print(

            f"{pid:<10}"

            f"{metadata['name']:<38}"

            f"{metadata['initial_age']:>18.2f}"
        )


# ================================================================
# COLLECT ONE PROCESS
# ================================================================

def collect_process_sample(

    monitor: ProcessMonitor,

    process_info: dict,

):

    pid = (
        process_info.get(
            "pid"
        )
    )


    ppid = (
        process_info.get(
            "ppid"
        )
    )


    # ============================================================
    # UPDATE TEMPORAL CONTEXT
    # ============================================================

    shared_process_behavior_context.record_process_activity(
        pid
    )


    if ppid is not None:

        shared_process_behavior_context.record_child_process(
            ppid
        )


    context = (

        shared_process_behavior_context
        .get_context(
            pid
        )
    )


    # ============================================================
    # RUN REAL FEATURE + MULTI-AI PIPELINE
    # ============================================================

    result = (

        monitor.collect_ai_behavior_features(

            process_info=
                process_info,

            context=
                context,
        )
    )


    isolation_result = (
        result.get(
            "isolation_forest"
        )
    )


    autoencoder_result = (
        result.get(
            "autoencoder"
        )
    )


    success = (

        result.get(
            "record_id"
        )
        is not None

        and

        valid_ai_result(
            isolation_result
        )

        and

        valid_ai_result(
            autoencoder_result
        )
    )


    return {

        "success":
            success,

        "record_id":
            result.get(
                "record_id"
            ),

        "isolation":
            isolation_result,

        "autoencoder":
            autoencoder_result,

        "error":
            result.get(
                "error"
            ),
    }


# ================================================================
# MAIN
# ================================================================

def main():

    print()

    print(
        "=" * 90
    )

    print(
        "SENTINEL-X CONTROLLED TEMPORAL COLLECTION"
    )

    print(
        "=" * 90
    )


    print()

    print(
        "Sampling interval :",
        SAMPLE_INTERVAL_SECONDS,
        "seconds",
    )


    print(
        "Target processes  :",
        TARGET_PROCESS_COUNT,
    )


    print(
        "Target cycles     :",
        TARGET_COLLECTION_CYCLES,
    )


    print(
        "Sequence target   : 8 observations"
    )


    # ============================================================
    # CREATE PROCESS MONITOR
    #
    # IMPORTANT:
    #
    # We intentionally do NOT call monitor.initialize().
    # ============================================================

    print()

    print(
        "[1] Creating ProcessMonitor without full initialization..."
    )


    monitor = (
        ProcessMonitor(
            poll_interval=2.0
        )
    )


    # ============================================================
    # VERIFY MODELS
    # ============================================================

    isolation_status = (

        monitor
        .isolation_forest_predictor
        .get_status()
    )


    autoencoder_status = (

        monitor
        .autoencoder_predictor
        .get_status()
    )


    print()

    print(
        "Isolation Forest:"
    )


    print(
        "  Available:",
        isolation_status.get(
            "available"
        ),
    )


    print(
        "  Version  :",
        isolation_status.get(
            "model_version"
        ),
    )


    print()

    print(
        "Autoencoder:"
    )


    print(
        "  Available :",
        autoencoder_status.get(
            "available"
        ),
    )


    print(
        "  Version   :",
        autoencoder_status.get(
            "model_version"
        ),
    )


    print(
        "  Activation:",
        autoencoder_status.get(
            "hidden_activation"
        ),
    )


    if not isolation_status.get(
        "available",
        False,
    ):

        raise RuntimeError(

            "Isolation Forest is unavailable."
        )


    if not autoencoder_status.get(
        "available",
        False,
    ):

        raise RuntimeError(

            "Autoencoder is unavailable."
        )


    # ============================================================
    # INITIAL SNAPSHOT
    # ============================================================

    print()

    print(
        "[2] Taking process snapshot..."
    )


    snapshot = (
        monitor.get_process_snapshot()
    )


    print(
        "Processes visible:",
        len(
            snapshot
        ),
    )


    # ============================================================
    # SELECT STABLE PROCESSES
    # ============================================================

    print()

    print(
        "[3] Selecting stable processes..."
    )


    selected = (
        select_stable_processes(

            snapshot=

                snapshot,

            limit=
                TARGET_PROCESS_COUNT,
        )
    )


    if not selected:

        raise RuntimeError(

            "Unable to find stable processes "
            "for temporal collection."
        )


    print_selected_processes(
        selected
    )


    # ============================================================
    # COUNTERS
    # ============================================================

    successful_samples = Counter()


    failed_samples = Counter()


    initial_paired_count = (
        count_paired_records()
    )


    print()

    print(
        "Initial paired database records:",
        initial_paired_count,
    )


    print()

    print(
        "=" * 90
    )

    print(
        "TEMPORAL COLLECTION STARTED"
    )

    print(
        "=" * 90
    )


    # ============================================================
    # COLLECTION
    # ============================================================

    try:

        for cycle in range(

            1,

            TARGET_COLLECTION_CYCLES + 1,
        ):

            cycle_started = (
                time.perf_counter()
            )


            print()

            print(
                "=" * 90
            )


            print(

                f"CYCLE "
                f"{cycle}/"
                f"{TARGET_COLLECTION_CYCLES}"
            )


            print(
                "=" * 90
            )


            # ====================================================
            # REFRESH LIVE PROCESS INFORMATION
            # ====================================================

            snapshot = (
                monitor.get_process_snapshot()
            )


            # ====================================================
            # REMOVE DEAD / PID-REUSED PROCESSES
            # ====================================================

            dead_pids = []


            for (
                pid,
                metadata,
            ) in selected.items():

                process_info = (
                    snapshot.get(
                        pid
                    )
                )


                if process_info is None:

                    dead_pids.append(
                        pid
                    )

                    continue


                try:

                    current_create_time = float(

                        process_info.get(
                            "create_time"
                        )
                    )

                except (
                    TypeError,
                    ValueError,
                ):

                    dead_pids.append(
                        pid
                    )

                    continue


                # ------------------------------------------------
                # PID reuse protection
                # ------------------------------------------------

                if (

                    abs(

                        current_create_time

                        - metadata[
                            "create_time"
                        ]

                    )

                    > 1.0

                ):

                    dead_pids.append(
                        pid
                    )


            for pid in dead_pids:

                metadata = (
                    selected.pop(
                        pid
                    )
                )


                print(

                    "Process removed | "
                    f"PID={pid} | "
                    f"Process={metadata['name']}"
                )


            # ====================================================
            # REPLACE LOST PROCESSES
            # ====================================================

            refill_selected_processes(

                selected=
                    selected,

                snapshot=
                    snapshot,
            )


            cycle_success = 0

            cycle_failed = 0


            # ====================================================
            # COLLECT SELECTED PROCESSES
            # ====================================================

            for (
                pid,
                metadata,
            ) in list(
                selected.items()
            ):

                process_info = (
                    snapshot.get(
                        pid
                    )
                )


                if process_info is None:

                    continue


                process_name = (

                    process_info.get(
                        "name"
                    )

                    or metadata[
                        "name"
                    ]
                )


                try:

                    result = (
                        collect_process_sample(

                            monitor=
                                monitor,

                            process_info=
                                process_info,
                        )
                    )


                    if result[
                        "success"
                    ]:

                        successful_samples[
                            pid
                        ] += 1


                        cycle_success += 1


                        isolation_score = (

                            result[
                                "isolation"
                            ].get(
                                "anomaly_confidence"
                            )
                        )


                        autoencoder_score = (

                            result[
                                "autoencoder"
                            ].get(
                                "anomaly_confidence"
                            )
                        )


                        print(

                            f"OK | "
                            f"PID={pid:<7} | "
                            f"{process_name:<30} | "
                            f"Depth="
                            f"{successful_samples[pid]:<3} | "
                            f"IF={str(isolation_score):<6} | "
                            f"AE={str(autoencoder_score):<6}"
                        )


                    else:

                        failed_samples[
                            pid
                        ] += 1


                        cycle_failed += 1


                        print(

                            f"FAIL | "
                            f"PID={pid:<7} | "
                            f"{process_name:<30} | "
                            f"Error="
                            f"{result.get('error')}"
                        )


                except KeyboardInterrupt:

                    raise


                except Exception as error:

                    failed_samples[
                        pid
                    ] += 1


                    cycle_failed += 1


                    print(

                        f"ERROR | "
                        f"PID={pid:<7} | "
                        f"{process_name:<30} | "
                        f"{error}"
                    )


            # ====================================================
            # CYCLE SUMMARY
            # ====================================================

            cycle_duration = (

                time.perf_counter()

                - cycle_started
            )


            current_paired = (
                count_paired_records()
            )


            deepest = (

                max(
                    successful_samples.values()
                )

                if successful_samples

                else 0
            )


            reached_sequence_target = sum(

                1

                for count in (
                    successful_samples.values()
                )

                if count >= 8
            )


            print()

            print(
                "Cycle summary:"
            )


            print(
                "  Successful samples:",
                cycle_success,
            )


            print(
                "  Failed samples    :",
                cycle_failed,
            )


            print(
                "  Cycle duration    :",
                f"{cycle_duration:.2f}s",
            )


            print(
                "  Deepest sequence  :",
                deepest,
            )


            print(
                "  Processes >=8     :",
                reached_sequence_target,
            )


            print(
                "  Paired DB records :",
                current_paired,
            )


            # ====================================================
            # START-TO-START INTERVAL
            # ====================================================

            if cycle < TARGET_COLLECTION_CYCLES:

                remaining = (

                    SAMPLE_INTERVAL_SECONDS

                    - cycle_duration
                )


                if remaining > 0:

                    print(

                        "  Interval control  : "
                        f"sleep {remaining:.2f}s"
                    )


                    time.sleep(
                        remaining
                    )


                else:

                    print(

                        "  Interval control  : "
                        "inference exceeded configured interval"
                    )


    except KeyboardInterrupt:

        print()

        print(
            "Collection interrupted by user."
        )


    # ============================================================
    # FINAL SUMMARY
    # ============================================================

    final_paired_count = (
        count_paired_records()
    )


    print()

    print(
        "=" * 90
    )

    print(
        "TEMPORAL COLLECTION SUMMARY"
    )

    print(
        "=" * 90
    )


    print()

    print(
        "Paired records before:",
        initial_paired_count,
    )


    print(
        "Paired records after :",
        final_paired_count,
    )


    print(
        "New paired records   :",
        (
            final_paired_count

            - initial_paired_count
        ),
    )


    print()

    print(

        f"{'PID':<9}"
        f"{'Process':<34}"
        f"{'Success':>10}"
        f"{'Failures':>10}"
    )


    print(
        "-" * 70
    )


    final_snapshot = (
        monitor.get_process_snapshot()
    )


    for (
        pid,
        metadata,
    ) in sorted(

        selected.items(),

        key=lambda item:
            successful_samples[
                item[
                    0
                ]
            ],

        reverse=True,
    ):

        current_info = (
            final_snapshot.get(
                pid,
                {}
            )
        )


        name = (

            current_info.get(
                "name"
            )

            or metadata[
                "name"
            ]
        )


        print(

            f"{pid:<9}"

            f"{name:<34}"

            f"{successful_samples[pid]:>10}"

            f"{failed_samples[pid]:>10}"
        )


    processes_with_8 = sum(

        1

        for samples in (
            successful_samples.values()
        )

        if samples >= 8
    )


    print()

    print(
        "Processes with >=8 observations:",
        processes_with_8,
    )


    print()


    if processes_with_8 > 0:

        print(
            "TEMPORAL COLLECTION: SEQUENCE DATA AVAILABLE"
        )


        print()

        print(
            "Next command:"
        )


        print(
            "python -m "
            "ai_detection.temporal."
            "process_sequence_dataset_builder_v2"
        )


    else:

        print(
            "TEMPORAL COLLECTION: INSUFFICIENT DEPTH"
        )


        print()

        print(
            "No process reached the required "
            "8-observation sequence depth."
        )


# ================================================================
# ENTRY POINT
# ================================================================

if __name__ == "__main__":

    main()