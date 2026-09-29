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

from typing import (
    Any,
    Dict,
    Optional,
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


# ================================================================
# SENTINEL-X IMPORTS
# ================================================================

from endpoint.collectors.fusion_v3_process_monitor import (
    FusionV3ProcessMonitor,
)


from ai_detection.behavior.process_context_tracker import (
    shared_process_behavior_context,
)


# ================================================================
# SENTINEL-X
# REAL LIVE FUSION V3 SHADOW VALIDATION
#
# Purpose:
#
#   1. Use genuine Windows process telemetry.
#   2. Execute existing Phase-2 detectors.
#   3. Execute Temporal Transformer.
#   4. Execute Fusion v3.
#   5. Verify evidence mapping.
#   6. Compare Fusion v2 and Fusion v3.
#   7. Keep Fusion v3 in SHADOW_VALIDATION.
#
#
# IMPORTANT:
#
# This script does NOT call monitor.initialize().
#
# It therefore avoids the expensive full-machine startup baseline.
#
# It samples a controlled group of stable processes repeatedly.
# ================================================================


# ================================================================
# CONFIGURATION
# ================================================================

TARGET_PROCESS_COUNT = 8


TARGET_CYCLES = 10


SAMPLE_INTERVAL_SECONDS = 15.0


MINIMUM_PROCESS_AGE_SECONDS = 120.0


EXCLUDED_PROCESS_NAMES = {

    "system idle process",

    "system",

    "registry",

    "secure system",

    "memory compression",

    "unknown",
}


# ================================================================
# PROCESS SELECTION
# ================================================================

def select_stable_processes(
    snapshot: Dict[int, Dict[str, Any]],
    limit: int,
) -> Dict[int, Dict[str, Any]]:

    now = time.time()

    current_pid = os.getpid()

    candidates = []


    for (
        pid,
        process_info,
    ) in snapshot.items():

        try:

            pid_value = int(
                pid
            )

        except (
            TypeError,
            ValueError,
        ):

            continue


        if pid_value == current_pid:

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

            create_time_value = float(
                create_time
            )

        except (
            TypeError,
            ValueError,
        ):

            continue


        age = (
            now
            - create_time_value
        )


        if age < MINIMUM_PROCESS_AGE_SECONDS:

            continue


        candidates.append(
            {
                "pid":
                    pid_value,

                "name":
                    name,

                "create_time":
                    create_time_value,

                "age":
                    age,
            }
        )


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

            "age":
                item[
                    "age"
                ],
        }


    return selected


# ================================================================
# PHASE-2 / FUSION V2 RESULT LOOKUP
# ================================================================

def find_fusion_v2(
    result: Dict[str, Any],
) -> Optional[
    Dict[str, Any]
]:

    candidate_keys = [

        "fusion_v2",

        "fusion",

        "threat_fusion",

        "fusion_result",

        "process_threat_fusion",
    ]


    for key in candidate_keys:

        value = (
            result.get(
                key
            )
        )


        if not isinstance(
            value,
            dict,
        ):

            continue


        version = str(

            value.get(
                "fusion_version"
            )

            or value.get(
                "version"
            )

            or ""
        ).lower()


        # --------------------------------------------------------
        # Prefer explicit v2.
        # --------------------------------------------------------

        if "v2" in version:

            return value


        # --------------------------------------------------------
        # Fallback if structure clearly looks like threat fusion.
        # --------------------------------------------------------

        if (

            "fusion_score" in value

            or

            "final_score" in value

            or

            "severity" in value

        ):

            return value


    return None


# ================================================================
# SCORE EXTRACTION
# ================================================================

def extract_score(
    result: Optional[
        Dict[str, Any]
    ],
) -> Optional[float]:

    if not isinstance(
        result,
        dict,
    ):

        return None


    for key in [

        "fusion_score",

        "final_score",

        "score",

        "risk_score",

        "threat_score",

    ]:

        if key not in result:

            continue


        try:

            return float(
                result[
                    key
                ]
            )


        except (
            TypeError,
            ValueError,
        ):

            continue


    return None


# ================================================================
# V2 SEVERITY
# ================================================================

def extract_severity(
    result: Optional[
        Dict[str, Any]
    ],
) -> Optional[str]:

    if not isinstance(
        result,
        dict,
    ):

        return None


    for key in [

        "severity",

        "risk_level",

        "threat_level",

    ]:

        value = (
            result.get(
                key
            )
        )


        if value is not None:

            return str(
                value
            )


    return None


# ================================================================
# PRINT SELECTED PROCESSES
# ================================================================

def print_selected(
    selected: Dict[
        int,
        Dict[str, Any],
    ],
) -> None:

    print()

    print(
        "=" * 100
    )

    print(
        "SELECTED LIVE PROCESSES"
    )

    print(
        "=" * 100
    )


    print(

        f"{'PID':<10}"
        f"{'Process':<40}"
        f"{'Age (seconds)':>18}"
    )


    print(
        "-" * 100
    )


    for (
        pid,
        metadata,
    ) in selected.items():

        print(

            f"{pid:<10}"

            f"{metadata['name']:<40}"

            f"{metadata['age']:>18.2f}"
        )


# ================================================================
# CATEGORY FORMAT
# ================================================================

def category_text(
    category: Optional[
        Dict[str, Any]
    ],
) -> str:

    if not isinstance(
        category,
        dict,
    ):

        return "MISSING"


    available = bool(
        category.get(
            "available",
            False,
        )
    )


    score = category.get(
        "score"
    )


    active = category.get(
        "active"
    )


    strong = category.get(
        "strong"
    )


    return (

        f"A={available} "
        f"S={score} "
        f"Active={active} "
        f"Strong={strong}"
    )


# ================================================================
# MAIN
# ================================================================

def main():

    print()

    print(
        "=" * 100
    )

    print(
        "SENTINEL-X REAL LIVE FUSION V3 SHADOW VALIDATION"
    )

    print(
        "=" * 100
    )


    print()

    print(
        "Processes :",
        TARGET_PROCESS_COUNT,
    )


    print(
        "Cycles    :",
        TARGET_CYCLES,
    )


    print(
        "Interval  :",
        SAMPLE_INTERVAL_SECONDS,
        "seconds",
    )


    # ============================================================
    # CREATE MONITOR
    # ============================================================

    print()

    print(
        "[1] Creating FusionV3ProcessMonitor..."
    )


    monitor = (
        FusionV3ProcessMonitor(
            poll_interval=2.0
        )
    )


    initial_status = (
        monitor.get_fusion_v3_status()
    )


    print()

    print(
        "Fusion version:",
        initial_status[
            "fusion_version"
        ],
    )


    print(
        "Fusion mode:",
        initial_status[
            "operating_mode"
        ],
    )


    print(
        "Temporal predictor available:",
        initial_status[
            "temporal"
        ][
            "predictor"
        ][
            "available"
        ],
    )


    print(
        "Temporal model version:",
        initial_status[
            "temporal"
        ][
            "predictor"
        ][
            "model_version"
        ],
    )


    print(
        "Temporal embedding:",
        initial_status[
            "temporal"
        ][
            "predictor"
        ][
            "representation_dimension"
        ],
    )


    if (

        initial_status[
            "operating_mode"
        ]

        != "SHADOW_VALIDATION"

    ):

        raise RuntimeError(

            "Fusion v3 must remain in "
            "SHADOW_VALIDATION for this test."
        )


    if not (

        initial_status[
            "temporal"
        ][
            "predictor"
        ][
            "available"
        ]

    ):

        raise RuntimeError(

            "Temporal Transformer is unavailable."
        )


    # ============================================================
    # INITIAL DATABASE COUNTS
    # ============================================================

    initial_fusion_count = (
        monitor
        .fusion_v3_store
        .count()
    )


    initial_temporal_count = (
        monitor
        .temporal_result_store
        .count()
    )


    # ============================================================
    # INITIAL SNAPSHOT
    # ============================================================

    print()

    print(
        "[2] Taking real process snapshot..."
    )


    snapshot = (
        monitor.get_process_snapshot()
    )


    print(
        "Visible processes:",
        len(
            snapshot
        ),
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

            "No stable live processes were found."
        )


    print_selected(
        selected
    )


    # ============================================================
    # COUNTERS
    # ============================================================

    counters = Counter()


    process_depths = Counter()


    diagnostic_keys_printed = False


    # ============================================================
    # COLLECTION
    # ============================================================

    print()

    print(
        "=" * 100
    )

    print(
        "LIVE SHADOW COLLECTION STARTED"
    )

    print(
        "=" * 100
    )


    try:

        for cycle in range(
            1,
            TARGET_CYCLES + 1,
        ):

            cycle_started = (
                time.perf_counter()
            )


            print()

            print(
                "=" * 100
            )


            print(

                f"CYCLE "
                f"{cycle}/"
                f"{TARGET_CYCLES}"
            )


            print(
                "=" * 100
            )


            snapshot = (
                monitor.get_process_snapshot()
            )


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


                # =================================================
                # PROCESS EXITED
                # =================================================

                if process_info is None:

                    print(

                        f"SKIP | "
                        f"PID={pid} | "
                        f"{metadata['name']} | "
                        "process exited"
                    )


                    counters[
                        "process_exited"
                    ] += 1


                    continue


                # =================================================
                # PID REUSE CHECK
                # =================================================

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

                    counters[
                        "invalid_create_time"
                    ] += 1

                    continue


                if (

                    abs(

                        current_create_time

                        - metadata[
                            "create_time"
                        ]

                    )

                    > 1.0

                ):

                    print(

                        f"SKIP | "
                        f"PID={pid} | "
                        "PID reuse detected"
                    )


                    counters[
                        "pid_reuse"
                    ] += 1


                    continue


                # =================================================
                # BUILD REAL CONTEXT
                # =================================================

                shared_process_behavior_context.record_process_activity(
                    pid
                )


                ppid = (
                    process_info.get(
                        "ppid"
                    )
                )


                if ppid is not None:

                    try:

                        shared_process_behavior_context.record_child_process(
                            int(
                                ppid
                            )
                        )

                    except (
                        TypeError,
                        ValueError,
                    ):

                        pass


                context = (
                    shared_process_behavior_context
                    .get_context(
                        pid
                    )
                )


                # =================================================
                # REAL LIVE PIPELINE
                # =================================================

                try:

                    result = (
                        monitor.collect_ai_behavior_features(

                            process_info=
                                process_info,

                            context=
                                context,
                        )
                    )


                except KeyboardInterrupt:

                    raise


                except Exception as error:

                    counters[
                        "pipeline_exception"
                    ] += 1


                    print(

                        f"ERROR | "
                        f"PID={pid:<7} | "
                        f"{metadata['name']:<30} | "
                        f"{error}"
                    )


                    continue


                counters[
                    "samples"
                ] += 1


                if not isinstance(
                    result,
                    dict,
                ):

                    counters[
                        "invalid_result"
                    ] += 1

                    continue


                # =================================================
                # FEATURE RECORD
                # =================================================

                record_id = (

                    result.get(
                        "record_id"
                    )

                    or

                    result.get(
                        "feature_record_id"
                    )
                )


                if record_id is not None:

                    counters[
                        "feature_record"
                    ] += 1


                # =================================================
                # TEMPORAL WRAPPER
                # =================================================

                temporal_wrapper = (
                    result.get(
                        "temporal",
                        {}
                    )
                )


                temporal_state = (

                    temporal_wrapper.get(
                        "state"
                    )

                    if isinstance(
                        temporal_wrapper,
                        dict,
                    )

                    else None
                )


                temporal_depth = (

                    temporal_wrapper.get(
                        "depth",
                        0,
                    )

                    if isinstance(
                        temporal_wrapper,
                        dict,
                    )

                    else 0
                )


                try:

                    process_depths[
                        pid
                    ] = max(

                        process_depths[
                            pid
                        ],

                        int(
                            temporal_depth
                            or 0
                        ),
                    )

                except (
                    TypeError,
                    ValueError,
                ):

                    pass


                if (

                    temporal_state

                    == "COLLECTING_HISTORY"

                ):

                    counters[
                        "temporal_collecting"
                    ] += 1


                elif (

                    temporal_state

                    == "TEMPORAL_INFERENCE_COMPLETE"

                ):

                    counters[
                        "temporal_inference"
                    ] += 1


                elif temporal_state:

                    counters[
                        "temporal_other_state"
                    ] += 1


                # =================================================
                # FUSION V3
                # =================================================

                fusion_v3 = (
                    result.get(
                        "fusion_v3"
                    )
                )


                if not isinstance(
                    fusion_v3,
                    dict,
                ):

                    counters[
                        "fusion_v3_missing"
                    ] += 1


                    print(

                        f"MISS | "
                        f"PID={pid:<7} | "
                        f"{metadata['name']:<30} | "
                        "Fusion v3 missing"
                    )


                    continue


                if (

                    fusion_v3.get(
                        "state"
                    )

                    == "FUSION_V3_EXCEPTION"

                ):

                    counters[
                        "fusion_v3_exception"
                    ] += 1


                    print(

                        f"FAIL | "
                        f"PID={pid:<7} | "
                        f"{metadata['name']:<30} | "
                        f"{fusion_v3.get('error')}"
                    )


                    continue


                if "fusion_score" not in fusion_v3:

                    counters[
                        "fusion_v3_incomplete"
                    ] += 1

                    continue


                counters[
                    "fusion_v3_success"
                ] += 1


                # =================================================
                # CATEGORY MAPPING
                # =================================================

                categories = (
                    fusion_v3.get(
                        "categories",
                        {}
                    )
                )


                rule_category = (
                    categories.get(
                        "rules",
                        {}
                    )
                )


                statistical_category = (
                    categories.get(
                        "statistical",
                        {}
                    )
                )


                behavioral_category = (
                    categories.get(
                        "behavioral_ai",
                        {}
                    )
                )


                temporal_category = (
                    categories.get(
                        "temporal_ai",
                        {}
                    )
                )


                if rule_category.get(
                    "available",
                    False,
                ):

                    counters[
                        "rule_available"
                    ] += 1


                if statistical_category.get(
                    "available",
                    False,
                ):

                    counters[
                        "statistical_available"
                    ] += 1


                if behavioral_category.get(
                    "available",
                    False,
                ):

                    counters[
                        "behavioral_available"
                    ] += 1


                if temporal_category.get(
                    "available",
                    False,
                ):

                    counters[
                        "temporal_available"
                    ] += 1


                if fusion_v3.get(
                    "should_alert",
                    False,
                ):

                    counters[
                        "fusion_v3_alert"
                    ] += 1


                # =================================================
                # FIND FUSION V2
                # =================================================

                fusion_v2 = (
                    find_fusion_v2(
                        result
                    )
                )


                v2_score = (
                    extract_score(
                        fusion_v2
                    )
                )


                v2_severity = (
                    extract_severity(
                        fusion_v2
                    )
                )


                if fusion_v2 is not None:

                    counters[
                        "fusion_v2_found"
                    ] += 1


                # =================================================
                # PRINT STRUCTURE ONCE IF MAPPING IS MISSING
                # =================================================

                if (

                    not diagnostic_keys_printed

                    and

                    (
                        not rule_category.get(
                            "available",
                            False,
                        )

                        or

                        not statistical_category.get(
                            "available",
                            False,
                        )
                    )

                ):

                    print()

                    print(
                        "DIAGNOSTIC — REAL PHASE-2 RESULT KEYS"
                    )


                    print(
                        sorted(
                            result.keys()
                        )
                    )


                    print()


                    diagnostic_keys_printed = True


                # =================================================
                # DISPLAY SAMPLE
                # =================================================

                print()

                print(

                    f"PID={pid} | "
                    f"Process="
                    f"{process_info.get('name')}"
                )


                print(
                    "  Temporal state :",
                    temporal_state,
                )


                print(
                    "  Temporal depth :",
                    temporal_depth,
                )


                print(
                    "  Rules          :",
                    category_text(
                        rule_category
                    ),
                )


                print(
                    "  Statistical    :",
                    category_text(
                        statistical_category
                    ),
                )


                print(
                    "  Behavioral AI  :",
                    category_text(
                        behavioral_category
                    ),
                )


                print(
                    "  Temporal AI    :",
                    category_text(
                        temporal_category
                    ),
                )


                print(

                    "  Fusion v3      : "
                    f"Score="
                    f"{fusion_v3['fusion_score']} | "
                    f"Severity="
                    f"{fusion_v3['severity']} | "
                    f"Alert="
                    f"{fusion_v3['should_alert']}"
                )


                if fusion_v2 is not None:

                    print(

                        "  Fusion v2      : "
                        f"Score={v2_score} | "
                        f"Severity={v2_severity}"
                    )


                    if v2_score is not None:

                        difference = (

                            float(
                                fusion_v3[
                                    "fusion_score"
                                ]
                            )

                            - float(
                                v2_score
                            )
                        )


                        print(

                            "  v3-v2 Δ score : "
                            f"{difference:+.2f}"
                        )


                else:

                    print(
                        "  Fusion v2      : NOT FOUND"
                    )


            # ====================================================
            # CYCLE STATUS
            # ====================================================

            cycle_duration = (

                time.perf_counter()

                - cycle_started
            )


            temporal_status = (
                monitor
                .temporal_buffer
                .get_status()
            )


            print()

            print(
                "-" * 100
            )


            print(

                "Cycle summary | "
                f"Duration="
                f"{cycle_duration:.2f}s | "
                f"TemporalMaxDepth="
                f"{temporal_status['maximum_depth']} | "
                f"ReadyTemporalProcesses="
                f"{temporal_status['ready_process_instances']} | "
                f"FusionV3Success="
                f"{counters['fusion_v3_success']}"
            )


            print(
                "-" * 100
            )


            if cycle < TARGET_CYCLES:

                remaining = (

                    SAMPLE_INTERVAL_SECONDS

                    - cycle_duration
                )


                if remaining > 0:

                    time.sleep(
                        remaining
                    )


    except KeyboardInterrupt:

        print()

        print(
            "Validation interrupted by user."
        )


    # ============================================================
    # FINAL DATABASE STATUS
    # ============================================================

    final_fusion_count = (
        monitor
        .fusion_v3_store
        .count()
    )


    final_temporal_count = (
        monitor
        .temporal_result_store
        .count()
    )


    new_fusion_results = (

        final_fusion_count

        - initial_fusion_count
    )


    new_temporal_results = (

        final_temporal_count

        - initial_temporal_count
    )


    # ============================================================
    # REPORT
    # ============================================================

    print()

    print(
        "=" * 100
    )

    print(
        "REAL LIVE FUSION V3 SHADOW REPORT"
    )

    print(
        "=" * 100
    )


    print()

    print(
        "Samples processed             :",
        counters[
            "samples"
        ],
    )


    print(
        "Feature records               :",
        counters[
            "feature_record"
        ],
    )


    print(
        "Fusion v3 successes           :",
        counters[
            "fusion_v3_success"
        ],
    )


    print(
        "Fusion v3 exceptions          :",
        counters[
            "fusion_v3_exception"
        ],
    )


    print()

    print(
        "Rule evidence mapped          :",
        counters[
            "rule_available"
        ],
    )


    print(
        "Statistical evidence mapped   :",
        counters[
            "statistical_available"
        ],
    )


    print(
        "Behavioral AI mapped          :",
        counters[
            "behavioral_available"
        ],
    )


    print(
        "Temporal AI mapped            :",
        counters[
            "temporal_available"
        ],
    )


    print()

    print(
        "Temporal collecting-history   :",
        counters[
            "temporal_collecting"
        ],
    )


    print(
        "Temporal inferences completed :",
        counters[
            "temporal_inference"
        ],
    )


    print()

    print(
        "Fusion v2 results found       :",
        counters[
            "fusion_v2_found"
        ],
    )


    print(
        "Fusion v3 alert candidates    :",
        counters[
            "fusion_v3_alert"
        ],
    )


    print()

    print(
        "New Fusion-v3 DB rows         :",
        new_fusion_results,
    )


    print(
        "New Temporal DB rows          :",
        new_temporal_results,
    )


    print()

    print(
        "Maximum per-process depths:"
    )


    for (
        pid,
        depth,
    ) in process_depths.most_common():

        print(

            f"  PID={pid:<8} "
            f"Depth={depth}"
        )


    # ============================================================
    # READINESS CHECKS
    # ============================================================

    checks = {
        "phase2_feature_generation":
            counters[
                "feature_record"
            ] > 0,

        "fusion_v3_execution":
            counters[
                "fusion_v3_success"
            ] > 0,

        "rule_mapping":
            counters[
                "rule_available"
            ] > 0,

        "statistical_mapping":
            counters[
                "statistical_available"
            ] > 0,

        "behavioral_ai_mapping":
            counters[
                "behavioral_available"
            ] > 0,

        "temporal_inference":
            counters[
                "temporal_inference"
            ] > 0,

        "temporal_mapping":
            counters[
                "temporal_available"
            ] > 0,

        "fusion_v2_comparison":
            counters[
                "fusion_v2_found"
            ] > 0,

        "fusion_v3_persistence":
            new_fusion_results > 0,

        "temporal_persistence":
            new_temporal_results > 0,

        "no_fusion_v3_exceptions":
            counters[
                "fusion_v3_exception"
            ] == 0,
    }


    print()

    print(
        "=" * 100
    )

    print(
        "READINESS CHECKS"
    )

    print(
        "=" * 100
    )


    for (
        name,
        passed,
    ) in checks.items():

        print(

            f"{name:<38}: "
            f"{'PASS' if passed else 'REVIEW'}"
        )


    ready = all(
        checks.values()
    )


    print()

    print(
        "=" * 100
    )


    if ready:

        print(
            "FUSION V3 LIVE SHADOW VALIDATION: PASS"
        )


        print()

        print(
            "Fusion v3 is technically ready for "
            "primary-engine promotion."
        )


    else:

        print(
            "FUSION V3 LIVE SHADOW VALIDATION: REVIEW REQUIRED"
        )


        print()

        print(
            "Do not promote Fusion v3 to the primary "
            "decision engine yet."
        )


    print(
        "=" * 100
    )


# ================================================================
# ENTRY
# ================================================================

if __name__ == "__main__":

    main()