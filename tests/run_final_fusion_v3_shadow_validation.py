from __future__ import annotations

import os
import sys
import time

from collections import Counter
from pathlib import Path
from typing import Any, Dict


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
# IMPORTS
# ================================================================

from endpoint.collectors.fusion_v3_evidence_bridge_monitor import (
    FusionV3EvidenceBridgeMonitor,
)

from ai_detection.behavior.process_context_tracker import (
    shared_process_behavior_context,
)


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
# HELPERS
# ================================================================

def heading(
    text: str,
) -> None:

    print()

    print(
        "=" * 110
    )

    print(
        text
    )

    print(
        "=" * 110
    )


def select_stable_processes(
    snapshot: Dict[int, Dict[str, Any]],
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


        name = str(

            process_info.get(
                "name"
            )

            or "UNKNOWN"

        ).strip()


        if name.lower() in EXCLUDED_PROCESS_NAMES:

            continue


        try:

            create_time = float(

                process_info.get(
                    "create_time"
                )
            )

        except (
            TypeError,
            ValueError,
        ):

            continue


        age = (
            now
            - create_time
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
                    create_time,

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


    return {

        item[
            "pid"
        ]:
            item

        for item
        in candidates[
            :TARGET_PROCESS_COUNT
        ]
    }


def category_text(
    category: Dict[str, Any],
) -> str:

    if not isinstance(
        category,
        dict,
    ):

        return "MISSING"


    return (

        f"A={category.get('available')} "
        f"S={category.get('score')} "
        f"Active={category.get('active')} "
        f"Strong={category.get('strong')}"
    )


# ================================================================
# MAIN
# ================================================================

def main():

    heading(
        "SENTINEL-X FINAL REAL LIVE FUSION V3 SHADOW VALIDATION"
    )


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
    # MONITOR
    # ============================================================

    print()

    print(
        "[1] Creating Fusion-v3 Evidence Bridge runtime..."
    )


    monitor = (
        FusionV3EvidenceBridgeMonitor(
            poll_interval=2.0
        )
    )


    status = (
        monitor.get_evidence_bridge_status()
    )


    temporal_status = (

        status[
            "temporal_runtime"
        ][
            "predictor"
        ]
    )


    print()

    print(
        "Bridge:",
        status[
            "bridge_version"
        ],
    )


    print(
        "Fusion mode:",
        status[
            "operating_mode"
        ],
    )


    print(
        "Temporal model:",
        temporal_status[
            "model_version"
        ],
    )


    print(
        "Temporal calibration:",
        temporal_status[
            "calibration_version"
        ],
    )


    print(
        "Temporal feature count:",
        temporal_status[
            "feature_count"
        ],
    )


    print(
        "Temporal removed feature:",
        temporal_status[
            "removed_feature"
        ],
    )


    if (

        status[
            "operating_mode"
        ]

        != "SHADOW_VALIDATION"

    ):

        raise RuntimeError(

            "Fusion v3 must remain in SHADOW_VALIDATION."
        )


    if temporal_status[
        "model_version"
    ] != "v2":

        raise RuntimeError(

            "Temporal Transformer v2 is not active."
        )


    if temporal_status[
        "feature_count"
    ] != 26:

        raise RuntimeError(

            "Temporal runtime is not using 26D schema."
        )


    # ============================================================
    # INITIAL COUNTS
    # ============================================================

    initial_v3_rows = (
        monitor
        .fusion_v3_store
        .count()
    )


    initial_temporal_rows = (
        monitor
        .temporal_result_store
        .count()
    )


    # ============================================================
    # PROCESS SELECTION
    # ============================================================

    print()

    print(
        "[2] Selecting stable Windows processes..."
    )


    snapshot = (
        monitor.get_process_snapshot()
    )


    selected = (
        select_stable_processes(
            snapshot
        )
    )


    if not selected:

        raise RuntimeError(

            "No stable Windows processes found."
        )


    print()

    print(
        "Selected:"
    )


    for item in selected.values():

        print(

            f"PID={item['pid']:<8} "
            f"Process={item['name']:<30} "
            f"Age={item['age']:.1f}s"
        )


    # ============================================================
    # COUNTERS
    # ============================================================

    counters = Counter()

    process_depths = Counter()

    v2_scores = []

    v3_scores = []

    score_deltas = []

    temporal_scores = []


    # ============================================================
    # COLLECTION
    # ============================================================

    heading(
        "LIVE COLLECTION"
    )


    for cycle in range(
        1,
        TARGET_CYCLES + 1,
    ):

        cycle_started = (
            time.perf_counter()
        )


        print()

        print(
            "=" * 110
        )

        print(

            f"CYCLE "
            f"{cycle}/"
            f"{TARGET_CYCLES}"
        )

        print(
            "=" * 110
        )


        snapshot = (
            monitor.get_process_snapshot()
        )


        for (
            pid,
            original,
        ) in selected.items():

            process_info = (
                snapshot.get(
                    pid
                )
            )


            if process_info is None:

                counters[
                    "process_exited"
                ] += 1

                continue


            # ====================================================
            # PID REUSE PROTECTION
            # ====================================================

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

                    - original[
                        "create_time"
                    ]

                )

                > 1.0

            ):

                counters[
                    "pid_reuse"
                ] += 1

                continue


            # ====================================================
            # CONTEXT
            # ====================================================

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


            # ====================================================
            # IMPORTANT
            #
            # For this final bridge validation we reproduce the
            # exact ordering from handle_process_start():
            #
            #     Rule
            #     Statistical
            #     AI
            #     Fusion
            #
            # No detector is executed twice.
            # ====================================================

            try:

                # ------------------------------------------------
                # RULE
                # ------------------------------------------------

                behavior_result = (
                    monitor
                    .behavior_detector
                    .analyze(
                        process_info
                    )
                )


                # ------------------------------------------------
                # STATISTICAL
                # ------------------------------------------------

                anomaly_result = (
                    monitor
                    .anomaly_detector
                    .analyze(
                        process_info
                    )
                )


                # ------------------------------------------------
                # AI + TEMPORAL V2
                #
                # Bridge caches this exact ai_result.
                # ------------------------------------------------

                ai_result = (
                    monitor
                    .collect_ai_behavior_features(

                        process_info=
                            process_info,

                        context=
                            context,
                    )
                )


                if not isinstance(
                    ai_result,
                    dict,
                ):

                    counters[
                        "invalid_ai_result"
                    ] += 1

                    continue


                isolation_result = (
                    ai_result.get(
                        "isolation_forest"
                    )
                )


                autoencoder_result = (
                    ai_result.get(
                        "autoencoder"
                    )
                )


                # ------------------------------------------------
                # FUSION V2 + EVIDENCE BRIDGE → V3
                # ------------------------------------------------

                fusion_v2 = (
                    monitor.calculate_fusion(

                        behavior_result=
                            behavior_result,

                        anomaly_result=
                            anomaly_result,

                        isolation_result=
                            isolation_result,

                        autoencoder_result=
                            autoencoder_result,
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
                    f"PID={pid} | "
                    f"Process={process_info.get('name')} | "
                    f"{error}"
                )


                continue


            counters[
                "samples"
            ] += 1


            # ====================================================
            # VERIFY V3 ATTACHED
            # ====================================================

            fusion_v3 = (
                ai_result.get(
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

                continue


            if (

                fusion_v3.get(
                    "state"
                )

                == "FUSION_V3_BRIDGE_EXCEPTION"

            ):

                counters[
                    "bridge_exception"
                ] += 1


                print(

                    "BRIDGE ERROR:",
                    fusion_v3.get(
                        "error"
                    ),
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


            # ====================================================
            # CATEGORIES
            # ====================================================

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


            # ====================================================
            # TEMPORAL STATE
            # ====================================================

            temporal_wrapper = (
                ai_result.get(
                    "temporal",
                    {}
                )
            )


            temporal_state = (
                temporal_wrapper.get(
                    "state"
                )
            )


            temporal_depth = (
                temporal_wrapper.get(
                    "depth",
                    0,
                )
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

                == "TEMPORAL_INFERENCE_COMPLETE"

            ):

                counters[
                    "temporal_inference"
                ] += 1


                temporal_result = (
                    temporal_wrapper.get(
                        "temporal_result",
                        {}
                    )
                )


                if isinstance(
                    temporal_result,
                    dict,
                ):

                    try:

                        temporal_score = float(

                            temporal_result.get(
                                "anomaly_score"
                            )
                        )


                        temporal_scores.append(
                            temporal_score
                        )


                        if temporal_score >= 99.0:

                            counters[
                                "temporal_saturation"
                            ] += 1


                    except (
                        TypeError,
                        ValueError,
                    ):

                        pass


            elif (

                temporal_state

                == "COLLECTING_HISTORY"

            ):

                counters[
                    "temporal_collecting"
                ] += 1


            # ====================================================
            # V2 COMPARISON
            # ====================================================

            comparison = (
                fusion_v3.get(
                    "fusion_v2_comparison"
                )
            )


            if (

                isinstance(
                    comparison,
                    dict,
                )

                and

                comparison.get(
                    "available"
                )

            ):

                counters[
                    "fusion_v2_comparison"
                ] += 1


                try:

                    v2_score = float(

                        comparison[
                            "fusion_v2_score"
                        ]
                    )


                    v3_score = float(

                        fusion_v3[
                            "fusion_score"
                        ]
                    )


                    delta = float(

                        comparison[
                            "score_delta_v3_minus_v2"
                        ]
                    )


                    v2_scores.append(
                        v2_score
                    )


                    v3_scores.append(
                        v3_score
                    )


                    score_deltas.append(
                        delta
                    )


                except (
                    TypeError,
                    ValueError,
                    KeyError,
                ):

                    pass


            # ====================================================
            # ALERT
            # ====================================================

            if fusion_v3.get(
                "should_alert",
                False,
            ):

                counters[
                    "fusion_v3_alert"
                ] += 1


            # ====================================================
            # DISPLAY
            # ====================================================

            print()

            print(

                f"PID={pid} | "
                f"Process="
                f"{process_info.get('name')}"
            )


            print(
                "  Rule          :",
                category_text(
                    rule_category
                ),
            )


            print(
                "  Statistical   :",
                category_text(
                    statistical_category
                ),
            )


            print(
                "  Behavioral AI :",
                category_text(
                    behavioral_category
                ),
            )


            print(
                "  Temporal AI   :",
                category_text(
                    temporal_category
                ),
            )


            print(
                "  Temporal depth:",
                temporal_depth,
            )


            print(

                "  Fusion v2     : "
                f"Score="
                f"{fusion_v2.get('fusion_score')} | "
                f"Severity="
                f"{fusion_v2.get('severity')}"
            )


            print(

                "  Fusion v3     : "
                f"Score="
                f"{fusion_v3.get('fusion_score')} | "
                f"Severity="
                f"{fusion_v3.get('severity')} | "
                f"Alert="
                f"{fusion_v3.get('should_alert')}"
            )


            if isinstance(
                comparison,
                dict,
            ):

                print(

                    "  v3-v2 delta   :",
                    comparison.get(
                        "score_delta_v3_minus_v2"
                    ),
                )


        # ========================================================
        # CYCLE SUMMARY
        # ========================================================

        cycle_duration = (

            time.perf_counter()

            - cycle_started
        )


        buffer_status = (
            monitor
            .temporal_buffer
            .get_status()
        )


        print()

        print(
            "-" * 110
        )


        print(

            f"Cycle duration="
            f"{cycle_duration:.2f}s | "
            f"MaxDepth="
            f"{buffer_status['maximum_depth']} | "
            f"ReadyTemporal="
            f"{buffer_status['ready_process_instances']} | "
            f"FusionV3="
            f"{counters['fusion_v3_success']}"
        )


        print(
            "-" * 110
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


    # ============================================================
    # FINAL COUNTS
    # ============================================================

    final_v3_rows = (
        monitor
        .fusion_v3_store
        .count()
    )


    final_temporal_rows = (
        monitor
        .temporal_result_store
        .count()
    )


    new_v3_rows = (

        final_v3_rows

        - initial_v3_rows
    )


    new_temporal_rows = (

        final_temporal_rows

        - initial_temporal_rows
    )


    bridge_status = (
        monitor
        .get_evidence_bridge_status()
    )


    # ============================================================
    # REPORT
    # ============================================================

    heading(
        "FINAL FUSION V3 SHADOW REPORT"
    )


    print(
        "Samples processed             :",
        counters[
            "samples"
        ],
    )


    print(
        "Fusion v3 successes           :",
        counters[
            "fusion_v3_success"
        ],
    )


    print(
        "Pipeline exceptions           :",
        counters[
            "pipeline_exception"
        ],
    )


    print(
        "Bridge exceptions             :",
        counters[
            "bridge_exception"
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


    print(
        "Temporal >= 99                :",
        counters[
            "temporal_saturation"
        ],
    )


    print()

    print(
        "Fusion-v2 comparisons         :",
        counters[
            "fusion_v2_comparison"
        ],
    )


    print(
        "Fusion-v3 alert candidates    :",
        counters[
            "fusion_v3_alert"
        ],
    )


    print()

    print(
        "New Fusion-v3 DB rows         :",
        new_v3_rows,
    )


    print(
        "New Temporal DB rows          :",
        new_temporal_rows,
    )


    print()

    print(
        "Bridge statistics:"
    )


    for (
        key,
        value,
    ) in (

        bridge_status[
            "statistics"
        ].items()

    ):

        print(

            f"  {key:<30}: "
            f"{value}"
        )


    # ============================================================
    # SCORE COMPARISON
    # ============================================================

    if score_deltas:

        import numpy as np


        deltas = np.asarray(

            score_deltas,

            dtype=np.float64,
        )


        print()

        print(
            "Fusion-v3 minus Fusion-v2 score:"
        )


        print(
            "  Minimum:",
            round(
                float(
                    np.min(
                        deltas
                    )
                ),
                2,
            ),
        )


        print(
            "  Median :",
            round(
                float(
                    np.median(
                        deltas
                    )
                ),
                2,
            ),
        )


        print(
            "  Mean   :",
            round(
                float(
                    np.mean(
                        deltas
                    )
                ),
                2,
            ),
        )


        print(
            "  Maximum:",
            round(
                float(
                    np.max(
                        deltas
                    )
                ),
                2,
            ),
        )


    # ============================================================
    # TEMPORAL SATURATION
    # ============================================================

    temporal_inference_count = (
        counters[
            "temporal_inference"
        ]
    )


    temporal_saturation_ratio = (

        (
            counters[
                "temporal_saturation"
            ]

            / temporal_inference_count
        )

        if temporal_inference_count > 0

        else 1.0
    )


    # ============================================================
    # READINESS
    # ============================================================

    checks = {
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

        "temporal_v2_inference":
            counters[
                "temporal_inference"
            ] > 0,

        "temporal_v2_mapping":
            counters[
                "temporal_available"
            ] > 0,

        "fusion_v2_comparison":
            counters[
                "fusion_v2_comparison"
            ] > 0,

        "fusion_v3_persistence":
            new_v3_rows > 0,

        "temporal_persistence":
            new_temporal_rows > 0,

        "no_bridge_exceptions":
            counters[
                "bridge_exception"
            ] == 0,

        "no_pipeline_exceptions":
            counters[
                "pipeline_exception"
            ] == 0,

        "temporal_not_saturated":
            temporal_saturation_ratio
            < 0.50,

        "bridge_consumed_packages":
            (
                bridge_status[
                    "pending_package"
                ]

                is False
            ),
    }


    heading(
        "FINAL READINESS CHECKS"
    )


    for (
        name,
        passed,
    ) in checks.items():

        print(

            f"{name:<42}: "
            f"{'PASS' if passed else 'REVIEW'}"
        )


    print()

    print(
        "Temporal >=99 ratio:",
        round(
            temporal_saturation_ratio
            * 100.0,
            2,
        ),
        "%",
    )


    ready = all(
        checks.values()
    )


    print()

    print(
        "=" * 110
    )


    if ready:

        print(
            "FINAL FUSION V3 LIVE SHADOW VALIDATION: PASS"
        )


        print()

        print(
            "All evidence categories are reaching Fusion v3."
        )


        print(
            "Temporal v2 is active."
        )


        print(
            "Fusion v2 remains available for rollback/comparison."
        )


        print()

        print(
            "Fusion v3 is technically eligible "
            "for production promotion."
        )


    else:

        print(
            "FINAL FUSION V3 LIVE SHADOW VALIDATION: REVIEW REQUIRED"
        )


        print()

        print(
            "Do not promote Fusion v3 yet."
        )


    print(
        "=" * 110
    )


# ================================================================
# ENTRY
# ================================================================

if __name__ == "__main__":

    main()