from __future__ import annotations

import os
import sys
import time

from collections import Counter
from pathlib import Path
from typing import Any, Dict, Optional

import numpy as np


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

from endpoint.collectors.fusion_v3_evidence_bridge_monitor import (
    FusionV3EvidenceBridgeMonitor,
)

from ai_detection.behavior.process_context_tracker import (
    shared_process_behavior_context,
)


# ================================================================
# SENTINEL-X
# FINAL LIVE FUSION V3 SHADOW VALIDATION
#
#
# This test validates the complete real evidence path:
#
#       Real Windows process
#               ↓
#       Rule detector
#               ↓
#       Statistical detector
#               ↓
#       IF + Autoencoder
#               ↓
#       Temporal Transformer v2
#               ↓
#       Fusion v2
#               ↓
#       Fusion-v3 Evidence Bridge
#               ↓
#       Fusion v3 shadow decision
#
#
# IMPORTANT:
#
# Fusion v2 remains production.
#
# Fusion v3 remains SHADOW_VALIDATION.
#
# No Fusion-v3 SOC enforcement is performed here.
# ================================================================


# ================================================================
# CONFIGURATION
# ================================================================

TARGET_PROCESS_COUNT = 8

TARGET_CYCLES = 10

SAMPLE_INTERVAL_SECONDS = 15.0

MINIMUM_PROCESS_AGE_SECONDS = 120.0


EXCLUDED_PROCESS_NAMES = {
    "",
    "unknown",
    "system idle process",
    "system",
    "registry",
    "secure system",
    "memory compression",
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


def safe_float(
    value,
) -> Optional[float]:

    try:

        return float(
            value
        )

    except (
        TypeError,
        ValueError,
    ):

        return None


# ================================================================
# PROCESS SELECTION
# ================================================================

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


        process_name = (
            str(
                process_info.get(
                    "name"
                )
                or ""
            )
            .strip()
        )


        if (
            process_name.lower()
            in EXCLUDED_PROCESS_NAMES
        ):

            continue


        create_time = safe_float(
            process_info.get(
                "create_time"
            )
        )


        if create_time is None:

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
                    process_name,

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


    selected = {}


    for item in candidates[
        :TARGET_PROCESS_COUNT
    ]:

        selected[
            item[
                "pid"
            ]
        ] = item


    return selected


# ================================================================
# CATEGORY STRING
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


    return (
        f"available="
        f"{category.get('available')} | "
        f"score="
        f"{category.get('score')} | "
        f"active="
        f"{category.get('active')} | "
        f"strong="
        f"{category.get('strong')}"
    )


# ================================================================
# BUILD PROCESS CONTEXT
# ================================================================

def build_process_context(
    process_info: Dict[str, Any],
):

    pid = int(
        process_info[
            "pid"
        ]
    )


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


    return (
        shared_process_behavior_context
        .get_context(
            pid
        )
    )


# ================================================================
# MAIN
# ================================================================

def main():

    heading(
        "SENTINEL-X FINAL REAL LIVE FUSION V3 SHADOW VALIDATION"
    )


    print()

    print(
        "Process count :",
        TARGET_PROCESS_COUNT,
    )


    print(
        "Cycles        :",
        TARGET_CYCLES,
    )


    print(
        "Interval      :",
        SAMPLE_INTERVAL_SECONDS,
        "seconds",
    )


    print()

    print(
        "Fusion v2     : PRODUCTION / unchanged"
    )


    print(
        "Fusion v3     : SHADOW_VALIDATION"
    )


    # ============================================================
    # CREATE MONITOR
    # ============================================================

    print()

    print(
        "[1] Creating Evidence-Bridge monitor..."
    )


    monitor = (
        FusionV3EvidenceBridgeMonitor(
            poll_interval=2.0
        )
    )


    bridge_status = (
        monitor.get_evidence_bridge_status()
    )


    temporal_status = (
        bridge_status[
            "temporal_runtime"
        ][
            "predictor"
        ]
    )


    print()

    print(
        "Bridge:",
        bridge_status[
            "bridge_version"
        ],
    )


    print(
        "Fusion mode:",
        bridge_status[
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
        "Temporal predictor:",
        temporal_status[
            "predictor_version"
        ],
    )


    print(
        "Temporal calibration:",
        temporal_status[
            "calibration_version"
        ],
    )


    print(
        "Temporal features:",
        temporal_status[
            "feature_count"
        ],
    )


    print(
        "Temporal embedding:",
        temporal_status[
            "representation_dimension"
        ],
    )


    if (

        bridge_status[
            "operating_mode"
        ]

        != "SHADOW_VALIDATION"

    ):

        raise RuntimeError(

            "Fusion v3 must remain in "
            "SHADOW_VALIDATION."
        )


    if not temporal_status[
        "available"
    ]:

        raise RuntimeError(

            "Temporal Predictor v2 is unavailable."
        )


    if temporal_status[
        "model_version"
    ] != "v2":

        raise RuntimeError(

            "Expected Temporal Transformer v2."
        )


    if temporal_status[
        "feature_count"
    ] != 26:

        raise RuntimeError(

            "Expected corrected 26D temporal schema."
        )


    # ============================================================
    # INITIAL DATABASE COUNTS
    # ============================================================

    initial_fusion_v3_count = (
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
    # SELECT PROCESSES
    # ============================================================

    print()

    print(
        "[2] Selecting stable real Windows processes..."
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

            "No stable live processes found."
        )


    print()

    print(
        f"{'PID':<10}"
        f"{'Process':<35}"
        f"{'Age seconds':>18}"
    )


    print(
        "-" * 70
    )


    for item in selected.values():

        print(

            f"{item['pid']:<10}"
            f"{item['name']:<35}"
            f"{item['age']:>18.2f}"
        )


    # ============================================================
    # METRICS
    # ============================================================

    counters = Counter()


    temporal_scores = []

    fusion_v2_scores = []

    fusion_v3_scores = []

    fusion_score_deltas = []


    per_process = {}


    # ============================================================
    # COLLECTION
    # ============================================================

    heading(
        "LIVE COMPLETE-EVIDENCE COLLECTION"
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
                selected_info,
            ) in selected.items():

                process_info = (
                    snapshot.get(
                        pid
                    )
                )


                # =================================================
                # EXITED
                # =================================================

                if process_info is None:

                    counters[
                        "process_exited"
                    ] += 1


                    print(

                        f"SKIP | PID={pid} | "
                        f"{selected_info['name']} | exited"
                    )


                    continue


                # =================================================
                # PID REUSE
                # =================================================

                current_create_time = safe_float(

                    process_info.get(
                        "create_time"
                    )
                )


                if current_create_time is None:

                    counters[
                        "invalid_create_time"
                    ] += 1

                    continue


                if (

                    abs(

                        current_create_time

                        - selected_info[
                            "create_time"
                        ]

                    )

                    > 1.0

                ):

                    counters[
                        "pid_reuse"
                    ] += 1


                    print(

                        f"SKIP | PID={pid} | "
                        "PID reuse detected"
                    )


                    continue


                counters[
                    "attempted_samples"
                ] += 1


                # =================================================
                # EXACT PRODUCTION ORDER
                # =================================================

                try:

                    # =============================================
                    # 1. RULE DETECTOR
                    # =============================================

                    behavior_result = (
                        monitor
                        .behavior_detector
                        .analyze(
                            process_info
                        )
                    )


                    counters[
                        "rule_execution"
                    ] += 1


                    # =============================================
                    # 2. STATISTICAL DETECTOR
                    # =============================================

                    anomaly_result = (
                        monitor
                        .anomaly_detector
                        .analyze(
                            process_info
                        )
                    )


                    counters[
                        "statistical_execution"
                    ] += 1


                    # =============================================
                    # 3. PROCESS CONTEXT
                    # =============================================

                    context = (
                        build_process_context(
                            process_info
                        )
                    )


                    # =============================================
                    # 4. IF + AE + TEMPORAL V2
                    #
                    # This creates the pending evidence package
                    # consumed by calculate_fusion().
                    # =============================================

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


                    counters[
                        "ai_execution"
                    ] += 1


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


                    if not isinstance(
                        isolation_result,
                        dict,
                    ):

                        counters[
                            "missing_isolation"
                        ] += 1

                        continue


                    if not isinstance(
                        autoencoder_result,
                        dict,
                    ):

                        counters[
                            "missing_autoencoder"
                        ] += 1

                        continue


                    # =============================================
                    # 5. FUSION V2 + EVIDENCE BRIDGE + FUSION V3
                    #
                    # calculate_fusion() returns Fusion v2
                    # unchanged and mutates ai_result with
                    # complete Fusion v3.
                    # =============================================

                    fusion_v2_result = (
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


                    counters[
                        "fusion_v2_execution"
                    ] += 1


                except KeyboardInterrupt:

                    raise


                except Exception as error:

                    counters[
                        "pipeline_exception"
                    ] += 1


                    print()

                    print(

                        f"ERROR | PID={pid} | "
                        f"Process="
                        f"{process_info.get('name')} | "
                        f"{error}"
                    )


                    continue


                # =================================================
                # VERIFY BRIDGE CONSUMED PACKAGE
                # =================================================

                bridge_runtime = (
                    monitor
                    .get_evidence_bridge_status()
                )


                if bridge_runtime[
                    "pending_package"
                ]:

                    counters[
                        "pending_package_leak"
                    ] += 1


                # =================================================
                # FEATURE RECORD
                # =================================================

                feature_record_id = (

                    ai_result.get(
                        "record_id"
                    )

                    or

                    ai_result.get(
                        "feature_record_id"
                    )
                )


                if feature_record_id is not None:

                    counters[
                        "feature_record"
                    ] += 1


                # =================================================
                # TEMPORAL
                # =================================================

                temporal_wrapper = (
                    ai_result.get(
                        "temporal"
                    )

                    or {}
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


                    temporal_result = (
                        temporal_wrapper.get(
                            "temporal_result"
                        )

                        or {}
                    )


                    temporal_score = safe_float(

                        temporal_result.get(
                            "anomaly_score"
                        )
                    )


                    if temporal_score is not None:

                        temporal_scores.append(
                            temporal_score
                        )


                        if temporal_score >= 99.0:

                            counters[
                                "temporal_saturated_99"
                            ] += 1


                # =================================================
                # FUSION V3
                # =================================================

                fusion_v3_result = (
                    ai_result.get(
                        "fusion_v3"
                    )
                )


                if not isinstance(
                    fusion_v3_result,
                    dict,
                ):

                    counters[
                        "fusion_v3_missing"
                    ] += 1


                    print()

                    print(

                        f"FAIL | PID={pid} | "
                        "Fusion v3 missing"
                    )


                    continue


                if (

                    fusion_v3_result.get(
                        "state"
                    )

                    == "FUSION_V3_BRIDGE_EXCEPTION"

                ):

                    counters[
                        "fusion_v3_exception"
                    ] += 1


                    print()

                    print(

                        f"FAIL | PID={pid} | "
                        f"{fusion_v3_result.get('error')}"
                    )


                    continue


                if not fusion_v3_result.get(
                    "evidence_bridge_complete",
                    False,
                ):

                    counters[
                        "bridge_incomplete"
                    ] += 1


                    continue


                counters[
                    "fusion_v3_complete"
                ] += 1


                # =================================================
                # CATEGORIES
                # =================================================

                categories = (
                    fusion_v3_result.get(
                        "categories"
                    )

                    or {}
                )


                rules = (
                    categories.get(
                        "rules"
                    )

                    or {}
                )


                statistical = (
                    categories.get(
                        "statistical"
                    )

                    or {}
                )


                behavioral_ai = (
                    categories.get(
                        "behavioral_ai"
                    )

                    or {}
                )


                temporal_ai = (
                    categories.get(
                        "temporal_ai"
                    )

                    or {}
                )


                if rules.get(
                    "available",
                    False,
                ):

                    counters[
                        "rule_available"
                    ] += 1


                if statistical.get(
                    "available",
                    False,
                ):

                    counters[
                        "statistical_available"
                    ] += 1


                if behavioral_ai.get(
                    "available",
                    False,
                ):

                    counters[
                        "behavioral_ai_available"
                    ] += 1


                if temporal_ai.get(
                    "available",
                    False,
                ):

                    counters[
                        "temporal_ai_available"
                    ] += 1


                # =================================================
                # V2 COMPARISON
                # =================================================

                comparison = (
                    fusion_v3_result.get(
                        "fusion_v2_comparison"
                    )

                    or {}
                )


                if comparison.get(
                    "available",
                    False,
                ):

                    counters[
                        "fusion_v2_comparison"
                    ] += 1


                v2_score = safe_float(

                    fusion_v2_result.get(
                        "fusion_score"
                    )
                )


                v3_score = safe_float(

                    fusion_v3_result.get(
                        "fusion_score"
                    )
                )


                if v2_score is not None:

                    fusion_v2_scores.append(
                        v2_score
                    )


                if v3_score is not None:

                    fusion_v3_scores.append(
                        v3_score
                    )


                if (

                    v2_score is not None

                    and

                    v3_score is not None

                ):

                    delta = (

                        v3_score

                        - v2_score
                    )


                    fusion_score_deltas.append(
                        delta
                    )


                if fusion_v3_result.get(
                    "should_alert",
                    False,
                ):

                    counters[
                        "fusion_v3_alert_candidate"
                    ] += 1


                if fusion_v2_result.get(
                    "should_alert",
                    False,
                ):

                    counters[
                        "fusion_v2_alert"
                    ] += 1


                # =================================================
                # PER-PROCESS
                # =================================================

                name = str(

                    process_info.get(
                        "name"
                    )

                    or "UNKNOWN"
                )


                per_process.setdefault(

                    name,

                    {
                        "samples":
                            0,

                        "v2":
                            [],

                        "v3":
                            [],

                        "temporal":
                            [],
                    },
                )


                per_process[
                    name
                ][
                    "samples"
                ] += 1


                if v2_score is not None:

                    per_process[
                        name
                    ][
                        "v2"
                    ].append(
                        v2_score
                    )


                if v3_score is not None:

                    per_process[
                        name
                    ][
                        "v3"
                    ].append(
                        v3_score
                    )


                if temporal_ai.get(
                    "available",
                    False,
                ):

                    temporal_score = safe_float(

                        temporal_ai.get(
                            "score"
                        )
                    )


                    if temporal_score is not None:

                        per_process[
                            name
                        ][
                            "temporal"
                        ].append(
                            temporal_score
                        )


                # =================================================
                # DISPLAY
                # =================================================

                print()

                print(

                    f"PID={pid} | "
                    f"Process={name} | "
                    f"Record={feature_record_id}"
                )


                print(
                    "  Rule         :",
                    category_text(
                        rules
                    ),
                )


                print(
                    "  Statistical  :",
                    category_text(
                        statistical
                    ),
                )


                print(
                    "  Behavioral AI:",
                    category_text(
                        behavioral_ai
                    ),
                )


                print(
                    "  Temporal AI  :",
                    category_text(
                        temporal_ai
                    ),
                )


                print(

                    "  Temporal     : "
                    f"state={temporal_state} | "
                    f"depth={temporal_depth}"
                )


                print(

                    "  Fusion v2    : "
                    f"score="
                    f"{fusion_v2_result.get('fusion_score')} | "
                    f"severity="
                    f"{fusion_v2_result.get('severity')}"
                )


                print(

                    "  Fusion v3    : "
                    f"score="
                    f"{fusion_v3_result.get('fusion_score')} | "
                    f"severity="
                    f"{fusion_v3_result.get('severity')} | "
                    f"alert="
                    f"{fusion_v3_result.get('should_alert')}"
                )


                if (

                    v2_score is not None

                    and

                    v3_score is not None

                ):

                    print(

                        "  v3-v2 Δ      : "
                        f"{v3_score - v2_score:+.2f}"
                    )


            # ====================================================
            # CYCLE SUMMARY
            # ====================================================

            duration = (

                time.perf_counter()

                - cycle_started
            )


            temporal_buffer_status = (
                monitor
                .temporal_buffer
                .get_status()
            )


            current_bridge_status = (
                monitor
                .get_evidence_bridge_status()
            )


            print()

            print(
                "-" * 110
            )


            print(

                "Cycle summary | "
                f"Duration={duration:.2f}s | "
                f"TemporalMaxDepth="
                f"{temporal_buffer_status['maximum_depth']} | "
                f"TemporalReady="
                f"{temporal_buffer_status['ready_process_instances']} | "
                f"BridgeSuccess="
                f"{current_bridge_status['statistics']['bridge_success']} | "
                f"FusionV3Complete="
                f"{counters['fusion_v3_complete']}"
            )


            print(
                "-" * 110
            )


            # ====================================================
            # WAIT
            # ====================================================

            if cycle < TARGET_CYCLES:

                remaining = (

                    SAMPLE_INTERVAL_SECONDS

                    - duration
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
    # FINAL COUNTS
    # ============================================================

    final_fusion_v3_count = (
        monitor
        .fusion_v3_store
        .count()
    )


    final_temporal_count = (
        monitor
        .temporal_result_store
        .count()
    )


    new_fusion_v3_rows = (

        final_fusion_v3_count

        - initial_fusion_v3_count
    )


    new_temporal_rows = (

        final_temporal_count

        - initial_temporal_count
    )


    final_bridge_status = (
        monitor.get_evidence_bridge_status()
    )


    bridge_statistics = (
        final_bridge_status[
            "statistics"
        ]
    )


    # ============================================================
    # REPORT
    # ============================================================

    heading(
        "FINAL FUSION V3 LIVE SHADOW REPORT"
    )


    print()

    print(
        "Attempted samples             :",
        counters[
            "attempted_samples"
        ],
    )


    print(
        "Feature records               :",
        counters[
            "feature_record"
        ],
    )


    print()

    print(
        "Rule executions               :",
        counters[
            "rule_execution"
        ],
    )


    print(
        "Statistical executions        :",
        counters[
            "statistical_execution"
        ],
    )


    print(
        "AI executions                 :",
        counters[
            "ai_execution"
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
            "behavioral_ai_available"
        ],
    )


    print(
        "Temporal AI mapped            :",
        counters[
            "temporal_ai_available"
        ],
    )


    print()

    print(
        "Temporal collecting history   :",
        counters[
            "temporal_collecting"
        ],
    )


    print(
        "Temporal inferences           :",
        counters[
            "temporal_inference"
        ],
    )


    print()

    print(
        "Fusion v2 executions          :",
        counters[
            "fusion_v2_execution"
        ],
    )


    print(
        "Fusion v2 comparisons         :",
        counters[
            "fusion_v2_comparison"
        ],
    )


    print(
        "Fusion v3 complete decisions  :",
        counters[
            "fusion_v3_complete"
        ],
    )


    print()

    print(
        "Fusion v2 alert decisions     :",
        counters[
            "fusion_v2_alert"
        ],
    )


    print(
        "Fusion v3 alert candidates    :",
        counters[
            "fusion_v3_alert_candidate"
        ],
    )


    print()

    print(
        "Pipeline exceptions           :",
        counters[
            "pipeline_exception"
        ],
    )


    print(
        "Fusion v3 bridge exceptions   :",
        counters[
            "fusion_v3_exception"
        ],
    )


    print(
        "Incomplete bridges            :",
        counters[
            "bridge_incomplete"
        ],
    )


    print(
        "Pending-package leaks         :",
        counters[
            "pending_package_leak"
        ],
    )


    print()

    print(
        "New Fusion-v3 DB rows         :",
        new_fusion_v3_rows,
    )


    print(
        "New Temporal DB rows          :",
        new_temporal_rows,
    )


    # ============================================================
    # TEMPORAL DISTRIBUTION
    # ============================================================

    if temporal_scores:

        temporal_array = np.asarray(

            temporal_scores,

            dtype=np.float64,
        )


        temporal_saturation_ratio = (

            counters[
                "temporal_saturated_99"
            ]

            / len(
                temporal_array
            )
        )


        print()

        print(
            "Temporal score minimum       :",
            round(
                float(
                    np.min(
                        temporal_array
                    )
                ),
                2,
            ),
        )


        print(
            "Temporal score median        :",
            round(
                float(
                    np.median(
                        temporal_array
                    )
                ),
                2,
            ),
        )


        print(
            "Temporal score mean          :",
            round(
                float(
                    np.mean(
                        temporal_array
                    )
                ),
                2,
            ),
        )


        print(
            "Temporal score P95           :",
            round(
                float(
                    np.percentile(
                        temporal_array,
                        95,
                    )
                ),
                2,
            ),
        )


        print(
            "Temporal score maximum       :",
            round(
                float(
                    np.max(
                        temporal_array
                    )
                ),
                2,
            ),
        )


        print(
            "Temporal >=99 ratio          :",
            round(
                temporal_saturation_ratio
                * 100.0,
                2,
            ),
            "%",
        )


    else:

        temporal_saturation_ratio = 1.0


    # ============================================================
    # FUSION COMPARISON
    # ============================================================

    if fusion_score_deltas:

        delta_array = np.asarray(

            fusion_score_deltas,

            dtype=np.float64,
        )


        print()

        print(
            "Fusion v3-v2 delta minimum   :",
            round(
                float(
                    np.min(
                        delta_array
                    )
                ),
                2,
            ),
        )


        print(
            "Fusion v3-v2 delta median    :",
            round(
                float(
                    np.median(
                        delta_array
                    )
                ),
                2,
            ),
        )


        print(
            "Fusion v3-v2 delta mean      :",
            round(
                float(
                    np.mean(
                        delta_array
                    )
                ),
                2,
            ),
        )


        print(
            "Fusion v3-v2 delta maximum   :",
            round(
                float(
                    np.max(
                        delta_array
                    )
                ),
                2,
            ),
        )


    # ============================================================
    # PER-PROCESS
    # ============================================================

    print()

    print(
        "Per-process summary:"
    )


    for (
        process_name,
        result,
    ) in per_process.items():

        v2 = np.asarray(
            result[
                "v2"
            ],
            dtype=np.float64,
        )


        v3 = np.asarray(
            result[
                "v3"
            ],
            dtype=np.float64,
        )


        temporal = np.asarray(
            result[
                "temporal"
            ],
            dtype=np.float64,
        )


        print()

        print(
            f"  {process_name}"
        )


        print(
            f"    samples       : "
            f"{result['samples']}"
        )


        if v2.size:

            print(

                f"    Fusion v2 mean: "
                f"{np.mean(v2):.2f}"
            )


        if v3.size:

            print(

                f"    Fusion v3 mean: "
                f"{np.mean(v3):.2f}"
            )


        if temporal.size:

            print(

                f"    Temporal mean : "
                f"{np.mean(temporal):.2f} | "
                f"min={np.min(temporal):.2f} | "
                f"max={np.max(temporal):.2f}"
            )


    # ============================================================
    # BRIDGE STATISTICS
    # ============================================================

    print()

    print(
        "Evidence bridge statistics:"
    )


    for (
        key,
        value,
    ) in bridge_statistics.items():

        print(

            f"  {key:<30}: "
            f"{value}"
        )


    # ============================================================
    # READINESS CHECKS
    # ============================================================

    complete_decisions = (
        counters[
            "fusion_v3_complete"
        ]
    )


    checks = {
        # --------------------------------------------------------
        # Core collection
        # --------------------------------------------------------

        "feature_generation":
            counters[
                "feature_record"
            ] > 0,

        "rule_detector_execution":
            counters[
                "rule_execution"
            ] > 0,

        "statistical_detector_execution":
            counters[
                "statistical_execution"
            ] > 0,

        "behavioral_ai_execution":
            counters[
                "ai_execution"
            ] > 0,

        # --------------------------------------------------------
        # Complete routing
        # --------------------------------------------------------

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
                "behavioral_ai_available"
            ] > 0,

        # --------------------------------------------------------
        # Temporal v2
        # --------------------------------------------------------

        "temporal_v2_inference":
            counters[
                "temporal_inference"
            ] > 0,

        "temporal_v2_mapping":
            counters[
                "temporal_ai_available"
            ] > 0,

        "temporal_no_universal_saturation":
            temporal_saturation_ratio
            < 0.50,

        # --------------------------------------------------------
        # Fusion
        # --------------------------------------------------------

        "fusion_v2_execution":
            counters[
                "fusion_v2_execution"
            ] > 0,

        "fusion_v2_comparison":
            counters[
                "fusion_v2_comparison"
            ] > 0,

        "fusion_v3_complete":
            complete_decisions > 0,

        "fusion_v3_persistence":
            new_fusion_v3_rows > 0,

        "temporal_persistence":
            new_temporal_rows > 0,

        # --------------------------------------------------------
        # Bridge safety
        # --------------------------------------------------------

        "bridge_success":
            bridge_statistics[
                "bridge_success"
            ] > 0,

        "no_bridge_exceptions":
            bridge_statistics[
                "bridge_exceptions"
            ] == 0,

        "no_pipeline_exceptions":
            counters[
                "pipeline_exception"
            ] == 0,

        "no_incomplete_bridges":
            counters[
                "bridge_incomplete"
            ] == 0,

        "no_pending_package_leaks":
            counters[
                "pending_package_leak"
            ] == 0,
    }


    heading(
        "FINAL READINESS CHECKS"
    )


    for (
        name,
        passed,
    ) in checks.items():

        print(

            f"{name:<44}: "
            f"{'PASS' if passed else 'REVIEW'}"
        )


    all_passed = all(
        checks.values()
    )


    print()

    print(
        "=" * 110
    )


    if all_passed:

        print(
            "FINAL FUSION V3 LIVE SHADOW VALIDATION: PASS"
        )


        print()

        print(
            "All four evidence categories are routed correctly."
        )


        print(
            "Temporal Transformer v2 is operating with the "
            "corrected 26D schema."
        )


        print(
            "Fusion v2 comparison is available."
        )


        print(
            "Fusion v3 remains SHADOW_VALIDATION."
        )


        print()

        print(
            "System is technically ready for the "
            "production-promotion step."
        )


    else:

        print(
            "FINAL FUSION V3 LIVE SHADOW VALIDATION: "
            "REVIEW REQUIRED"
        )


        print()

        print(
            "Do NOT promote Fusion v3 yet."
        )


    print(
        "=" * 110
    )


if __name__ == "__main__":

    main()