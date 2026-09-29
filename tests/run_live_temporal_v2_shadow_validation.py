from __future__ import annotations

import os
import sys
import time

from collections import (
    Counter,
)

from pathlib import Path

from typing import (
    Any,
    Dict,
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
# IMPORTS
# ================================================================

from endpoint.collectors.fusion_v3_process_monitor_v2 import (
    FusionV3ProcessMonitorV2,
)


from ai_detection.behavior.process_context_tracker import (
    shared_process_behavior_context,
)


# ================================================================
# CONFIG
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
):

    current_pid = os.getpid()

    now = time.time()

    candidates = []


    for (
        pid,
        info,
    ) in snapshot.items():

        try:

            pid = int(
                pid
            )


        except (
            TypeError,
            ValueError,
        ):

            continue


        if pid == current_pid:

            continue


        name = (

            str(
                info.get(
                    "name"
                )

                or "UNKNOWN"
            )
            .strip()
        )


        if name.lower() in EXCLUDED_PROCESS_NAMES:

            continue


        try:

            create_time = float(

                info.get(
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
                    pid,

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


# ================================================================
# MAIN
# ================================================================

def main():

    print()

    print(
        "=" * 100
    )

    print(
        "SENTINEL-X REAL LIVE TEMPORAL V2 SHADOW VALIDATION"
    )

    print(
        "=" * 100
    )


    # ============================================================
    # MONITOR
    # ============================================================

    monitor = (
        FusionV3ProcessMonitorV2(
            poll_interval=2.0
        )
    )


    status = (
        monitor.get_temporal_v2_status()
    )


    predictor = (
        status[
            "predictor"
        ]
    )


    print()

    print(
        "Model version:",
        predictor[
            "model_version"
        ],
    )


    print(
        "Predictor version:",
        predictor[
            "predictor_version"
        ],
    )


    print(
        "Calibration version:",
        predictor[
            "calibration_version"
        ],
    )


    print(
        "Feature count:",
        predictor[
            "feature_count"
        ],
    )


    print(
        "Removed feature:",
        predictor[
            "removed_feature"
        ],
    )


    print(
        "Fusion mode:",
        status[
            "fusion_v3_mode"
        ],
    )


    if not predictor[
        "available"
    ]:

        raise RuntimeError(

            "Temporal Predictor v2 unavailable."
        )


    # ============================================================
    # SELECT PROCESSES
    # ============================================================

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

            "No stable Windows processes available."
        )


    print()

    print(
        "Selected processes:"
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

    temporal_scores = []

    temporal_errors = []

    per_process_scores = {}


    # ============================================================
    # COLLECTION
    # ============================================================

    for cycle in range(
        1,
        TARGET_CYCLES + 1,
    ):

        started = (
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
            original,
        ) in selected.items():

            process_info = (
                snapshot.get(
                    pid
                )
            )


            if process_info is None:

                counters[
                    "exited"
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
            # REAL PIPELINE
            # ====================================================

            try:

                result = (
                    monitor.collect_ai_behavior_features(

                        process_info=
                            process_info,

                        context=
                            context,
                    )
                )


            except Exception as error:

                counters[
                    "exceptions"
                ] += 1


                print(

                    f"ERROR | PID={pid} | "
                    f"{process_info.get('name')} | "
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

                continue


            temporal_wrapper = (
                result.get(
                    "temporal"
                )

                or {}
            )


            state = (
                temporal_wrapper.get(
                    "state"
                )
            )


            depth = (
                temporal_wrapper.get(
                    "depth"
                )
            )


            print()

            print(

                f"PID={pid} | "
                f"Process="
                f"{process_info.get('name')} | "
                f"Depth={depth} | "
                f"State={state}"
            )


            # ====================================================
            # COLLECTING
            # ====================================================

            if state == "COLLECTING_HISTORY":

                counters[
                    "collecting"
                ] += 1


                continue


            # ====================================================
            # INFERENCE
            # ====================================================

            if state != "TEMPORAL_INFERENCE_COMPLETE":

                counters[
                    "other_state"
                ] += 1


                print(
                    "  Temporal:",
                    temporal_wrapper,
                )


                continue


            counters[
                "inference"
            ] += 1


            temporal_result = (
                temporal_wrapper[
                    "temporal_result"
                ]
            )


            score = float(

                temporal_result[
                    "anomaly_score"
                ]
            )


            error = float(

                temporal_result[
                    "raw_temporal_reconstruction_error"
                ]
            )


            label = (
                temporal_result[
                    "anomaly_label"
                ]
            )


            temporal_scores.append(
                score
            )


            temporal_errors.append(
                error
            )


            per_process_scores.setdefault(

                str(
                    process_info.get(
                        "name"
                    )
                ),

                [],
            ).append(
                score
            )


            counters[
                f"label_{label}"
            ] += 1


            if score >= 99.0:

                counters[
                    "saturated_99"
                ] += 1


            if score >= 80.0:

                counters[
                    "strong"
                ] += 1


            if score >= 60.0:

                counters[
                    "active"
                ] += 1


            print(
                "  Model       :",
                temporal_result[
                    "model_version"
                ],
            )


            print(
                "  Features    :",
                temporal_result[
                    "feature_count"
                ],
            )


            print(
                "  Raw error   :",
                round(
                    error,
                    6,
                ),
            )


            print(
                "  Score       :",
                round(
                    score,
                    2,
                ),
            )


            print(
                "  Label       :",
                label,
            )


            print(
                "  Embedding   :",
                temporal_result[
                    "temporal_embedding_dimension"
                ],
            )


        # ========================================================
        # CYCLE
        # ========================================================

        duration = (

            time.perf_counter()

            - started
        )


        buffer_status = (
            monitor.temporal_buffer
            .get_status()
        )


        print()

        print(
            "-" * 100
        )


        print(

            f"Cycle duration={duration:.2f}s | "
            f"MaxDepth="
            f"{buffer_status['maximum_depth']} | "
            f"Ready="
            f"{buffer_status['ready_process_instances']} | "
            f"Inferences="
            f"{counters['inference']}"
        )


        print(
            "-" * 100
        )


        if cycle < TARGET_CYCLES:

            remaining = (

                SAMPLE_INTERVAL_SECONDS

                - duration
            )


            if remaining > 0:

                time.sleep(
                    remaining
                )


    # ============================================================
    # REPORT
    # ============================================================

    print()

    print(
        "=" * 100
    )

    print(
        "TEMPORAL V2 LIVE SHADOW REPORT"
    )

    print(
        "=" * 100
    )


    print()

    print(
        "Samples:",
        counters[
            "samples"
        ],
    )


    print(
        "Collecting-history samples:",
        counters[
            "collecting"
        ],
    )


    print(
        "Temporal inferences:",
        counters[
            "inference"
        ],
    )


    print(
        "Exceptions:",
        counters[
            "exceptions"
        ],
    )


    if temporal_scores:

        import numpy as np


        scores = np.asarray(

            temporal_scores,

            dtype=np.float64,
        )


        errors = np.asarray(

            temporal_errors,

            dtype=np.float64,
        )


        print()

        print(
            "Score minimum :",
            round(
                float(
                    np.min(
                        scores
                    )
                ),
                2,
            ),
        )


        print(
            "Score median  :",
            round(
                float(
                    np.median(
                        scores
                    )
                ),
                2,
            ),
        )


        print(
            "Score mean    :",
            round(
                float(
                    np.mean(
                        scores
                    )
                ),
                2,
            ),
        )


        print(
            "Score P95     :",
            round(
                float(
                    np.percentile(
                        scores,
                        95,
                    )
                ),
                2,
            ),
        )


        print(
            "Score maximum :",
            round(
                float(
                    np.max(
                        scores
                    )
                ),
                2,
            ),
        )


        print()

        print(
            "Error median  :",
            round(
                float(
                    np.median(
                        errors
                    )
                ),
                6,
            ),
        )


        print(
            "Error P95     :",
            round(
                float(
                    np.percentile(
                        errors,
                        95,
                    )
                ),
                6,
            ),
        )


        print()

        print(
            "Scores >= 60  :",
            counters[
                "active"
            ],
        )


        print(
            "Scores >= 80  :",
            counters[
                "strong"
            ],
        )


        print(
            "Scores >= 99  :",
            counters[
                "saturated_99"
            ],
        )


        print()

        print(
            "Labels:"
        )


        for label in [

            "NORMAL",

            "UNUSUAL",

            "SUSPICIOUS",

            "HIGH_ANOMALY",

        ]:

            print(

                f"  {label:<15}: "
                f"{counters[f'label_{label}']}"
            )


        print()

        print(
            "Per-process temporal scores:"
        )


        for (
            process_name,
            values,
        ) in per_process_scores.items():

            values = np.asarray(

                values,

                dtype=np.float64,
            )


            print(

                f"  {process_name:<30} "
                f"min="
                f"{np.min(values):>6.2f} | "
                f"mean="
                f"{np.mean(values):>6.2f} | "
                f"max="
                f"{np.max(values):>6.2f}"
            )


    # ============================================================
    # ACCEPTANCE
    # ============================================================

    inference_count = (
        counters[
            "inference"
        ]
    )


    saturation_ratio = (

        (
            counters[
                "saturated_99"
            ]

            / inference_count
        )

        if inference_count > 0

        else 1.0
    )


    checks = {
        "predictor_v2_loaded":
            (
                predictor[
                    "model_version"
                ]
                == "v2"

                and

                predictor[
                    "calibration_version"
                ]
                == "v2"
            ),

        "correct_26d_schema":
            predictor[
                "feature_count"
            ] == 26,

        "temporal_inference_completed":
            inference_count > 0,

        "no_pipeline_exceptions":
            counters[
                "exceptions"
            ] == 0,

        # --------------------------------------------------------
        # Primary correction target:
        #
        # v1 produced approximately universal saturation.
        #
        # v2 should NOT have most normal Windows sequences pinned
        # at 99-100.
        # --------------------------------------------------------

        "no_universal_saturation":
            saturation_ratio < 0.50,
    }


    print()

    print(
        "=" * 100
    )

    print(
        "ACCEPTANCE CHECKS"
    )

    print(
        "=" * 100
    )


    for (
        name,
        passed,
    ) in checks.items():

        print(

            f"{name:<40}: "
            f"{'PASS' if passed else 'REVIEW'}"
        )


    print()

    print(
        "Saturation ratio:",
        round(
            saturation_ratio
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
        "=" * 100
    )


    if ready:

        print(
            "TEMPORAL V2 LIVE SHADOW VALIDATION: PASS"
        )


        print()

        print(
            "The process-age distribution bug "
            "is no longer causing universal "
            "Temporal-AI saturation."
        )


    else:

        print(
            "TEMPORAL V2 LIVE SHADOW VALIDATION: REVIEW REQUIRED"
        )


        print()

        print(
            "Do not promote Temporal AI."
        )


    print(
        "=" * 100
    )


if __name__ == "__main__":

    main()