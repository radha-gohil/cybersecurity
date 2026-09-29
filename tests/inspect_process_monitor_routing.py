from __future__ import annotations

import inspect
import os
import sys
import time

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

from endpoint.collectors.process_monitor import (
    ProcessMonitor,
)

from ai_detection.behavior.process_context_tracker import (
    shared_process_behavior_context,
)


# ================================================================
# CONFIGURATION
# ================================================================

SEARCH_TERMS = [

    "rule",
    "behavior",
    "anomaly",
    "stat",
    "fusion",
    "detector",
    "threat",
]


SOURCE_SEARCH_TERMS = [

    "ProcessBehaviorDetector",
    "ProcessAnomalyDetector",
    "ProcessThreatFusionV2",

    "behavior_detector",
    "anomaly_detector",
    "fusion",

    "collect_ai_behavior_features",
    "check_processes",

    ".detect(",
    ".analyze(",
    ".evaluate(",
    ".calculate(",
]


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


def matches_search_term(
    name: str,
) -> bool:

    lowered = (
        str(
            name
        )
        .lower()
    )


    return any(

        term in lowered

        for term
        in SEARCH_TERMS
    )


def safe_signature(
    obj,
) -> str:

    try:

        return str(
            inspect.signature(
                obj
            )
        )


    except Exception:

        return "<signature unavailable>"


def safe_type_name(
    obj,
) -> str:

    try:

        return (
            f"{obj.__class__.__module__}."
            f"{obj.__class__.__name__}"
        )


    except Exception:

        return str(
            type(
                obj
            )
        )


# ================================================================
# FIND ONE STABLE PROCESS
# ================================================================

def find_stable_process(
    monitor,
) -> Dict[str, Any]:

    snapshot = (
        monitor.get_process_snapshot()
    )


    current_pid = (
        os.getpid()
    )


    now = (
        time.time()
    )


    candidates = []


    for (
        pid,
        info,
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


        if age < 120.0:

            continue


        process_name = str(

            info.get(
                "name"
            )

            or "UNKNOWN"
        )


        if process_name.lower() in {

            "system idle process",
            "system",
            "registry",
            "secure system",
            "memory compression",
        }:

            continue


        candidates.append(
            (
                age,
                pid_value,
                info,
            )
        )


    if not candidates:

        raise RuntimeError(

            "No stable Windows process found."
        )


    candidates.sort(

        key=lambda item:
            item[
                0
            ],

        reverse=True,
    )


    return candidates[
        0
    ][
        2
    ]


# ================================================================
# INSTANCE ATTRIBUTES
# ================================================================

def inspect_instance_attributes(
    monitor,
) -> None:

    heading(
        "1. MONITOR ATTRIBUTES RELATED TO DETECTION / FUSION"
    )


    attributes = []


    for name in dir(
        monitor
    ):

        if name.startswith(
            "__"
        ):

            continue


        if not matches_search_term(
            name
        ):

            continue


        try:

            value = getattr(
                monitor,
                name,
            )


        except Exception:

            continue


        # --------------------------------------------------------
        # Skip methods here; methods are printed separately.
        # --------------------------------------------------------

        if callable(
            value
        ):

            continue


        attributes.append(
            (
                name,
                value,
            )
        )


    for (
        name,
        value,
    ) in attributes:

        print()

        print(
            f"{name}"
        )


        print(
            f"  type: {safe_type_name(value)}"
        )


        # --------------------------------------------------------
        # Inspect methods on detector/fusion objects.
        # --------------------------------------------------------

        interesting_methods = []


        for child_name in dir(
            value
        ):

            if child_name.startswith(
                "_"
            ):

                continue


            try:

                child = getattr(
                    value,
                    child_name,
                )


            except Exception:

                continue


            if not callable(
                child
            ):

                continue


            if matches_search_term(
                child_name
            ) or child_name in {

                "detect",
                "analyze",
                "evaluate",
                "calculate",
                "predict",
                "update",
                "add",
                "score",
            }:

                interesting_methods.append(
                    (
                        child_name,
                        child,
                    )
                )


        for (
            child_name,
            child,
        ) in interesting_methods:

            print(

                f"    method: "
                f"{child_name}"
                f"{safe_signature(child)}"
            )


# ================================================================
# PROCESS MONITOR METHODS
# ================================================================

def inspect_monitor_methods(
    monitor,
) -> None:

    heading(
        "2. PROCESS MONITOR METHODS RELATED TO DETECTION / FUSION"
    )


    for name in dir(
        monitor
    ):

        if name.startswith(
            "_"
        ):

            continue


        if not matches_search_term(
            name
        ):

            continue


        try:

            value = getattr(
                monitor,
                name,
            )


        except Exception:

            continue


        if not callable(
            value
        ):

            continue


        print(

            f"{name}"
            f"{safe_signature(value)}"
        )


# ================================================================
# PRINT REAL PHASE-2 RESULT
# ================================================================

def inspect_live_return_structure(
    monitor,
) -> None:

    heading(
        "3. REAL collect_ai_behavior_features() RETURN STRUCTURE"
    )


    process_info = (
        find_stable_process(
            monitor
        )
    )


    pid = int(

        process_info[
            "pid"
        ]
    )


    print(
        "Selected PID:",
        pid,
    )


    print(
        "Selected process:",
        process_info.get(
            "name"
        ),
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


    context = (
        shared_process_behavior_context
        .get_context(
            pid
        )
    )


    result = (
        monitor.collect_ai_behavior_features(

            process_info=
                process_info,

            context=
                context,
        )
    )


    if not isinstance(
        result,
        dict,
    ):

        print(
            "Returned type:",
            type(
                result
            ),
        )


        print(
            "Returned value:",
            result,
        )


        return


    print()

    print(
        "TOP-LEVEL RESULT KEYS:"
    )


    for key in sorted(
        result.keys()
    ):

        value = (
            result[
                key
            ]
        )


        print(

            f"  {key:<40} "
            f"{type(value).__name__}"
        )


    # ============================================================
    # NESTED DICTIONARIES
    # ============================================================

    print()

    print(
        "NESTED DICTIONARY KEYS:"
    )


    for (
        key,
        value,
    ) in result.items():

        if not isinstance(
            value,
            dict,
        ):

            continue


        print()

        print(
            f"[{key}]"
        )


        for nested_key in sorted(
            value.keys()
        ):

            nested_value = (
                value[
                    nested_key
                ]
            )


            # Avoid printing large embeddings.
            if isinstance(
                nested_value,
                list,
            ):

                print(

                    f"  {nested_key:<38} "
                    f"list(len={len(nested_value)})"
                )


            elif isinstance(
                nested_value,
                dict,
            ):

                print(

                    f"  {nested_key:<38} "
                    f"dict(keys="
                    f"{list(nested_value.keys())})"
                )


            else:

                print(

                    f"  {nested_key:<38} "
                    f"{repr(nested_value)}"
                )


# ================================================================
# CLASS SOURCE INSPECTION
# ================================================================

def inspect_source_file() -> None:

    heading(
        "4. RELEVANT process_monitor.py SOURCE LINES"
    )


    source_path = Path(

        inspect.getsourcefile(
            ProcessMonitor
        )
    )


    print(
        "Source:",
        source_path,
    )


    if not source_path.exists():

        print(
            "Source file unavailable."
        )

        return


    lines = (

        source_path
        .read_text(
            encoding="utf-8",
            errors="replace",
        )
        .splitlines()
    )


    matched_lines = []


    for (
        index,
        line,
    ) in enumerate(
        lines,
        start=1,
    ):

        if any(

            term.lower()
            in line.lower()

            for term
            in SOURCE_SEARCH_TERMS

        ):

            matched_lines.append(
                index
            )


    # ============================================================
    # MERGE NEARBY MATCHES INTO SMALL BLOCKS
    # ============================================================

    ranges = []


    for line_number in matched_lines:

        start = max(
            1,
            line_number - 5,
        )


        end = min(
            len(
                lines
            ),
            line_number + 10,
        )


        if (

            ranges

            and

            start
            <= ranges[
                -1
            ][
                1
            ]
            + 1

        ):

            ranges[
                -1
            ] = (

                ranges[
                    -1
                ][
                    0
                ],

                max(
                    ranges[
                        -1
                    ][
                        1
                    ],
                    end,
                ),
            )


        else:

            ranges.append(
                (
                    start,
                    end,
                )
            )


    # Prevent huge output.
    ranges = ranges[
        :20
    ]


    for (
        start,
        end,
    ) in ranges:

        print()

        print(
            "-" * 110
        )


        print(
            f"LINES {start}-{end}"
        )


        print(
            "-" * 110
        )


        for line_number in range(

            start,
            end + 1,
        ):

            print(

                f"{line_number:>5} | "
                f"{lines[line_number - 1]}"
            )


# ================================================================
# CLASS DEFINITIONS
# ================================================================

def inspect_detector_classes(
    monitor,
) -> None:

    heading(
        "5. DETECTOR / FUSION OBJECT PUBLIC API"
    )


    seen_classes = set()


    for name in dir(
        monitor
    ):

        if name.startswith(
            "_"
        ):

            continue


        try:

            value = getattr(
                monitor,
                name,
            )


        except Exception:

            continue


        if callable(
            value
        ):

            continue


        class_name = (
            value
            .__class__
            .__name__
        )


        lowered = (
            class_name.lower()
        )


        if not any(

            keyword in lowered

            for keyword in [

                "detector",
                "fusion",
                "anomaly",
                "behavior",

            ]

        ):

            continue


        identity = (

            value
            .__class__
            .__module__,

            class_name,
        )


        if identity in seen_classes:

            continue


        seen_classes.add(
            identity
        )


        print()

        print(
            "-" * 110
        )


        print(
            f"{identity[0]}.{identity[1]}"
        )


        print(
            "-" * 110
        )


        for method_name in dir(
            value
        ):

            if method_name.startswith(
                "_"
            ):

                continue


            try:

                method = getattr(
                    value,
                    method_name,
                )


            except Exception:

                continue


            if not callable(
                method
            ):

                continue


            print(

                f"  "
                f"{method_name}"
                f"{safe_signature(method)}"
            )


# ================================================================
# ENTRY
# ================================================================

def main():

    heading(
        "SENTINEL-X PROCESS DETECTION ROUTING INSPECTION"
    )


    print(
        "This script does NOT call initialize()."
    )


    print(
        "It performs one controlled live Phase-2 sample."
    )


    print()

    print(
        "Creating Temporal-v2 + Fusion-v3 shadow monitor..."
    )


    monitor = (
        FusionV3ProcessMonitorV2(
            poll_interval=2.0
        )
    )


    inspect_instance_attributes(
        monitor
    )


    inspect_monitor_methods(
        monitor
    )


    inspect_live_return_structure(
        monitor
    )


    inspect_detector_classes(
        monitor
    )


    inspect_source_file()


    heading(
        "ROUTING INSPECTION COMPLETE"
    )


    print(
        "Copy the output sections for:"
    )


    print(
        "  1. monitor attributes"
    )


    print(
        "  2. real top-level result keys"
    )


    print(
        "  3. detector/fusion method signatures"
    )


    print(
        "  4. relevant process_monitor.py source lines"
    )


if __name__ == "__main__":

    main()