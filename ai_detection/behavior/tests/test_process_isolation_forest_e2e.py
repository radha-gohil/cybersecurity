from __future__ import annotations

import copy
import sys
import ai_detection

from datetime import (
    datetime,
    timezone,
)

from typing import (
    Any,
    Dict,
    List,
)


from ai_detection.behavior.behavior_feature_store import (
    BehaviorFeatureStore,
)

from ai_detection.behavior.process_feature_schema import (
    PROCESS_FEATURE_NAMES,
    PROCESS_FEATURE_SCHEMA_VERSION,
    ProcessBehaviorFeatures,
    ProcessFeatureRecord,
)

from ai_detection.behavior.process_isolation_forest_predictor import (
    ProcessIsolationForestPredictor,
)


# ================================================================
# SENTINEL-X
# CONTROLLED PROCESS BEHAVIOR AI E2E TEST
#
# IMPORTANT:
#
# This test performs NO real suspicious activity.
#
# It does not:
#
# - execute malware
# - launch PowerShell
# - make network connections
# - modify files
# - modify registry
# - kill processes
#
# It only creates synthetic numerical feature vectors in memory
# and passes them through the trained Isolation Forest model.
# ================================================================


# ================================================================
# TIME
# ================================================================

def now_iso() -> str:

    return (
        datetime
        .now(
            timezone.utc
        )
        .isoformat()
    )


# ================================================================
# PRINT SECTION
# ================================================================

def print_section(
    title: str,
) -> None:

    print()

    print(
        "=" * 78
    )

    print(
        title
    )

    print(
        "=" * 78
    )


# ================================================================
# FEATURE DICTIONARY NORMALIZATION
# ================================================================

def normalize_feature_dict(
    features: Dict[
        str,
        Any,
    ],
) -> Dict[
    str,
    float,
]:

    normalized = {}

    for feature_name in (
        PROCESS_FEATURE_NAMES
    ):

        try:

            normalized[
                feature_name
            ] = float(

                features.get(
                    feature_name,
                    0.0,
                )
            )

        except (
            TypeError,
            ValueError,
        ):

            normalized[
                feature_name
            ] = 0.0

    return normalized


# ================================================================
# BUILD FEATURE RECORD
# ================================================================

def build_feature_record(

    feature_values: Dict[
        str,
        float,
    ],

    process_name: str,

    pid: int,

    parent_process_name: str = "synthetic-parent.exe",

) -> ProcessFeatureRecord:


    normalized = (
        normalize_feature_dict(
            feature_values
        )
    )


    features = (
        ProcessBehaviorFeatures(

            **{

                feature_name:
                    normalized[
                        feature_name
                    ]

                for feature_name
                in PROCESS_FEATURE_NAMES
            }
        )
    )


    return ProcessFeatureRecord(

        schema_version=
            PROCESS_FEATURE_SCHEMA_VERSION,

        extracted_at=
            now_iso(),

        pid=
            pid,

        process_name=
            process_name,

        parent_process_name=
            parent_process_name,

        executable_path=(
            rf"C:\Synthetic\{process_name}"
        ),

        features=
            features,
    )


# ================================================================
# FIND REAL BASELINE RECORD
#
# Prefer a record already classified NORMAL.
#
# If no prediction exists yet, use a recent valid record.
# ================================================================

def find_baseline_record(

    store: BehaviorFeatureStore,

) -> Dict[
    str,
    Any,
]:


    records = (
        store.get_recent(
            limit=5000
        )
    )


    if not records:

        raise RuntimeError(

            "No process behavior records exist. "
            "Run SENTINEL-X first and collect baseline data."
        )


    # ============================================================
    # FIRST CHOICE:
    # A REAL RECORD ALREADY CLASSIFIED NORMAL
    # ============================================================

    for record in records:

        if (

            record.get(
                "anomaly_prediction"
            )

            == "NORMAL"

            and record.get(
                "features"
            )
        ):

            return record


    # ============================================================
    # SECOND CHOICE:
    # ANY VALID REAL FEATURE RECORD
    # ============================================================

    for record in records:

        if record.get(
            "features"
        ):

            return record


    raise RuntimeError(
        "No valid behavioral feature record was found."
    )


# ================================================================
# TRAINING FEATURE STATISTICS
# ================================================================

def get_feature_stats(

    predictor: ProcessIsolationForestPredictor,

    feature_name: str,

) -> Dict[
    str,
    float,
]:


    feature_summary = (

        predictor.metadata.get(
            "feature_summary"
        )

        or {}
    )


    stats = (

        feature_summary.get(
            feature_name
        )

        or {}
    )


    def value(
        key: str,
        default: float = 0.0,
    ) -> float:

        try:

            return float(

                stats.get(
                    key,
                    default,
                )
            )

        except (
            TypeError,
            ValueError,
        ):

            return default


    return {

        "mean":
            value(
                "mean"
            ),

        "std":
            value(
                "std"
            ),

        "min":
            value(
                "min"
            ),

        "max":
            value(
                "max"
            ),

        "median":
            value(
                "median"
            ),
    }


# ================================================================
# BUILD ANOMALOUS NUMERIC VALUE
# ================================================================

def abnormal_numeric_value(

    predictor: ProcessIsolationForestPredictor,

    feature_name: str,

    strength: float,

) -> float:


    stats = (
        get_feature_stats(

            predictor,

            feature_name,
        )
    )


    baseline_mean = (
        stats[
            "mean"
        ]
    )


    baseline_std = (
        stats[
            "std"
        ]
    )


    baseline_max = (
        stats[
            "max"
        ]
    )


    # ============================================================
    # STANDARD DEVIATION BASED VALUE
    # ============================================================

    effective_std = max(

        baseline_std,

        abs(
            baseline_mean
        )
        * 0.10,

        1.0,
    )


    deviation_candidate = (

        baseline_mean

        + (
            strength
            * effective_std
        )
    )


    # ============================================================
    # MAXIMUM BASED VALUE
    # ============================================================

    maximum_candidate = (

        baseline_max

        + max(

            abs(
                baseline_max
            )
            * (
                0.25
                * strength
            ),

            strength,
        )
    )


    return max(

        0.0,

        deviation_candidate,

        maximum_candidate,
    )


# ================================================================
# MILD ANOMALY
#
# Modify only a few behavioral fields.
# ================================================================

def build_mild_features(

    baseline: Dict[
        str,
        float,
    ],

    predictor: ProcessIsolationForestPredictor,

) -> Dict[
    str,
    float,
]:


    features = copy.deepcopy(
        baseline
    )


    mild_numeric_features = [

        "cpu_percent",

        "num_threads",

        "recent_event_count",

        "network_connection_count",
    ]


    for feature_name in (
        mild_numeric_features
    ):

        if (
            feature_name
            not in predictor.feature_names
        ):

            continue


        features[
            feature_name
        ] = (

            abnormal_numeric_value(

                predictor,

                feature_name,

                strength=2.5,
            )
        )


    return features


# ================================================================
# STRONG ANOMALY
#
# Create a multi-dimensional anomaly.
#
# This is ONLY synthetic feature manipulation.
# ================================================================

def build_strong_features(

    baseline: Dict[
        str,
        float,
    ],

    predictor: ProcessIsolationForestPredictor,

) -> Dict[
    str,
    float,
]:


    features = copy.deepcopy(
        baseline
    )


    # ============================================================
    # STRONGLY ALTER CONTINUOUS FEATURES
    # ============================================================

    strong_numeric_features = [

        "cpu_percent",

        "memory_percent",

        "rss_mb",

        "num_threads",

        "num_handles",

        "child_process_count",

        "network_connection_count",

        "unique_remote_ip_count",

        "recent_event_count",

        "command_line_length",

        "command_arg_count",

        "executable_path_depth",
    ]


    for feature_name in (
        strong_numeric_features
    ):

        if (
            feature_name
            not in predictor.feature_names
        ):

            continue


        features[
            feature_name
        ] = (

            abnormal_numeric_value(

                predictor,

                feature_name,

                strength=8.0,
            )
        )


    # ============================================================
    # SUSPICIOUS BINARY BEHAVIOR COMBINATION
    #
    # Again, these are numbers in memory.
    # Nothing is actually executed.
    # ============================================================

    strong_binary_features = [

        "is_temp_path",

        "is_user_profile_path",

        "is_script_interpreter",

        "has_encoded_command",

        "has_hidden_flag",

        "has_download_keyword",

        "has_network_tool_keyword",

        "parent_is_office_app",

        "parent_is_script_interpreter",
    ]


    for feature_name in (
        strong_binary_features
    ):

        if (
            feature_name
            in predictor.feature_names
        ):

            features[
                feature_name
            ] = 1.0


    return features


# ================================================================
# PRINT PREDICTION
# ================================================================

def print_prediction(

    title: str,

    prediction: Dict[
        str,
        Any,
    ],

) -> None:


    print()

    print(
        "-" * 78
    )

    print(
        title
    )

    print(
        "-" * 78
    )


    print(
        "Available          :",
        prediction.get(
            "available"
        ),
    )


    if prediction.get(
        "prediction_failed"
    ):

        print(
            "ERROR              :",
            prediction.get(
                "error"
            ),
        )

        return


    print(
        "Process            :",
        prediction.get(
            "process_name"
        ),
    )


    print(
        "Decision score     :",
        prediction.get(
            "decision_score"
        ),
    )


    print(
        "Raw score          :",
        prediction.get(
            "raw_score"
        ),
    )


    print(
        "Model prediction   :",
        prediction.get(
            "model_prediction"
        ),
    )


    print(
        "Model outlier      :",
        prediction.get(
            "model_outlier"
        ),
    )


    print(
        "AI confidence      :",
        prediction.get(
            "anomaly_confidence"
        ),
    )


    print(
        "AI label           :",
        prediction.get(
            "anomaly_label"
        ),
    )


    print(
        "Severity           :",
        prediction.get(
            "severity"
        ),
    )


    print(
        "Should alert       :",
        prediction.get(
            "should_alert"
        ),
    )


    print(
        "\nTop feature deviations:"
    )


    deviations = (

        prediction.get(
            "feature_deviations"
        )

        or []
    )


    if not deviations:

        print(
            "  None"
        )


    for item in deviations:

        print(

            "  "
            f"{item.get('feature'):<30} "
            f"value={item.get('value'):<12} "
            f"baseline={item.get('baseline_mean'):<12} "
            f"deviation={item.get('deviation_std')}σ"
        )


# ================================================================
# CONFIDENCE
# ================================================================

def prediction_confidence(
    prediction: Dict[
        str,
        Any,
    ],
) -> float:

    try:

        return float(

            prediction.get(
                "anomaly_confidence",
                0.0,
            )
        )

    except (
        TypeError,
        ValueError,
    ):

        return 0.0


# ================================================================
# MAIN TEST
# ================================================================

def main() -> int:


    print_section(
        "SENTINEL-X CONTROLLED BEHAVIORAL AI E2E TEST"
    )


    print(
        """
This test uses synthetic feature values only.

NO malware is executed.
NO process is launched.
NO network connection is created.
NO registry value is modified.
NO file is modified.
"""
    )


    # ============================================================
    # STEP 1 — LOAD TRAINED MODEL
    # ============================================================

    print_section(
        "STEP 1 — LOAD TRAINED MODEL"
    )


    predictor = (
        ProcessIsolationForestPredictor(
            auto_load=True
        )
    )


    status = (
        predictor.get_status()
    )


    print(
        "Available     :",
        status.get(
            "available"
        ),
    )


    print(
        "Model         :",
        status.get(
            "model_name"
        ),
    )


    print(
        "Version       :",
        status.get(
            "model_version"
        ),
    )


    print(
        "Feature count :",
        status.get(
            "feature_count"
        ),
    )


    if not status.get(
        "available"
    ):

        print(
            "ERROR:",
            status.get(
                "load_error"
            ),
        )

        return 1


    # ============================================================
    # STEP 2 — LOAD REAL BASELINE SAMPLE
    # ============================================================

    print_section(
        "STEP 2 — LOAD REAL BASELINE SAMPLE"
    )


    store = (
        BehaviorFeatureStore()
    )


    baseline_row = (
        find_baseline_record(
            store
        )
    )


    baseline_features = (
        normalize_feature_dict(

            baseline_row.get(
                "features"
            )

            or {}
        )
    )


    print(
        "Record ID     :",
        baseline_row.get(
            "id"
        ),
    )


    print(
        "Process        :",
        baseline_row.get(
            "process_name"
        ),
    )


    print(
        "Stored label   :",
        baseline_row.get(
            "anomaly_prediction"
        ),
    )


    print(
        "Stored score   :",
        baseline_row.get(
            "anomaly_score"
        ),
    )


    # ============================================================
    # STEP 3 — BASELINE REPLAY
    # ============================================================

    baseline_record = (
        build_feature_record(

            feature_values=
                baseline_features,

            process_name=
                "synthetic_baseline_replay.exe",

            pid=
                90001,
        )
    )


    baseline_prediction = (
        predictor.predict(
            baseline_record
        )
    )


    print_prediction(

        "BASELINE REPLAY",

        baseline_prediction,
    )


    # ============================================================
    # STEP 4 — MILD SYNTHETIC DEVIATION
    # ============================================================

    mild_features = (
        build_mild_features(

            baseline=
                baseline_features,

            predictor=
                predictor,
        )
    )


    mild_record = (
        build_feature_record(

            feature_values=
                mild_features,

            process_name=
                "synthetic_mild_behavior.exe",

            pid=
                90002,
        )
    )


    mild_prediction = (
        predictor.predict(
            mild_record
        )
    )


    print_prediction(

        "MILD SYNTHETIC DEVIATION",

        mild_prediction,
    )


    # ============================================================
    # STEP 5 — STRONG SYNTHETIC DEVIATION
    # ============================================================

    strong_features = (
        build_strong_features(

            baseline=
                baseline_features,

            predictor=
                predictor,
        )
    )


    strong_record = (
        build_feature_record(

            feature_values=
                strong_features,

            process_name=
                "synthetic_high_anomaly.exe",

            pid=
                90003,

            parent_process_name=
                "synthetic_office_parent.exe",
        )
    )


    strong_prediction = (
        predictor.predict(
            strong_record
        )
    )


    print_prediction(

        "STRONG SYNTHETIC DEVIATION",

        strong_prediction,
    )


    # ============================================================
    # STEP 6 — COMPARE
    # ============================================================

    print_section(
        "STEP 6 — RESULT COMPARISON"
    )


    baseline_confidence = (
        prediction_confidence(
            baseline_prediction
        )
    )


    mild_confidence = (
        prediction_confidence(
            mild_prediction
        )
    )


    strong_confidence = (
        prediction_confidence(
            strong_prediction
        )
    )


    print(
        f"Baseline confidence : "
        f"{baseline_confidence:.2f}"
    )


    print(
        f"Mild confidence     : "
        f"{mild_confidence:.2f}"
    )


    print(
        f"Strong confidence   : "
        f"{strong_confidence:.2f}"
    )


    # ============================================================
    # TEST CONDITIONS
    # ============================================================

    checks = {}


    checks[
        "model_loaded"
    ] = bool(
        status.get(
            "available"
        )
    )


    checks[
        "baseline_prediction_success"
    ] = (

        baseline_prediction.get(
            "available"
        )

        and not baseline_prediction.get(
            "prediction_failed",
            False,
        )
    )


    checks[
        "mild_prediction_success"
    ] = (

        mild_prediction.get(
            "available"
        )

        and not mild_prediction.get(
            "prediction_failed",
            False,
        )
    )


    checks[
        "strong_prediction_success"
    ] = (

        strong_prediction.get(
            "available"
        )

        and not strong_prediction.get(
            "prediction_failed",
            False,
        )
    )


    checks[
        "strong_more_anomalous_than_baseline"
    ] = (

        strong_confidence

        > baseline_confidence
    )


    checks[
        "strong_materially_more_anomalous"
    ] = (

        strong_confidence

        >= (
            baseline_confidence
            + 10.0
        )
    )


    # ------------------------------------------------------------
    # ALERT THRESHOLD CHECK
    #
    # We report this separately.
    #
    # Depending on the personalized baseline, the synthetic sample
    # may or may not cross 75 on the first model version.
    # ------------------------------------------------------------

    checks[
        "strong_crosses_alert_threshold"
    ] = (

        strong_confidence
        >= 75.0
    )


    print()

    print(
        "TEST CHECKS"
    )

    print(
        "-" * 78
    )


    for (
        check_name,
        passed,
    ) in checks.items():

        print(

            f"{check_name:<45}: "

            + (
                "PASS"
                if passed
                else "FAIL"
            )
        )


    # ============================================================
    # CRITICAL TESTS
    #
    # Alert-threshold crossing is diagnostic, not a hard failure.
    # The main requirement is that strongly altered behavior is
    # scored materially more anomalous than real baseline behavior.
    # ============================================================

    critical_checks = [

        checks[
            "model_loaded"
        ],

        checks[
            "baseline_prediction_success"
        ],

        checks[
            "mild_prediction_success"
        ],

        checks[
            "strong_prediction_success"
        ],

        checks[
            "strong_more_anomalous_than_baseline"
        ],

        checks[
            "strong_materially_more_anomalous"
        ],
    ]


    print_section(
        "FINAL RESULT"
    )


    if all(
        critical_checks
    ):

        print(
            "BEHAVIORAL AI E2E TEST: PASS"
        )


        if checks[
            "strong_crosses_alert_threshold"
        ]:

            print(
                "Strong synthetic behavior also crossed "
                "the current 75-point alert threshold."
            )

        else:

            print(
                "The model detected stronger abnormality, "
                "but the synthetic sample did not cross "
                "the current 75-point alert threshold."
            )


        print(
            "\nNo real suspicious system activity was performed."
        )

        return 0


    print(
        "BEHAVIORAL AI E2E TEST: FAIL"
    )


    print(
        "\nThe model did not separate the synthetic abnormal "
        "behavior sufficiently from the real baseline."
    )


    print(
        "Do NOT change thresholds yet. Inspect the scores and "
        "feature deviations first."
    )


    return 1


# ================================================================
# ENTRY POINT
# ================================================================

if __name__ == "__main__":

    exit_code = (
        main()
    )

    sys.exit(
        exit_code
    )