from __future__ import annotations

import math

from collections import (
    Counter,
    defaultdict,
)

from statistics import (
    mean,
    median,
    pstdev,
)

from typing import (
    Any,
    Dict,
    List,
)


from ai_detection.behavior.behavior_feature_store import (
    BehaviorFeatureStore,
)

from ai_detection.behavior.process_isolation_forest_predictor import (
    ProcessIsolationForestPredictor,
)


# ================================================================
# SENTINEL-X BEHAVIOR MODEL EVALUATOR
#
# Purpose:
#
# Evaluate the real behavior of the trained Isolation Forest model
# before it is fused with the existing rule/statistical engines.
#
# IMPORTANT:
#
# Because the live endpoint data does not contain verified
# ground-truth malicious/benign labels, this module DOES NOT claim
# to calculate:
#
#     accuracy
#     precision
#     recall
#     F1
#     false-positive rate
#
# Instead it measures:
#
#     score distribution
#     alert burden
#     saturation
#     label distribution
#     process distribution
#     process-specific alert rates
#     model-version consistency
#     feature drift against training baseline
#
# ================================================================


# ================================================================
# EVALUATION CONFIGURATION
# ================================================================

MAX_RECORDS = 5000


# Current real-time alert threshold from predictor.
CURRENT_ALERT_THRESHOLD = 75.0


# Scores very close to 100 indicate confidence saturation.
SATURATION_THRESHOLD = 99.5


# Minimum amount of scored endpoint behavior for useful evaluation.
MINIMUM_SCORED_RECORDS = 200


# These are operational diagnostics only.
#
# They are NOT claims about actual false positives.
MAX_DIAGNOSTIC_ALERT_RATE_PERCENT = 10.0

MAX_DIAGNOSTIC_SATURATION_PERCENT = 5.0


# Feature drift threshold:
#
# live feature mean differs by > 2 training standard deviations.
HIGH_DRIFT_STD = 2.0


# ================================================================
# SAFE FLOAT
# ================================================================

def safe_float(
    value: Any,
    default: float | None = None,
) -> float | None:

    try:

        number = float(
            value
        )

    except (
        TypeError,
        ValueError,
    ):

        return default

    if not math.isfinite(
        number
    ):

        return default

    return number


# ================================================================
# PERCENTAGE
# ================================================================

def percentage(
    value: float,
    total: float,
) -> float:

    if total <= 0:

        return 0.0

    return round(

        (
            value
            / total
        )
        * 100.0,

        2,
    )


# ================================================================
# PERCENTILE
# ================================================================

def percentile(
    values: List[float],
    percent: float,
) -> float:

    if not values:

        return 0.0

    ordered = sorted(
        values
    )

    if len(
        ordered
    ) == 1:

        return float(
            ordered[0]
        )

    position = (

        (
            len(
                ordered
            )
            - 1
        )

        * (
            percent
            / 100.0
        )
    )

    lower_index = int(
        math.floor(
            position
        )
    )

    upper_index = int(
        math.ceil(
            position
        )
    )

    if lower_index == upper_index:

        return float(
            ordered[
                lower_index
            ]
        )

    fraction = (

        position
        - lower_index
    )

    lower_value = (
        ordered[
            lower_index
        ]
    )

    upper_value = (
        ordered[
            upper_index
        ]
    )

    return float(

        lower_value

        + (
            upper_value
            - lower_value
        )
        * fraction
    )


# ================================================================
# MAIN EVALUATOR
# ================================================================

class BehaviorModelEvaluator:

    def __init__(
        self,
    ):

        self.store = (
            BehaviorFeatureStore()
        )

        self.predictor = (
            ProcessIsolationForestPredictor(
                auto_load=True
            )
        )


    # ============================================================
    # LOAD SCORED RECORDS
    # ============================================================

    def load_scored_records(
        self,
    ) -> List[
        Dict[
            str,
            Any,
        ]
    ]:

        records = (
            self.store.get_recent(
                limit=MAX_RECORDS
            )
        )

        scored_records = []

        for record in records:

            score = safe_float(

                record.get(
                    "anomaly_score"
                )
            )

            if score is None:

                continue

            cleaned = dict(
                record
            )

            cleaned[
                "anomaly_score"
            ] = score

            scored_records.append(
                cleaned
            )

        return scored_records


    # ============================================================
    # SCORE DISTRIBUTION
    # ============================================================

    def calculate_score_statistics(

        self,

        records: List[
            Dict[
                str,
                Any,
            ]
        ],

    ) -> Dict[
        str,
        Any,
    ]:

        scores = [

            float(
                record[
                    "anomaly_score"
                ]
            )

            for record
            in records
        ]

        if not scores:

            return {

                "count":
                    0,
            }

        return {

            "count":
                len(
                    scores
                ),

            "min":
                min(
                    scores
                ),

            "max":
                max(
                    scores
                ),

            "mean":
                mean(
                    scores
                ),

            "median":
                median(
                    scores
                ),

            "std":
                (
                    pstdev(
                        scores
                    )

                    if len(
                        scores
                    ) > 1

                    else 0.0
                ),

            "p50":
                percentile(
                    scores,
                    50,
                ),

            "p75":
                percentile(
                    scores,
                    75,
                ),

            "p90":
                percentile(
                    scores,
                    90,
                ),

            "p95":
                percentile(
                    scores,
                    95,
                ),

            "p97":
                percentile(
                    scores,
                    97,
                ),

            "p99":
                percentile(
                    scores,
                    99,
                ),
        }


    # ============================================================
    # LABEL DISTRIBUTION
    # ============================================================

    def calculate_label_distribution(

        self,

        records: List[
            Dict[
                str,
                Any,
            ]
        ],

    ) -> Dict[
        str,
        Any,
    ]:

        counter = Counter()

        for record in records:

            label = (

                str(

                    record.get(
                        "anomaly_prediction"
                    )

                    or "UNKNOWN"

                )
                .strip()
                .upper()
            )

            counter[
                label
            ] += 1

        total = len(
            records
        )

        ordered_labels = [

            "NORMAL",

            "UNUSUAL",

            "SUSPICIOUS",

            "HIGH_ANOMALY",

            "UNKNOWN",
        ]

        result = {}

        for label in ordered_labels:

            count = (
                counter.get(
                    label,
                    0,
                )
            )

            result[
                label
            ] = {

                "count":
                    count,

                "percent":
                    percentage(
                        count,
                        total,
                    ),
            }

        # Include any unexpected labels too.

        for (
            label,
            count,
        ) in counter.items():

            if label in result:

                continue

            result[
                label
            ] = {

                "count":
                    count,

                "percent":
                    percentage(
                        count,
                        total,
                    ),
            }

        return result


    # ============================================================
    # ALERT BURDEN
    #
    # This is NOT a false-positive rate.
    #
    # We do not have verified labels.
    # ============================================================

    def calculate_alert_statistics(

        self,

        records: List[
            Dict[
                str,
                Any,
            ]
        ],

    ) -> Dict[
        str,
        Any,
    ]:

        total = len(
            records
        )

        alert_count = 0

        suspicious_count = 0

        high_anomaly_count = 0

        saturated_count = 0

        for record in records:

            score = float(
                record[
                    "anomaly_score"
                ]
            )

            if score >= CURRENT_ALERT_THRESHOLD:

                alert_count += 1

            if score >= 60:

                suspicious_count += 1

            if score >= 80:

                high_anomaly_count += 1

            if score >= SATURATION_THRESHOLD:

                saturated_count += 1

        return {

            "total":
                total,

            "alert_threshold":
                CURRENT_ALERT_THRESHOLD,

            "alert_count":
                alert_count,

            "alert_rate_percent":
                percentage(
                    alert_count,
                    total,
                ),

            "suspicious_or_higher_count":
                suspicious_count,

            "suspicious_or_higher_percent":
                percentage(
                    suspicious_count,
                    total,
                ),

            "high_anomaly_count":
                high_anomaly_count,

            "high_anomaly_percent":
                percentage(
                    high_anomaly_count,
                    total,
                ),

            "saturated_count":
                saturated_count,

            "saturation_percent":
                percentage(
                    saturated_count,
                    total,
                ),
        }


    # ============================================================
    # MODEL VERSION DISTRIBUTION
    # ============================================================

    def calculate_model_versions(

        self,

        records: List[
            Dict[
                str,
                Any,
            ]
        ],

    ) -> List[
        Dict[
            str,
            Any,
        ]
    ]:

        counter = Counter()

        for record in records:

            key = (

                str(
                    record.get(
                        "model_name"
                    )
                    or "UNKNOWN"
                ),

                str(
                    record.get(
                        "model_version"
                    )
                    or "UNKNOWN"
                ),
            )

            counter[
                key
            ] += 1

        result = []

        for (
            model_key,
            count,
        ) in counter.most_common():

            result.append(
                {

                    "model_name":
                        model_key[
                            0
                        ],

                    "model_version":
                        model_key[
                            1
                        ],

                    "count":
                        count,
                }
            )

        return result


    # ============================================================
    # PROCESS STATISTICS
    # ============================================================

    def calculate_process_statistics(

        self,

        records: List[
            Dict[
                str,
                Any,
            ]
        ],

    ) -> List[
        Dict[
            str,
            Any,
        ]
    ]:

        process_data = defaultdict(
            lambda: {

                "scores": [],

                "labels": Counter(),

                "alert_count": 0,
            }
        )

        for record in records:

            process_name = (

                str(

                    record.get(
                        "process_name"
                    )

                    or "UNKNOWN"

                )
                .strip()
                .lower()
            )

            score = float(
                record[
                    "anomaly_score"
                ]
            )

            label = (

                str(

                    record.get(
                        "anomaly_prediction"
                    )

                    or "UNKNOWN"

                )
                .strip()
                .upper()
            )

            process_data[
                process_name
            ][
                "scores"
            ].append(
                score
            )

            process_data[
                process_name
            ][
                "labels"
            ][
                label
            ] += 1

            if score >= CURRENT_ALERT_THRESHOLD:

                process_data[
                    process_name
                ][
                    "alert_count"
                ] += 1

        result = []

        for (
            process_name,
            data,
        ) in process_data.items():

            scores = (
                data[
                    "scores"
                ]
            )

            sample_count = len(
                scores
            )

            result.append(
                {

                    "process_name":
                        process_name,

                    "sample_count":
                        sample_count,

                    "mean_score":
                        mean(
                            scores
                        ),

                    "max_score":
                        max(
                            scores
                        ),

                    "median_score":
                        median(
                            scores
                        ),

                    "alert_count":
                        data[
                            "alert_count"
                        ],

                    "alert_rate_percent":
                        percentage(

                            data[
                                "alert_count"
                            ],

                            sample_count,
                        ),

                    "labels":
                        dict(
                            data[
                                "labels"
                            ]
                        ),
                }
            )

        result.sort(

            key=lambda item: (

                item[
                    "alert_count"
                ],

                item[
                    "max_score"
                ],
            ),

            reverse=True,
        )

        return result


    # ============================================================
    # TOP ANOMALOUS RECORDS
    # ============================================================

    def get_top_anomalies(

        self,

        records: List[
            Dict[
                str,
                Any,
            ]
        ],

        limit: int = 20,

    ) -> List[
        Dict[
            str,
            Any,
        ]
    ]:

        ordered = sorted(

            records,

            key=lambda record:
                float(
                    record[
                        "anomaly_score"
                    ]
                ),

            reverse=True,
        )

        result = []

        for record in ordered[
            :limit
        ]:

            result.append(
                {

                    "id":
                        record.get(
                            "id"
                        ),

                    "process_name":
                        record.get(
                            "process_name"
                        ),

                    "pid":
                        record.get(
                            "pid"
                        ),

                    "score":
                        record.get(
                            "anomaly_score"
                        ),

                    "label":
                        record.get(
                            "anomaly_prediction"
                        ),

                    "extracted_at":
                        record.get(
                            "extracted_at"
                        ),
                }
            )

        return result


    # ============================================================
    # FEATURE DRIFT
    #
    # Compare the mean value of recent live features against the
    # training baseline.
    #
    # This is a basic drift diagnostic, not yet a formal concept
    # drift detector.
    # ============================================================

    def calculate_feature_drift(

        self,

        records: List[
            Dict[
                str,
                Any,
            ]
        ],

    ) -> List[
        Dict[
            str,
            Any,
        ]
    ]:

        training_summary = (

            self.predictor.metadata.get(
                "feature_summary"
            )

            or {}
        )

        model_features = (
            self.predictor.feature_names
        )

        feature_values = {

            feature_name: []

            for feature_name
            in model_features
        }

        for record in records:

            features = (

                record.get(
                    "features"
                )

                or {}
            )

            for feature_name in model_features:

                value = safe_float(

                    features.get(
                        feature_name
                    )
                )

                if value is None:

                    continue

                feature_values[
                    feature_name
                ].append(
                    value
                )

        drift_results = []

        for feature_name in model_features:

            values = (
                feature_values[
                    feature_name
                ]
            )

            if not values:

                continue

            live_mean = mean(
                values
            )

            stats = (

                training_summary.get(
                    feature_name
                )

                or {}
            )

            training_mean = safe_float(

                stats.get(
                    "mean"
                ),

                0.0,
            )

            training_std = safe_float(

                stats.get(
                    "std"
                ),

                0.0,
            )

            if training_mean is None:

                training_mean = 0.0

            if training_std is None:

                training_std = 0.0

            if training_std <= 1e-12:

                if live_mean == training_mean:

                    drift_std = 0.0

                else:

                    drift_std = abs(

                        live_mean

                        - training_mean
                    )

            else:

                drift_std = abs(

                    (
                        live_mean

                        - training_mean
                    )

                    / training_std
                )

            if drift_std >= HIGH_DRIFT_STD:

                drift_level = (
                    "HIGH"
                )

            elif drift_std >= 1.0:

                drift_level = (
                    "MODERATE"
                )

            else:

                drift_level = (
                    "LOW"
                )

            drift_results.append(
                {

                    "feature":
                        feature_name,

                    "training_mean":
                        training_mean,

                    "live_mean":
                        live_mean,

                    "training_std":
                        training_std,

                    "drift_std":
                        drift_std,

                    "drift_level":
                        drift_level,
                }
            )

        drift_results.sort(

            key=lambda item:
                item[
                    "drift_std"
                ],

            reverse=True,
        )

        return drift_results


    # ============================================================
    # EVALUATION HEALTH CHECKS
    # ============================================================

    def calculate_health_checks(

        self,

        records: List[
            Dict[
                str,
                Any,
            ]
        ],

        alert_statistics: Dict[
            str,
            Any,
        ],

        feature_drift: List[
            Dict[
                str,
                Any,
            ]
        ],

        model_versions: List[
            Dict[
                str,
                Any,
            ]
        ],

    ) -> Dict[
        str,
        bool,
    ]:

        high_drift_count = sum(

            1

            for item
            in feature_drift

            if item[
                "drift_level"
            ] == "HIGH"
        )

        feature_count = len(
            feature_drift
        )

        high_drift_ratio = (

            high_drift_count
            / feature_count

            if feature_count
            else 0.0
        )

        return {

            "enough_live_samples":

                len(
                    records
                )
                >= MINIMUM_SCORED_RECORDS,


            "alert_burden_reasonable":

                alert_statistics[
                    "alert_rate_percent"
                ]
                <= MAX_DIAGNOSTIC_ALERT_RATE_PERCENT,


            "score_saturation_reasonable":

                alert_statistics[
                    "saturation_percent"
                ]
                <= MAX_DIAGNOSTIC_SATURATION_PERCENT,


            "feature_drift_reasonable":

                high_drift_ratio
                <= 0.20,


            "single_model_version":

                len(
                    model_versions
                )
                == 1,
        }


    # ============================================================
    # FULL EVALUATION
    # ============================================================

    def evaluate(
        self,
    ) -> Dict[
        str,
        Any,
    ]:

        if not self.predictor.available:

            raise RuntimeError(

                "Behavioral Isolation Forest model is unavailable: "
                f"{self.predictor.load_error}"
            )

        records = (
            self.load_scored_records()
        )

        score_statistics = (
            self.calculate_score_statistics(
                records
            )
        )

        label_distribution = (
            self.calculate_label_distribution(
                records
            )
        )

        alert_statistics = (
            self.calculate_alert_statistics(
                records
            )
        )

        process_statistics = (
            self.calculate_process_statistics(
                records
            )
        )

        model_versions = (
            self.calculate_model_versions(
                records
            )
        )

        top_anomalies = (
            self.get_top_anomalies(
                records
            )
        )

        feature_drift = (
            self.calculate_feature_drift(
                records
            )
        )

        health_checks = (
            self.calculate_health_checks(

                records=
                    records,

                alert_statistics=
                    alert_statistics,

                feature_drift=
                    feature_drift,

                model_versions=
                    model_versions,
            )
        )

        all_health_checks_pass = all(
            health_checks.values()
        )

        return {

            "model_status":
                self.predictor.get_status(),

            "scored_records":
                len(
                    records
                ),

            "score_statistics":
                score_statistics,

            "label_distribution":
                label_distribution,

            "alert_statistics":
                alert_statistics,

            "process_statistics":
                process_statistics,

            "model_versions":
                model_versions,

            "top_anomalies":
                top_anomalies,

            "feature_drift":
                feature_drift,

            "health_checks":
                health_checks,

            "healthy_for_fusion":
                all_health_checks_pass,
        }


    # ============================================================
    # PRINT REPORT
    # ============================================================

    def print_report(

        self,

        report: Dict[
            str,
            Any,
        ],

    ) -> None:

        print()

        print(
            "=" * 82
        )

        print(
            "SENTINEL-X BEHAVIORAL AI LIVE EVALUATION"
        )

        print(
            "=" * 82
        )

        # ========================================================
        # MODEL
        # ========================================================

        model_status = (
            report[
                "model_status"
            ]
        )

        print(
            "\nMODEL"
        )

        print(
            "-" * 82
        )

        print(
            "Name              :",
            model_status.get(
                "model_name"
            ),
        )

        print(
            "Version           :",
            model_status.get(
                "model_version"
            ),
        )

        print(
            "Features          :",
            model_status.get(
                "feature_count"
            ),
        )

        print(
            "Scored records    :",
            report[
                "scored_records"
            ],
        )

        # ========================================================
        # SCORE DISTRIBUTION
        # ========================================================

        stats = (
            report[
                "score_statistics"
            ]
        )

        print(
            "\nANOMALY SCORE DISTRIBUTION"
        )

        print(
            "-" * 82
        )

        if stats.get(
            "count",
            0,
        ) > 0:

            print(
                f"Minimum           : {stats['min']:.2f}"
            )

            print(
                f"Maximum           : {stats['max']:.2f}"
            )

            print(
                f"Mean              : {stats['mean']:.2f}"
            )

            print(
                f"Median            : {stats['median']:.2f}"
            )

            print(
                f"Std               : {stats['std']:.2f}"
            )

            print(
                f"P75               : {stats['p75']:.2f}"
            )

            print(
                f"P90               : {stats['p90']:.2f}"
            )

            print(
                f"P95               : {stats['p95']:.2f}"
            )

            print(
                f"P97               : {stats['p97']:.2f}"
            )

            print(
                f"P99               : {stats['p99']:.2f}"
            )

        # ========================================================
        # LABEL DISTRIBUTION
        # ========================================================

        print(
            "\nLABEL DISTRIBUTION"
        )

        print(
            "-" * 82
        )

        for (
            label,
            data,
        ) in (
            report[
                "label_distribution"
            ].items()
        ):

            print(

                f"{label:<20} "
                f"{data['count']:>7} "
                f"({data['percent']:>6.2f}%)"
            )

        # ========================================================
        # ALERT BURDEN
        # ========================================================

        alert_stats = (
            report[
                "alert_statistics"
            ]
        )

        print(
            "\nOPERATIONAL ALERT DIAGNOSTICS"
        )

        print(
            "-" * 82
        )

        print(
            "Current threshold :",
            alert_stats[
                "alert_threshold"
            ],
        )

        print(
            "Alert count       :",
            alert_stats[
                "alert_count"
            ],
        )

        print(
            "Alert rate        :",
            f"{alert_stats['alert_rate_percent']:.2f}%",
        )

        print(
            ">= 60 score       :",
            f"{alert_stats['suspicious_or_higher_percent']:.2f}%",
        )

        print(
            ">= 80 score       :",
            f"{alert_stats['high_anomaly_percent']:.2f}%",
        )

        print(
            "Score saturation  :",
            f"{alert_stats['saturation_percent']:.2f}%",
        )

        print(
            "\nNOTE:"
        )

        print(
            "Alert rate is NOT a false-positive rate because "
            "these live records do not have verified ground-truth labels."
        )

        # ========================================================
        # MODEL VERSIONS
        # ========================================================

        print(
            "\nMODEL VERSION DISTRIBUTION"
        )

        print(
            "-" * 82
        )

        for item in (
            report[
                "model_versions"
            ]
        ):

            print(

                f"{item['model_name']} "
                f"{item['model_version']} "
                f"-> {item['count']} records"
            )

        # ========================================================
        # TOP ANOMALOUS PROCESSES
        # ========================================================

        print(
            "\nTOP PROCESS GROUPS BY ALERT ACTIVITY"
        )

        print(
            "-" * 82
        )

        print(

            f"{'Process':<32}"
            f"{'Samples':>9}"
            f"{'Mean':>9}"
            f"{'Max':>9}"
            f"{'Alerts':>9}"
            f"{'Alert %':>10}"
        )

        print(
            "-" * 82
        )

        for item in (
            report[
                "process_statistics"
            ][
                :20
            ]
        ):

            print(

                f"{item['process_name']:<32}"

                f"{item['sample_count']:>9}"

                f"{item['mean_score']:>9.2f}"

                f"{item['max_score']:>9.2f}"

                f"{item['alert_count']:>9}"

                f"{item['alert_rate_percent']:>9.2f}%"
            )

        # ========================================================
        # TOP INDIVIDUAL ANOMALIES
        # ========================================================

        print(
            "\nTOP INDIVIDUAL AI SCORES"
        )

        print(
            "-" * 82
        )

        for item in (
            report[
                "top_anomalies"
            ][
                :15
            ]
        ):

            print(

                f"ID={item['id']} | "
                f"Process={item['process_name']} | "
                f"PID={item['pid']} | "
                f"Score={item['score']} | "
                f"Label={item['label']}"
            )

        # ========================================================
        # FEATURE DRIFT
        # ========================================================

        print(
            "\nFEATURE DRIFT VS TRAINING BASELINE"
        )

        print(
            "-" * 82
        )

        print(

            f"{'Feature':<31}"
            f"{'Train Mean':>13}"
            f"{'Live Mean':>13}"
            f"{'Drift σ':>11}"
            f"{'Level':>12}"
        )

        print(
            "-" * 82
        )

        for item in (
            report[
                "feature_drift"
            ]
        ):

            print(

                f"{item['feature']:<31}"

                f"{item['training_mean']:>13.3f}"

                f"{item['live_mean']:>13.3f}"

                f"{item['drift_std']:>11.3f}"

                f"{item['drift_level']:>12}"
            )

        # ========================================================
        # HEALTH CHECKS
        # ========================================================

        print(
            "\nFUSION READINESS CHECKS"
        )

        print(
            "-" * 82
        )

        for (
            check_name,
            passed,
        ) in (
            report[
                "health_checks"
            ].items()
        ):

            print(

                f"{check_name:<35}: "

                + (
                    "PASS"
                    if passed
                    else "REVIEW"
                )
            )

        # ========================================================
        # THRESHOLD REFERENCES
        # ========================================================

        print(
            "\nOBSERVED SCORE REFERENCES"
        )

        print(
            "-" * 82
        )

        print(
            "These are reference values only. "
            "Do not automatically replace the alert threshold."
        )

        if stats.get(
            "count",
            0,
        ) > 0:

            print(
                f"Observed P95 : {stats['p95']:.2f}"
            )

            print(
                f"Observed P97 : {stats['p97']:.2f}"
            )

            print(
                f"Observed P99 : {stats['p99']:.2f}"
            )

            print(
                f"Current alert threshold : "
                f"{CURRENT_ALERT_THRESHOLD:.2f}"
            )

        # ========================================================
        # FINAL
        # ========================================================

        print()

        print(
            "=" * 82
        )

        if report[
            "healthy_for_fusion"
        ]:

            print(
                "RESULT: MODEL BEHAVIOR IS HEALTHY ENOUGH TO PROCEED TO FUSION"
            )

        else:

            print(
                "RESULT: REVIEW MODEL CALIBRATION BEFORE FUSION"
            )

        print(
            "=" * 82
        )


# ================================================================
# MAIN
# ================================================================

if __name__ == "__main__":

    evaluator = (
        BehaviorModelEvaluator()
    )

    evaluation_report = (
        evaluator.evaluate()
    )

    evaluator.print_report(
        evaluation_report
    )