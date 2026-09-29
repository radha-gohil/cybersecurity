from __future__ import annotations

from collections import (
    Counter,
    defaultdict,
)

from statistics import (
    mean,
    median,
)

from typing import (
    Any,
    Dict,
    List,
)

import numpy as np


from ai_detection.behavior.behavior_feature_store import (
    get_connection,
)

from ai_detection.behavior.dual_ai_agreement import (
    DualAIAgreementEngine,
)


# ================================================================
# SENTINEL-X LIVE FUSION V2 HEALTH EVALUATOR
#
# Evaluates REAL stored endpoint behavior results:
#
#   process behavior record
#          │
#          ├── Isolation Forest v1
#          │
#          └── Autoencoder v2
#                   │
#                   ↓
#             Dual-AI consensus
#
#
# Purpose:
#
#   - verify both models are producing live results
#   - measure paired-model coverage
#   - measure agreement/disagreement
#   - identify noisy recurring processes
#   - inspect consensus anomaly burden
#   - detect one-model-only extreme anomalies
#
#
# IMPORTANT:
#
# These diagnostics do NOT measure:
#
#   accuracy
#   precision
#   recall
#   false-positive rate
#
# because live endpoint samples do not currently have verified
# ground-truth security labels.
# ================================================================


# ================================================================
# CONFIGURATION
# ================================================================

MAX_RESULT_ROWS = 10000


MINIMUM_PAIRED_SAMPLES = 200


# Diagnostic thresholds only.
# These are calibration/review limits, not academic performance
# metrics.

MINIMUM_PAIR_COVERAGE_PERCENT = 95.0


MAX_DIAGNOSTIC_DISAGREEMENT_PERCENT = 20.0


MAX_DIAGNOSTIC_CONSENSUS_ACTIVE_PERCENT = 10.0


MAX_DIAGNOSTIC_CONSENSUS_STRONG_PERCENT = 5.0


MAX_EXTREME_SINGLE_MODEL_DISAGREEMENT_PERCENT = 5.0


ACTIVE_THRESHOLD = 60.0


STRONG_THRESHOLD = 80.0


# ================================================================
# HELPERS
# ================================================================

def safe_float(
    value: Any,
    default: float = 0.0,
) -> float:

    try:

        number = float(
            value
        )

    except (
        TypeError,
        ValueError,
    ):

        return default


    if not np.isfinite(
        number
    ):

        return default


    return number


def percentage(
    value: int,
    total: int,
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


def percentile(
    values: List[float],
    value: float,
) -> float:

    if not values:

        return 0.0


    return float(

        np.percentile(

            np.asarray(
                values,
                dtype=np.float64,
            ),

            value,
        )
    )


# ================================================================
# EVALUATOR
# ================================================================

class LiveFusionV2Evaluator:

    def __init__(
        self,
    ):

        self.ai_agreement = (
            DualAIAgreementEngine()
        )


    # ============================================================
    # LOAD MODEL RESULTS
    # ============================================================

    def load_rows(
        self,
    ) -> List[
        Dict[
            str,
            Any,
        ]
    ]:

        connection = (
            get_connection()
        )


        try:

            rows = (
                connection.execute(
                    """
                    SELECT
                        r.id AS result_id,
                        r.feature_record_id,
                        r.model_family,
                        r.model_name,
                        r.model_version,
                        r.anomaly_score,
                        r.anomaly_label,
                        r.severity,
                        r.is_alert_candidate,
                        r.raw_metric_name,
                        r.raw_metric_value,
                        r.created_at,

                        f.pid,
                        f.process_name,
                        f.parent_process_name,
                        f.executable_path,
                        f.extracted_at

                    FROM behavior_model_results AS r

                    INNER JOIN process_behavior_features AS f
                        ON f.id = r.feature_record_id

                    WHERE r.model_family IN (
                        'isolation_forest',
                        'autoencoder'
                    )

                    ORDER BY r.id DESC

                    LIMIT ?
                    """,
                    (
                        MAX_RESULT_ROWS,
                    ),
                )
                .fetchall()
            )


            return [

                dict(
                    row
                )

                for row
                in rows
            ]


        finally:

            connection.close()


    # ============================================================
    # BUILD FEATURE-RECORD PAIRS
    # ============================================================

    def build_pairs(

        self,

        rows: List[
            Dict[
                str,
                Any,
            ]
        ],

    ) -> Dict[
        int,
        Dict[
            str,
            Any,
        ]
    ]:

        pairs = {}


        # Rows arrive newest first.
        # If multiple model versions ever exist for the same
        # feature record, keep the newest result for each family.

        for row in rows:

            feature_record_id = int(

                row[
                    "feature_record_id"
                ]
            )


            model_family = str(

                row.get(
                    "model_family"
                )

                or ""
            )


            if feature_record_id not in pairs:

                pairs[
                    feature_record_id
                ] = {

                    "feature_record_id":
                        feature_record_id,

                    "pid":
                        row.get(
                            "pid"
                        ),

                    "process_name":
                        row.get(
                            "process_name"
                        )
                        or "UNKNOWN",

                    "parent_process_name":
                        row.get(
                            "parent_process_name"
                        ),

                    "executable_path":
                        row.get(
                            "executable_path"
                        ),

                    "extracted_at":
                        row.get(
                            "extracted_at"
                        ),

                    "isolation_forest":
                        None,

                    "autoencoder":
                        None,
                }


            pair = (
                pairs[
                    feature_record_id
                ]
            )


            if (

                model_family
                == "isolation_forest"

                and

                pair[
                    "isolation_forest"
                ]
                is None

            ):

                pair[
                    "isolation_forest"
                ] = row


            elif (

                model_family
                == "autoencoder"

                and

                pair[
                    "autoencoder"
                ]
                is None

            ):

                pair[
                    "autoencoder"
                ] = row


        return pairs


    # ============================================================
    # MODEL SCORE STATISTICS
    # ============================================================

    def score_statistics(

        self,

        values: List[float],

    ) -> Dict[
        str,
        Any,
    ]:

        if not values:

            return {

                "count":
                    0,

                "min":
                    0.0,

                "max":
                    0.0,

                "mean":
                    0.0,

                "median":
                    0.0,

                "p75":
                    0.0,

                "p90":
                    0.0,

                "p95":
                    0.0,

                "p99":
                    0.0,
            }


        return {

            "count":
                len(
                    values
                ),

            "min":
                min(
                    values
                ),

            "max":
                max(
                    values
                ),

            "mean":
                mean(
                    values
                ),

            "median":
                median(
                    values
                ),

            "p75":
                percentile(
                    values,
                    75,
                ),

            "p90":
                percentile(
                    values,
                    90,
                ),

            "p95":
                percentile(
                    values,
                    95,
                ),

            "p99":
                percentile(
                    values,
                    99,
                ),
        }


    # ============================================================
    # EVALUATE
    # ============================================================

    def evaluate(
        self,
    ) -> Dict[
        str,
        Any,
    ]:

        rows = (
            self.load_rows()
        )


        pairs = (
            self.build_pairs(
                rows
            )
        )


        total_feature_records = len(
            pairs
        )


        paired_samples = []


        isolation_only = 0

        autoencoder_only = 0


        model_versions = {

            "isolation_forest":
                Counter(),

            "autoencoder":
                Counter(),
        }


        # ========================================================
        # BUILD VALID PAIRS
        # ========================================================

        for pair in (
            pairs.values()
        ):

            isolation_row = (
                pair[
                    "isolation_forest"
                ]
            )


            autoencoder_row = (
                pair[
                    "autoencoder"
                ]
            )


            if isolation_row:

                model_versions[
                    "isolation_forest"
                ][
                    str(
                        isolation_row.get(
                            "model_version"
                        )
                    )
                ] += 1


            if autoencoder_row:

                model_versions[
                    "autoencoder"
                ][
                    str(
                        autoencoder_row.get(
                            "model_version"
                        )
                    )
                ] += 1


            if (

                isolation_row is not None

                and

                autoencoder_row is not None

            ):

                isolation_score = safe_float(

                    isolation_row.get(
                        "anomaly_score"
                    )
                )


                autoencoder_score = safe_float(

                    autoencoder_row.get(
                        "anomaly_score"
                    )
                )


                consensus = (

                    self.ai_agreement.calculate(

                        isolation_result={

                            "available":
                                True,

                            "anomaly_confidence":
                                isolation_score,
                        },

                        autoencoder_result={

                            "available":
                                True,

                            "anomaly_confidence":
                                autoencoder_score,
                        },
                    )
                )


                paired_samples.append(
                    {

                        **pair,

                        "isolation_score":
                            isolation_score,

                        "autoencoder_score":
                            autoencoder_score,

                        "isolation_label":
                            isolation_row.get(
                                "anomaly_label"
                            ),

                        "autoencoder_label":
                            autoencoder_row.get(
                                "anomaly_label"
                            ),

                        "consensus":
                            consensus,

                        "consensus_score":
                            safe_float(

                                consensus.get(
                                    "consensus_score"
                                )
                            ),
                    }
                )


            elif isolation_row is not None:

                isolation_only += 1


            elif autoencoder_row is not None:

                autoencoder_only += 1


        paired_count = len(
            paired_samples
        )


        pair_coverage = percentage(

            paired_count,

            total_feature_records,
        )


        # ========================================================
        # SCORE LISTS
        # ========================================================

        isolation_scores = [

            sample[
                "isolation_score"
            ]

            for sample
            in paired_samples
        ]


        autoencoder_scores = [

            sample[
                "autoencoder_score"
            ]

            for sample
            in paired_samples
        ]


        consensus_scores = [

            sample[
                "consensus_score"
            ]

            for sample
            in paired_samples
        ]


        # ========================================================
        # AGREEMENT
        # ========================================================

        agreement_counter = Counter()


        disagreement_count = 0


        both_active_count = 0

        both_strong_count = 0


        consensus_active_count = 0

        consensus_strong_count = 0


        extreme_single_model_disagreement = 0


        for sample in paired_samples:

            consensus = (
                sample[
                    "consensus"
                ]
            )


            agreement_counter[
                consensus.get(
                    "agreement",
                    "UNKNOWN",
                )
            ] += 1


            if consensus.get(
                "disagreement",
                False,
            ):

                disagreement_count += 1


            if consensus.get(
                "both_active",
                False,
            ):

                both_active_count += 1


            if consensus.get(
                "both_strong",
                False,
            ):

                both_strong_count += 1


            consensus_score = (
                sample[
                    "consensus_score"
                ]
            )


            if (

                consensus_score
                >= ACTIVE_THRESHOLD

            ):

                consensus_active_count += 1


            if (

                consensus_score
                >= STRONG_THRESHOLD

            ):

                consensus_strong_count += 1


            isolation_score = (
                sample[
                    "isolation_score"
                ]
            )


            autoencoder_score = (
                sample[
                    "autoencoder_score"
                ]
            )


            # ----------------------------------------------------
            # One model says very anomalous while the other says
            # clearly normal/low.
            # ----------------------------------------------------

            if (

                (
                    isolation_score >= 80

                    and

                    autoencoder_score < 40
                )

                or

                (
                    autoencoder_score >= 80

                    and

                    isolation_score < 40
                )

            ):

                extreme_single_model_disagreement += 1


        # ========================================================
        # CORRELATION
        # ========================================================

        score_correlation = None


        if (

            len(
                isolation_scores
            )
            >= 2

            and

            np.std(
                isolation_scores
            )
            > 0

            and

            np.std(
                autoencoder_scores
            )
            > 0

        ):

            score_correlation = float(

                np.corrcoef(

                    isolation_scores,

                    autoencoder_scores,
                )[
                    0,
                    1
                ]
            )


        # ========================================================
        # PROCESS-LEVEL STATISTICS
        # ========================================================

        process_groups = defaultdict(
            list
        )


        for sample in paired_samples:

            process_name = (

                str(

                    sample.get(
                        "process_name"
                    )

                    or "UNKNOWN"
                )
                .strip()
                .lower()
            )


            process_groups[
                process_name
            ].append(
                sample
            )


        process_statistics = []


        for (
            process_name,
            samples,
        ) in process_groups.items():

            sample_count = len(
                samples
            )


            if_scores = [

                sample[
                    "isolation_score"
                ]

                for sample
                in samples
            ]


            ae_scores = [

                sample[
                    "autoencoder_score"
                ]

                for sample
                in samples
            ]


            consensus_values = [

                sample[
                    "consensus_score"
                ]

                for sample
                in samples
            ]


            process_disagreements = sum(

                1

                for sample
                in samples

                if sample[
                    "consensus"
                ].get(
                    "disagreement",
                    False,
                )
            )


            process_active = sum(

                1

                for value
                in consensus_values

                if value
                >= ACTIVE_THRESHOLD
            )


            process_strong = sum(

                1

                for value
                in consensus_values

                if value
                >= STRONG_THRESHOLD
            )


            process_statistics.append(
                {

                    "process_name":
                        process_name,

                    "samples":
                        sample_count,

                    "if_mean":
                        mean(
                            if_scores
                        ),

                    "if_max":
                        max(
                            if_scores
                        ),

                    "ae_mean":
                        mean(
                            ae_scores
                        ),

                    "ae_max":
                        max(
                            ae_scores
                        ),

                    "consensus_mean":
                        mean(
                            consensus_values
                        ),

                    "consensus_max":
                        max(
                            consensus_values
                        ),

                    "disagreement_count":
                        process_disagreements,

                    "disagreement_rate":
                        percentage(

                            process_disagreements,

                            sample_count,
                        ),

                    "active_count":
                        process_active,

                    "active_rate":
                        percentage(

                            process_active,

                            sample_count,
                        ),

                    "strong_count":
                        process_strong,

                    "strong_rate":
                        percentage(

                            process_strong,

                            sample_count,
                        ),
                }
            )


        # ========================================================
        # RECURRING NOISY PROCESSES
        # ========================================================

        noisy_processes = [

            stats

            for stats
            in process_statistics

            if (

                stats[
                    "samples"
                ]
                >= 5

                and

                (
                    stats[
                        "active_rate"
                    ]
                    >= 20.0

                    or

                    stats[
                        "disagreement_rate"
                    ]
                    >= 30.0

                    or

                    stats[
                        "consensus_max"
                    ]
                    >= 90.0
                )
            )
        ]


        noisy_processes.sort(

            key=lambda item:
                (
                    item[
                        "active_count"
                    ],

                    item[
                        "strong_count"
                    ],

                    item[
                        "consensus_max"
                    ],
                ),

            reverse=True,
        )


        # ========================================================
        # TOP CONSENSUS ANOMALIES
        # ========================================================

        top_anomalies = sorted(

            paired_samples,

            key=lambda sample:
                sample[
                    "consensus_score"
                ],

            reverse=True,
        )[
            :20
        ]


        # ========================================================
        # EXTREME DISAGREEMENTS
        # ========================================================

        top_disagreements = sorted(

            [

                sample

                for sample
                in paired_samples

                if sample[
                    "consensus"
                ].get(
                    "disagreement",
                    False,
                )
            ],

            key=lambda sample:
                abs(

                    sample[
                        "isolation_score"
                    ]

                    - sample[
                        "autoencoder_score"
                    ]
                ),

            reverse=True,
        )[
            :20
        ]


        # ========================================================
        # HEALTH CONDITIONS
        # ========================================================

        disagreement_percent = percentage(

            disagreement_count,

            paired_count,
        )


        consensus_active_percent = percentage(

            consensus_active_count,

            paired_count,
        )


        consensus_strong_percent = percentage(

            consensus_strong_count,

            paired_count,
        )


        extreme_disagreement_percent = percentage(

            extreme_single_model_disagreement,

            paired_count,
        )


        health_checks = {

            "enough_paired_samples":

                paired_count
                >= MINIMUM_PAIRED_SAMPLES,


            "paired_model_coverage":

                pair_coverage
                >= MINIMUM_PAIR_COVERAGE_PERCENT,


            "disagreement_rate_acceptable":

                disagreement_percent
                <= MAX_DIAGNOSTIC_DISAGREEMENT_PERCENT,


            "consensus_active_rate_acceptable":

                consensus_active_percent
                <= MAX_DIAGNOSTIC_CONSENSUS_ACTIVE_PERCENT,


            "consensus_strong_rate_acceptable":

                consensus_strong_percent
                <= MAX_DIAGNOSTIC_CONSENSUS_STRONG_PERCENT,


            "extreme_disagreement_rate_acceptable":

                extreme_disagreement_percent
                <= MAX_EXTREME_SINGLE_MODEL_DISAGREEMENT_PERCENT,
        }


        healthy_for_phase3 = all(
            health_checks.values()
        )


        return {

            "row_count":
                len(
                    rows
                ),

            "feature_record_count":
                total_feature_records,

            "paired_count":
                paired_count,

            "isolation_only":
                isolation_only,

            "autoencoder_only":
                autoencoder_only,

            "pair_coverage_percent":
                pair_coverage,

            "model_versions": {

                family:
                    dict(
                        versions
                    )

                for (
                    family,
                    versions,
                )
                in model_versions.items()
            },

            "isolation_statistics":
                self.score_statistics(
                    isolation_scores
                ),

            "autoencoder_statistics":
                self.score_statistics(
                    autoencoder_scores
                ),

            "consensus_statistics":
                self.score_statistics(
                    consensus_scores
                ),

            "agreement_distribution":
                dict(
                    agreement_counter
                ),

            "disagreement_count":
                disagreement_count,

            "disagreement_percent":
                disagreement_percent,

            "both_active_count":
                both_active_count,

            "both_active_percent":
                percentage(

                    both_active_count,

                    paired_count,
                ),

            "both_strong_count":
                both_strong_count,

            "both_strong_percent":
                percentage(

                    both_strong_count,

                    paired_count,
                ),

            "consensus_active_count":
                consensus_active_count,

            "consensus_active_percent":
                consensus_active_percent,

            "consensus_strong_count":
                consensus_strong_count,

            "consensus_strong_percent":
                consensus_strong_percent,

            "extreme_single_model_disagreement":
                extreme_single_model_disagreement,

            "extreme_single_model_disagreement_percent":
                extreme_disagreement_percent,

            "score_correlation":
                score_correlation,

            "process_statistics":
                process_statistics,

            "noisy_processes":
                noisy_processes,

            "top_anomalies":
                top_anomalies,

            "top_disagreements":
                top_disagreements,

            "health_checks":
                health_checks,

            "healthy_for_phase3":
                healthy_for_phase3,
        }


    # ============================================================
    # PRINT MODEL STATS
    # ============================================================

    def print_score_stats(

        self,

        title: str,

        stats: Dict[
            str,
            Any,
        ],

    ) -> None:

        print()

        print(
            title
        )

        print(
            "-" * 82
        )

        print(
            f"Count  : {stats['count']}"
        )

        print(
            f"Mean   : {stats['mean']:.2f}"
        )

        print(
            f"Median : {stats['median']:.2f}"
        )

        print(
            f"P75    : {stats['p75']:.2f}"
        )

        print(
            f"P90    : {stats['p90']:.2f}"
        )

        print(
            f"P95    : {stats['p95']:.2f}"
        )

        print(
            f"P99    : {stats['p99']:.2f}"
        )

        print(
            f"Max    : {stats['max']:.2f}"
        )


    # ============================================================
    # PRINT REPORT
    # ============================================================

    def print_report(
        self,
        report,
    ) -> None:

        print()

        print(
            "=" * 82
        )

        print(
            "SENTINEL-X LIVE FUSION V2 HEALTH EVALUATION"
        )

        print(
            "=" * 82
        )


        print()

        print(
            "DATA COVERAGE"
        )

        print(
            "-" * 82
        )


        print(
            "Model-result rows      :",
            report[
                "row_count"
            ],
        )


        print(
            "Feature records         :",
            report[
                "feature_record_count"
            ],
        )


        print(
            "Paired IF + AE records  :",
            report[
                "paired_count"
            ],
        )


        print(
            "Isolation-only records  :",
            report[
                "isolation_only"
            ],
        )


        print(
            "Autoencoder-only records:",
            report[
                "autoencoder_only"
            ],
        )


        print(
            "Pair coverage           :",
            f"{report['pair_coverage_percent']:.2f}%",
        )


        print()

        print(
            "MODEL VERSIONS"
        )

        print(
            "-" * 82
        )


        print(
            "Isolation Forest:",
            report[
                "model_versions"
            ][
                "isolation_forest"
            ],
        )


        print(
            "Autoencoder     :",
            report[
                "model_versions"
            ][
                "autoencoder"
            ],
        )


        self.print_score_stats(

            "ISOLATION FOREST SCORE DISTRIBUTION",

            report[
                "isolation_statistics"
            ],
        )


        self.print_score_stats(

            "AUTOENCODER SCORE DISTRIBUTION",

            report[
                "autoencoder_statistics"
            ],
        )


        self.print_score_stats(

            "DUAL-AI CONSENSUS DISTRIBUTION",

            report[
                "consensus_statistics"
            ],
        )


        # ========================================================
        # AGREEMENT
        # ========================================================

        print()

        print(
            "AI AGREEMENT"
        )

        print(
            "-" * 82
        )


        print(
            "Agreement distribution:",
            report[
                "agreement_distribution"
            ],
        )


        print(
            "Disagreements          :",
            report[
                "disagreement_count"
            ],
            (
                f"({report['disagreement_percent']:.2f}%)"
            ),
        )


        print(
            "Both AI active         :",
            report[
                "both_active_count"
            ],
            (
                f"({report['both_active_percent']:.2f}%)"
            ),
        )


        print(
            "Both AI strong         :",
            report[
                "both_strong_count"
            ],
            (
                f"({report['both_strong_percent']:.2f}%)"
            ),
        )


        print(
            "Consensus >= 60        :",
            report[
                "consensus_active_count"
            ],
            (
                f"({report['consensus_active_percent']:.2f}%)"
            ),
        )


        print(
            "Consensus >= 80        :",
            report[
                "consensus_strong_count"
            ],
            (
                f"({report['consensus_strong_percent']:.2f}%)"
            ),
        )


        print(
            "Extreme one-model split:",
            report[
                "extreme_single_model_disagreement"
            ],
            (
                f"({report['extreme_single_model_disagreement_percent']:.2f}%)"
            ),
        )


        correlation = (
            report[
                "score_correlation"
            ]
        )


        if correlation is None:

            print(
                "IF ↔ AE score correlation: unavailable"
            )

        else:

            print(

                "IF ↔ AE score correlation:",

                round(
                    correlation,
                    4,
                ),
            )


        # ========================================================
        # NOISY PROCESSES
        # ========================================================

        print()

        print(
            "RECURRING HIGH/NOISY PROCESSES"
        )

        print(
            "-" * 82
        )


        noisy = (
            report[
                "noisy_processes"
            ]
        )


        if not noisy:

            print(
                "No recurring noisy process met diagnostic thresholds."
            )

        else:

            print(

                f"{'Process':<30}"
                f"{'N':>6}"
                f"{'IF Max':>9}"
                f"{'AE Max':>9}"
                f"{'AI Max':>9}"
                f"{'Act%':>8}"
                f"{'Dis%':>8}"
            )


            print(
                "-" * 82
            )


            for item in noisy[
                :20
            ]:

                print(

                    f"{item['process_name']:<30}"

                    f"{item['samples']:>6}"

                    f"{item['if_max']:>9.2f}"

                    f"{item['ae_max']:>9.2f}"

                    f"{item['consensus_max']:>9.2f}"

                    f"{item['active_rate']:>7.2f}%"

                    f"{item['disagreement_rate']:>7.2f}%"
                )


        # ========================================================
        # TOP ANOMALIES
        # ========================================================

        print()

        print(
            "TOP DUAL-AI CONSENSUS SAMPLES"
        )

        print(
            "-" * 82
        )


        for sample in (
            report[
                "top_anomalies"
            ][
                :10
            ]
        ):

            consensus = (
                sample[
                    "consensus"
                ]
            )


            print(

                f"Record={sample['feature_record_id']:<7} "
                f"Process={sample['process_name']:<25} "
                f"IF={sample['isolation_score']:>6.2f} "
                f"AE={sample['autoencoder_score']:>6.2f} "
                f"AI={sample['consensus_score']:>6.2f} "
                f"Agree={consensus.get('agreement')}"
            )


        # ========================================================
        # TOP DISAGREEMENTS
        # ========================================================

        print()

        print(
            "LARGEST AI DISAGREEMENTS"
        )

        print(
            "-" * 82
        )


        disagreements = (
            report[
                "top_disagreements"
            ]
        )


        if not disagreements:

            print(
                "No AI disagreements found."
            )

        else:

            for sample in disagreements[
                :10
            ]:

                difference = abs(

                    sample[
                        "isolation_score"
                    ]

                    - sample[
                        "autoencoder_score"
                    ]
                )


                print(

                    f"Record={sample['feature_record_id']:<7} "
                    f"Process={sample['process_name']:<25} "
                    f"IF={sample['isolation_score']:>6.2f} "
                    f"AE={sample['autoencoder_score']:>6.2f} "
                    f"Diff={difference:>6.2f} "
                    f"AI={sample['consensus_score']:>6.2f}"
                )


        # ========================================================
        # HEALTH CHECKS
        # ========================================================

        print()

        print(
            "=" * 82
        )

        print(
            "DIAGNOSTIC HEALTH CHECKS"
        )

        print(
            "=" * 82
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

                f"{check_name:<48}: "

                + (
                    "PASS"

                    if passed

                    else "REVIEW"
                )
            )


        # ========================================================
        # FINAL RESULT
        # ========================================================

        print()

        print(
            "=" * 82
        )

        print(
            "FINAL RESULT"
        )

        print(
            "=" * 82
        )


        if report[
            "healthy_for_phase3"
        ]:

            print()

            print(
                "LIVE DUAL-AI BEHAVIOR IS HEALTHY ENOUGH "
                "TO FREEZE PHASE 2."
            )

            print()

            print(
                "NEXT:"
            )

            print(
                "Proceed to Phase 3 — temporal process/event "
                "sequence intelligence."
            )


        else:

            print()

            print(
                "LIVE DUAL-AI CALIBRATION REQUIRES REVIEW "
                "BEFORE PHASE 3."
            )

            print()

            print(
                "Inspect recurring noisy processes and AI "
                "disagreement statistics before changing thresholds."
            )


        print()

        print(
            "NOTE:"
        )

        print(
            "These live diagnostics are not accuracy, precision, "
            "recall, or false-positive-rate measurements because "
            "the samples have no verified security ground truth."
        )


# ================================================================
# MAIN
# ================================================================

if __name__ == "__main__":

    evaluator = (
        LiveFusionV2Evaluator()
    )


    report = (
        evaluator.evaluate()
    )


    evaluator.print_report(
        report
    )