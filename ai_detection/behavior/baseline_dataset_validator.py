from __future__ import annotations

import json
import math
import sqlite3

from collections import (
    Counter,
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
    Optional,
    Tuple,
)


from ai_detection.behavior.behavior_feature_store import (
    get_connection,
)

from ai_detection.behavior.process_feature_schema import (
    PROCESS_FEATURE_NAMES,
    PROCESS_FEATURE_SCHEMA_VERSION,
)


# ================================================================
# SENTINEL-X BASELINE DATASET VALIDATOR
#
# Purpose:
#
# Validate the real endpoint behavioral dataset BEFORE training
# Isolation Forest.
#
# This module does NOT train AI.
# ================================================================


# ================================================================
# DATASET REQUIREMENTS
# ================================================================

MINIMUM_RECORDS = 500

RECOMMENDED_RECORDS = 1000

MINIMUM_UNIQUE_PROCESSES = 10

MAX_INVALID_RATIO = 0.02

MAX_DUPLICATE_RATIO = 0.90


# ================================================================
# FEATURES WHICH ARE EXPECTED TO BE SPARSE
#
# A value of zero is completely normal for these features.
# ================================================================

SPARSE_BINARY_FEATURES = {

    "is_temp_path",

    "is_user_profile_path",

    "is_system_path",

    "is_script_interpreter",

    "has_encoded_command",

    "has_hidden_flag",

    "has_download_keyword",

    "has_network_tool_keyword",

    "parent_is_office_app",

    "parent_is_script_interpreter",
}


# ================================================================
# FEATURES NOT YET FULLY AVAILABLE
#
# Current Watchdog / registry polling telemetry cannot reliably
# attribute events to a PID.
#
# These features remain in the schema for future Sysmon/ETW
# integration, but zero variance here should NOT fail validation.
# ================================================================

FUTURE_CONTEXT_FEATURES = {

    "file_activity_count",

    "registry_activity_count",
}


# ================================================================
# SECURITY-SENSITIVE BEHAVIOR FLAGS
#
# Presence does NOT automatically mean malicious.
#
# We only use these to detect possible baseline contamination.
# ================================================================

SECURITY_SENSITIVE_FLAGS = {

    "has_encoded_command",

    "has_hidden_flag",

    "has_download_keyword",

    "parent_is_office_app",
}


# ================================================================
# SAFE FLOAT
# ================================================================

def safe_float(
    value: Any,
) -> Optional[float]:

    try:

        number = float(
            value
        )

    except (
        TypeError,
        ValueError,
    ):

        return None

    if not math.isfinite(
        number
    ):

        return None

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
# FEATURE STATISTICS
# ================================================================

def calculate_feature_statistics(

    feature_name: str,

    values: List[float],

) -> Dict[str, Any]:


    if not values:

        return {

            "feature":
                feature_name,

            "count":
                0,

            "min":
                None,

            "max":
                None,

            "mean":
                None,

            "median":
                None,

            "std":
                None,

            "zero_ratio":
                1.0,

            "zero_percent":
                100.0,

            "unique_values":
                0,

            "constant":
                True,
        }


    zero_count = sum(

        1

        for value
        in values

        if value == 0
    )


    unique_values = len(
        set(
            values
        )
    )


    try:

        deviation = (
            pstdev(
                values
            )
            if len(
                values
            ) > 1
            else 0.0
        )

    except Exception:

        deviation = 0.0


    return {

        "feature":
            feature_name,

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

        "std":
            deviation,

        "zero_ratio":
            (
                zero_count
                / len(
                    values
                )
            ),

        "zero_percent":
            percentage(
                zero_count,
                len(
                    values
                ),
            ),

        "unique_values":
            unique_values,

        "constant":
            unique_values <= 1,
    }

def is_epoch_process_age_artifact(vector) -> bool:
    """
    Identify the historical zero-create-time artifact.

    This is a training-data quality rule, not a
    live security detection rule.
    """
    import math

    try:
        age_index = PROCESS_FEATURE_NAMES.index(
            "process_age_seconds"
        )
        age = float(vector[age_index])

        return (
            math.isfinite(age)
            and age > 1_000_000_000
        )

    except (
        TypeError,
        ValueError,
        IndexError,
        KeyError,
    ):
        return False
# ================================================================
# MAIN VALIDATOR
# ================================================================

class BaselineDatasetValidator:

    def __init__(
        self,
    ):

        self.feature_names = list(
            PROCESS_FEATURE_NAMES
        )


    # ============================================================
    # LOAD RAW DATA
    # ============================================================

    def load_records(
        self,
    ) -> List[
        Dict[
            str,
            Any,
        ]
    ]:

        with get_connection() as connection:

            rows = connection.execute(

                """
                SELECT

                    id,

                    schema_version,

                    extracted_at,

                    pid,

                    process_name,

                    parent_process_name,

                    executable_path,

                    feature_json,

                    feature_vector_json,

                    anomaly_score,

                    anomaly_prediction,

                    model_name,

                    model_version

                FROM process_behavior_features

                ORDER BY id ASC
                """

            ).fetchall()


        records = []


        for row in rows:

            records.append(
                dict(
                    row
                )
            )


        return records


    # ============================================================
    # PARSE VECTOR
    # ============================================================

    def parse_vector(

        self,

        raw_vector: Any,

    ) -> Optional[
        List[
            float
        ]
    ]:


        try:

            if isinstance(
                raw_vector,
                str,
            ):

                vector = json.loads(
                    raw_vector
                )

            else:

                vector = (
                    raw_vector
                )


        except json.JSONDecodeError:

            return None


        if not isinstance(
            vector,
            list,
        ):

            return None


        if len(
            vector
        ) != len(
            self.feature_names
        ):

            return None


        parsed_vector = []


        for value in vector:

            number = safe_float(
                value
            )


            if number is None:

                return None


            parsed_vector.append(
                number
            )


        return parsed_vector


    # ============================================================
    # VECTOR SIGNATURE
    #
    # Used only for duplicate analysis.
    # ============================================================

    def vector_signature(

        self,

        vector: List[
            float
        ],

    ) -> Tuple[
        float,
        ...
    ]:


        return tuple(

            round(
                value,
                6,
            )

            for value
            in vector
        )


    # ============================================================
    # VALIDATE
    # ============================================================

    def validate(
        self,
    ) -> Dict[
        str,
        Any,
    ]:


        records = (
            self.load_records()
        )


        total_records = len(
            records
        )


        valid_vectors = []


        valid_records = []


        invalid_vector_count = 0


        schema_mismatch_count = 0


        process_counter = Counter()


        vector_counter = Counter()


        feature_values = {

            feature_name: []

            for feature_name
            in self.feature_names
        }


        security_sensitive_records = 0


        network_active_records = 0


        # ========================================================
        # PROCESS EVERY ROW
        # ========================================================

        for record in records:

            schema_version = (

                record.get(
                    "schema_version"
                )
            )


            if (
                schema_version
                != PROCESS_FEATURE_SCHEMA_VERSION
            ):

                schema_mismatch_count += 1


            vector = (
                self.parse_vector(

                    record.get(
                        "feature_vector_json"
                    )
                )
            )


            if vector is None:

                invalid_vector_count += 1

                continue
            # Exclude historical epoch artifacts from
            # candidate baseline statistics.
            if is_epoch_process_age_artifact(vector):
                continue

            valid_vectors.append(
                vector
            )


            valid_records.append(
                record
            )


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


            process_counter[
                process_name
            ] += 1


            signature = (
                self.vector_signature(
                    vector
                )
            )


            vector_counter[
                signature
            ] += 1


            # ----------------------------------------------------
            # FEATURE VALUES
            # ----------------------------------------------------

            for (
                index,
                feature_name,
            ) in enumerate(
                self.feature_names
            ):

                feature_values[
                    feature_name
                ].append(
                    vector[
                        index
                    ]
                )


            # ----------------------------------------------------
            # NETWORK COVERAGE
            # ----------------------------------------------------

            network_index = (
                self.feature_names.index(
                    "network_connection_count"
                )
            )


            if (
                vector[
                    network_index
                ]
                > 0
            ):

                network_active_records += 1


            # ----------------------------------------------------
            # BASELINE CONTAMINATION INDICATORS
            # ----------------------------------------------------

            security_flag_present = False


            for feature_name in (
                SECURITY_SENSITIVE_FLAGS
            ):

                feature_index = (
                    self.feature_names.index(
                        feature_name
                    )
                )


                if (
                    vector[
                        feature_index
                    ]
                    > 0
                ):

                    security_flag_present = True

                    break


            if security_flag_present:

                security_sensitive_records += 1


        # ========================================================
        # VALID DATASET INFORMATION
        # ========================================================

        valid_record_count = len(
            valid_vectors
        )


        invalid_ratio = (

            invalid_vector_count
            / total_records

            if total_records
            else 0.0
        )


        # ========================================================
        # DUPLICATE ANALYSIS
        # ========================================================

        unique_vector_count = len(
            vector_counter
        )


        duplicate_count = (

            valid_record_count

            - unique_vector_count
        )


        duplicate_ratio = (

            duplicate_count
            / valid_record_count

            if valid_record_count
            else 0.0
        )


        # ========================================================
        # PROCESS DISTRIBUTION
        # ========================================================

        unique_process_count = len(
            process_counter
        )


        top_processes = (
            process_counter.most_common(
                15
            )
        )


        dominant_process_share = 0.0


        if (
            valid_record_count
            and top_processes
        ):

            dominant_process_share = (

                top_processes[0][1]

                / valid_record_count
            )


        # ========================================================
        # FEATURE STATISTICS
        # ========================================================

        feature_statistics = {}


        constant_features = []


        zero_heavy_features = []


        useful_variable_features = []


        for feature_name in (
            self.feature_names
        ):

            stats = (
                calculate_feature_statistics(

                    feature_name,

                    feature_values[
                        feature_name
                    ],
                )
            )


            feature_statistics[
                feature_name
            ] = stats


            # ----------------------------------------------------
            # CONSTANT FEATURE
            # ----------------------------------------------------

            if stats[
                "constant"
            ]:

                constant_features.append(
                    feature_name
                )


            # ----------------------------------------------------
            # ZERO-HEAVY FEATURE
            # ----------------------------------------------------

            if (
                stats[
                    "zero_ratio"
                ]
                >= 0.95
            ):

                zero_heavy_features.append(
                    feature_name
                )


            # ----------------------------------------------------
            # USEFUL VARIABLE FEATURE
            #
            # Sparse binary features are allowed to be mostly zero.
            # Future context features are ignored for readiness.
            # ----------------------------------------------------

            if (

                not stats[
                    "constant"
                ]

                and feature_name
                not in FUTURE_CONTEXT_FEATURES

            ):

                useful_variable_features.append(
                    feature_name
                )


        # ========================================================
        # DATASET WARNINGS
        # ========================================================

        warnings = []


        if total_records < MINIMUM_RECORDS:

            warnings.append(

                f"Only {total_records} records are available. "
                f"Collect at least {MINIMUM_RECORDS} before training."
            )


        elif total_records < RECOMMENDED_RECORDS:

            warnings.append(

                f"{total_records} records are available. "
                f"Training is possible, but {RECOMMENDED_RECORDS}+ "
                f"normal-behavior records are recommended."
            )


        if invalid_ratio > MAX_INVALID_RATIO:

            warnings.append(

                "Too many invalid feature vectors were found."
            )


        if schema_mismatch_count > 0:

            warnings.append(

                f"{schema_mismatch_count} records use a different "
                f"feature schema version."
            )


        if (
            unique_process_count
            < MINIMUM_UNIQUE_PROCESSES
        ):

            warnings.append(

                "The baseline contains too few unique process names."
            )


        if duplicate_ratio > MAX_DUPLICATE_RATIO:

            warnings.append(

                "The dataset contains a very high proportion of "
                "duplicate feature vectors."
            )


        if dominant_process_share > 0.50:

            warnings.append(

                "More than 50% of the baseline belongs to one "
                "process. This can bias the anomaly model."
            )


        if (
            network_active_records == 0
            and valid_record_count > 0
        ):

            warnings.append(

                "No process feature vectors contain network "
                "behavior. Verify NetworkMonitor context sharing."
            )


        contamination_ratio = (

            security_sensitive_records
            / valid_record_count

            if valid_record_count
            else 0.0
        )


        if contamination_ratio > 0.10:

            warnings.append(

                "More than 10% of baseline records contain "
                "security-sensitive command behavior. Verify that "
                "the baseline was collected during normal usage."
            )


        # ========================================================
        # TRAINING READINESS
        # ========================================================

        readiness_checks = {

            "enough_records":

                valid_record_count
                >= MINIMUM_RECORDS,


            "low_invalid_ratio":

                invalid_ratio
                <= MAX_INVALID_RATIO,


            "process_diversity":

                unique_process_count
                >= MINIMUM_UNIQUE_PROCESSES,


            "acceptable_duplicates":

                duplicate_ratio
                <= MAX_DUPLICATE_RATIO,


            "feature_variability":

                len(
                    useful_variable_features
                )
                >= 8,
        }


        ready_for_training = all(
            readiness_checks.values()
        )


        # ========================================================
        # RECOMMENDED MODEL FEATURES
        #
        # We do NOT include completely constant features.
        #
        # File/registry process attribution is not reliable yet,
        # therefore those two fields are excluded from v1 training.
        # ========================================================

        recommended_model_features = []


        excluded_model_features = []


        for feature_name in (
            self.feature_names
        ):

            stats = (
                feature_statistics[
                    feature_name
                ]
            )


            if (
                feature_name
                in FUTURE_CONTEXT_FEATURES
            ):

                excluded_model_features.append(

                    {

                        "feature":
                            feature_name,

                        "reason":
                            "PID attribution not yet available",
                    }
                )

                continue


            if stats[
                "constant"
            ]:

                excluded_model_features.append(

                    {

                        "feature":
                            feature_name,

                        "reason":
                            "constant in current baseline",
                    }
                )

                continue


            recommended_model_features.append(
                feature_name
            )


        # ========================================================
        # FINAL REPORT
        # ========================================================

        return {

            "schema_version":
                PROCESS_FEATURE_SCHEMA_VERSION,

            "total_records":
                total_records,

            "valid_records":
                valid_record_count,

            "invalid_vectors":
                invalid_vector_count,

            "invalid_percent":
                percentage(
                    invalid_vector_count,
                    total_records,
                ),

            "schema_mismatches":
                schema_mismatch_count,


            "unique_processes":
                unique_process_count,

            "top_processes":
                [

                    {

                        "process":
                            process_name,

                        "records":
                            count,

                        "percent":
                            percentage(
                                count,
                                valid_record_count,
                            ),
                    }

                    for (
                        process_name,
                        count,
                    )
                    in top_processes
                ],


            "unique_vectors":
                unique_vector_count,

            "duplicate_vectors":
                duplicate_count,

            "duplicate_percent":
                percentage(
                    duplicate_count,
                    valid_record_count,
                ),


            "network_active_records":
                network_active_records,

            "network_coverage_percent":
                percentage(
                    network_active_records,
                    valid_record_count,
                ),


            "security_sensitive_records":
                security_sensitive_records,

            "security_sensitive_percent":
                percentage(
                    security_sensitive_records,
                    valid_record_count,
                ),


            "constant_features":
                constant_features,

            "zero_heavy_features":
                zero_heavy_features,

            "useful_variable_feature_count":
                len(
                    useful_variable_features
                ),

            "useful_variable_features":
                useful_variable_features,


            "recommended_model_feature_count":
                len(
                    recommended_model_features
                ),

            "recommended_model_features":
                recommended_model_features,

            "excluded_model_features":
                excluded_model_features,


            "feature_statistics":
                feature_statistics,


            "readiness_checks":
                readiness_checks,

            "ready_for_training":
                ready_for_training,

            "warnings":
                warnings,
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


        print(
            "\n"
            + "=" * 78
        )

        print(
            "SENTINEL-X PROCESS BEHAVIOR BASELINE VALIDATION"
        )

        print(
            "=" * 78
        )


        # ========================================================
        # DATASET
        # ========================================================

        print(
            "\nDATASET"
        )

        print(
            "-" * 78
        )

        print(
            f"Schema version           : "
            f"{report['schema_version']}"
        )

        print(
            f"Total records            : "
            f"{report['total_records']}"
        )

        print(
            f"Valid records            : "
            f"{report['valid_records']}"
        )

        print(
            f"Invalid vectors          : "
            f"{report['invalid_vectors']} "
            f"({report['invalid_percent']}%)"
        )

        print(
            f"Schema mismatches        : "
            f"{report['schema_mismatches']}"
        )


        # ========================================================
        # DIVERSITY
        # ========================================================

        print(
            "\nPROCESS DIVERSITY"
        )

        print(
            "-" * 78
        )

        print(
            f"Unique processes         : "
            f"{report['unique_processes']}"
        )


        print(
            "\nTop processes:"
        )


        for process in (
            report[
                "top_processes"
            ]
        ):

            print(

                f"  {process['process']:<30} "
                f"{process['records']:>6} "
                f"({process['percent']:>6.2f}%)"
            )


        # ========================================================
        # DUPLICATES
        # ========================================================

        print(
            "\nVECTOR QUALITY"
        )

        print(
            "-" * 78
        )

        print(
            f"Unique vectors           : "
            f"{report['unique_vectors']}"
        )

        print(
            f"Duplicate vectors        : "
            f"{report['duplicate_vectors']} "
            f"({report['duplicate_percent']}%)"
        )


        # ========================================================
        # CONTEXT COVERAGE
        # ========================================================

        print(
            "\nCROSS-DOMAIN CONTEXT"
        )

        print(
            "-" * 78
        )

        print(
            f"Network-active records   : "
            f"{report['network_active_records']} "
            f"({report['network_coverage_percent']}%)"
        )

        print(
            f"Sensitive-behavior rows  : "
            f"{report['security_sensitive_records']} "
            f"({report['security_sensitive_percent']}%)"
        )


        # ========================================================
        # FEATURE SUMMARY
        # ========================================================

        print(
            "\nFEATURE QUALITY"
        )

        print(
            "-" * 78
        )

        print(
            f"Useful variable features : "
            f"{report['useful_variable_feature_count']}"
        )

        print(
            f"Model v1 features        : "
            f"{report['recommended_model_feature_count']}"
        )


        print(
            "\nConstant features:"
        )


        if report[
            "constant_features"
        ]:

            for feature_name in (
                report[
                    "constant_features"
                ]
            ):

                print(
                    f"  - {feature_name}"
                )

        else:

            print(
                "  None"
            )


        print(
            "\nZero-heavy features:"
        )


        if report[
            "zero_heavy_features"
        ]:

            for feature_name in (
                report[
                    "zero_heavy_features"
                ]
            ):

                print(
                    f"  - {feature_name}"
                )

        else:

            print(
                "  None"
            )


        # ========================================================
        # FEATURE STATISTICS
        # ========================================================

        print(
            "\nFEATURE STATISTICS"
        )

        print(
            "-" * 78
        )

        print(

            f"{'Feature':<31}"
            f"{'Mean':>11}"
            f"{'Std':>11}"
            f"{'Min':>11}"
            f"{'Max':>11}"
            f"{'Zero %':>10}"
        )


        print(
            "-" * 78
        )


        for feature_name in (
            self.feature_names
        ):

            stats = (
                report[
                    "feature_statistics"
                ][
                    feature_name
                ]
            )


            if stats[
                "mean"
            ] is None:

                continue


            print(

                f"{feature_name:<31}"

                f"{stats['mean']:>11.3f}"

                f"{stats['std']:>11.3f}"

                f"{stats['min']:>11.3f}"

                f"{stats['max']:>11.3f}"

                f"{stats['zero_percent']:>9.2f}%"
            )


        # ========================================================
        # MODEL FEATURES
        # ========================================================

        print(
            "\nRECOMMENDED ISOLATION FOREST V1 FEATURES"
        )

        print(
            "-" * 78
        )


        for feature_name in (
            report[
                "recommended_model_features"
            ]
        ):

            print(
                f"  + {feature_name}"
            )


        print(
            "\nEXCLUDED FROM MODEL V1"
        )

        print(
            "-" * 78
        )


        for item in (
            report[
                "excluded_model_features"
            ]
        ):

            print(

                f"  - {item['feature']}: "
                f"{item['reason']}"
            )


        # ========================================================
        # READINESS
        # ========================================================

        print(
            "\nTRAINING READINESS"
        )

        print(
            "-" * 78
        )


        for (
            check_name,
            result,
        ) in (
            report[
                "readiness_checks"
            ].items()
        ):

            print(

                f"{check_name:<30}: "

                + (
                    "PASS"
                    if result
                    else "FAIL"
                )
            )


        # ========================================================
        # WARNINGS
        # ========================================================

        print(
            "\nWARNINGS"
        )

        print(
            "-" * 78
        )


        if report[
            "warnings"
        ]:

            for warning in (
                report[
                    "warnings"
                ]
            ):

                print(
                    f"  ! {warning}"
                )

        else:

            print(
                "  None"
            )


        # ========================================================
        # FINAL RESULT
        # ========================================================

        print(
            "\n"
            + "=" * 78
        )


        if report[
            "ready_for_training"
        ]:

            print(
                "RESULT: BASELINE DATASET IS READY FOR ISOLATION FOREST TRAINING"
            )

        else:

            print(
                "RESULT: BASELINE DATASET IS NOT READY FOR TRAINING"
            )


        print(
            "=" * 78
        )


# ================================================================
# MAIN
# ================================================================

if __name__ == "__main__":

    validator = (
        BaselineDatasetValidator()
    )


    validation_report = (
        validator.validate()
    )


    validator.print_report(
        validation_report
    )