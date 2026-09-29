from __future__ import annotations

import json
import sys

from datetime import (
    datetime,
    timezone,
)

from pathlib import Path

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

from endpoint.runtime.collector_heartbeat import (
    get_collector_heartbeats,
)


from ai_detection.behavior.process_fusion_v3_result_store import (
    ProcessFusionV3ResultStore,
)


# ================================================================
# ARTIFACT PATHS
# ================================================================

TRANSFORMER_METADATA_PATH = (
    PROJECT_ROOT
    / "models"
    / "temporal"
    / "sentinelx_process_temporal_transformer_v2_metadata.json"
)


CALIBRATION_PATH = (
    PROJECT_ROOT
    / "models"
    / "temporal"
    / "sentinelx_temporal_anomaly_calibration_v2.json"
)


TRANSFORMER_MODEL_PATH = (
    PROJECT_ROOT
    / "models"
    / "temporal"
    / "sentinelx_process_temporal_transformer_v2.pt"
)


TEMPORAL_SCALER_PATH = (
    PROJECT_ROOT
    / "models"
    / "temporal"
    / "process_temporal_scaler_v2.joblib"
)


# ================================================================
# CONFIG
# ================================================================

EXPECTED_COLLECTORS = {
    "process",
    "file",
    "network",
    "registry",
}


EXPECTED_PRIMARY_MODE = (
    "PRODUCTION_PRIMARY"
)


EXPECTED_TEMPORAL_MODEL_VERSION = "v2"

EXPECTED_TEMPORAL_FEATURE_COUNT = 26

EXPECTED_TEMPORAL_SEQUENCE_LENGTH = 8


MAX_HEARTBEAT_AGE_SECONDS = 20.0


# ================================================================
# HELPERS
# ================================================================

def heading(
    value: str,
):

    print()

    print(
        "=" * 100
    )

    print(
        value
    )

    print(
        "=" * 100
    )


def load_json(
    path: Path,
) -> Dict[str, Any]:

    if not path.exists():

        raise FileNotFoundError(
            f"Missing file: {path}"
        )


    with open(
        path,
        "r",
        encoding="utf-8",
    ) as file:

        result = json.load(
            file
        )


    if not isinstance(
        result,
        dict,
    ):

        raise RuntimeError(
            f"Expected dictionary JSON: {path}"
        )


    return result


def parse_datetime(
    value,
) -> Optional[datetime]:

    if not value:

        return None


    try:

        parsed = (
            datetime.fromisoformat(
                str(
                    value
                )
                .replace(
                    "Z",
                    "+00:00",
                )
            )
        )


        if parsed.tzinfo is None:

            parsed = (
                parsed.replace(
                    tzinfo=timezone.utc
                )
            )


        return parsed.astimezone(
            timezone.utc
        )


    except (
        TypeError,
        ValueError,
    ):

        return None


def heartbeat_age(
    value,
) -> Optional[float]:

    timestamp = (
        parse_datetime(
            value
        )
    )


    if timestamp is None:

        return None


    return (

        datetime.now(
            timezone.utc
        )

        - timestamp

    ).total_seconds()


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
# TEMPORAL ARTIFACT VERIFICATION
# ================================================================

def verify_temporal_artifacts():

    heading(
        "1. TEMPORAL V2 ARTIFACTS"
    )


    artifacts = {
        "transformer_model":
            TRANSFORMER_MODEL_PATH,

        "transformer_metadata":
            TRANSFORMER_METADATA_PATH,

        "calibration":
            CALIBRATION_PATH,

        "scaler":
            TEMPORAL_SCALER_PATH,
    }


    files_ok = True


    for (
        name,
        path,
    ) in artifacts.items():

        exists = (
            path.exists()
        )


        print(

            f"{name:<28}: "
            f"{'PASS' if exists else 'MISSING'}"
        )


        if not exists:

            print(
                "  ",
                path,
            )


            files_ok = False


    if not files_ok:

        return {
            "passed":
                False,
        }


    metadata = (
        load_json(
            TRANSFORMER_METADATA_PATH
        )
    )


    calibration = (
        load_json(
            CALIBRATION_PATH
        )
    )


    # ============================================================
    # MODEL METADATA
    # ============================================================

    model_version = (
        metadata.get(
            "model_version"
        )
    )


    architecture = (
        metadata.get(
            "architecture",
            {}
        )
    )


    feature_count = (

        architecture.get(
            "input_feature_count"
        )

        or

        metadata.get(
            "feature_policy",
            {}
        ).get(
            "input_feature_count"
        )
    )


    sequence_length = (
        architecture.get(
            "sequence_length"
        )
    )


    removed_feature = (
        metadata.get(
            "feature_policy",
            {}
        ).get(
            "removed_feature"
        )
    )


    calibration_version = (
        calibration.get(
            "calibration_version"
        )
    )


    calibration_model_version = (
        calibration.get(
            "model_version"
        )
    )


    calibration_feature_count = (
        calibration.get(
            "input_feature_count"
        )
    )


    calibration_sequence_length = (
        calibration.get(
            "sequence_length"
        )
    )


    checks = {
        "transformer_v2":
            (
                model_version
                == EXPECTED_TEMPORAL_MODEL_VERSION
            ),

        "feature_count_26":
            (
                int(
                    feature_count
                    or -1
                )
                == EXPECTED_TEMPORAL_FEATURE_COUNT
            ),

        "sequence_length_8":
            (
                int(
                    sequence_length
                    or -1
                )
                == EXPECTED_TEMPORAL_SEQUENCE_LENGTH
            ),

        "process_age_removed":
            (
                removed_feature
                == "process_age_seconds"
            ),

        "calibration_v2":
            (
                calibration_version
                == "v2"
            ),

        "calibration_matches_model":
            (
                calibration_model_version
                == EXPECTED_TEMPORAL_MODEL_VERSION
            ),

        "calibration_features_26":
            (
                int(
                    calibration_feature_count
                    or -1
                )
                == EXPECTED_TEMPORAL_FEATURE_COUNT
            ),

        "calibration_sequence_8":
            (
                int(
                    calibration_sequence_length
                    or -1
                )
                == EXPECTED_TEMPORAL_SEQUENCE_LENGTH
            ),
    }


    print()

    for (
        name,
        passed,
    ) in checks.items():

        print(

            f"{name:<38}: "
            f"{'PASS' if passed else 'REVIEW'}"
        )


    return {
        "passed":
            (
                files_ok
                and all(
                    checks.values()
                )
            ),

        "metadata":
            metadata,

        "calibration":
            calibration,
    }


# ================================================================
# COLLECTOR HEARTBEATS
# ================================================================

def verify_collectors():

    heading(
        "2. REAL SENTINEL AGENT COLLECTOR HEARTBEATS"
    )


    heartbeats = (
        get_collector_heartbeats()
    )


    if not heartbeats:

        print(
            "No collector heartbeat records found."
        )


        return {
            "passed":
                False,

            "heartbeats":
                {},
        }


    collector_checks = {}


    print()

    print(

        f"{'Collector':<15}"
        f"{'Status':<12}"
        f"{'Thread':<12}"
        f"{'Age':<14}"
        f"{'Result'}"
    )


    print(
        "-" * 72
    )


    for collector_name in sorted(
        EXPECTED_COLLECTORS
    ):

        heartbeat = (
            heartbeats.get(
                collector_name
            )
        )


        if heartbeat is None:

            collector_checks[
                collector_name
            ] = False


            print(

                f"{collector_name:<15}"
                f"{'MISSING':<12}"
                f"{'-':<12}"
                f"{'-':<14}"
                f"REVIEW"
            )


            continue


        status = str(

            heartbeat.get(
                "status",
                ""
            )

        ).upper()


        thread_alive = bool(

            heartbeat.get(
                "thread_alive",
                False,
            )
        )


        age = (
            heartbeat_age(

                heartbeat.get(
                    "last_seen"
                )
            )
        )


        fresh = (

            age is not None

            and

            age
            <= MAX_HEARTBEAT_AGE_SECONDS
        )


        no_error = (

            not heartbeat.get(
                "error"
            )
        )


        passed = (

            status
            == "ACTIVE"

            and

            thread_alive

            and

            fresh

            and

            no_error
        )


        collector_checks[
            collector_name
        ] = passed


        age_text = (

            f"{age:.1f}s"

            if age is not None

            else "UNKNOWN"
        )


        print(

            f"{collector_name:<15}"
            f"{status:<12}"
            f"{str(thread_alive):<12}"
            f"{age_text:<14}"
            f"{'PASS' if passed else 'REVIEW'}"
        )


        if heartbeat.get(
            "error"
        ):

            print(

                "  Error:",
                heartbeat.get(
                    "error"
                ),
            )


    return {
        "passed":
            all(
                collector_checks.values()
            ),

        "heartbeats":
            heartbeats,

        "checks":
            collector_checks,
    }


# ================================================================
# FUSION V3 DATABASE
# ================================================================

def verify_fusion_v3():

    heading(
        "3. FUSION V3 PRIMARY PERSISTENCE"
    )


    store = (
        ProcessFusionV3ResultStore()
    )


    total = (
        store.count()
    )


    alerts = (
        store.count_alerts()
    )


    recent = (
        store.get_recent(
            limit=20
        )
    )


    print()

    print(
        "Total Fusion-v3 rows :",
        total,
    )


    print(
        "Alert rows           :",
        alerts,
    )


    print(
        "Recent rows loaded   :",
        len(
            recent
        ),
    )


    primary_rows = []


    for row in recent:

        if not isinstance(
            row,
            dict,
        ):

            continue


        operating_mode = str(

            row.get(
                "operating_mode",
                ""
            )

        ).upper()


        fusion_version = str(

            row.get(
                "fusion_version",
                ""
            )

        ).lower()


        if (

            operating_mode
            == EXPECTED_PRIMARY_MODE

            and

            fusion_version
            in {
                "v3",
                "",
            }

        ):

            primary_rows.append(
                row
            )


    print()

    print(
        "Recent PRODUCTION_PRIMARY rows:",
        len(
            primary_rows
        ),
    )


    if recent:

        print()

        print(
            "Recent Fusion-v3 records:"
        )


        for row in recent[
            :10
        ]:

            print()

            print(

                "  PID       :",
                row.get(
                    "pid"
                ),
            )


            print(

                "  Process   :",
                row.get(
                    "process_name"
                ),
            )


            print(

                "  Score     :",
                row.get(
                    "fusion_score"
                ),
            )


            print(

                "  Severity  :",
                row.get(
                    "severity"
                ),
            )


            print(

                "  Mode      :",
                row.get(
                    "operating_mode"
                ),
            )


            print(

                "  Alert     :",
                row.get(
                    "should_alert"
                ),
            )


    checks = {
        "fusion_rows_exist":
            total > 0,

        "recent_rows_exist":
            len(
                recent
            ) > 0,

        "primary_mode_rows_exist":
            len(
                primary_rows
            ) > 0,
    }


    print()

    for (
        name,
        passed,
    ) in checks.items():

        print(

            f"{name:<38}: "
            f"{'PASS' if passed else 'REVIEW'}"
        )


    return {
        "passed":
            all(
                checks.values()
            ),

        "total":
            total,

        "alerts":
            alerts,

        "recent":
            recent,

        "primary_rows":
            primary_rows,
    }


# ================================================================
# TEMPORAL / FUSION CONTENT SANITY
# ================================================================

def verify_recent_fusion_content(
    fusion_result,
):

    heading(
        "4. RECENT PRIMARY FUSION CONTENT"
    )


    recent = (
        fusion_result.get(
            "recent",
            []
        )
    )


    if not recent:

        print(
            "No recent Fusion-v3 records."
        )


        return {
            "passed":
                False,
        }


    category_complete = 0

    temporal_available = 0

    valid_scores = 0


    for row in recent:

        if not isinstance(
            row,
            dict,
        ):

            continue


        score = safe_float(

            row.get(
                "fusion_score"
            )
        )


        if (

            score is not None

            and

            0.0
            <= score
            <= 100.0

        ):

            valid_scores += 1


        categories = (
            row.get(
                "categories"
            )

            or {}
        )


        if isinstance(
            categories,
            dict,
        ):

            required = {
                "rules",
                "statistical",
                "behavioral_ai",
                "temporal_ai",
            }


            if required.issubset(
                categories.keys()
            ):

                category_complete += 1


            temporal = (
                categories.get(
                    "temporal_ai"
                )

                or {}
            )


            if temporal.get(
                "available",
                False,
            ):

                temporal_available += 1


    checks = {
        "valid_fusion_scores":
            valid_scores > 0,

        "four_category_schema":
            category_complete > 0,

        "temporal_v2_evidence_seen":
            temporal_available > 0,
    }


    print()

    print(
        "Valid scores              :",
        valid_scores,
    )


    print(
        "Four-category rows         :",
        category_complete,
    )


    print(
        "Temporal-available rows    :",
        temporal_available,
    )


    print()

    for (
        name,
        passed,
    ) in checks.items():

        print(

            f"{name:<38}: "
            f"{'PASS' if passed else 'REVIEW'}"
        )


    return {
        "passed":
            all(
                checks.values()
            ),

        "checks":
            checks,
    }


# ================================================================
# MAIN
# ================================================================

def main():

    heading(
        "SENTINEL-X PRODUCTION PRIMARY RUNTIME VERIFICATION"
    )


    print()

    print(
        "IMPORTANT:"
    )


    print(
        "Run the real SentinelAgent in another PowerShell window:"
    )


    print()

    print(
        "python -m endpoint.agent.sentinel_agent"
    )


    # ============================================================
    # 1. TEMPORAL
    # ============================================================

    temporal = (
        verify_temporal_artifacts()
    )


    # ============================================================
    # 2. HEARTBEATS
    # ============================================================

    collectors = (
        verify_collectors()
    )


    # ============================================================
    # 3. FUSION V3
    # ============================================================

    fusion = (
        verify_fusion_v3()
    )


    # ============================================================
    # 4. CONTENT
    # ============================================================

    content = (
        verify_recent_fusion_content(
            fusion
        )
    )


    # ============================================================
    # FINAL
    # ============================================================

    checks = {
        "temporal_v2_artifacts":
            temporal[
                "passed"
            ],

        "agent_collectors_active":
            collectors[
                "passed"
            ],

        "fusion_v3_primary_persistence":
            fusion[
                "passed"
            ],

        "complete_fusion_v3_content":
            content[
                "passed"
            ],
    }


    heading(
        "FINAL PRODUCTION RUNTIME READINESS"
    )


    for (
        name,
        passed,
    ) in checks.items():

        print(

            f"{name:<42}: "
            f"{'PASS' if passed else 'REVIEW'}"
        )


    passed = all(
        checks.values()
    )


    print()

    print(
        "=" * 100
    )


    if passed:

        print(
            "SENTINEL-X FUSION V3 PRIMARY RUNTIME: PASS"
        )


        print()

        print(
            "Fusion v3 primary runtime is healthy."
        )


        print(
            "Temporal Transformer v2 artifacts are valid."
        )


        print(
            "All endpoint collector threads are active."
        )


        print(
            "Production-primary Fusion-v3 results are being persisted."
        )


    else:

        print(
            "SENTINEL-X FUSION V3 PRIMARY RUNTIME: REVIEW REQUIRED"
        )


        print()

        print(
            "Do not continue to the API/dashboard promotion "
            "until the REVIEW checks are resolved."
        )


    print(
        "=" * 100
    )


if __name__ == "__main__":

    main()