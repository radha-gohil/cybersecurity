from __future__ import annotations

import json

from datetime import (
    datetime,
    timezone,
)

from pathlib import Path

from typing import (
    Any,
    Dict,
    List,
    Optional,
)


# ================================================================
# SENTINEL-X RUNTIME SOURCES
# ================================================================

from endpoint.runtime.collector_heartbeat import (
    get_collector_heartbeats,
)


from ai_detection.behavior.process_fusion_v3_result_store import (
    ProcessFusionV3ResultStore,
)


# ================================================================
# PROJECT PATHS
# ================================================================

PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[1]
)


TRANSFORMER_MODEL_PATH = (
    PROJECT_ROOT
    / "models"
    / "temporal"
    / "sentinelx_process_temporal_transformer_v2.pt"
)


TRANSFORMER_METADATA_PATH = (
    PROJECT_ROOT
    / "models"
    / "temporal"
    / "sentinelx_process_temporal_transformer_v2_metadata.json"
)


TEMPORAL_CALIBRATION_PATH = (
    PROJECT_ROOT
    / "models"
    / "temporal"
    / "sentinelx_temporal_anomaly_calibration_v2.json"
)


TEMPORAL_SCALER_PATH = (
    PROJECT_ROOT
    / "models"
    / "temporal"
    / "process_temporal_scaler_v2.joblib"
)


# ================================================================
# EXPECTED PRODUCTION CONFIGURATION
# ================================================================

PRIMARY_ENGINE = (
    "process_threat_fusion_v3"
)


PRIMARY_VERSION = "v3"


PRIMARY_MODE = (
    "PRODUCTION_PRIMARY"
)


ROLLBACK_ENGINE = (
    "process_threat_fusion_v2"
)


EXPECTED_TEMPORAL_MODEL_VERSION = "v2"

EXPECTED_TEMPORAL_CALIBRATION_VERSION = "v2"

EXPECTED_TEMPORAL_SEQUENCE_LENGTH = 8

EXPECTED_TEMPORAL_FEATURE_COUNT = 26

EXPECTED_TEMPORAL_EMBEDDING_DIMENSION = 64


EXPECTED_COLLECTORS = (
    "process",
    "file",
    "network",
    "registry",
)


HEARTBEAT_FRESH_SECONDS = 20.0


# ================================================================
# HELPERS
# ================================================================

def now_iso() -> str:

    return (
        datetime
        .now(
            timezone.utc
        )
        .isoformat()
    )


def load_json(
    path: Path,
) -> Dict[str, Any]:

    if not path.exists():

        return {}


    try:

        with open(
            path,
            "r",
            encoding="utf-8",
        ) as file:

            result = (
                json.load(
                    file
                )
            )


        if isinstance(
            result,
            dict,
        ):

            return result


    except Exception:

        pass


    return {}


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
                ).replace(
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


        return (
            parsed.astimezone(
                timezone.utc
            )
        )


    except (
        TypeError,
        ValueError,
    ):

        return None


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


def safe_int(
    value,
    default: int = 0,
) -> int:

    try:

        return int(
            value
        )

    except (
        TypeError,
        ValueError,
    ):

        return default


# ================================================================
# SECURITY RUNTIME SERVICE
# ================================================================

class SecurityRuntimeService:

    def __init__(
        self,
    ):

        self.fusion_v3_store = (
            ProcessFusionV3ResultStore()
        )


    # ============================================================
    # COLLECTORS
    # ============================================================

    def get_collectors(
        self,
    ) -> Dict[str, Any]:

        raw_heartbeats = (
            get_collector_heartbeats()
        )


        now = (
            datetime.now(
                timezone.utc
            )
        )


        collectors = {}


        active_count = 0


        for collector_name in EXPECTED_COLLECTORS:

            heartbeat = (
                raw_heartbeats.get(
                    collector_name,
                    {}
                )
            )


            status = str(

                heartbeat.get(
                    "status",
                    "UNKNOWN",
                )

            ).upper()


            thread_alive = bool(

                heartbeat.get(
                    "thread_alive",
                    False,
                )
            )


            last_seen = (
                heartbeat.get(
                    "last_seen"
                )
            )


            parsed_last_seen = (
                parse_datetime(
                    last_seen
                )
            )


            age_seconds = None


            if parsed_last_seen is not None:

                age_seconds = max(

                    0.0,

                    (
                        now
                        - parsed_last_seen
                    ).total_seconds(),
                )


            fresh = (

                age_seconds is not None

                and

                age_seconds
                <= HEARTBEAT_FRESH_SECONDS
            )


            error = (
                heartbeat.get(
                    "error"
                )
            )


            healthy = (

                status
                == "ACTIVE"

                and

                thread_alive

                and

                fresh

                and

                not error
            )


            if healthy:

                active_count += 1


            collectors[
                collector_name
            ] = {
                "collector_name":
                    collector_name,

                "status":
                    status,

                "thread_alive":
                    thread_alive,

                "last_seen":
                    last_seen,

                "heartbeat_age_seconds":
                    (
                        round(
                            age_seconds,
                            2,
                        )

                        if age_seconds
                        is not None

                        else None
                    ),

                "fresh":
                    fresh,

                "healthy":
                    healthy,

                "error":
                    error,
            }


        return {
            "expected_count":
                len(
                    EXPECTED_COLLECTORS
                ),

            "healthy_count":
                active_count,

            "all_healthy":
                (
                    active_count
                    == len(
                        EXPECTED_COLLECTORS
                    )
                ),

            "collectors":
                collectors,
        }


    # ============================================================
    # TEMPORAL MODEL
    # ============================================================

    def get_temporal_runtime(
        self,
    ) -> Dict[str, Any]:

        metadata = (
            load_json(
                TRANSFORMER_METADATA_PATH
            )
        )


        calibration = (
            load_json(
                TEMPORAL_CALIBRATION_PATH
            )
        )


        architecture = (
            metadata.get(
                "architecture",
                {}
            )

            or {}
        )


        feature_policy = (
            metadata.get(
                "feature_policy",
                {}
            )

            or {}
        )


        representation_health = (
            metadata.get(
                "representation_health",
                {}
            )

            or {}
        )


        artifact_files = {
            "transformer_model":
                TRANSFORMER_MODEL_PATH.exists(),

            "transformer_metadata":
                TRANSFORMER_METADATA_PATH.exists(),

            "scaler":
                TEMPORAL_SCALER_PATH.exists(),

            "calibration":
                TEMPORAL_CALIBRATION_PATH.exists(),
        }


        artifacts_ready = all(
            artifact_files.values()
        )


        model_version = (
            metadata.get(
                "model_version"
            )
        )


        sequence_length = safe_int(

            architecture.get(
                "sequence_length"
            ),

            -1,
        )


        feature_count = safe_int(

            architecture.get(
                "input_feature_count"
            )
            or
            feature_policy.get(
                "input_feature_count"
            ),

            -1,
        )


        representation_dimension = (
            safe_int(

                architecture.get(
                    "representation_dimension"
                ),

                -1,
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
            safe_int(

                calibration.get(
                    "input_feature_count"
                ),

                -1,
            )
        )


        calibration_sequence_length = (
            safe_int(

                calibration.get(
                    "sequence_length"
                ),

                -1,
            )
        )


        removed_feature = (
            feature_policy.get(
                "removed_feature"
            )
        )


        model_configuration_valid = all(
            [
                artifacts_ready,

                (
                    model_version
                    == EXPECTED_TEMPORAL_MODEL_VERSION
                ),

                (
                    sequence_length
                    == EXPECTED_TEMPORAL_SEQUENCE_LENGTH
                ),

                (
                    feature_count
                    == EXPECTED_TEMPORAL_FEATURE_COUNT
                ),

                (
                    representation_dimension
                    == EXPECTED_TEMPORAL_EMBEDDING_DIMENSION
                ),

                (
                    removed_feature
                    == "process_age_seconds"
                ),

                (
                    calibration_version
                    == EXPECTED_TEMPORAL_CALIBRATION_VERSION
                ),

                (
                    calibration_model_version
                    == EXPECTED_TEMPORAL_MODEL_VERSION
                ),

                (
                    calibration_feature_count
                    == EXPECTED_TEMPORAL_FEATURE_COUNT
                ),

                (
                    calibration_sequence_length
                    == EXPECTED_TEMPORAL_SEQUENCE_LENGTH
                ),
            ]
        )


        return {
            "available":
                artifacts_ready,

            "healthy":
                model_configuration_valid,

            "model_name":
                metadata.get(
                    "model_name"
                ),

            "model_version":
                model_version,

            "predictor_version":
                "v2",

            "calibration_version":
                calibration_version,

            "schema_version":
                metadata.get(
                    "schema_version"
                ),

            "sequence_length":
                sequence_length,

            "feature_count":
                feature_count,

            "representation_dimension":
                representation_dimension,

            "removed_feature":
                removed_feature,

            "representation_health":
                representation_health,

            "test_split_used":
                metadata.get(
                    "test_split_used"
                ),

            "artifacts":
                artifact_files,

            "artifacts_ready":
                artifacts_ready,

            "configuration_valid":
                model_configuration_valid,
        }


    # ============================================================
    # FUSION V3
    # ============================================================

    def get_fusion_runtime(
        self,
    ) -> Dict[str, Any]:

        total_rows = (
            self.fusion_v3_store
            .count()
        )


        alert_rows = (
            self.fusion_v3_store
            .count_alerts()
        )


        recent = (
            self.fusion_v3_store
            .get_recent(
                limit=50
            )
        )


        recent = [

            row

            for row in recent

            if isinstance(
                row,
                dict,
            )
        ]


        production_rows = [

            row

            for row in recent

            if str(
                row.get(
                    "operating_mode",
                    ""
                )
            ).upper()
            == PRIMARY_MODE
        ]


        latest = (

            production_rows[
                0
            ]

            if production_rows

            else (
                recent[
                    0
                ]

                if recent

                else None
            )
        )


        temporal_evidence_count = 0

        four_category_count = 0


        for row in production_rows:

            categories = (
                row.get(
                    "categories"
                )

                or {}
            )


            if not isinstance(
                categories,
                dict,
            ):

                continue


            required_categories = {
                "rules",
                "statistical",
                "behavioral_ai",
                "temporal_ai",
            }


            if required_categories.issubset(
                categories.keys()
            ):

                four_category_count += 1


            temporal = (
                categories.get(
                    "temporal_ai"
                )

                or {}
            )


            if (

                isinstance(
                    temporal,
                    dict,
                )

                and

                temporal.get(
                    "available",
                    False,
                )

            ):

                temporal_evidence_count += 1


        latest_summary = None


        if isinstance(
            latest,
            dict,
        ):

            latest_summary = {
                "result_id":
                    latest.get(
                        "result_id"
                    ),

                "pid":
                    latest.get(
                        "pid"
                    ),

                "process_name":
                    latest.get(
                        "process_name"
                    ),

                "fusion_score":
                    latest.get(
                        "fusion_score"
                    ),

                "severity":
                    latest.get(
                        "severity"
                    ),

                "should_alert":
                    latest.get(
                        "should_alert"
                    ),

                "evidence_confidence":
                    latest.get(
                        "evidence_confidence"
                    ),

                "operating_mode":
                    latest.get(
                        "operating_mode"
                    ),

                "scores":
                    latest.get(
                        "scores"
                    ),

                "categories":
                    latest.get(
                        "categories"
                    ),

                "active_categories":
                    latest.get(
                        "active_categories"
                    ),

                "strong_categories":
                    latest.get(
                        "strong_categories"
                    ),

                "created_at":
                    (
                        latest.get(
                            "created_at"
                        )
                        or
                        latest.get(
                            "timestamp"
                        )
                    ),
            }


        primary_runtime_seen = (

            len(
                production_rows
            )
            > 0
        )


        return {
            "primary_engine":
                PRIMARY_ENGINE,

            "primary_version":
                PRIMARY_VERSION,

            "operating_mode":
                PRIMARY_MODE,

            "promoted_to_primary":
                True,

            "rollback_engine":
                ROLLBACK_ENGINE,

            "rollback_available":
                True,

            "total_persisted_results":
                total_rows,

            "alert_results":
                alert_rows,

            "recent_results_examined":
                len(
                    recent
                ),

            "recent_primary_results":
                len(
                    production_rows
                ),

            "four_category_primary_results":
                four_category_count,

            "temporal_evidence_primary_results":
                temporal_evidence_count,

            "primary_runtime_seen":
                primary_runtime_seen,

            "latest":
                latest_summary,
        }


    # ============================================================
    # OVERALL STATUS
    # ============================================================

    def get_runtime_status(
        self,
    ) -> Dict[str, Any]:

        collectors = (
            self.get_collectors()
        )


        temporal = (
            self.get_temporal_runtime()
        )


        fusion = (
            self.get_fusion_runtime()
        )


        checks = {
            "collectors":
                bool(
                    collectors.get(
                        "all_healthy",
                        False,
                    )
                ),

            "temporal_v2":
                bool(
                    temporal.get(
                        "healthy",
                        False,
                    )
                ),

            "fusion_v3_primary":
                bool(
                    fusion.get(
                        "primary_runtime_seen",
                        False,
                    )
                ),
        }


        healthy = all(
            checks.values()
        )


        return {
            "status":
                (
                    "HEALTHY"

                    if healthy

                    else "DEGRADED"
                ),

            "timestamp":
                now_iso(),

            "product":
                "SENTINEL-X",

            "runtime_phase":
                "FUSION_V3_PRIMARY",

            "primary_decision_engine":
                PRIMARY_ENGINE,

            "primary_version":
                PRIMARY_VERSION,

            "operating_mode":
                PRIMARY_MODE,

            "rollback_engine":
                ROLLBACK_ENGINE,

            "rollback_available":
                True,

            "checks":
                checks,

            "collectors":
                collectors,

            "temporal_ai":
                temporal,

            "fusion_v3":
                fusion,

            # Response execution remains simulated.
            "simulation_mode":
                True,

            "real_response_execution":
                False,
        }