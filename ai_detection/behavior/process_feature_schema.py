from __future__ import annotations

from dataclasses import (
    asdict,
    dataclass,
)

from typing import (
    Any,
    Dict,
    List,
)


# ================================================================
# FEATURE SCHEMA VERSION
# ================================================================

PROCESS_FEATURE_SCHEMA_VERSION = (
    "process_behavior_v1"
)


# ================================================================
# MODEL FEATURE ORDER
#
# IMPORTANT:
# Never randomly change this order after a model is trained.
# Training and real-time inference must use the same feature order.
# ================================================================

PROCESS_FEATURE_NAMES = [

    # ------------------------------------------------------------
    # RESOURCE BEHAVIOR
    # ------------------------------------------------------------

    "cpu_percent",
    "memory_percent",
    "rss_mb",
    "num_threads",
    "num_handles",
    "process_age_seconds",

    # ------------------------------------------------------------
    # CROSS-DOMAIN BEHAVIOR
    # ------------------------------------------------------------

    "child_process_count",
    "network_connection_count",
    "unique_remote_ip_count",
    "file_activity_count",
    "registry_activity_count",
    "recent_event_count",

    # ------------------------------------------------------------
    # COMMAND-LINE BEHAVIOR
    # ------------------------------------------------------------

    "command_line_length",
    "command_arg_count",

    # ------------------------------------------------------------
    # EXECUTABLE LOCATION
    # ------------------------------------------------------------

    "executable_path_depth",
    "is_temp_path",
    "is_user_profile_path",
    "is_system_path",

    # ------------------------------------------------------------
    # EXECUTION BEHAVIOR
    # ------------------------------------------------------------

    "is_script_interpreter",
    "has_encoded_command",
    "has_hidden_flag",
    "has_download_keyword",
    "has_network_tool_keyword",

    # ------------------------------------------------------------
    # PARENT-CHILD RELATIONSHIP
    # ------------------------------------------------------------

    "parent_is_office_app",
    "parent_is_script_interpreter",
]


# ================================================================
# PROCESS BEHAVIOR FEATURES
# ================================================================

@dataclass
class ProcessBehaviorFeatures:

    # ------------------------------------------------------------
    # RESOURCE BEHAVIOR
    # ------------------------------------------------------------

    cpu_percent: float = 0.0

    memory_percent: float = 0.0

    rss_mb: float = 0.0

    num_threads: float = 0.0

    num_handles: float = 0.0

    process_age_seconds: float = 0.0


    # ------------------------------------------------------------
    # CROSS-DOMAIN BEHAVIOR
    # ------------------------------------------------------------

    child_process_count: float = 0.0

    network_connection_count: float = 0.0

    unique_remote_ip_count: float = 0.0

    file_activity_count: float = 0.0

    registry_activity_count: float = 0.0

    recent_event_count: float = 0.0


    # ------------------------------------------------------------
    # COMMAND-LINE BEHAVIOR
    # ------------------------------------------------------------

    command_line_length: float = 0.0

    command_arg_count: float = 0.0


    # ------------------------------------------------------------
    # EXECUTABLE LOCATION
    # ------------------------------------------------------------

    executable_path_depth: float = 0.0

    is_temp_path: float = 0.0

    is_user_profile_path: float = 0.0

    is_system_path: float = 0.0


    # ------------------------------------------------------------
    # EXECUTION BEHAVIOR
    # ------------------------------------------------------------

    is_script_interpreter: float = 0.0

    has_encoded_command: float = 0.0

    has_hidden_flag: float = 0.0

    has_download_keyword: float = 0.0

    has_network_tool_keyword: float = 0.0


    # ------------------------------------------------------------
    # PARENT-CHILD RELATIONSHIP
    # ------------------------------------------------------------

    parent_is_office_app: float = 0.0

    parent_is_script_interpreter: float = 0.0


    # ============================================================
    # CONVERT TO DICTIONARY
    # ============================================================

    def to_dict(
        self,
    ) -> Dict[
        str,
        float,
    ]:

        raw = asdict(
            self
        )


        return {

            feature_name:
                float(
                    raw.get(
                        feature_name,
                        0.0,
                    )
                )

            for feature_name
            in PROCESS_FEATURE_NAMES
        }


    # ============================================================
    # CONVERT TO MODEL VECTOR
    # ============================================================

    def to_vector(
        self,
    ) -> List[
        float
    ]:

        feature_dict = (
            self.to_dict()
        )


        return [

            feature_dict[
                feature_name
            ]

            for feature_name
            in PROCESS_FEATURE_NAMES
        ]


# ================================================================
# COMPLETE FEATURE RECORD
#
# Metadata is kept separate from model input.
#
# We do NOT send PID/process names directly into Isolation Forest.
# ================================================================

@dataclass
class ProcessFeatureRecord:

    schema_version: str

    extracted_at: str

    pid: int | None

    process_name: str | None

    parent_process_name: str | None

    executable_path: str | None

    features: ProcessBehaviorFeatures


    # ============================================================
    # SERIALIZABLE DICTIONARY
    # ============================================================

    def to_dict(
        self,
    ) -> Dict[
        str,
        Any,
    ]:

        return {

            "schema_version":
                self.schema_version,

            "extracted_at":
                self.extracted_at,

            "pid":
                self.pid,

            "process_name":
                self.process_name,

            "parent_process_name":
                self.parent_process_name,

            "executable_path":
                self.executable_path,

            "feature_names":
                list(
                    PROCESS_FEATURE_NAMES
                ),

            "features":
                self.features.to_dict(),

            "vector":
                self.features.to_vector(),
        }