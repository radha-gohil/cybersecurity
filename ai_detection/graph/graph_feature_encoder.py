from __future__ import annotations

import math

from typing import (
    Any,
    Dict,
    List,
)

import numpy as np


# ================================================================
# SENTINEL-X GRAPH FEATURE ENCODER
#
# Converts heterogeneous provenance nodes into one fixed numerical
# feature space.
#
# FEATURE DIMENSION: 32
#
# IMPORTANT:
#
# These are engineered graph features.
#
# They are NOT:
#   - learned embeddings
#   - GNN outputs
#   - calibrated maliciousness probabilities
#
# ================================================================


class GraphFeatureEncoder:

    SCHEMA_VERSION = (
        "sentinelx_graph_features_v1"
    )


    FEATURE_NAMES = [

        # --------------------------------------------------------
        # NODE TYPE
        # --------------------------------------------------------

        "type_process",                    # 0
        "type_file",                       # 1
        "type_network_endpoint",           # 2
        "type_registry",                   # 3
        "type_event",                      # 4

        # --------------------------------------------------------
        # STRUCTURAL
        # --------------------------------------------------------

        "is_center_process",               # 5
        "hop_distance_norm",               # 6

        # --------------------------------------------------------
        # PROCESS INTELLIGENCE
        # --------------------------------------------------------

        "process_behavior_score",           # 7
        "process_anomaly_score",            # 8
        "process_combined_threat_score",    # 9

        "process_isolation_forest_score",   # 10
        "process_autoencoder_score",        # 11
        "process_dual_ai_consensus_score",  # 12
        "process_temporal_ai_score",        # 13
        "process_fusion_score",             # 14

        # --------------------------------------------------------
        # PROCESS TELEMETRY
        # --------------------------------------------------------

        "process_cpu_percent",              # 15
        "process_memory_percent",           # 16

        "process_network_connection_count", # 17
        "process_file_activity_count",      # 18
        "process_registry_activity_count",  # 19

        "process_is_script_interpreter",    # 20
        "process_has_encoded_command",      # 21

        # --------------------------------------------------------
        # FILE INTELLIGENCE
        # --------------------------------------------------------

        "file_static_risk_score",           # 22
        "file_malware_probability",         # 23
        "file_entropy",                     # 24
        "file_is_pe",                       # 25

        # --------------------------------------------------------
        # NETWORK
        # --------------------------------------------------------

        "network_remote_port",              # 26
        "network_remote_present",           # 27

        # --------------------------------------------------------
        # REGISTRY
        # --------------------------------------------------------

        "registry_run_key",                 # 28
        "registry_value_present",           # 29

        # --------------------------------------------------------
        # EVENT
        # --------------------------------------------------------

        "event_severity",                   # 30
        "event_is_detection",                # 31
    ]


    FEATURE_COUNT = len(
        FEATURE_NAMES
    )


    NODE_TYPE_IDS = {

        "PROCESS":
            0,

        "FILE":
            1,

        "NETWORK_ENDPOINT":
            2,

        "REGISTRY":
            3,

        "EVENT":
            4,
    }


    SEVERITY_VALUES = {

        "INFO":
            0.0,

        "LOW":
            0.25,

        "MEDIUM":
            0.50,

        "HIGH":
            0.75,

        "CRITICAL":
            1.0,
    }


    # ============================================================
    # SAFE DICTIONARY
    # ============================================================

    def safe_dict(
        self,
        value,
    ) -> Dict[str, Any]:

        if isinstance(
            value,
            dict,
        ):

            return value


        return {}


    # ============================================================
    # SAFE FLOAT
    # ============================================================

    def safe_float(
        self,
        value,
        default: float = 0.0,
    ) -> float:

        try:

            result = float(
                value
            )


            if not math.isfinite(
                result
            ):

                return default


            return result


        except (
            TypeError,
            ValueError,
        ):

            return default


    # ============================================================
    # CLAMP
    # ============================================================

    def clamp01(
        self,
        value,
    ) -> float:

        value = (
            self.safe_float(
                value
            )
        )


        return float(

            max(
                0.0,

                min(
                    1.0,
                    value,
                ),
            )
        )


    # ============================================================
    # NORMALIZE 0-100 SCORE
    #
    # Also accepts already normalized 0-1 values.
    # ============================================================

    def score01(
        self,
        value,
    ) -> float:

        value = (
            self.safe_float(
                value
            )
        )


        if value <= 0:

            return 0.0


        if value <= 1.0:

            return (
                self.clamp01(
                    value
                )
            )


        return (
            self.clamp01(
                value
                / 100.0
            )
        )


    # ============================================================
    # BOOLEAN
    # ============================================================

    def bool01(
        self,
        value,
    ) -> float:

        if isinstance(
            value,
            str,
        ):

            return (

                1.0

                if value.strip().lower()
                in {
                    "true",
                    "yes",
                    "1",
                    "enabled",
                }

                else 0.0
            )


        return (
            1.0
            if bool(
                value
            )
            else 0.0
        )


    # ============================================================
    # FIRST PRESENT VALUE
    # ============================================================

    def first_value(
        self,
        properties: Dict[str, Any],
        keys: List[str],
        default=None,
    ):

        for key in keys:

            if key in properties:

                value = (
                    properties.get(
                        key
                    )
                )


                if value is not None:

                    return value


        return default


    # ============================================================
    # LOG NORMALIZED COUNT
    #
    # 0 -> 0
    #
    # Large activity counts approach 1.
    # ============================================================

    def normalized_count(
        self,
        value,
        maximum: float = 100.0,
    ) -> float:

        value = max(

            0.0,

            self.safe_float(
                value
            ),
        )


        if value == 0:

            return 0.0


        denominator = (
            math.log1p(
                maximum
            )
        )


        if denominator <= 0:

            return 0.0


        normalized = (

            math.log1p(
                value
            )

            / denominator
        )


        return (
            self.clamp01(
                normalized
            )
        )


    # ============================================================
    # EVENT SEVERITY
    # ============================================================

    def severity_score(
        self,
        value,
    ) -> float:

        severity = str(
            value
            or "INFO"
        ).upper()


        return float(

            self.SEVERITY_VALUES.get(
                severity,
                0.0,
            )
        )


    # ============================================================
    # NODE TYPE ONE HOT
    # ============================================================

    def set_node_type(
        self,
        features: np.ndarray,
        node_type: str,
    ):

        mapping = {

            "PROCESS":
                0,

            "FILE":
                1,

            "NETWORK_ENDPOINT":
                2,

            "REGISTRY":
                3,

            "EVENT":
                4,
        }


        index = (
            mapping.get(
                node_type
            )
        )


        if index is not None:

            features[
                index
            ] = 1.0


    # ============================================================
    # PROCESS FEATURES
    # ============================================================

    def encode_process(
        self,
        features: np.ndarray,
        properties: Dict[str, Any],
    ):

        # --------------------------------------------------------
        # Behavioral / rule/statistical evidence
        # --------------------------------------------------------

        features[
            7
        ] = self.score01(

            self.first_value(
                properties,
                [
                    "behavior_score",
                    "rule_score",
                ],
            )
        )


        features[
            8
        ] = self.score01(

            self.first_value(
                properties,
                [
                    "anomaly_score",
                    "statistical_score",
                ],
            )
        )


        features[
            9
        ] = self.score01(

            self.first_value(
                properties,
                [
                    "combined_threat_score",
                    "threat_score",
                ],
            )
        )


        # --------------------------------------------------------
        # Isolation Forest
        # --------------------------------------------------------

        features[
            10
        ] = self.score01(

            self.first_value(
                properties,
                [
                    "isolation_forest_score",
                    "isolation_score",
                    "if_score",
                ],
            )
        )


        # --------------------------------------------------------
        # Autoencoder
        # --------------------------------------------------------

        features[
            11
        ] = self.score01(

            self.first_value(
                properties,
                [
                    "autoencoder_score",
                    "reconstruction_score",
                    "ae_score",
                ],
            )
        )


        # --------------------------------------------------------
        # Behavioral AI consensus
        # --------------------------------------------------------

        features[
            12
        ] = self.score01(

            self.first_value(
                properties,
                [
                    "dual_ai_consensus_score",
                    "ai_consensus_score",
                    "behavioral_ai_consensus",
                ],
            )
        )


        # --------------------------------------------------------
        # Temporal AI
        # --------------------------------------------------------

        features[
            13
        ] = self.score01(

            self.first_value(
                properties,
                [
                    "temporal_ai_score",
                    "temporal_score",
                    "temporal_anomaly_score",
                ],
            )
        )


        # --------------------------------------------------------
        # Fusion
        # --------------------------------------------------------

        features[
            14
        ] = self.score01(

            self.first_value(
                properties,
                [
                    "fusion_score",
                    "fusion_v3_score",
                ],
            )
        )


        # --------------------------------------------------------
        # CPU
        # --------------------------------------------------------

        features[
            15
        ] = self.clamp01(

            self.safe_float(

                self.first_value(
                    properties,
                    [
                        "cpu_percent",
                    ],
                )

            )
            / 100.0
        )


        # --------------------------------------------------------
        # Memory %
        # --------------------------------------------------------

        features[
            16
        ] = self.clamp01(

            self.safe_float(

                self.first_value(
                    properties,
                    [
                        "memory_percent",
                    ],
                )

            )
            / 100.0
        )


        # --------------------------------------------------------
        # Activity Counts
        # --------------------------------------------------------

        features[
            17
        ] = self.normalized_count(

            self.first_value(
                properties,
                [
                    "network_connection_count",
                ],
            )
        )


        features[
            18
        ] = self.normalized_count(

            self.first_value(
                properties,
                [
                    "file_activity_count",
                ],
            )
        )


        features[
            19
        ] = self.normalized_count(

            self.first_value(
                properties,
                [
                    "registry_activity_count",
                ],
            )
        )


        # --------------------------------------------------------
        # Behavioral flags
        # --------------------------------------------------------

        features[
            20
        ] = self.bool01(

            self.first_value(
                properties,
                [
                    "is_script_interpreter",
                ],
            )
        )


        features[
            21
        ] = self.bool01(

            self.first_value(
                properties,
                [
                    "has_encoded_command",
                    "encoded_command",
                ],
            )
        )


    # ============================================================
    # FILE FEATURES
    # ============================================================

    def encode_file(
        self,
        features: np.ndarray,
        properties: Dict[str, Any],
    ):

        features[
            22
        ] = self.score01(

            self.first_value(
                properties,
                [
                    "static_risk_score",
                    "risk_score",
                ],
            )
        )


        features[
            23
        ] = self.score01(

            self.first_value(
                properties,
                [
                    "malware_probability",
                    "malicious_probability",
                ],
            )
        )


        # --------------------------------------------------------
        # PE entropy normally approximately 0-8.
        # --------------------------------------------------------

        entropy = self.safe_float(

            self.first_value(
                properties,
                [
                    "entropy",
                ],
            )
        )


        features[
            24
        ] = self.clamp01(

            entropy
            / 8.0
        )


        features[
            25
        ] = self.bool01(

            self.first_value(
                properties,
                [
                    "is_pe",
                ],
            )
        )


    # ============================================================
    # NETWORK FEATURES
    # ============================================================

    def encode_network(
        self,
        features: np.ndarray,
        properties: Dict[str, Any],
    ):

        remote_port = self.safe_float(

            self.first_value(
                properties,
                [
                    "remote_port",
                    "destination_port",
                ],
            )
        )


        features[
            26
        ] = self.clamp01(

            remote_port
            / 65535.0
        )


        remote_ip = self.first_value(
            properties,
            [
                "remote_ip",
                "destination_ip",
            ],
        )


        features[
            27
        ] = (

            1.0

            if (
                remote_ip is not None

                and

                str(
                    remote_ip
                ).strip()
                not in {
                    "",
                    "0.0.0.0",
                    "::",
                }
            )

            else 0.0
        )


    # ============================================================
    # REGISTRY FEATURES
    # ============================================================

    def encode_registry(
        self,
        features: np.ndarray,
        properties: Dict[str, Any],
    ):

        key = str(

            self.first_value(
                properties,
                [
                    "key",
                    "registry_key",
                    "path",
                ],
                "",
            )

            or ""
        ).lower()


        run_key = (

            "\\run" in key

            or

            "\\runonce" in key
        )


        features[
            28
        ] = (
            1.0
            if run_key
            else 0.0
        )


        value = (
            self.first_value(
                properties,
                [
                    "value_data",
                    "data",
                    "value",
                ],
            )
        )


        features[
            29
        ] = (

            1.0

            if (
                value is not None

                and

                str(
                    value
                ).strip()
            )

            else 0.0
        )


    # ============================================================
    # EVENT FEATURES
    # ============================================================

    def encode_event(
        self,
        features: np.ndarray,
        properties: Dict[str, Any],
    ):

        features[
            30
        ] = self.severity_score(

            properties.get(
                "severity"
            )
        )


        event_type = str(

            properties.get(
                "event_type"
            )

            or ""

        ).lower()


        is_detection = (

            "detection"
            in event_type

            or

            "security"
            in event_type
        )


        features[
            31
        ] = (
            1.0
            if is_detection
            else 0.0
        )


    # ============================================================
    # ENCODE ONE NODE
    # ============================================================

    def encode_node(
        self,
        node: Dict[str, Any],
        *,
        center_node_id: str,
        max_hops: int,
    ) -> np.ndarray:

        features = np.zeros(
            self.FEATURE_COUNT,
            dtype=np.float32,
        )


        node_type = str(

            node.get(
                "node_type"
            )

            or ""

        ).upper()


        properties = (
            self.safe_dict(
                node.get(
                    "properties"
                )
            )
        )


        # ========================================================
        # NODE TYPE
        # ========================================================

        self.set_node_type(
            features,
            node_type,
        )


        # ========================================================
        # CENTER PROCESS
        # ========================================================

        features[
            5
        ] = (

            1.0

            if (
                node.get(
                    "node_id"
                )
                ==
                center_node_id
            )

            else 0.0
        )


        # ========================================================
        # HOP DISTANCE
        # ========================================================

        hop_distance = max(

            0,

            int(
                node.get(
                    "hop_distance",
                    0,
                )
                or 0
            ),
        )


        denominator = max(
            1,
            int(
                max_hops
            ),
        )


        features[
            6
        ] = self.clamp01(

            hop_distance
            / denominator
        )


        # ========================================================
        # TYPE SPECIFIC
        # ========================================================

        if node_type == "PROCESS":

            self.encode_process(
                features,
                properties,
            )


        elif node_type == "FILE":

            self.encode_file(
                features,
                properties,
            )


        elif node_type == "NETWORK_ENDPOINT":

            self.encode_network(
                features,
                properties,
            )


        elif node_type == "REGISTRY":

            self.encode_registry(
                features,
                properties,
            )


        elif node_type == "EVENT":

            self.encode_event(
                features,
                properties,
            )


        # ========================================================
        # NUMERICAL SAFETY
        # ========================================================

        features = np.nan_to_num(

            features,

            nan=0.0,

            posinf=1.0,

            neginf=0.0,
        )


        features = np.clip(
            features,
            0.0,
            1.0,
        )


        return (
            features.astype(
                np.float32
            )
        )


    # ============================================================
    # ENCODE SUBGRAPH
    # ============================================================

    def encode_subgraph(
        self,
        subgraph: Dict[str, Any],
    ) -> Dict[str, Any]:

        if not subgraph.get(
            "found",
            False,
        ):

            return {
                "found":
                    False,

                "x":
                    np.empty(
                        (
                            0,
                            self.FEATURE_COUNT,
                        ),
                        dtype=np.float32,
                    ),

                "node_type_ids":
                    np.empty(
                        0,
                        dtype=np.int64,
                    ),
            }


        nodes = (
            subgraph.get(
                "nodes",
                []
            )
        )


        center_node_id = (
            subgraph.get(
                "center_node_id"
            )
        )


        max_hops = int(

            subgraph.get(
                "max_hops",
                2,
            )
            or 2
        )


        encoded = []


        node_type_ids = []


        for node in nodes:

            encoded.append(

                self.encode_node(

                    node,

                    center_node_id=
                        center_node_id,

                    max_hops=
                        max_hops,
                )
            )


            node_type = str(

                node.get(
                    "node_type"
                )

                or ""

            ).upper()


            node_type_ids.append(

                self.NODE_TYPE_IDS.get(
                    node_type,
                    -1,
                )
            )


        if encoded:

            x = np.stack(
                encoded,
                axis=0,
            )

        else:

            x = np.empty(
                (
                    0,
                    self.FEATURE_COUNT,
                ),
                dtype=np.float32,
            )


        return {
            "found":
                True,

            "schema_version":
                self.SCHEMA_VERSION,

            "feature_count":
                self.FEATURE_COUNT,

            "feature_names":
                list(
                    self.FEATURE_NAMES
                ),

            "x":
                x,

            "node_type_ids":
                np.asarray(
                    node_type_ids,
                    dtype=np.int64,
                ),
        }