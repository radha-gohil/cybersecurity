from __future__ import annotations

import json
import math

from pathlib import Path
from typing import Optional

import numpy as np
import torch


from ai_detection.graph.graph_feature_encoder import (
    GraphFeatureEncoder,
)

from ai_detection.graph.process_subgraph_service import (
    ProcessSubgraphService,
)

from ai_detection.graph.graph_anomaly_calibrator_v1 import (
    build_type_aware_reconstruction_mask,
    load_graph_model,
    CALIBRATION_PATH,
    MODEL_PATH,
)


# ================================================================
# SENTINEL-X PROCESS GRAPH ANOMALY PREDICTOR
# ================================================================


class ProcessGraphAnomalyPredictor:

    PREDICTOR_NAME = (
        "sentinelx_process_graph_anomaly"
    )


    PREDICTOR_VERSION = "v1"


    OPERATING_MODE = (
        "SHADOW_GRAPH_AI"
    )


    def __init__(
        self,
        *,
        database_path=None,
        model_path=None,
        calibration_path=None,
        device=None,
        max_hops: int = 2,
    ):

        self.model_path = Path(
            model_path
            or MODEL_PATH
        )


        self.calibration_path = Path(
            calibration_path
            or CALIBRATION_PATH
        )


        self.max_hops = int(
            max_hops
        )


        if device is None:

            device = (
                "cuda"

                if torch.cuda.is_available()

                else "cpu"
            )


        self.device = (
            device
        )


        # ========================================================
        # ARTIFACT CHECKS
        # ========================================================

        if not self.model_path.exists():

            raise FileNotFoundError(
                f"Graph model missing: {self.model_path}"
            )


        if not self.calibration_path.exists():

            raise FileNotFoundError(
                (
                    "Graph calibration missing: "
                    f"{self.calibration_path}"
                )
            )


        # ========================================================
        # MODEL
        # ========================================================

        (
            self.model,
            self.checkpoint,
        ) = load_graph_model(

            model_path=
                self.model_path,

            device=
                self.device,
        )


        # ========================================================
        # CALIBRATION
        # ========================================================

        with open(
            self.calibration_path,
            "r",
            encoding="utf-8",
        ) as file:

            self.calibration = (
                json.load(
                    file
                )
            )


        # ========================================================
        # GRAPH SERVICES
        # ========================================================

        self.subgraph_service = (
            ProcessSubgraphService(
                database_path=
                    database_path
            )
        )


        self.feature_encoder = (
            GraphFeatureEncoder()
        )


    # ============================================================
    # CALIBRATE RAW RECONSTRUCTION ERROR
    # ============================================================

    def calibrate_error(
        self,
        raw_error: float,
    ) -> float:

        raw_error = float(
            raw_error
        )


        anchors = (
            self.calibration.get(
                "score_anchors",
                [],
            )
        )


        if not anchors:

            return 0.0


        anchors = sorted(

            anchors,

            key=lambda item:
                float(
                    item[
                        "error"
                    ]
                ),
        )


        minimum = float(
            anchors[
                0
            ][
                "error"
            ]
        )


        maximum = float(
            anchors[
                -1
            ][
                "error"
            ]
        )


        # ========================================================
        # BELOW REFERENCE MINIMUM
        # ========================================================

        if raw_error <= minimum:

            return 0.0


        # ========================================================
        # INTERPOLATE BETWEEN ANCHORS
        # ========================================================

        for index in range(
            len(
                anchors
            )
            - 1
        ):

            left = (
                anchors[
                    index
                ]
            )


            right = (
                anchors[
                    index
                    + 1
                ]
            )


            x1 = float(
                left[
                    "error"
                ]
            )


            x2 = float(
                right[
                    "error"
                ]
            )


            y1 = float(
                left[
                    "score"
                ]
            )


            y2 = float(
                right[
                    "score"
                ]
            )


            if (
                x2
                <= x1
            ):

                continue


            if (
                x1
                <= raw_error
                <= x2
            ):

                ratio = (

                    (
                        raw_error
                        - x1
                    )

                    /

                    (
                        x2
                        - x1
                    )
                )


                score = (

                    y1

                    +

                    ratio
                    *
                    (
                        y2
                        - y1
                    )
                )


                return float(

                    max(
                        0.0,

                        min(
                            100.0,
                            score,
                        ),
                    )
                )


        # ========================================================
        # ABOVE REFERENCE MAXIMUM
        #
        # Smoothly approach 100.
        # ========================================================

        p50 = float(

            next(
                (
                    item[
                        "error"
                    ]

                    for item in anchors

                    if (
                        item.get(
                            "percentile"
                        )
                        == 50
                    )
                ),

                minimum,
            )
        )


        spread = max(

            maximum
            - p50,

            maximum
            * 0.10,

            1e-8,
        )


        excess = max(

            0.0,

            raw_error
            - maximum,
        )


        score = (

            95.0

            +

            5.0
            *
            (
                1.0

                -

                math.exp(
                    -excess
                    / spread
                )
            )
        )


        return float(

            max(
                0.0,

                min(
                    100.0,
                    score,
                ),
            )
        )


    # ============================================================
    # SCORE BAND
    # ============================================================

    def score_band(
        self,
        score: float,
    ) -> str:

        if score >= 80:

            return (
                "HIGH_ANOMALY"
            )


        if score >= 60:

            return (
                "SUSPICIOUS"
            )


        if score >= 40:

            return (
                "UNUSUAL"
            )


        return "NORMAL"


    # ============================================================
    # CENTER AI EVIDENCE COVERAGE
    #
    # Missing score is NOT treated as proof of normal behavior.
    # This diagnostic reports how much upstream AI evidence was
    # actually present on the center process node.
    # ============================================================

    def calculate_ai_evidence_coverage(
        self,
        subgraph,
    ):

        center = (
            subgraph.get(
                "center_node",
                {}
            )
        )


        properties = (
            center.get(
                "properties",
                {}
            )

            or {}
        )


        groups = {

            "isolation_forest": [
                "isolation_forest_score",
                "isolation_score",
                "if_score",
            ],

            "autoencoder": [
                "autoencoder_score",
                "reconstruction_score",
                "ae_score",
            ],

            "behavioral_consensus": [
                "dual_ai_consensus_score",
                "ai_consensus_score",
                "behavioral_ai_consensus",
            ],

            "temporal_ai": [
                "temporal_ai_score",
                "temporal_score",
                "temporal_anomaly_score",
            ],

            "fusion": [
                "fusion_score",
                "fusion_v3_score",
            ],
        }


        availability = {}


        for (
            group,
            keys,
        ) in groups.items():

            availability[
                group
            ] = any(

                (
                    key
                    in properties

                    and

                    properties.get(
                        key
                    )
                    is not None
                )

                for key in keys
            )


        available_count = sum(

            1

            for value
            in availability.values()

            if value
        )


        coverage = (

            available_count

            /

            len(
                groups
            )
        )


        return {
            "availability":
                availability,

            "available_count":
                available_count,

            "expected_count":
                len(
                    groups
                ),

            "coverage":
                float(
                    coverage
                ),
        }


    # ============================================================
    # PREDICT
    # ============================================================

    @torch.no_grad()
    def predict(
        self,
        *,
        pid,
        process_name: Optional[str] = None,
        device_id: Optional[str] = None,
    ):

        # ========================================================
        # PROCESS SUBGRAPH
        # ========================================================

        subgraph = (
            self.subgraph_service
            .get_process_subgraph(

                pid=
                    pid,

                process_name=
                    process_name,

                device_id=
                    device_id,

                max_hops=
                    self.max_hops,

                include_event_nodes=
                    True,
            )
        )


        if not subgraph.get(
            "found",
            False,
        ):

            return {
                "available":
                    False,

                "state":
                    "PROCESS_GRAPH_NOT_FOUND",

                "pid":
                    pid,

                "process_name":
                    process_name,

                "graph_anomaly_score":
                    None,

                "embedding":
                    None,

                "operating_mode":
                    self.OPERATING_MODE,
            }


        # ========================================================
        # FEATURES
        # ========================================================

        encoded = (
            self.feature_encoder
            .encode_subgraph(
                subgraph
            )
        )


        # ========================================================
        # STRUCTURE
        # ========================================================

        structure = (
            self.subgraph_service
            .export_gnn_structure(
                subgraph
            )
        )


        x_array = (
            encoded[
                "x"
            ]
        )


        node_type_array = (
            encoded[
                "node_type_ids"
            ]
        )


        edge_index_array = (
            np.asarray(

                structure[
                    "edge_index"
                ],

                dtype=np.int64,
            )
        )


        edge_type_array = (
            np.asarray(

                structure[
                    "edge_type_ids"
                ],

                dtype=np.int64,
            )
        )


        center_index = (
            structure[
                "center_node_index"
            ]
        )


        if center_index is None:

            return {
                "available":
                    False,

                "state":
                    "CENTER_PROCESS_NOT_RESOLVED",

                "pid":
                    pid,

                "graph_anomaly_score":
                    None,

                "embedding":
                    None,

                "operating_mode":
                    self.OPERATING_MODE,
            }


        # ========================================================
        # TYPE SAFETY
        # ========================================================

        if (
            node_type_array.size > 0

            and

            (
                node_type_array.min()
                < 0

                or

                node_type_array.max()
                >= int(
                    self.checkpoint[
                        "num_node_types"
                    ]
                )
            )
        ):

            raise RuntimeError(
                "Unsupported graph node type encountered."
            )


        if (
            edge_type_array.size > 0

            and

            (
                edge_type_array.min()
                < 0

                or

                edge_type_array.max()
                >= int(
                    self.checkpoint[
                        "num_edge_types"
                    ]
                )
            )
        ):

            raise RuntimeError(
                "Unsupported graph edge type encountered."
            )


        # ========================================================
        # TORCH
        # ========================================================

        x = torch.tensor(

            x_array,

            dtype=torch.float32,

            device=self.device,
        )


        node_type_ids = torch.tensor(

            node_type_array,

            dtype=torch.long,

            device=self.device,
        )


        edge_index = torch.tensor(

            edge_index_array,

            dtype=torch.long,

            device=self.device,
        )


        edge_type_ids = torch.tensor(

            edge_type_array,

            dtype=torch.long,

            device=self.device,
        )


        center_indices = torch.tensor(

            [
                int(
                    center_index
                )
            ],

            dtype=torch.long,

            device=self.device,
        )


        # ========================================================
        # MODEL
        # ========================================================

        self.model.eval()


        result = (
            self.model(

                x=
                    x,

                node_type_ids=
                    node_type_ids,

                edge_index=
                    edge_index,

                edge_type_ids=
                    edge_type_ids,

                center_node_indices=
                    center_indices,
            )
        )


        reconstruction = (
            result[
                "reconstructed_features"
            ]
        )


        # ========================================================
        # TYPE-AWARE ERROR
        # ========================================================

        mask = (
            build_type_aware_reconstruction_mask(

                node_type_ids,

                feature_count=
                    x.shape[
                        1
                    ],
            )
        )


        squared_error = (
            reconstruction
            -
            x
        ) ** 2


        raw_error = float(

            squared_error[
                mask
            ]
            .mean()
            .cpu()
            .item()
        )


        center_mask = (
            mask[
                center_index
            ]
        )


        center_error = float(

            squared_error[
                center_index
            ][
                center_mask
            ]
            .mean()
            .cpu()
            .item()
        )


        # ========================================================
        # CALIBRATION
        # ========================================================

        graph_score = (
            self.calibrate_error(
                raw_error
            )
        )


        band = (
            self.score_band(
                graph_score
            )
        )


        # ========================================================
        # 64-D EMBEDDING
        # ========================================================

        embedding = (

            result[
                "center_embeddings"
            ][
                0
            ]
            .cpu()
            .numpy()
            .astype(
                np.float32
            )
        )


        if not np.isfinite(
            embedding
        ).all():

            raise RuntimeError(
                "Graph embedding contains NaN/Inf."
            )


        evidence_coverage = (
            self.calculate_ai_evidence_coverage(
                subgraph
            )
        )


        # ========================================================
        # RESULT
        # ========================================================

        return {
            "available":
                True,

            "state":
                "GRAPH_INFERENCE_COMPLETE",

            "predictor_name":
                self.PREDICTOR_NAME,

            "predictor_version":
                self.PREDICTOR_VERSION,

            "model_name":
                self.checkpoint.get(
                    "model_name"
                ),

            "model_version":
                self.checkpoint.get(
                    "model_version"
                ),

            "calibration_version":
                self.calibration.get(
                    "calibration_version"
                ),

            "calibration_source":
                self.calibration.get(
                    "calibration_source"
                ),

            "calibration_quality":
                self.calibration.get(
                    "calibration_quality"
                ),

            "operating_mode":
                self.OPERATING_MODE,

            "pid":
                subgraph.get(
                    "pid"
                ),

            "process_name":
                subgraph.get(
                    "process_name"
                ),

            "device_id":
                subgraph.get(
                    "device_id"
                ),

            "graph_node_count":
                subgraph[
                    "summary"
                ][
                    "node_count"
                ],

            "graph_edge_count":
                subgraph[
                    "summary"
                ][
                    "edge_count"
                ],

            "graph_node_types":
                subgraph[
                    "summary"
                ][
                    "node_types"
                ],

            "graph_edge_types":
                subgraph[
                    "summary"
                ][
                    "edge_types"
                ],

            "raw_reconstruction_error":
                raw_error,

            "center_reconstruction_error":
                center_error,

            "graph_anomaly_score":
                graph_score,

            "graph_anomaly_band":
                band,

            "graph_signal_active":
                (
                    graph_score
                    >= 60
                ),

            "graph_signal_strong":
                (
                    graph_score
                    >= 80
                ),

            # ----------------------------------------------------
            # Graph AI is shadow evidence only at this stage.
            # It must not independently create an authoritative
            # production alert.
            # ----------------------------------------------------

            "authoritative_alert":
                False,

            "embedding_dimension":
                int(
                    embedding.shape[
                        0
                    ]
                ),

            "embedding":
                embedding.tolist(),

            "ai_evidence_coverage":
                evidence_coverage,

            "interpretation":
                (
                    "Graph anomaly score represents "
                    "relative structural/reconstruction "
                    "anomaly compared with the graph "
                    "calibration reference distribution. "
                    "It is not a malware probability."
                ),
        }


    # ============================================================
    # CLOSE
    # ============================================================

    def close(
        self,
    ):

        self.subgraph_service.close()