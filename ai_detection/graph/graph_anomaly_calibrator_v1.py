from __future__ import annotations

import json
import math
import sys

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import numpy as np
import torch


# ================================================================
# PROJECT ROOT
# ================================================================

PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[2]
)


if str(PROJECT_ROOT) not in sys.path:

    sys.path.insert(
        0,
        str(PROJECT_ROOT),
    )


# ================================================================
# IMPORTS
# ================================================================

from ai_detection.graph.relation_aware_graph_encoder import (
    SentinelXGraphEncoder,
)


# ================================================================
# ARTIFACT PATHS
# ================================================================

DATASET_PATH = (
    PROJECT_ROOT
    / "data"
    / "graph"
    / "sentinelx_process_graph_dataset_v1.npz"
)


MODEL_PATH = (
    PROJECT_ROOT
    / "models"
    / "graph"
    / "sentinelx_graph_encoder_v1.pt"
)


TRAINING_REPORT_PATH = (
    PROJECT_ROOT
    / "models"
    / "graph"
    / "sentinelx_graph_encoder_v1_training_report.json"
)


CALIBRATION_PATH = (
    PROJECT_ROOT
    / "models"
    / "graph"
    / "sentinelx_graph_anomaly_calibration_v1.json"
)


CALIBRATION_VERSION = "v1"


# ================================================================
# TYPE-AWARE RECONSTRUCTION MASK
#
# Common:
#   0-6
#
# PROCESS:
#   7-21
#
# FILE:
#   22-25
#
# NETWORK:
#   26-27
#
# REGISTRY:
#   28-29
#
# EVENT:
#   30-31
#
# This prevents irrelevant zero-filled feature groups from
# dominating reconstruction error.
# ================================================================

def build_type_aware_reconstruction_mask(
    node_type_ids: torch.Tensor,
    feature_count: int = 32,
) -> torch.Tensor:

    node_count = (
        node_type_ids.shape[
            0
        ]
    )


    mask = torch.zeros(

        (
            node_count,
            feature_count,
        ),

        dtype=torch.bool,

        device=node_type_ids.device,
    )


    # ------------------------------------------------------------
    # COMMON FEATURES
    # ------------------------------------------------------------

    mask[
        :,
        0:7
    ] = True


    # ------------------------------------------------------------
    # PROCESS = 0
    # ------------------------------------------------------------

    process_rows = (
        node_type_ids
        == 0
    )


    mask[
        process_rows,
        7:22
    ] = True


    # ------------------------------------------------------------
    # FILE = 1
    # ------------------------------------------------------------

    file_rows = (
        node_type_ids
        == 1
    )


    mask[
        file_rows,
        22:26
    ] = True


    # ------------------------------------------------------------
    # NETWORK = 2
    # ------------------------------------------------------------

    network_rows = (
        node_type_ids
        == 2
    )


    mask[
        network_rows,
        26:28
    ] = True


    # ------------------------------------------------------------
    # REGISTRY = 3
    # ------------------------------------------------------------

    registry_rows = (
        node_type_ids
        == 3
    )


    mask[
        registry_rows,
        28:30
    ] = True


    # ------------------------------------------------------------
    # EVENT = 4
    # ------------------------------------------------------------

    event_rows = (
        node_type_ids
        == 4
    )


    mask[
        event_rows,
        30:32
    ] = True


    return mask


# ================================================================
# LOAD MODEL
# ================================================================

def load_graph_model(
    model_path=MODEL_PATH,
    device="cpu",
):

    checkpoint = torch.load(

        model_path,

        map_location=device,

        weights_only=False,
    )


    model = SentinelXGraphEncoder(

        input_dim=
            int(
                checkpoint[
                    "input_dim"
                ]
            ),

        hidden_dim=
            int(
                checkpoint[
                    "hidden_dim"
                ]
            ),

        embedding_dim=
            int(
                checkpoint[
                    "embedding_dim"
                ]
            ),

        num_node_types=
            int(
                checkpoint[
                    "num_node_types"
                ]
            ),

        num_edge_types=
            int(
                checkpoint[
                    "num_edge_types"
                ]
            ),

        num_layers=
            int(
                checkpoint[
                    "num_layers"
                ]
            ),

        dropout=
            float(
                checkpoint[
                    "dropout"
                ]
            ),
    )


    model.load_state_dict(
        checkpoint[
            "state_dict"
        ]
    )


    model.to(
        device
    )


    model.eval()


    return (
        model,
        checkpoint,
    )


# ================================================================
# LOAD DATASET
#
# Copies everything before closing the NPZ file.
# ================================================================

def load_graph_dataset(
    dataset_path=DATASET_PATH,
):

    with np.load(
        dataset_path,
        allow_pickle=False,
    ) as loaded:

        return {
            "x":
                loaded[
                    "x"
                ].copy(),

            "node_type_ids":
                loaded[
                    "node_type_ids"
                ].copy(),

            "edge_index":
                loaded[
                    "edge_index"
                ].copy(),

            "edge_type_ids":
                loaded[
                    "edge_type_ids"
                ].copy(),

            "graph_ptr":
                loaded[
                    "graph_ptr"
                ].copy(),

            "edge_ptr":
                loaded[
                    "edge_ptr"
                ].copy(),

            "center_node_indices":
                loaded[
                    "center_node_indices"
                ].copy(),

            "graph_ids":
                loaded[
                    "graph_ids"
                ].copy(),

            "pids":
                loaded[
                    "pids"
                ].copy(),

            "process_names":
                loaded[
                    "process_names"
                ].copy(),

            "device_ids":
                (
                    loaded[
                        "device_ids"
                    ].copy()

                    if "device_ids"
                    in loaded.files

                    else np.asarray(
                        [],
                        dtype=str,
                    )
                ),
        }


# ================================================================
# EXTRACT ONE GRAPH
# ================================================================

def extract_graph(
    dataset: Dict[str, Any],
    graph_index: int,
):

    graph_index = int(
        graph_index
    )


    node_start = int(
        dataset[
            "graph_ptr"
        ][
            graph_index
        ]
    )


    node_end = int(
        dataset[
            "graph_ptr"
        ][
            graph_index
            + 1
        ]
    )


    edge_start = int(
        dataset[
            "edge_ptr"
        ][
            graph_index
        ]
    )


    edge_end = int(
        dataset[
            "edge_ptr"
        ][
            graph_index
            + 1
        ]
    )


    # ------------------------------------------------------------
    # NODE DATA
    # ------------------------------------------------------------

    x = (
        dataset[
            "x"
        ][
            node_start:
            node_end
        ]
        .copy()
    )


    node_type_ids = (
        dataset[
            "node_type_ids"
        ][
            node_start:
            node_end
        ]
        .copy()
    )


    # ------------------------------------------------------------
    # EDGE DATA
    # ------------------------------------------------------------

    edge_index = (
        dataset[
            "edge_index"
        ][
            :,
            edge_start:
            edge_end
        ]
        .copy()
    )


    if (
        edge_index.shape[
            1
        ]
        > 0
    ):

        edge_index -= (
            node_start
        )


    edge_type_ids = (
        dataset[
            "edge_type_ids"
        ][
            edge_start:
            edge_end
        ]
        .copy()
    )


    # ------------------------------------------------------------
    # CENTER PROCESS
    # ------------------------------------------------------------

    center_global = int(

        dataset[
            "center_node_indices"
        ][
            graph_index
        ]
    )


    center_local = (
        center_global
        -
        node_start
    )


    return {
        "x":
            x,

        "node_type_ids":
            node_type_ids,

        "edge_index":
            edge_index,

        "edge_type_ids":
            edge_type_ids,

        "center_node_index":
            center_local,

        "graph_id":
            str(
                dataset[
                    "graph_ids"
                ][
                    graph_index
                ]
            ),

        "pid":
            str(
                dataset[
                    "pids"
                ][
                    graph_index
                ]
            ),

        "process_name":
            str(
                dataset[
                    "process_names"
                ][
                    graph_index
                ]
            ),
    }


# ================================================================
# GRAPH RECONSTRUCTION ERROR
# ================================================================

@torch.no_grad()
def calculate_graph_error(
    model,
    graph,
    device="cpu",
):

    x = torch.tensor(

        graph[
            "x"
        ],

        dtype=torch.float32,

        device=device,
    )


    node_type_ids = torch.tensor(

        graph[
            "node_type_ids"
        ],

        dtype=torch.long,

        device=device,
    )


    edge_index = torch.tensor(

        graph[
            "edge_index"
        ],

        dtype=torch.long,

        device=device,
    )


    edge_type_ids = torch.tensor(

        graph[
            "edge_type_ids"
        ],

        dtype=torch.long,

        device=device,
    )


    center_node_indices = torch.tensor(

        [
            graph[
                "center_node_index"
            ]
        ],

        dtype=torch.long,

        device=device,
    )


    result = model(

        x=
            x,

        node_type_ids=
            node_type_ids,

        edge_index=
            edge_index,

        edge_type_ids=
            edge_type_ids,

        center_node_indices=
            center_node_indices,
    )


    reconstruction = (
        result[
            "reconstructed_features"
        ]
    )


    feature_mask = (
        build_type_aware_reconstruction_mask(
            node_type_ids,
            feature_count=x.shape[1],
        )
    )


    squared_error = (
        reconstruction
        -
        x
    ) ** 2


    masked_error = (
        squared_error[
            feature_mask
        ]
    )


    graph_error = float(

        masked_error
        .mean()
        .cpu()
        .item()
    )


    # ------------------------------------------------------------
    # CENTER PROCESS ERROR
    # ------------------------------------------------------------

    center_index = (
        graph[
            "center_node_index"
        ]
    )


    center_mask = (
        feature_mask[
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


    embedding = (

        result[
            "center_embeddings"
        ][
            0
        ]
        .cpu()
        .numpy()
    )


    return {
        "graph_error":
            graph_error,

        "center_error":
            center_error,

        "embedding":
            embedding,
    }


# ================================================================
# CALIBRATION QUALITY
# ================================================================

def calibration_quality(
    count: int,
) -> str:

    if count >= 50:

        return "HIGH"


    if count >= 20:

        return "MEDIUM"


    if count >= 10:

        return "LIMITED"


    return "LOW"


# ================================================================
# MAIN
# ================================================================

def main():

    print()

    print(
        "=" * 100
    )

    print(
        "SENTINEL-X GRAPH ANOMALY CALIBRATION V1"
    )

    print(
        "=" * 100
    )


    # ============================================================
    # ARTIFACT CHECK
    # ============================================================

    for path in (
        DATASET_PATH,
        MODEL_PATH,
    ):

        if not path.exists():

            raise FileNotFoundError(
                f"Required artifact missing: {path}"
            )


    dataset = (
        load_graph_dataset()
    )


    graph_count = (
        len(
            dataset[
                "center_node_indices"
            ]
        )
    )


    if graph_count < 2:

        raise RuntimeError(
            (
                "At least 2 real process graphs are "
                "required for graph anomaly calibration."
            )
        )


    # ============================================================
    # LOAD TRAINING REPORT
    # ============================================================

    validation_indices = []


    if TRAINING_REPORT_PATH.exists():

        with open(
            TRAINING_REPORT_PATH,
            "r",
            encoding="utf-8",
        ) as file:

            training_report = (
                json.load(
                    file
                )
            )


        validation_indices = [

            int(
                value
            )

            for value in training_report.get(
                "validation_indices",
                [],
            )

            if (
                0
                <= int(value)
                < graph_count
            )
        ]


    # ============================================================
    # REFERENCE SET
    #
    # Prefer held-out graphs when there are enough.
    #
    # Otherwise use the entire observed reference distribution
    # and state that explicitly in calibration metadata.
    # ============================================================

    if (
        len(
            validation_indices
        )
        >= 5
    ):

        calibration_indices = (
            validation_indices
        )


        calibration_source = (
            "HELD_OUT_VALIDATION_GRAPHS"
        )


        held_out = True


    else:

        calibration_indices = list(
            range(
                graph_count
            )
        )


        calibration_source = (
            "FULL_REFERENCE_GRAPH_SET_FALLBACK"
        )


        held_out = False


    print()

    print(
        "Total process graphs:",
        graph_count,
    )


    print(
        "Calibration graphs:",
        len(
            calibration_indices
        ),
    )


    print(
        "Calibration source:",
        calibration_source,
    )


    print(
        "Held-out calibration:",
        held_out,
    )


    # ============================================================
    # LOAD MODEL
    # ============================================================

    device = (
        "cuda"

        if torch.cuda.is_available()

        else "cpu"
    )


    model, checkpoint = (
        load_graph_model(
            device=device
        )
    )


    print(
        "Device:",
        device,
    )


    # ============================================================
    # CALCULATE REFERENCE ERRORS
    # ============================================================

    graph_errors = []

    center_errors = []


    for position, graph_index in enumerate(
        calibration_indices,
        start=1,
    ):

        graph = (
            extract_graph(
                dataset,
                graph_index,
            )
        )


        result = (
            calculate_graph_error(
                model,
                graph,
                device=device,
            )
        )


        graph_errors.append(
            result[
                "graph_error"
            ]
        )


        center_errors.append(
            result[
                "center_error"
            ]
        )


        print(
            f"[{position:03d}/"
            f"{len(calibration_indices):03d}] "
            f"PID={graph['pid']} | "
            f"Process={graph['process_name']} | "
            f"GraphError="
            f"{result['graph_error']:.8f}"
        )


    graph_errors = np.asarray(
        graph_errors,
        dtype=np.float64,
    )


    center_errors = np.asarray(
        center_errors,
        dtype=np.float64,
    )


    if not np.isfinite(
        graph_errors
    ).all():

        raise RuntimeError(
            "Calibration graph errors contain NaN/Inf."
        )


    # ============================================================
    # ERROR ANCHORS
    #
    # Same conceptual scale used by Temporal-v2:
    #
    # p50  -> 10
    # p90  -> 30
    # p95  -> 40
    # p97  -> 60
    # p99  -> 80
    # max  -> 95
    #
    # > max approaches 100.
    # ============================================================

    percentile_definitions = [
        (0, 0),
        (50, 10),
        (90, 30),
        (95, 40),
        (97, 60),
        (99, 80),
        (100, 95),
    ]


    anchors = []


    for (
        percentile,
        score,
    ) in percentile_definitions:

        error_value = float(

            np.percentile(
                graph_errors,
                percentile,
            )
        )


        anchors.append(
            {
                "percentile":
                    percentile,

                "error":
                    error_value,

                "score":
                    score,
            }
        )


    # ============================================================
    # CALIBRATION ARTIFACT
    # ============================================================

    calibration = {

        "calibration_name":
            "sentinelx_graph_anomaly_calibration",

        "calibration_version":
            CALIBRATION_VERSION,

        "model_name":
            checkpoint.get(
                "model_name"
            ),

        "model_version":
            checkpoint.get(
                "model_version"
            ),

        "created_at":
            datetime.now(
                timezone.utc
            ).isoformat(),

        "input_feature_count":
            int(
                checkpoint[
                    "input_dim"
                ]
            ),

        "embedding_dimension":
            int(
                checkpoint[
                    "embedding_dim"
                ]
            ),

        "calibration_graph_count":
            int(
                len(
                    graph_errors
                )
            ),

        "calibration_source":
            calibration_source,

        "held_out_calibration":
            held_out,

        "calibration_quality":
            calibration_quality(
                len(
                    graph_errors
                )
            ),

        "type_aware_reconstruction":
            True,

        "reference_error_mean":
            float(
                graph_errors.mean()
            ),

        "reference_error_std":
            float(
                graph_errors.std()
            ),

        "reference_error_min":
            float(
                graph_errors.min()
            ),

        "reference_error_max":
            float(
                graph_errors.max()
            ),

        "center_error_mean":
            float(
                center_errors.mean()
            ),

        "score_anchors":
            anchors,

        "thresholds": {

            "normal_below":
                40,

            "unusual_from":
                40,

            "suspicious_from":
                60,

            "high_anomaly_from":
                80,

            "active_signal_from":
                60,

            "strong_signal_from":
                80,
        },

        "interpretation":
            (
                "Score represents reconstruction-based "
                "graph anomaly relative to the reference "
                "provenance graph distribution. It is not "
                "a malware probability or attack probability."
            ),
    }


    CALIBRATION_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )


    with open(
        CALIBRATION_PATH,
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            calibration,
            file,
            indent=2,
            ensure_ascii=False,
        )


    print()

    print(
        "=" * 100
    )

    print(
        "CALIBRATION SUMMARY"
    )

    print(
        "=" * 100
    )


    print()

    print(
        "Reference mean:",
        calibration[
            "reference_error_mean"
        ],
    )


    print(
        "Reference std:",
        calibration[
            "reference_error_std"
        ],
    )


    print(
        "Reference min:",
        calibration[
            "reference_error_min"
        ],
    )


    print(
        "Reference max:",
        calibration[
            "reference_error_max"
        ],
    )


    print(
        "Quality:",
        calibration[
            "calibration_quality"
        ],
    )


    print()

    print(
        "Anchors:"
    )


    for anchor in anchors:

        print(
            f"p{anchor['percentile']:<3} "
            f"error={anchor['error']:.8f} "
            f"-> score={anchor['score']}"
        )


    print()

    print(
        "Calibration:",
        CALIBRATION_PATH,
    )


    print()

    print(
        "=" * 100
    )

    print(
        "GRAPH ANOMALY CALIBRATION V1: PASS"
    )

    print(
        "=" * 100
    )


if __name__ == "__main__":

    main()