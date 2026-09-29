from __future__ import annotations

import json
import sys

from pathlib import Path
from typing import (
    Any,
    Dict,
    List,
    Optional,
)


import numpy as np
import torch
import torch.nn.functional as F


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
        str(
            PROJECT_ROOT
        ),
    )


# ================================================================
# SENTINEL-X IMPORTS
# ================================================================

from ai_detection.graph.graph_dataset_builder import (
    GraphDatasetBuilder,
)


from ai_detection.graph.graph_self_supervised_trainer import (
    GraphSelfSupervisedTrainer,
)


# ================================================================
# PATHS
# ================================================================

DATASET_PATH = (

    PROJECT_ROOT
    / "data"
    / "graph"
    / "sentinelx_process_graph_dataset_v1.npz"
)


MANIFEST_PATH = (

    PROJECT_ROOT
    / "data"
    / "graph"
    / "sentinelx_process_graph_dataset_v1.manifest.json"
)


MODEL_PATH = (

    PROJECT_ROOT
    / "models"
    / "graph"
    / "sentinelx_graph_encoder_v1.pt"
)


MODEL_METADATA_PATH = (

    PROJECT_ROOT
    / "models"
    / "graph"
    / "sentinelx_graph_encoder_v1_metadata.json"
)


TRAINING_REPORT_PATH = (

    PROJECT_ROOT
    / "models"
    / "graph"
    / "sentinelx_graph_encoder_v1_training_report.json"
)


EMBEDDINGS_PATH = (

    PROJECT_ROOT
    / "models"
    / "graph"
    / "sentinelx_graph_encoder_v1_embeddings.npz"
)


# ================================================================
# CONFIGURATION
# ================================================================

RANDOM_SEED = 42


MAX_HOPS = 2


INCLUDE_EVENT_NODES = True


TRAIN_RATIO = 0.80


EPOCHS = 60


LEARNING_RATE = 1e-3


WEIGHT_DECAY = 1e-5


MASK_PROBABILITY = 0.20


HIDDEN_DIMENSION = 64


EMBEDDING_DIMENSION = 64


GRAPH_LAYERS = 2


DROPOUT = 0.10


# ================================================================
# DISPLAY
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


# ================================================================
# JSON SAFE
# ================================================================

def json_safe(
    value,
):

    if isinstance(
        value,
        np.ndarray,
    ):

        return (
            value.tolist()
        )


    if isinstance(
        value,
        np.integer,
    ):

        return int(
            value
        )


    if isinstance(
        value,
        np.floating,
    ):

        return float(
            value
        )


    if isinstance(
        value,
        Path,
    ):

        return str(
            value
        )


    raise TypeError(
        (
            "Unsupported JSON value: "
            f"{type(value)}"
        )
    )


# ================================================================
# SUBSET GRAPH DATASET
#
# The graph dataset is stored as one concatenated graph collection.
#
# graph_ptr:
#
#   tells where each graph's nodes begin/end.
#
# edge_ptr:
#
#   tells where each graph's edges begin/end.
#
# This function safely extracts selected whole graphs.
# ================================================================

def subset_dataset(
    dataset: Dict[str, Any],
    graph_indices: List[int],
) -> Dict[str, Any]:

    graph_indices = [

        int(
            index
        )

        for index in graph_indices
    ]


    if not graph_indices:

        return {
            "x":
                np.empty(
                    (
                        0,
                        dataset[
                            "x"
                        ].shape[
                            1
                        ],
                    ),
                    dtype=np.float32,
                ),

            "node_type_ids":
                np.empty(
                    0,
                    dtype=np.int64,
                ),

            "edge_index":
                np.empty(
                    (
                        2,
                        0,
                    ),
                    dtype=np.int64,
                ),

            "edge_type_ids":
                np.empty(
                    0,
                    dtype=np.int64,
                ),

            "graph_ptr":
                np.asarray(
                    [
                        0
                    ],
                    dtype=np.int64,
                ),

            "edge_ptr":
                np.asarray(
                    [
                        0
                    ],
                    dtype=np.int64,
                ),

            "center_node_indices":
                np.empty(
                    0,
                    dtype=np.int64,
                ),

            "graph_ids":
                np.asarray(
                    [],
                    dtype=str,
                ),

            "pids":
                np.asarray(
                    [],
                    dtype=str,
                ),

            "process_names":
                np.asarray(
                    [],
                    dtype=str,
                ),

            "device_ids":
                np.asarray(
                    [],
                    dtype=str,
                ),
        }


    x_parts = []

    node_type_parts = []

    edge_source_parts = []

    edge_target_parts = []

    edge_type_parts = []


    new_graph_ptr = [
        0
    ]


    new_edge_ptr = [
        0
    ]


    new_centers = []


    graph_ids = []

    pids = []

    process_names = []

    device_ids = []


    current_node_offset = 0

    current_edge_offset = 0


    graph_ptr = (
        dataset[
            "graph_ptr"
        ]
    )


    edge_ptr = (
        dataset[
            "edge_ptr"
        ]
    )


    for graph_index in graph_indices:

        # ========================================================
        # ORIGINAL NODE RANGE
        # ========================================================

        node_start = int(
            graph_ptr[
                graph_index
            ]
        )


        node_end = int(
            graph_ptr[
                graph_index
                + 1
            ]
        )


        # ========================================================
        # ORIGINAL EDGE RANGE
        # ========================================================

        edge_start = int(
            edge_ptr[
                graph_index
            ]
        )


        edge_end = int(
            edge_ptr[
                graph_index
                + 1
            ]
        )


        # ========================================================
        # NODE FEATURES
        # ========================================================

        graph_x = (
            dataset[
                "x"
            ][
                node_start:
                node_end
            ]
        )


        graph_node_types = (
            dataset[
                "node_type_ids"
            ][
                node_start:
                node_end
            ]
        )


        x_parts.append(
            graph_x
        )


        node_type_parts.append(
            graph_node_types
        )


        # ========================================================
        # EDGES
        # ========================================================

        graph_edges = (
            dataset[
                "edge_index"
            ][
                :,
                edge_start:
                edge_end
            ]
            .copy()
        )


        graph_edge_types = (
            dataset[
                "edge_type_ids"
            ][
                edge_start:
                edge_end
            ]
        )


        # --------------------------------------------------------
        # Convert original global node indices into local indices.
        # --------------------------------------------------------

        if (
            graph_edges.shape[
                1
            ]
            > 0
        ):

            graph_edges = (
                graph_edges
                - node_start
            )


            # ----------------------------------------------------
            # Convert local indices into NEW global indices.
            # ----------------------------------------------------

            graph_edges = (
                graph_edges
                + current_node_offset
            )


            edge_source_parts.extend(
                graph_edges[
                    0
                ].tolist()
            )


            edge_target_parts.extend(
                graph_edges[
                    1
                ].tolist()
            )


            edge_type_parts.extend(
                graph_edge_types.tolist()
            )


        # ========================================================
        # CENTER NODE
        # ========================================================

        old_center = int(

            dataset[
                "center_node_indices"
            ][
                graph_index
            ]
        )


        local_center = (
            old_center
            - node_start
        )


        new_center = (
            current_node_offset
            +
            local_center
        )


        new_centers.append(
            new_center
        )


        # ========================================================
        # METADATA
        # ========================================================

        graph_ids.append(

            str(
                dataset[
                    "graph_ids"
                ][
                    graph_index
                ]
            )
        )


        pids.append(

            str(
                dataset[
                    "pids"
                ][
                    graph_index
                ]
            )
        )


        process_names.append(

            str(
                dataset[
                    "process_names"
                ][
                    graph_index
                ]
            )
        )


        if (
            "device_ids"
            in dataset
        ):

            device_ids.append(

                str(
                    dataset[
                        "device_ids"
                    ][
                        graph_index
                    ]
                )
            )

        else:

            device_ids.append(
                ""
            )


        # ========================================================
        # UPDATE POINTERS
        # ========================================================

        current_node_offset += (
            graph_x.shape[
                0
            ]
        )


        current_edge_offset += (
            edge_end
            - edge_start
        )


        new_graph_ptr.append(
            current_node_offset
        )


        new_edge_ptr.append(
            current_edge_offset
        )


    # ============================================================
    # CONCATENATE
    # ============================================================

    x = np.concatenate(
        x_parts,
        axis=0,
    ).astype(
        np.float32
    )


    node_type_ids = np.concatenate(
        node_type_parts,
        axis=0,
    ).astype(
        np.int64
    )


    edge_index = np.asarray(
        [
            edge_source_parts,
            edge_target_parts,
        ],
        dtype=np.int64,
    )


    edge_type_ids = np.asarray(
        edge_type_parts,
        dtype=np.int64,
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

        "graph_ptr":
            np.asarray(
                new_graph_ptr,
                dtype=np.int64,
            ),

        "edge_ptr":
            np.asarray(
                new_edge_ptr,
                dtype=np.int64,
            ),

        "center_node_indices":
            np.asarray(
                new_centers,
                dtype=np.int64,
            ),

        "graph_ids":
            np.asarray(
                graph_ids,
                dtype=str,
            ),

        "pids":
            np.asarray(
                pids,
                dtype=str,
            ),

        "process_names":
            np.asarray(
                process_names,
                dtype=str,
            ),

        "device_ids":
            np.asarray(
                device_ids,
                dtype=str,
            ),
    }


# ================================================================
# GRAPH-LEVEL SPLIT
# ================================================================

def split_dataset(
    dataset: Dict[str, Any],
):

    graph_count = (
        len(
            dataset[
                "center_node_indices"
            ]
        )
    )


    indices = np.arange(
        graph_count,
        dtype=np.int64,
    )


    rng = np.random.default_rng(
        RANDOM_SEED
    )


    rng.shuffle(
        indices
    )


    # ============================================================
    # SMALL DATASET
    #
    # With fewer than 5 process graphs, a validation split is too
    # unstable to be meaningful.
    # ============================================================

    if graph_count < 5:

        return {
            "train":
                dataset,

            "validation":
                None,

            "train_indices":
                indices.tolist(),

            "validation_indices":
                [],

            "validation_available":
                False,
        }


    train_count = int(

        round(
            graph_count
            *
            TRAIN_RATIO
        )
    )


    train_count = max(
        1,
        train_count,
    )


    train_count = min(
        graph_count - 1,
        train_count,
    )


    train_indices = (
        indices[
            :train_count
        ]
        .tolist()
    )


    validation_indices = (
        indices[
            train_count:
        ]
        .tolist()
    )


    train_dataset = (
        subset_dataset(
            dataset,
            train_indices,
        )
    )


    validation_dataset = (
        subset_dataset(
            dataset,
            validation_indices,
        )
    )


    return {
        "train":
            train_dataset,

        "validation":
            validation_dataset,

        "train_indices":
            train_indices,

        "validation_indices":
            validation_indices,

        "validation_available":
            True,
    }


# ================================================================
# MASKED VALIDATION LOSS
# ================================================================

@torch.no_grad()
def masked_validation_loss(
    trainer: GraphSelfSupervisedTrainer,
    dataset,
    seed: int = 2026,
):

    tensors = (
        trainer.tensorize(
            dataset
        )
    )


    trainer.model.eval()


    # ============================================================
    # FIXED RANDOM MASK
    #
    # Validation should be reproducible between runs.
    # ============================================================

    torch.manual_seed(
        seed
    )


    if torch.cuda.is_available():

        torch.cuda.manual_seed_all(
            seed
        )


    x = (
        tensors[
            "x"
        ]
    )


    mask = (

        torch.rand(
            x.shape,
            device=x.device,
        )

        < trainer.mask_probability
    )


    if not bool(
        mask.any()
    ):

        mask[
            0,
            0
        ] = True


    masked_x = (
        x.clone()
    )


    masked_x[
        mask
    ] = 0.0


    result = (
        trainer.model(

            x=
                masked_x,

            node_type_ids=
                tensors[
                    "node_type_ids"
                ],

            edge_index=
                tensors[
                    "edge_index"
                ],

            edge_type_ids=
                tensors[
                    "edge_type_ids"
                ],

            center_node_indices=
                tensors[
                    "center_node_indices"
                ],
        )
    )


    reconstruction = (
        result[
            "reconstructed_features"
        ]
    )


    loss = F.mse_loss(

        reconstruction[
            mask
        ],

        x[
            mask
        ],
    )


    center_embeddings = (
        result[
            "center_embeddings"
        ]
        .detach()
        .cpu()
        .numpy()
    )


    return {
        "masked_reconstruction_loss":
            float(
                loss.cpu()
                .item()
            ),

        "center_embeddings":
            center_embeddings,

        "embedding_health":
            trainer.embedding_health(
                center_embeddings
            ),
    }


# ================================================================
# EMBEDDING HEALTH DECISION
# ================================================================

def embedding_health_pass(
    health: Dict[str, Any],
):

    if not health.get(
        "finite",
        False,
    ):

        return False


    if (
        health.get(
            "all_zero_fraction",
            1.0,
        )
        > 0.0
    ):

        return False


    if (
        health.get(
            "mean_norm",
            0.0,
        )
        <= 0.0
    ):

        return False


    count = int(
        health.get(
            "count",
            0,
        )
    )


    # ============================================================
    # With only one process embedding uniqueness cannot be tested.
    # ============================================================

    if count >= 2:

        if (
            health.get(
                "unique_fraction",
                0.0,
            )
            <= 0.50
        ):

            return False


    return True


# ================================================================
# MAIN
# ================================================================

def main():

    heading(
        "SENTINEL-X REAL GRAPH ENCODER V1 TRAINING"
    )


    torch.set_num_threads(
        max(
            1,
            min(
                4,
                torch.get_num_threads(),
            ),
        )
    )


    # ============================================================
    # 1. BUILD REAL GRAPH DATASET
    # ============================================================

    heading(
        "1. BUILD REAL PROVENANCE GRAPH DATASET"
    )


    dataset_builder = (
        GraphDatasetBuilder(

            max_hops=
                MAX_HOPS,

            include_event_nodes=
                INCLUDE_EVENT_NODES,
        )
    )


    try:

        result = (
            dataset_builder
            .build_and_save(

                output_path=
                    DATASET_PATH
            )
        )


        dataset = (
            result[
                "dataset"
            ]
        )


        print()

        print(
            "Dataset:",
            result[
                "dataset_path"
            ],
        )


        print(
            "Manifest:",
            result[
                "manifest_path"
            ],
        )


        print()

        print(
            "Graphs:",
            dataset[
                "graph_count"
            ],
        )


        print(
            "Nodes:",
            dataset[
                "node_count"
            ],
        )


        print(
            "Edges:",
            dataset[
                "edge_count"
            ],
        )


        print(
            "Features:",
            dataset[
                "x"
            ].shape[
                1
            ],
        )


        # ========================================================
        # BASIC DATASET SAFETY
        # ========================================================

        if (
            dataset[
                "graph_count"
            ]
            == 0
        ):

            raise RuntimeError(
                (
                    "No process-centered provenance graphs "
                    "are available. Run the SentinelAgent "
                    "first so real telemetry populates the "
                    "provenance graph."
                )
            )


        if (
            dataset[
                "x"
            ].shape[
                1
            ]
            != 32
        ):

            raise RuntimeError(
                "Expected 32 graph node features."
            )


        if not np.isfinite(
            dataset[
                "x"
            ]
        ).all():

            raise RuntimeError(
                (
                    "Graph dataset contains "
                    "NaN or infinity."
                )
            )


    finally:

        dataset_builder.close()


    # ============================================================
    # 2. GRAPH-LEVEL SPLIT
    # ============================================================

    heading(
        "2. GRAPH-LEVEL TRAIN / VALIDATION SPLIT"
    )


    split = (
        split_dataset(
            dataset
        )
    )


    train_dataset = (
        split[
            "train"
        ]
    )


    validation_dataset = (
        split[
            "validation"
        ]
    )


    print()

    print(
        "Total graphs:",
        dataset[
            "graph_count"
        ],
    )


    print(
        "Training graphs:",
        len(
            train_dataset[
                "center_node_indices"
            ]
        ),
    )


    print(
        "Validation graphs:",
        (
            len(
                validation_dataset[
                    "center_node_indices"
                ]
            )

            if validation_dataset
            is not None

            else 0
        ),
    )


    print(
        "Validation available:",
        split[
            "validation_available"
        ],
    )


    if not split[
        "validation_available"
    ]:

        print()

        print(
            "NOTE:"
        )


        print(
            (
                "Fewer than 5 real process graphs are "
                "available, so this run trains on all "
                "graphs and does not claim held-out "
                "validation performance."
            )
        )


    # ============================================================
    # 3. TRAIN MODEL
    # ============================================================

    heading(
        "3. SELF-SUPERVISED GRAPH TRAINING"
    )


    trainer = (
        GraphSelfSupervisedTrainer(

            input_dim=
                32,

            hidden_dim=
                HIDDEN_DIMENSION,

            embedding_dim=
                EMBEDDING_DIMENSION,

            num_node_types=
                5,

            num_edge_types=
                8,

            num_layers=
                GRAPH_LAYERS,

            dropout=
                DROPOUT,

            learning_rate=
                LEARNING_RATE,

            weight_decay=
                WEIGHT_DECAY,

            mask_probability=
                MASK_PROBABILITY,

            seed=
                RANDOM_SEED,
        )
    )


    print()

    print(
        "Device:",
        trainer.device,
    )


    print(
        "Epochs:",
        EPOCHS,
    )


    print(
        "Mask probability:",
        MASK_PROBABILITY,
    )


    print()


    training_result = (
        trainer.train(

            train_dataset,

            epochs=
                EPOCHS,

            verbose=
                True,
        )
    )


    # ============================================================
    # 4. TRAIN EMBEDDING HEALTH
    # ============================================================

    heading(
        "4. TRAIN EMBEDDING HEALTH"
    )


    train_health = (
        training_result[
            "embedding_health"
        ]
    )


    for (
        key,
        value,
    ) in train_health.items():

        print(
            f"{key:<24}: "
            f"{value}"
        )


    train_health_pass = (
        embedding_health_pass(
            train_health
        )
    )


    print()

    print(
        "Train embedding health:",
        (
            "PASS"

            if train_health_pass

            else "REVIEW"
        ),
    )


    # ============================================================
    # 5. VALIDATION
    # ============================================================

    validation_result = None


    if (
        split[
            "validation_available"
        ]

        and

        validation_dataset
        is not None
    ):

        heading(
            "5. HELD-OUT GRAPH VALIDATION"
        )


        validation_result = (
            masked_validation_loss(

                trainer,

                validation_dataset,
            )
        )


        print()

        print(
            "Masked reconstruction loss:",
            validation_result[
                "masked_reconstruction_loss"
            ],
        )


        print()

        print(
            "Validation embedding health:"
        )


        validation_health = (
            validation_result[
                "embedding_health"
            ]
        )


        for (
            key,
            value,
        ) in validation_health.items():

            print(
                f"{key:<24}: "
                f"{value}"
            )


        validation_health_pass = (
            embedding_health_pass(
                validation_health
            )
        )


        print()

        print(
            "Validation embedding health:",
            (
                "PASS"

                if validation_health_pass

                else "REVIEW"
            ),
        )


    else:

        validation_health_pass = None


    # ============================================================
    # 6. SAVE MODEL
    # ============================================================

    heading(
        "6. SAVE GRAPH ENCODER V1"
    )


    save_result = (
        trainer.save_model(

            model_path=
                MODEL_PATH,

            metadata_path=
                MODEL_METADATA_PATH,

            training_result=
                training_result,

            dataset=
                train_dataset,
        )
    )


    print()

    print(
        "Model:",
        save_result[
            "model_path"
        ],
    )


    print(
        "Metadata:",
        save_result[
            "metadata_path"
        ],
    )


    # ============================================================
    # 7. SAVE REAL PROCESS EMBEDDINGS
    #
    # We run the trained encoder on the entire real dataset.
    # ============================================================

    heading(
        "7. EXPORT REAL PROCESS GRAPH EMBEDDINGS"
    )


    entire_tensors = (
        trainer.tensorize(
            dataset
        )
    )


    entire_evaluation = (
        trainer.evaluate_reconstruction(
            entire_tensors
        )
    )


    all_embeddings = (
        entire_evaluation[
            "center_embeddings"
        ]
    )


    all_embedding_health = (
        trainer.embedding_health(
            all_embeddings
        )
    )


    EMBEDDINGS_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )


    np.savez_compressed(

        EMBEDDINGS_PATH,

        embeddings=
            all_embeddings.astype(
                np.float32
            ),

        graph_ids=
            dataset[
                "graph_ids"
            ],

        pids=
            dataset[
                "pids"
            ],

        process_names=
            dataset[
                "process_names"
            ],

        device_ids=
            dataset[
                "device_ids"
            ],
    )


    print()

    print(
        "Embedding file:",
        EMBEDDINGS_PATH,
    )


    print(
        "Shape:",
        all_embeddings.shape,
    )


    print()

    for (
        key,
        value,
    ) in all_embedding_health.items():

        print(
            f"{key:<24}: "
            f"{value}"
        )


    all_health_pass = (
        embedding_health_pass(
            all_embedding_health
        )
    )


    print()

    print(
        "Entire-dataset embedding health:",
        (
            "PASS"

            if all_health_pass

            else "REVIEW"
        ),
    )


    # ============================================================
    # 8. TRAINING REPORT
    # ============================================================

    heading(
        "8. TRAINING REPORT"
    )


    report = {

        "model":
            "sentinelx_graph_encoder_v1",

        "learning_mode":
            (
                "SELF_SUPERVISED_MASKED_"
                "FEATURE_RECONSTRUCTION"
            ),

        "ground_truth_labels_used":
            False,

        "classifier_trained":
            False,

        "dataset_path":
            str(
                DATASET_PATH
            ),

        "model_path":
            str(
                MODEL_PATH
            ),

        "metadata_path":
            str(
                MODEL_METADATA_PATH
            ),

        "embeddings_path":
            str(
                EMBEDDINGS_PATH
            ),

        "total_graph_count":
            int(
                dataset[
                    "graph_count"
                ]
            ),

        "total_node_count":
            int(
                dataset[
                    "node_count"
                ]
            ),

        "total_edge_count":
            int(
                dataset[
                    "edge_count"
                ]
            ),

        "feature_count":
            32,

        "embedding_dimension":
            64,

        "train_graph_count":
            int(
                len(
                    train_dataset[
                        "center_node_indices"
                    ]
                )
            ),

        "validation_graph_count":
            int(

                len(
                    validation_dataset[
                        "center_node_indices"
                    ]
                )

                if validation_dataset
                is not None

                else 0
            ),

        "validation_available":
            bool(
                split[
                    "validation_available"
                ]
            ),

        "train_indices":
            split[
                "train_indices"
            ],

        "validation_indices":
            split[
                "validation_indices"
            ],

        "final_masked_training_loss":
            float(
                training_result[
                    "final_training_loss"
                ]
            ),

        "full_train_reconstruction_loss":
            float(
                training_result[
                    "full_reconstruction_loss"
                ]
            ),

        "train_embedding_health":
            train_health,

        "train_embedding_health_pass":
            bool(
                train_health_pass
            ),

        "entire_dataset_embedding_health":
            all_embedding_health,

        "entire_dataset_embedding_health_pass":
            bool(
                all_health_pass
            ),

        "validation":
            (
                {
                    "masked_reconstruction_loss":
                        float(
                            validation_result[
                                "masked_reconstruction_loss"
                            ]
                        ),

                    "embedding_health":
                        validation_result[
                            "embedding_health"
                        ],

                    "embedding_health_pass":
                        bool(
                            validation_health_pass
                        ),
                }

                if validation_result
                is not None

                else None
            ),

        "interpretation":
            (
                "The 64-D output is a learned "
                "process-centered graph representation. "
                "It is not a malware probability, "
                "attack probability, or calibrated "
                "threat score."
            ),
    }


    TRAINING_REPORT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )


    with open(
        TRAINING_REPORT_PATH,
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            report,
            file,
            indent=2,
            ensure_ascii=False,
            default=json_safe,
        )


    print()

    print(
        "Report:",
        TRAINING_REPORT_PATH,
    )


    # ============================================================
    # FINAL STATUS
    # ============================================================

    heading(
        "FINAL GRAPH ENCODER V1 STATUS"
    )


    checks = {

        "real_graph_dataset":
            (
                dataset[
                    "graph_count"
                ]
                > 0
            ),

        "feature_dimension_32":
            (
                dataset[
                    "x"
                ].shape[
                    1
                ]
                == 32
            ),

        "model_saved":
            MODEL_PATH.exists(),

        "metadata_saved":
            MODEL_METADATA_PATH.exists(),

        "embeddings_saved":
            EMBEDDINGS_PATH.exists(),

        "train_embedding_health":
            train_health_pass,

        "all_embedding_health":
            all_health_pass,
    }


    if (
        validation_health_pass
        is not None
    ):

        checks[
            "validation_embedding_health"
        ] = (
            validation_health_pass
        )


    for (
        name,
        passed,
    ) in checks.items():

        print(
            f"{name:<42}: "
            f"{'PASS' if passed else 'REVIEW'}"
        )


    overall = all(
        checks.values()
    )


    print()

    print(
        "=" * 100
    )


    if overall:

        print(
            "SENTINEL-X REAL GRAPH ENCODER V1: PASS"
        )

    else:

        print(
            "SENTINEL-X REAL GRAPH ENCODER V1: "
            "REVIEW REQUIRED"
        )


    print(
        "=" * 100
    )


if __name__ == "__main__":

    main()