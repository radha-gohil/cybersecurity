from __future__ import annotations

import json
import sys
import tempfile

from pathlib import Path


import numpy as np
import torch


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
        str(
            PROJECT_ROOT
        ),
    )


# ================================================================
# IMPORTS
# ================================================================

from ai_detection.graph.graph_self_supervised_trainer import (
    GraphSelfSupervisedTrainer,
)


# ================================================================
# DISPLAY
# ================================================================

def heading(
    value,
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
# SYNTHETIC GRAPH DATASET
# ================================================================

def build_dataset():

    rng = np.random.default_rng(
        42
    )


    # ============================================================
    # THREE SMALL PROCESS-CENTERED GRAPHS
    #
    # Graph 1 nodes: 0-4
    # Graph 2 nodes: 5-9
    # Graph 3 nodes: 10-14
    # ============================================================

    node_count = 15

    feature_count = 32


    x = rng.uniform(

        low=0.0,

        high=1.0,

        size=(
            node_count,
            feature_count,
        ),
    ).astype(
        np.float32
    )


    # ============================================================
    # NODE TYPES
    #
    # process=0
    # file=1
    # network=2
    # registry=3
    # event=4
    # ============================================================

    node_type_ids = np.asarray(
        [
            0, 1, 2, 3, 4,
            0, 1, 2, 3, 4,
            0, 1, 2, 3, 4,
        ],
        dtype=np.int64,
    )


    # ============================================================
    # MARK CENTER PROCESS FEATURE
    # ============================================================

    center_node_indices = np.asarray(
        [
            0,
            5,
            10,
        ],
        dtype=np.int64,
    )


    x[
        :,
        5
    ] = 0.0


    x[
        center_node_indices,
        5
    ] = 1.0


    # ============================================================
    # DIRECTED GRAPH EDGES
    # ============================================================

    edge_pairs = [

        # graph 1
        (4, 0),
        (0, 1),
        (0, 2),
        (0, 3),

        # graph 2
        (9, 5),
        (5, 6),
        (5, 7),
        (5, 8),

        # graph 3
        (14, 10),
        (10, 11),
        (10, 12),
        (10, 13),
    ]


    edge_index = np.asarray(
        edge_pairs,
        dtype=np.int64,
    ).T


    # ============================================================
    # EDGE RELATIONS
    # ============================================================

    edge_type_ids = np.asarray(
        [
            0, 3, 5, 7,
            0, 3, 5, 7,
            0, 3, 5, 7,
        ],
        dtype=np.int64,
    )


    graph_ptr = np.asarray(
        [
            0,
            5,
            10,
            15,
        ],
        dtype=np.int64,
    )


    edge_ptr = np.asarray(
        [
            0,
            4,
            8,
            12,
        ],
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
            graph_ptr,

        "edge_ptr":
            edge_ptr,

        "center_node_indices":
            center_node_indices,

        "graph_ids":
            np.asarray(
                [
                    "GRAPH-A",
                    "GRAPH-B",
                    "GRAPH-C",
                ],
                dtype=str,
            ),

        "pids":
            np.asarray(
                [
                    "1001",
                    "1002",
                    "1003",
                ],
                dtype=str,
            ),

        "process_names":
            np.asarray(
                [
                    "process_a.exe",
                    "process_b.exe",
                    "process_c.exe",
                ],
                dtype=str,
            ),
    }


# ================================================================
# MAIN
# ================================================================

def main():

    heading(
        "SENTINEL-X SELF-SUPERVISED GRAPH ENCODER TEST"
    )


    torch.set_num_threads(
        1
    )


    with tempfile.TemporaryDirectory() as directory:

        directory = Path(
            directory
        )


        dataset_path = (
            directory
            / "graph_dataset.npz"
        )


        model_path = (
            directory
            / "graph_encoder.pt"
        )


        metadata_path = (
            directory
            / "graph_encoder_metadata.json"
        )


        # ========================================================
        # DATASET
        # ========================================================

        dataset = (
            build_dataset()
        )


        np.savez_compressed(

            dataset_path,

            **dataset,
        )


        print()

        print(
            "Dataset:",
            dataset_path,
        )


        # ========================================================
        # TRAINER
        # ========================================================

        trainer = (
            GraphSelfSupervisedTrainer(

                input_dim=
                    32,

                hidden_dim=
                    64,

                embedding_dim=
                    64,

                num_node_types=
                    5,

                num_edge_types=
                    8,

                num_layers=
                    2,

                dropout=
                    0.05,

                learning_rate=
                    0.003,

                mask_probability=
                    0.20,

                seed=
                    42,

                device=
                    "cpu",
            )
        )


        # ========================================================
        # LOAD DATASET
        # ========================================================

        loaded = (
            trainer.load_dataset(
                dataset_path
            )
        )


        print(
            "X shape:",
            loaded[
                "x"
            ].shape,
        )


        print(
            "Edge index:",
            loaded[
                "edge_index"
            ].shape,
        )


        print(
            "Graphs:",
            len(
                loaded[
                    "center_node_indices"
                ]
            ),
        )


        assert (
            loaded[
                "x"
            ].shape
            ==
            (
                15,
                32,
            )
        )


        assert (
            loaded[
                "edge_index"
            ].shape
            ==
            (
                2,
                12,
            )
        )


        # ========================================================
        # TRAIN
        # ========================================================

        heading(
            "SELF-SUPERVISED TRAINING"
        )


        result = (
            trainer.train(

                loaded,

                epochs=
                    25,

                verbose=
                    True,
            )
        )


        # ========================================================
        # BASIC LOSS HEALTH
        # ========================================================

        assert (
            np.isfinite(
                result[
                    "final_training_loss"
                ]
            )
        )


        assert (
            np.isfinite(
                result[
                    "full_reconstruction_loss"
                ]
            )
        )


        print()

        print(
            "Final masked loss:",
            result[
                "final_training_loss"
            ],
        )


        print(
            "Full reconstruction loss:",
            result[
                "full_reconstruction_loss"
            ],
        )


        print(
            "Loss finite: PASS"
        )


        # ========================================================
        # NODE EMBEDDINGS
        # ========================================================

        node_embeddings = (
            result[
                "node_embeddings"
            ]
        )


        assert (
            node_embeddings.shape
            ==
            (
                15,
                64,
            )
        )


        assert (
            np.isfinite(
                node_embeddings
            ).all()
        )


        print()

        print(
            "Node embedding shape:",
            node_embeddings.shape,
        )


        print(
            "64-D node embeddings: PASS"
        )


        # ========================================================
        # CENTER PROCESS EMBEDDINGS
        # ========================================================

        center_embeddings = (
            result[
                "center_embeddings"
            ]
        )


        assert (
            center_embeddings.shape
            ==
            (
                3,
                64,
            )
        )


        assert (
            np.isfinite(
                center_embeddings
            ).all()
        )


        print(
            "Center embedding shape:",
            center_embeddings.shape,
        )


        print(
            "64-D center process embeddings: PASS"
        )


        # ========================================================
        # EMBEDDING HEALTH
        # ========================================================

        health = (
            result[
                "embedding_health"
            ]
        )


        heading(
            "EMBEDDING HEALTH"
        )


        print()

        for (
            key,
            value,
        ) in health.items():

            print(
                f"{key:<24}: "
                f"{value}"
            )


        assert (
            health[
                "finite"
            ]
            is True
        )


        assert (
            health[
                "all_zero_fraction"
            ]
            == 0.0
        )


        assert (
            health[
                "unique_fraction"
            ]
            > 0.5
        )


        assert (
            health[
                "mean_norm"
            ]
            > 0
        )


        print()

        print(
            "Embedding collapse check: PASS"
        )


        # ========================================================
        # SAVE
        # ========================================================

        save_result = (
            trainer.save_model(

                model_path=
                    model_path,

                metadata_path=
                    metadata_path,

                training_result=
                    result,

                dataset=
                    loaded,
            )
        )


        assert (
            save_result[
                "model_path"
            ].exists()
        )


        assert (
            save_result[
                "metadata_path"
            ].exists()
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


        # ========================================================
        # LOAD CHECKPOINT
        # ========================================================

        checkpoint = torch.load(

            model_path,

            map_location=
                "cpu",

            weights_only=
                False,
        )


        assert (
            checkpoint[
                "model_version"
            ]
            == "v1"
        )


        assert (
            checkpoint[
                "input_dim"
            ]
            == 32
        )


        assert (
            checkpoint[
                "embedding_dim"
            ]
            == 64
        )


        assert (
            checkpoint[
                "num_edge_types"
            ]
            == 8
        )


        print(
            "Checkpoint validation: PASS"
        )


        # ========================================================
        # METADATA
        # ========================================================

        with open(
            metadata_path,
            "r",
            encoding="utf-8",
        ) as file:

            metadata = (
                json.load(
                    file
                )
            )


        assert (
            metadata[
                "ground_truth_labels_used"
            ]
            is False
        )


        assert (
            metadata[
                "classifier_trained"
            ]
            is False
        )


        assert (
            metadata[
                "embedding_dimension"
            ]
            == 64
        )


        assert (
            metadata[
                "learning_mode"
            ]
            ==
            (
                "SELF_SUPERVISED_MASKED_"
                "FEATURE_RECONSTRUCTION"
            )
        )


        print(
            "Metadata validation: PASS"
        )


    heading(
        "SELF-SUPERVISED GRAPH ENCODER TEST: PASS"
    )


if __name__ == "__main__":

    main()