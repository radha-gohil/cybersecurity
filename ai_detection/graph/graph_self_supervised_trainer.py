from __future__ import annotations

import json
import random

from datetime import (
    datetime,
    timezone,
)

from pathlib import Path

from typing import Optional


import numpy as np

import torch

import torch.nn.functional as F


from ai_detection.graph.relation_aware_graph_encoder import (
    SentinelXGraphEncoder,
)


# ================================================================
# PROJECT ROOT
# ================================================================

PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[2]
)


DEFAULT_MODEL_PATH = (

    PROJECT_ROOT
    / "models"
    / "graph"
    / "sentinelx_graph_encoder_v1.pt"
)


DEFAULT_METADATA_PATH = (

    PROJECT_ROOT
    / "models"
    / "graph"
    / "sentinelx_graph_encoder_v1_metadata.json"
)


# ================================================================
# SELF-SUPERVISED GRAPH TRAINER
#
# OBJECTIVE
# ---------
#
# Randomly hide part of the 32-D node feature matrix.
#
# The graph encoder must reconstruct those hidden values using:
#
#   remaining node features
#   neighboring nodes
#   relation types
#   node types
#
#
# This is a self-supervised reconstruction objective.
#
# It does NOT require malicious / benign labels.
# ================================================================


class GraphSelfSupervisedTrainer:

    TRAINER_VERSION = "v1"


    def __init__(
        self,
        *,
        input_dim: int = 32,
        hidden_dim: int = 64,
        embedding_dim: int = 64,
        num_node_types: int = 5,
        num_edge_types: int = 8,
        num_layers: int = 2,
        dropout: float = 0.10,
        learning_rate: float = 1e-3,
        weight_decay: float = 1e-5,
        mask_probability: float = 0.20,
        seed: int = 42,
        device: Optional[str] = None,
    ):

        self.input_dim = int(
            input_dim
        )


        self.hidden_dim = int(
            hidden_dim
        )


        self.embedding_dim = int(
            embedding_dim
        )


        self.num_node_types = int(
            num_node_types
        )


        self.num_edge_types = int(
            num_edge_types
        )


        self.num_layers = int(
            num_layers
        )


        self.dropout = float(
            dropout
        )


        self.learning_rate = float(
            learning_rate
        )


        self.weight_decay = float(
            weight_decay
        )


        self.mask_probability = float(
            mask_probability
        )


        self.seed = int(
            seed
        )


        # ========================================================
        # RANDOM SEEDS
        # ========================================================

        random.seed(
            self.seed
        )


        np.random.seed(
            self.seed
        )


        torch.manual_seed(
            self.seed
        )


        if torch.cuda.is_available():

            torch.cuda.manual_seed_all(
                self.seed
            )


        # ========================================================
        # DEVICE
        # ========================================================

        if device is None:

            device = (
                "cuda"

                if torch.cuda.is_available()

                else "cpu"
            )


        self.device = torch.device(
            device
        )


        # ========================================================
        # MODEL
        # ========================================================

        self.model = (
            SentinelXGraphEncoder(

                input_dim=
                    self.input_dim,

                hidden_dim=
                    self.hidden_dim,

                embedding_dim=
                    self.embedding_dim,

                num_node_types=
                    self.num_node_types,

                num_edge_types=
                    self.num_edge_types,

                num_layers=
                    self.num_layers,

                dropout=
                    self.dropout,
            )
            .to(
                self.device
            )
        )


        self.optimizer = (
            torch.optim.AdamW(

                self.model.parameters(),

                lr=
                    self.learning_rate,

                weight_decay=
                    self.weight_decay,
            )
        )


    # ============================================================
    # TIME
    # ============================================================

    def now_iso(
        self,
    ):

        return (
            datetime.now(
                timezone.utc
            ).isoformat()
        )


    # ============================================================
    # LOAD DATASET
    #
    # IMPORTANT:
    #
    # np.load() uses a context manager so Windows does not retain
    # an open .npz handle.
    # ============================================================

    def load_dataset(
        self,
        dataset_path,
    ):

        dataset_path = Path(
            dataset_path
        )


        with np.load(
            dataset_path,
            allow_pickle=False,
        ) as loaded:

            dataset = {

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
                    (
                        loaded[
                            "graph_ids"
                        ].copy()

                        if "graph_ids"
                        in loaded.files

                        else np.asarray(
                            [],
                            dtype=str,
                        )
                    ),

                "pids":
                    (
                        loaded[
                            "pids"
                        ].copy()

                        if "pids"
                        in loaded.files

                        else np.asarray(
                            [],
                            dtype=str,
                        )
                    ),

                "process_names":
                    (
                        loaded[
                            "process_names"
                        ].copy()

                        if "process_names"
                        in loaded.files

                        else np.asarray(
                            [],
                            dtype=str,
                        )
                    ),
            }


        return dataset


    # ============================================================
    # NUMPY -> TORCH
    # ============================================================

    def tensorize(
        self,
        dataset,
    ):

        x = torch.tensor(

            dataset[
                "x"
            ],

            dtype=torch.float32,

            device=self.device,
        )


        node_type_ids = torch.tensor(

            dataset[
                "node_type_ids"
            ],

            dtype=torch.long,

            device=self.device,
        )


        edge_index = torch.tensor(

            dataset[
                "edge_index"
            ],

            dtype=torch.long,

            device=self.device,
        )


        edge_type_ids = torch.tensor(

            dataset[
                "edge_type_ids"
            ],

            dtype=torch.long,

            device=self.device,
        )


        center_node_indices = torch.tensor(

            dataset[
                "center_node_indices"
            ],

            dtype=torch.long,

            device=self.device,
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

            "center_node_indices":
                center_node_indices,
        }


    # ============================================================
    # CREATE FEATURE MASK
    # ============================================================

    def create_feature_mask(
        self,
        x: torch.Tensor,
    ):

        mask = (

            torch.rand(

                x.shape,

                device=x.device,
            )

            <

            self.mask_probability
        )


        # ========================================================
        # GUARANTEE AT LEAST ONE MASKED VALUE
        # ========================================================

        if not bool(
            mask.any()
        ):

            mask[
                0,
                0
            ] = True


        return mask


    # ============================================================
    # TRAIN ONE EPOCH
    # ============================================================

    def train_epoch(
        self,
        tensors,
    ):

        self.model.train()


        x = (
            tensors[
                "x"
            ]
        )


        mask = (
            self.create_feature_mask(
                x
            )
        )


        masked_x = (
            x.clone()
        )


        masked_x[
            mask
        ] = 0.0


        result = (
            self.model(

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


        reconstructed = (
            result[
                "reconstructed_features"
            ]
        )


        loss = F.mse_loss(

            reconstructed[
                mask
            ],

            x[
                mask
            ],
        )


        self.optimizer.zero_grad(
            set_to_none=True
        )


        loss.backward()


        torch.nn.utils.clip_grad_norm_(
            self.model.parameters(),
            max_norm=5.0,
        )


        self.optimizer.step()


        return float(
            loss.detach()
            .cpu()
            .item()
        )


    # ============================================================
    # FULL RECONSTRUCTION ERROR
    # ============================================================

    @torch.no_grad()
    def evaluate_reconstruction(
        self,
        tensors,
    ):

        self.model.eval()


        result = (
            self.model(

                x=
                    tensors[
                        "x"
                    ],

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

            reconstruction,

            tensors[
                "x"
            ],
        )


        return {
            "loss":
                float(
                    loss.cpu()
                    .item()
                ),

            "node_embeddings":
                result[
                    "node_embeddings"
                ]
                .cpu()
                .numpy(),

            "center_embeddings":
                result[
                    "center_embeddings"
                ]
                .cpu()
                .numpy(),

            "reconstruction":
                reconstruction
                .cpu()
                .numpy(),
        }


    # ============================================================
    # EMBEDDING HEALTH
    # ============================================================

    def embedding_health(
        self,
        center_embeddings,
    ):

        embeddings = np.asarray(
            center_embeddings,
            dtype=np.float32,
        )


        if embeddings.size == 0:

            return {
                "count":
                    0,

                "dimension":
                    self.embedding_dim,

                "finite":
                    True,

                "all_zero_fraction":
                    0.0,

                "unique_fraction":
                    0.0,

                "mean_norm":
                    0.0,
            }


        finite = bool(
            np.isfinite(
                embeddings
            ).all()
        )


        norms = np.linalg.norm(
            embeddings,
            axis=1,
        )


        all_zero = (
            norms
            < 1e-8
        )


        rounded = np.round(
            embeddings,
            decimals=5,
        )


        unique_count = (
            np.unique(
                rounded,
                axis=0,
            )
            .shape[
                0
            ]
        )


        return {
            "count":
                int(
                    embeddings.shape[
                        0
                    ]
                ),

            "dimension":
                int(
                    embeddings.shape[
                        1
                    ]
                ),

            "finite":
                finite,

            "all_zero_fraction":
                float(
                    all_zero.mean()
                ),

            "unique_fraction":
                float(

                    unique_count

                    /

                    max(
                        1,
                        embeddings.shape[
                            0
                        ],
                    )
                ),

            "mean_norm":
                float(
                    norms.mean()
                ),
        }


    # ============================================================
    # TRAIN
    # ============================================================

    def train(
        self,
        dataset,
        epochs: int = 50,
        verbose: bool = True,
    ):

        tensors = (
            self.tensorize(
                dataset
            )
        )


        if (
            tensors[
                "x"
            ].shape[
                0
            ]
            == 0
        ):

            raise ValueError(
                "Graph dataset contains no nodes."
            )


        history = []


        for epoch in range(
            1,
            int(
                epochs
            )
            + 1,
        ):

            loss = (
                self.train_epoch(
                    tensors
                )
            )


            history.append(
                loss
            )


            if verbose:

                print(
                    f"Epoch "
                    f"{epoch:03d}/"
                    f"{int(epochs):03d}"
                    f" | "
                    f"Masked Reconstruction Loss="
                    f"{loss:.6f}"
                )


        evaluation = (
            self.evaluate_reconstruction(
                tensors
            )
        )


        health = (
            self.embedding_health(

                evaluation[
                    "center_embeddings"
                ]
            )
        )


        return {
            "history":
                history,

            "final_training_loss":
                history[
                    -1
                ],

            "full_reconstruction_loss":
                evaluation[
                    "loss"
                ],

            "node_embeddings":
                evaluation[
                    "node_embeddings"
                ],

            "center_embeddings":
                evaluation[
                    "center_embeddings"
                ],

            "embedding_health":
                health,
        }


    # ============================================================
    # SAVE MODEL
    # ============================================================

    def save_model(
        self,
        *,
        model_path=None,
        metadata_path=None,
        training_result=None,
        dataset=None,
    ):

        if model_path is None:

            model_path = (
                DEFAULT_MODEL_PATH
            )


        if metadata_path is None:

            metadata_path = (
                DEFAULT_METADATA_PATH
            )


        model_path = Path(
            model_path
        )


        metadata_path = Path(
            metadata_path
        )


        model_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )


        metadata_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )


        # ========================================================
        # CHECKPOINT
        # ========================================================

        checkpoint = {

            "model_name":
                SentinelXGraphEncoder.MODEL_NAME,

            "model_version":
                SentinelXGraphEncoder.MODEL_VERSION,

            "trainer_version":
                self.TRAINER_VERSION,

            "input_dim":
                self.input_dim,

            "hidden_dim":
                self.hidden_dim,

            "embedding_dim":
                self.embedding_dim,

            "num_node_types":
                self.num_node_types,

            "num_edge_types":
                self.num_edge_types,

            "num_layers":
                self.num_layers,

            "dropout":
                self.dropout,

            "state_dict":
                self.model.state_dict(),
        }


        torch.save(
            checkpoint,
            model_path,
        )


        # ========================================================
        # METADATA
        # ========================================================

        metadata = {

            "model_name":
                SentinelXGraphEncoder.MODEL_NAME,

            "model_version":
                SentinelXGraphEncoder.MODEL_VERSION,

            "trainer_version":
                self.TRAINER_VERSION,

            "created_at":
                self.now_iso(),

            "learning_mode":
                (
                    "SELF_SUPERVISED_MASKED_"
                    "FEATURE_RECONSTRUCTION"
                ),

            "input_feature_count":
                self.input_dim,

            "hidden_dimension":
                self.hidden_dim,

            "embedding_dimension":
                self.embedding_dim,

            "graph_layers":
                self.num_layers,

            "node_type_count":
                self.num_node_types,

            "edge_type_count":
                self.num_edge_types,

            "mask_probability":
                self.mask_probability,

            "ground_truth_labels_used":
                False,

            "classifier_trained":
                False,

            "output_interpretation":
                (
                    "64-D learned graph representation. "
                    "It is not a malware probability "
                    "or calibrated threat probability."
                ),
        }


        if dataset is not None:

            metadata[
                "training_graph_count"
            ] = int(

                len(
                    dataset[
                        "center_node_indices"
                    ]
                )
            )


            metadata[
                "training_node_count"
            ] = int(

                dataset[
                    "x"
                ].shape[
                    0
                ]
            )


            metadata[
                "training_edge_count"
            ] = int(

                dataset[
                    "edge_index"
                ].shape[
                    1
                ]
            )


        if training_result is not None:

            metadata[
                "final_training_loss"
            ] = float(

                training_result[
                    "final_training_loss"
                ]
            )


            metadata[
                "full_reconstruction_loss"
            ] = float(

                training_result[
                    "full_reconstruction_loss"
                ]
            )


            metadata[
                "embedding_health"
            ] = (
                training_result[
                    "embedding_health"
                ]
            )


        with open(
            metadata_path,
            "w",
            encoding="utf-8",
        ) as file:

            json.dump(
                metadata,
                file,
                indent=2,
                ensure_ascii=False,
            )


        return {
            "model_path":
                model_path,

            "metadata_path":
                metadata_path,
        }