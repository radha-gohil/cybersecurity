from __future__ import annotations

from typing import Optional

import torch
import torch.nn as nn
import torch.nn.functional as F


# ================================================================
# RELATION-AWARE MESSAGE PASSING LAYER
# ================================================================


class RelationAwareGraphLayer(
    nn.Module
):

    def __init__(
        self,
        hidden_dim: int,
        num_edge_types: int,
        dropout: float = 0.10,
    ):

        super().__init__()


        self.hidden_dim = int(
            hidden_dim
        )


        self.num_edge_types = int(
            num_edge_types
        )


        # --------------------------------------------------------
        # SELF NODE TRANSFORMATION
        # --------------------------------------------------------

        self.self_linear = nn.Linear(
            self.hidden_dim,
            self.hidden_dim,
        )


        # --------------------------------------------------------
        # NEIGHBOR MESSAGE TRANSFORMATION
        # --------------------------------------------------------

        self.neighbor_linear = nn.Linear(
            self.hidden_dim,
            self.hidden_dim,
            bias=False,
        )


        # --------------------------------------------------------
        # RELATION EMBEDDING
        #
        # One learnable vector for each provenance edge type.
        # --------------------------------------------------------

        self.relation_embedding = (
            nn.Embedding(
                self.num_edge_types,
                self.hidden_dim,
            )
        )


        # --------------------------------------------------------
        # NORMALIZATION
        # --------------------------------------------------------

        self.norm = nn.LayerNorm(
            self.hidden_dim
        )


        self.dropout = nn.Dropout(
            dropout
        )


    # ============================================================
    # FORWARD
    # ============================================================

    def forward(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        edge_type_ids: torch.Tensor,
    ) -> torch.Tensor:

        if x.ndim != 2:

            raise ValueError(
                "x must have shape [N, hidden_dim]."
            )


        node_count = (
            x.shape[
                0
            ]
        )


        # ========================================================
        # NO EDGES
        # ========================================================

        if (
            edge_index.numel()
            == 0
        ):

            output = (
                self.self_linear(
                    x
                )
            )


            output = (
                self.norm(
                    output
                )
            )


            output = F.gelu(
                output
            )


            return (
                self.dropout(
                    output
                )
            )


        # ========================================================
        # EDGE VALIDATION
        # ========================================================

        if (
            edge_index.ndim
            != 2

            or

            edge_index.shape[
                0
            ]
            != 2
        ):

            raise ValueError(
                "edge_index must have shape [2, E]."
            )


        if (
            edge_index.shape[
                1
            ]
            !=
            edge_type_ids.shape[
                0
            ]
        ):

            raise ValueError(
                "edge_index and edge_type_ids length mismatch."
            )


        source = (
            edge_index[
                0
            ]
        )


        target = (
            edge_index[
                1
            ]
        )


        # ========================================================
        # SOURCE NODE REPRESENTATION
        # ========================================================

        source_hidden = (
            self.neighbor_linear(
                x[
                    source
                ]
            )
        )


        # ========================================================
        # RELATION REPRESENTATION
        # ========================================================

        relation_hidden = (
            self.relation_embedding(
                edge_type_ids
            )
        )


        # ========================================================
        # MESSAGE
        # ========================================================

        message = (
            source_hidden
            +
            relation_hidden
        )


        # ========================================================
        # AGGREGATE INTO TARGET NODE
        # ========================================================

        aggregate = torch.zeros(

            (
                node_count,
                self.hidden_dim,
            ),

            dtype=x.dtype,

            device=x.device,
        )


        aggregate.index_add_(
            0,
            target,
            message,
        )


        # ========================================================
        # DEGREE NORMALIZATION
        # ========================================================

        degree = torch.zeros(

            node_count,

            dtype=x.dtype,

            device=x.device,
        )


        degree.index_add_(

            0,

            target,

            torch.ones(

                target.shape[
                    0
                ],

                dtype=x.dtype,

                device=x.device,
            ),
        )


        degree = (
            degree.clamp(
                min=1.0
            )
        )


        aggregate = (

            aggregate

            /

            degree.unsqueeze(
                1
            )
        )


        # ========================================================
        # SELF + NEIGHBOR
        # ========================================================

        output = (

            self.self_linear(
                x
            )

            +

            aggregate
        )


        output = (
            self.norm(
                output
            )
        )


        output = F.gelu(
            output
        )


        output = (
            self.dropout(
                output
            )
        )


        return output


# ================================================================
# SENTINEL-X GRAPH ENCODER
# ================================================================


class SentinelXGraphEncoder(
    nn.Module
):

    MODEL_NAME = (
        "sentinelx_relation_aware_graph_encoder"
    )


    MODEL_VERSION = "v1"


    def __init__(
        self,
        input_dim: int = 32,
        hidden_dim: int = 64,
        embedding_dim: int = 64,
        num_node_types: int = 5,
        num_edge_types: int = 8,
        num_layers: int = 2,
        dropout: float = 0.10,
    ):

        super().__init__()


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


        # ========================================================
        # INPUT PROJECTION
        # ========================================================

        self.input_projection = (
            nn.Sequential(

                nn.Linear(
                    self.input_dim,
                    self.hidden_dim,
                ),

                nn.LayerNorm(
                    self.hidden_dim
                ),

                nn.GELU(),
            )
        )


        # ========================================================
        # NODE TYPE EMBEDDING
        # ========================================================

        self.node_type_embedding = (
            nn.Embedding(
                self.num_node_types,
                self.hidden_dim,
            )
        )


        # ========================================================
        # GRAPH LAYERS
        # ========================================================

        self.graph_layers = (
            nn.ModuleList(
                [
                    RelationAwareGraphLayer(

                        hidden_dim=
                            self.hidden_dim,

                        num_edge_types=
                            self.num_edge_types,

                        dropout=
                            dropout,
                    )

                    for _ in range(
                        self.num_layers
                    )
                ]
            )
        )


        # ========================================================
        # FINAL NODE REPRESENTATION
        # ========================================================

        self.embedding_projection = (
            nn.Sequential(

                nn.Linear(
                    self.hidden_dim,
                    self.embedding_dim,
                ),

                nn.LayerNorm(
                    self.embedding_dim
                ),
            )
        )


        # ========================================================
        # SELF-SUPERVISED FEATURE DECODER
        #
        # Attempts to reconstruct the original 32-D node features.
        # ========================================================

        self.feature_decoder = (
            nn.Sequential(

                nn.Linear(
                    self.embedding_dim,
                    self.hidden_dim,
                ),

                nn.GELU(),

                nn.Linear(
                    self.hidden_dim,
                    self.input_dim,
                ),

                nn.Sigmoid(),
            )
        )


    # ============================================================
    # BIDIRECTIONAL GRAPH
    #
    # The provenance DB keeps original direction.
    #
    # For representation learning, each stored relationship also
    # contributes a reverse message path.
    #
    # Relation identity itself is retained.
    # ============================================================

    def make_bidirectional(
        self,
        edge_index: torch.Tensor,
        edge_type_ids: torch.Tensor,
    ):

        if (
            edge_index.numel()
            == 0
        ):

            return (
                edge_index,
                edge_type_ids,
            )


        reversed_edges = torch.stack(
            [
                edge_index[
                    1
                ],

                edge_index[
                    0
                ],
            ],
            dim=0,
        )


        bidirectional_edges = torch.cat(
            [
                edge_index,
                reversed_edges,
            ],
            dim=1,
        )


        bidirectional_types = torch.cat(
            [
                edge_type_ids,
                edge_type_ids,
            ],
            dim=0,
        )


        return (
            bidirectional_edges,
            bidirectional_types,
        )


    # ============================================================
    # ENCODE NODES
    # ============================================================

    def encode(
        self,
        x: torch.Tensor,
        node_type_ids: torch.Tensor,
        edge_index: torch.Tensor,
        edge_type_ids: torch.Tensor,
    ) -> torch.Tensor:

        if (
            x.ndim != 2

            or

            x.shape[
                1
            ]
            != self.input_dim
        ):

            raise ValueError(
                (
                    "Expected x shape "
                    f"[N, {self.input_dim}]."
                )
            )


        # ========================================================
        # NODE TYPES
        # ========================================================

        safe_node_types = (
            node_type_ids.clamp(
                min=0,
                max=(
                    self.num_node_types
                    - 1
                ),
            )
        )


        # ========================================================
        # INPUT REPRESENTATION
        # ========================================================

        hidden = (
            self.input_projection(
                x
            )
        )


        hidden = (

            hidden

            +

            self.node_type_embedding(
                safe_node_types
            )
        )


        # ========================================================
        # MESSAGE PASSING GRAPH
        # ========================================================

        (
            message_edge_index,
            message_edge_types,
        ) = (
            self.make_bidirectional(
                edge_index,
                edge_type_ids,
            )
        )


        # ========================================================
        # GRAPH LAYERS
        # ========================================================

        for layer in self.graph_layers:

            residual = hidden


            hidden = (
                layer(
                    hidden,
                    message_edge_index,
                    message_edge_types,
                )
            )


            hidden = (
                hidden
                +
                residual
            )


        # ========================================================
        # NODE EMBEDDINGS
        # ========================================================

        node_embeddings = (
            self.embedding_projection(
                hidden
            )
        )


        return (
            node_embeddings
        )


    # ============================================================
    # CENTER PROCESS REPRESENTATIONS
    # ============================================================

    def center_embeddings(
        self,
        node_embeddings: torch.Tensor,
        center_node_indices: torch.Tensor,
    ) -> torch.Tensor:

        if (
            center_node_indices.numel()
            == 0
        ):

            return torch.empty(

                (
                    0,
                    self.embedding_dim,
                ),

                dtype=node_embeddings.dtype,

                device=node_embeddings.device,
            )


        return (
            node_embeddings[
                center_node_indices
            ]
        )


    # ============================================================
    # FORWARD
    # ============================================================

    def forward(
        self,
        x: torch.Tensor,
        node_type_ids: torch.Tensor,
        edge_index: torch.Tensor,
        edge_type_ids: torch.Tensor,
        center_node_indices: Optional[
            torch.Tensor
        ] = None,
    ):

        node_embeddings = (
            self.encode(

                x=
                    x,

                node_type_ids=
                    node_type_ids,

                edge_index=
                    edge_index,

                edge_type_ids=
                    edge_type_ids,
            )
        )


        reconstructed_features = (
            self.feature_decoder(
                node_embeddings
            )
        )


        result = {
            "node_embeddings":
                node_embeddings,

            "reconstructed_features":
                reconstructed_features,
        }


        if (
            center_node_indices
            is not None
        ):

            result[
                "center_embeddings"
            ] = (
                self.center_embeddings(

                    node_embeddings,

                    center_node_indices,
                )
            )


        return result