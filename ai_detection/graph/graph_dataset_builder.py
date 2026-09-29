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


import numpy as np


from ai_detection.graph.graph_feature_encoder import (
    GraphFeatureEncoder,
)


from ai_detection.graph.process_subgraph_service import (
    ProcessSubgraphService,
)


# ================================================================
# PROJECT PATH
# ================================================================

PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[2]
)


DEFAULT_OUTPUT_PATH = (

    PROJECT_ROOT
    / "data"
    / "graph"
    / "sentinelx_process_graph_dataset_v1.npz"
)


# ================================================================
# SENTINEL-X GRAPH DATASET BUILDER
#
# Creates a heterogeneous process-centered graph dataset.
#
# OUTPUT
# ------
#
# x
#     [total_nodes, 32]
#
# edge_index
#     [2, total_edges]
#
# node_type_ids
#     [total_nodes]
#
# edge_type_ids
#     [total_edges]
#
# graph_ptr
#     node offsets for each graph
#
# edge_ptr
#     edge offsets for each graph
#
# center_node_indices
#     global center-process index for each graph
#
#
# IMPORTANT
# ---------
#
# There are currently NO ground-truth attack labels.
#
# Therefore this dataset is intended for:
#
#   self-supervised graph learning
#   representation learning
#   anomaly detection
#
# not supervised malicious/benign classification yet.
# ================================================================


class GraphDatasetBuilder:

    DATASET_VERSION = (
        "sentinelx_graph_dataset_v1"
    )


    def __init__(
        self,
        database_path=None,
        max_hops: int = 2,
        include_event_nodes: bool = True,
    ):

        self.max_hops = int(
            max_hops
        )


        self.include_event_nodes = bool(
            include_event_nodes
        )


        self.service = (
            ProcessSubgraphService(
                database_path=
                    database_path
            )
        )


        self.encoder = (
            GraphFeatureEncoder()
        )


    # ============================================================
    # CURRENT TIME
    # ============================================================

    def now_iso(
        self,
    ) -> str:

        return (
            datetime.now(
                timezone.utc
            ).isoformat()
        )


    # ============================================================
    # DISCOVER PROCESS QUERIES
    # ============================================================

    def discover_process_queries(
        self,
    ) -> List[
        Dict[str, Any]
    ]:

        nodes = (
            self.service.store
            .get_nodes(
                limit=100000
            )
        )


        queries = []


        seen = set()


        for node in nodes:

            if (
                node.get(
                    "node_type"
                )
                != "PROCESS"
            ):

                continue


            properties = (
                node.get(
                    "properties"
                )

                or {}
            )


            if not isinstance(
                properties,
                dict,
            ):

                continue


            pid = (
                properties.get(
                    "pid"
                )
            )


            if pid is None:

                continue


            process_name = (

                properties.get(
                    "name"
                )

                or

                node.get(
                    "label"
                )
            )


            device_id = (
                properties.get(
                    "device_id"
                )
            )


            identity = (
                str(
                    pid
                ),

                str(
                    process_name
                    or ""
                ).lower(),

                str(
                    device_id
                    or ""
                ).lower(),
            )


            if identity in seen:

                continue


            seen.add(
                identity
            )


            queries.append(
                {
                    "pid":
                        pid,

                    "process_name":
                        process_name,

                    "device_id":
                        device_id,
                }
            )


        return queries


    # ============================================================
    # EMPTY DATASET
    # ============================================================

    def empty_dataset(
        self,
    ):

        return {
            "dataset_version":
                self.DATASET_VERSION,

            "feature_schema_version":
                self.encoder.SCHEMA_VERSION,

            "feature_names":
                list(
                    self.encoder.FEATURE_NAMES
                ),

            "x":
                np.empty(
                    (
                        0,
                        self.encoder.FEATURE_COUNT,
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

            "graph_count":
                0,

            "node_count":
                0,

            "edge_count":
                0,
        }


    # ============================================================
    # BUILD DATASET
    # ============================================================

    def build_dataset(
        self,
        process_queries: Optional[
            List[
                Dict[str, Any]
            ]
        ] = None,
        max_graphs: Optional[int] = None,
    ):

        if process_queries is None:

            process_queries = (
                self.discover_process_queries()
            )


        if max_graphs is not None:

            process_queries = (
                process_queries[
                    : int(
                        max_graphs
                    )
                ]
            )


        if not process_queries:

            return (
                self.empty_dataset()
            )


        all_x = []

        all_node_types = []

        all_edge_sources = []

        all_edge_targets = []

        all_edge_types = []


        graph_ptr = [
            0
        ]


        edge_ptr = [
            0
        ]


        center_node_indices = []


        graph_ids = []

        pids = []

        process_names = []

        device_ids = []


        node_offset = 0

        edge_offset = 0


        seen_centers = set()


        # ========================================================
        # PROCESS GRAPHS
        # ========================================================

        for query in process_queries:

            pid = (
                query.get(
                    "pid"
                )
            )


            process_name = (
                query.get(
                    "process_name"
                )
            )


            device_id = (
                query.get(
                    "device_id"
                )
            )


            subgraph = (
                self.service
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
                        self.include_event_nodes,
                )
            )


            if not subgraph.get(
                "found",
                False,
            ):

                continue


            center_node_id = (
                subgraph.get(
                    "center_node_id"
                )
            )


            if center_node_id in seen_centers:

                continue


            seen_centers.add(
                center_node_id
            )


            # ====================================================
            # NODE FEATURES
            # ====================================================

            encoded = (
                self.encoder
                .encode_subgraph(
                    subgraph
                )
            )


            x = (
                encoded[
                    "x"
                ]
            )


            node_type_ids = (
                encoded[
                    "node_type_ids"
                ]
            )


            # ====================================================
            # STRUCTURE
            # ====================================================

            structure = (
                self.service
                .export_gnn_structure(
                    subgraph
                )
            )


            local_edge_index = (
                np.asarray(

                    structure.get(
                        "edge_index",
                        [
                            [],
                            [],
                        ],
                    ),

                    dtype=np.int64,
                )
            )


            local_edge_types = (
                np.asarray(

                    structure.get(
                        "edge_type_ids",
                        [],
                    ),

                    dtype=np.int64,
                )
            )


            local_center = (
                structure.get(
                    "center_node_index"
                )
            )


            if (
                local_center
                is None
            ):

                continue


            # ====================================================
            # VALIDATE SHAPES
            # ====================================================

            if (
                x.ndim != 2

                or

                x.shape[
                    1
                ]
                !=
                self.encoder.FEATURE_COUNT
            ):

                raise RuntimeError(
                    "Invalid node feature matrix."
                )


            if (
                local_edge_index.ndim
                != 2

                or

                local_edge_index.shape[
                    0
                ]
                != 2
            ):

                raise RuntimeError(
                    "Invalid edge_index."
                )


            if (
                local_edge_index.shape[
                    1
                ]
                !=
                len(
                    local_edge_types
                )
            ):

                raise RuntimeError(
                    "edge_index / edge_type length mismatch."
                )


            # ====================================================
            # APPEND NODE DATA
            # ====================================================

            all_x.append(
                x
            )


            all_node_types.append(
                node_type_ids
            )


            # ====================================================
            # GLOBAL EDGE INDEX
            # ====================================================

            if (
                local_edge_index.shape[
                    1
                ]
                > 0
            ):

                all_edge_sources.extend(

                    (
                        local_edge_index[
                            0
                        ]
                        +
                        node_offset
                    ).tolist()
                )


                all_edge_targets.extend(

                    (
                        local_edge_index[
                            1
                        ]
                        +
                        node_offset
                    ).tolist()
                )


                all_edge_types.extend(
                    local_edge_types.tolist()
                )


            # ====================================================
            # CENTER PROCESS
            # ====================================================

            center_node_indices.append(

                int(
                    local_center
                )
                +
                node_offset
            )


            graph_ids.append(
                str(
                    center_node_id
                )
            )


            pids.append(
                str(
                    subgraph.get(
                        "pid"
                    )
                )
            )


            process_names.append(
                str(
                    subgraph.get(
                        "process_name"
                    )
                    or ""
                )
            )


            device_ids.append(
                str(
                    subgraph.get(
                        "device_id"
                    )
                    or ""
                )
            )


            # ====================================================
            # POINTERS
            # ====================================================

            node_offset += (
                x.shape[
                    0
                ]
            )


            edge_offset += (
                local_edge_index.shape[
                    1
                ]
            )


            graph_ptr.append(
                node_offset
            )


            edge_ptr.append(
                edge_offset
            )


        # ========================================================
        # NO VALID GRAPH
        # ========================================================

        if not all_x:

            return (
                self.empty_dataset()
            )


        # ========================================================
        # CONCATENATE
        # ========================================================

        x = np.concatenate(
            all_x,
            axis=0,
        ).astype(
            np.float32
        )


        node_type_ids = np.concatenate(
            all_node_types,
            axis=0,
        ).astype(
            np.int64
        )


        edge_index = np.asarray(
            [
                all_edge_sources,
                all_edge_targets,
            ],
            dtype=np.int64,
        )


        edge_type_ids = np.asarray(
            all_edge_types,
            dtype=np.int64,
        )


        # ========================================================
        # FINAL NUMERICAL VALIDATION
        # ========================================================

        if not np.isfinite(
            x
        ).all():

            raise RuntimeError(
                "Graph dataset contains NaN or infinity."
            )


        return {
            "dataset_version":
                self.DATASET_VERSION,

            "feature_schema_version":
                self.encoder.SCHEMA_VERSION,

            "feature_names":
                list(
                    self.encoder.FEATURE_NAMES
                ),

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
                    graph_ptr,
                    dtype=np.int64,
                ),

            "edge_ptr":
                np.asarray(
                    edge_ptr,
                    dtype=np.int64,
                ),

            "center_node_indices":
                np.asarray(
                    center_node_indices,
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

            "graph_count":
                len(
                    graph_ids
                ),

            "node_count":
                int(
                    x.shape[
                        0
                    ]
                ),

            "edge_count":
                int(
                    edge_index.shape[
                        1
                    ]
                ),
        }


    # ============================================================
    # SAVE DATASET
    # ============================================================

    def save_dataset(
        self,
        dataset,
        output_path=None,
    ):

        if output_path is None:

            output_path = (
                DEFAULT_OUTPUT_PATH
            )


        output_path = Path(
            output_path
        )


        output_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )


        np.savez_compressed(

            output_path,

            x=
                dataset[
                    "x"
                ],

            node_type_ids=
                dataset[
                    "node_type_ids"
                ],

            edge_index=
                dataset[
                    "edge_index"
                ],

            edge_type_ids=
                dataset[
                    "edge_type_ids"
                ],

            graph_ptr=
                dataset[
                    "graph_ptr"
                ],

            edge_ptr=
                dataset[
                    "edge_ptr"
                ],

            center_node_indices=
                dataset[
                    "center_node_indices"
                ],

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

            feature_names=
                np.asarray(
                    dataset[
                        "feature_names"
                    ],
                    dtype=str,
                ),
        )


        # ========================================================
        # MANIFEST
        # ========================================================

        manifest_path = (
            output_path.with_suffix(
                ".manifest.json"
            )
        )


        manifest = {

            "dataset_version":
                dataset[
                    "dataset_version"
                ],

            "feature_schema_version":
                dataset[
                    "feature_schema_version"
                ],

            "created_at":
                self.now_iso(),

            "graph_count":
                dataset[
                    "graph_count"
                ],

            "node_count":
                dataset[
                    "node_count"
                ],

            "edge_count":
                dataset[
                    "edge_count"
                ],

            "feature_count":
                self.encoder.FEATURE_COUNT,

            "feature_names":
                dataset[
                    "feature_names"
                ],

            "node_type_mapping":
                self.encoder.NODE_TYPE_IDS,

            "edge_type_mapping":
                self.service.EDGE_TYPE_IDS,

            "max_hops":
                self.max_hops,

            "include_event_nodes":
                self.include_event_nodes,

            "labels_available":
                False,

            "learning_mode":
                (
                    "SELF_SUPERVISED_"
                    "REPRESENTATION_LEARNING"
                ),

            "important_note":
                (
                    "No malicious/benign ground-truth "
                    "labels are assigned by this builder."
                ),
        }


        with open(
            manifest_path,
            "w",
            encoding="utf-8",
        ) as file:

            json.dump(
                manifest,
                file,
                indent=2,
                ensure_ascii=False,
            )


        return {
            "dataset_path":
                output_path,

            "manifest_path":
                manifest_path,
        }


    # ============================================================
    # BUILD + SAVE
    # ============================================================

    def build_and_save(
        self,
        process_queries=None,
        max_graphs=None,
        output_path=None,
    ):

        dataset = (
            self.build_dataset(

                process_queries=
                    process_queries,

                max_graphs=
                    max_graphs,
            )
        )


        paths = (
            self.save_dataset(

                dataset,

                output_path=
                    output_path,
            )
        )


        return {
            "dataset":
                dataset,

            **paths,
        }


    # ============================================================
    # CLOSE
    # ============================================================

    def close(
        self,
    ):

        self.service.close()