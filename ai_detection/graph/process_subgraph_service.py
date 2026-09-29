from __future__ import annotations

import json

from collections import deque
from pathlib import Path
from typing import (
    Any,
    Dict,
    List,
    Optional,
    Set,
)


from ai_detection.graph.provenance_graph_store import (
    ProvenanceGraphStore,
)


# ================================================================
# SENTINEL-X PROCESS SUBGRAPH SERVICE
#
# PURPOSE
# -------
#
# Given a process PID:
#
#       Process
#          |
#          +---- parent / children
#          |
#          +---- files
#          |
#          +---- network endpoints
#          |
#          +---- registry keys
#          |
#          +---- SecurityEvents
#
# the service extracts the local provenance neighborhood.
#
#
# This is the bridge between:
#
#       Persistent Provenance Graph
#
# and later:
#
#       GNN / GAT / Temporal Graph AI
#
#
# IMPORTANT
# ---------
#
# Graph traversal is UNDIRECTED for neighborhood discovery.
#
# Example:
#
# EVENT -> PROCESS
#
# Even though the stored edge direction is EVENT -> PROCESS,
# starting from the PROCESS should still discover that EVENT.
#
# The exported edges themselves retain their original direction.
# ================================================================


class ProcessSubgraphService:

    # ============================================================
    # NODE TYPE IDs
    #
    # These IDs are stable and can later be reused by the
    # Graph-AI dataset builder.
    # ============================================================

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


    # ============================================================
    # EDGE TYPE IDs
    # ============================================================

    EDGE_TYPE_IDS = {

        "OBSERVED_PROCESS":
            0,

        "SPAWNED":
            1,

        "OBSERVED_FILE":
            2,

        "TOUCHED_FILE":
            3,

        "OBSERVED_NETWORK":
            4,

        "CONNECTED_TO":
            5,

        "OBSERVED_REGISTRY":
            6,

        "MODIFIED_REGISTRY":
            7,
    }


    # ============================================================
    # INITIALIZATION
    # ============================================================

    def __init__(
        self,
        database_path=None,
        store: Optional[
            ProvenanceGraphStore
        ] = None,
    ):

        if store is not None:

            self.store = (
                store
            )

        else:

            self.store = (
                ProvenanceGraphStore(
                    database_path=
                        database_path
                )
            )


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
    # NORMALIZE TEXT
    # ============================================================

    def normalize_text(
        self,
        value,
    ) -> str:

        if value is None:

            return ""


        return (
            str(
                value
            )
            .strip()
        )


    # ============================================================
    # FIND PROCESS
    #
    # PID is the main identifier.
    #
    # Optional:
    #
    #       device_id
    #       process_name
    #
    # are used to narrow the match.
    #
    # If more than one candidate exists, the most recently seen
    # process node is selected.
    # ============================================================

    def find_process(
        self,
        *,
        pid,
        device_id: Optional[str] = None,
        process_name: Optional[str] = None,
    ) -> Optional[
        Dict[str, Any]
    ]:

        nodes = (
            self.store.get_nodes(
                limit=100000
            )
        )


        candidates = []


        for node in nodes:

            if (
                node.get(
                    "node_type"
                )
                != "PROCESS"
            ):

                continue


            properties = (
                self.safe_dict(
                    node.get(
                        "properties"
                    )
                )
            )


            stored_pid = (
                properties.get(
                    "pid"
                )
            )


            if (
                str(
                    stored_pid
                )
                !=
                str(
                    pid
                )
            ):

                continue


            # ====================================================
            # OPTIONAL DEVICE FILTER
            # ====================================================

            if device_id:

                stored_device = (
                    self.normalize_text(

                        properties.get(
                            "device_id"
                        )
                    )
                    .lower()
                )


                if (
                    stored_device

                    !=

                    self.normalize_text(
                        device_id
                    ).lower()
                ):

                    continue


            # ====================================================
            # OPTIONAL PROCESS NAME FILTER
            # ====================================================

            if process_name:

                stored_name = (
                    self.normalize_text(

                        properties.get(
                            "name"
                        )

                        or

                        node.get(
                            "label"
                        )
                    )
                    .lower()
                )


                expected_name = (
                    self.normalize_text(
                        process_name
                    )
                    .lower()
                )


                if (
                    stored_name
                    != expected_name
                ):

                    continue


            candidates.append(
                node
            )


        if not candidates:

            return None


        # ========================================================
        # NEWEST PROCESS NODE
        # ========================================================

        candidates.sort(

            key=lambda item:
                self.normalize_text(
                    item.get(
                        "last_seen"
                    )
                ),

            reverse=True,
        )


        return (
            candidates[
                0
            ]
        )


    # ============================================================
    # BUILD NODE MAP
    # ============================================================

    def build_node_map(
        self,
    ) -> Dict[
        str,
        Dict[str, Any],
    ]:

        nodes = (
            self.store.get_nodes(
                limit=100000
            )
        )


        return {

            node[
                "node_id"
            ]:
                node

            for node in nodes

            if node.get(
                "node_id"
            )
        }


    # ============================================================
    # BUILD EDGE LIST
    # ============================================================

    def build_edge_list(
        self,
    ) -> List[
        Dict[str, Any]
    ]:

        return (
            self.store.get_edges(
                limit=200000
            )
        )


    # ============================================================
    # BUILD UNDIRECTED ADJACENCY
    #
    # Used only for neighborhood discovery.
    #
    # Stored graph direction remains unchanged.
    # ============================================================

    def build_adjacency(
        self,
        edges: List[
            Dict[str, Any]
        ],
    ) -> Dict[
        str,
        Set[str],
    ]:

        adjacency = {}


        for edge in edges:

            source = (
                edge.get(
                    "source_node_id"
                )
            )


            target = (
                edge.get(
                    "target_node_id"
                )
            )


            if not source or not target:

                continue


            adjacency.setdefault(
                source,
                set(),
            ).add(
                target
            )


            adjacency.setdefault(
                target,
                set(),
            ).add(
                source
            )


        return adjacency


    # ============================================================
    # BFS NEIGHBORHOOD
    # ============================================================

    def discover_neighborhood(
        self,
        *,
        center_node_id: str,
        adjacency: Dict[
            str,
            Set[str],
        ],
        max_hops: int,
    ):

        if max_hops < 0:

            raise ValueError(
                "max_hops cannot be negative."
            )


        if max_hops > 5:

            raise ValueError(
                "max_hops cannot exceed 5 "
                "for process-centered queries."
            )


        distances = {
            center_node_id:
                0,
        }


        queue = deque(
            [
                center_node_id
            ]
        )


        while queue:

            current = (
                queue.popleft()
            )


            current_distance = (
                distances[
                    current
                ]
            )


            if (
                current_distance
                >= max_hops
            ):

                continue


            for neighbor in adjacency.get(
                current,
                set(),
            ):

                if neighbor in distances:

                    continue


                distances[
                    neighbor
                ] = (
                    current_distance
                    + 1
                )


                queue.append(
                    neighbor
                )


        return distances


    # ============================================================
    # SUBGRAPH SUMMARY
    # ============================================================

    def build_summary(
        self,
        nodes,
        edges,
    ):

        node_types = {}

        edge_types = {}


        for node in nodes:

            node_type = (
                node.get(
                    "node_type"
                )
                or
                "UNKNOWN"
            )


            node_types[
                node_type
            ] = (
                node_types.get(
                    node_type,
                    0,
                )
                + 1
            )


        for edge in edges:

            edge_type = (
                edge.get(
                    "edge_type"
                )
                or
                "UNKNOWN"
            )


            edge_types[
                edge_type
            ] = (
                edge_types.get(
                    edge_type,
                    0,
                )
                + 1
            )


        return {
            "node_count":
                len(
                    nodes
                ),

            "edge_count":
                len(
                    edges
                ),

            "node_types":
                node_types,

            "edge_types":
                edge_types,
        }


    # ============================================================
    # GET PROCESS SUBGRAPH
    # ============================================================

    def get_process_subgraph(
        self,
        *,
        pid,
        device_id: Optional[str] = None,
        process_name: Optional[str] = None,
        max_hops: int = 2,
        include_event_nodes: bool = True,
    ) -> Dict[str, Any]:

        # ========================================================
        # RESOLVE PROCESS
        # ========================================================

        process_node = (
            self.find_process(

                pid=
                    pid,

                device_id=
                    device_id,

                process_name=
                    process_name,
            )
        )


        if process_node is None:

            return {
                "found":
                    False,

                "pid":
                    pid,

                "device_id":
                    device_id,

                "process_name":
                    process_name,

                "max_hops":
                    max_hops,

                "center_node":
                    None,

                "nodes":
                    [],

                "edges":
                    [],

                "summary": {
                    "node_count":
                        0,

                    "edge_count":
                        0,

                    "node_types":
                        {},

                    "edge_types":
                        {},
                },
            }


        center_node_id = (
            process_node[
                "node_id"
            ]
        )


        # ========================================================
        # LOAD GRAPH
        # ========================================================

        node_map = (
            self.build_node_map()
        )


        all_edges = (
            self.build_edge_list()
        )


        adjacency = (
            self.build_adjacency(
                all_edges
            )
        )


        # ========================================================
        # DISCOVER NEIGHBORHOOD
        # ========================================================

        distances = (
            self.discover_neighborhood(

                center_node_id=
                    center_node_id,

                adjacency=
                    adjacency,

                max_hops=
                    max_hops,
            )
        )


        selected_ids = set(
            distances.keys()
        )


        # ========================================================
        # OPTIONAL EVENT FILTER
        # ========================================================

        if not include_event_nodes:

            selected_ids = {

                node_id

                for node_id
                in selected_ids

                if (
                    node_map.get(
                        node_id,
                        {}
                    ).get(
                        "node_type"
                    )
                    != "EVENT"
                )
            }


        # ========================================================
        # SELECT NODES
        # ========================================================

        selected_nodes = []


        for node_id in selected_ids:

            node = (
                node_map.get(
                    node_id
                )
            )


            if node is None:

                continue


            exported_node = dict(
                node
            )


            exported_node[
                "hop_distance"
            ] = (
                distances.get(
                    node_id
                )
            )


            selected_nodes.append(
                exported_node
            )


        # ========================================================
        # SORT NODES
        #
        # center first,
        # then closest neighbors,
        # then stable node ID.
        # ========================================================

        selected_nodes.sort(

            key=lambda node: (

                node.get(
                    "hop_distance",
                    999,
                ),

                node.get(
                    "node_type",
                    "",
                ),

                node.get(
                    "node_id",
                    "",
                ),
            )
        )


        # ========================================================
        # SELECT EDGES
        # ========================================================

        selected_edges = [

            edge

            for edge in all_edges

            if (
                edge.get(
                    "source_node_id"
                )
                in selected_ids

                and

                edge.get(
                    "target_node_id"
                )
                in selected_ids
            )
        ]


        selected_edges.sort(

            key=lambda edge: (

                edge.get(
                    "edge_type",
                    "",
                ),

                edge.get(
                    "edge_id",
                    "",
                ),
            )
        )


        # ========================================================
        # SUMMARY
        # ========================================================

        summary = (
            self.build_summary(
                selected_nodes,
                selected_edges,
            )
        )


        # ========================================================
        # PROCESS METADATA
        # ========================================================

        process_properties = (
            self.safe_dict(
                process_node.get(
                    "properties"
                )
            )
        )


        return {
            "found":
                True,

            "pid":
                process_properties.get(
                    "pid"
                ),

            "process_name":
                (
                    process_properties.get(
                        "name"
                    )

                    or

                    process_node.get(
                        "label"
                    )
                ),

            "device_id":
                process_properties.get(
                    "device_id"
                ),

            "max_hops":
                max_hops,

            "include_event_nodes":
                include_event_nodes,

            "center_node_id":
                center_node_id,

            "center_node":
                process_node,

            "nodes":
                selected_nodes,

            "edges":
                selected_edges,

            "summary":
                summary,
        }


    # ============================================================
    # GNN STRUCTURAL EXPORT
    #
    # This does NOT create ML features yet.
    #
    # It only converts the topology into:
    #
    #   node_index
    #   node_type_ids
    #   edge_index
    #   edge_type_ids
    #
    # Actual numerical features come in the next Graph-AI step.
    # ============================================================

    def export_gnn_structure(
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

                "node_index":
                    {},

                "node_ids":
                    [],

                "node_type_ids":
                    [],

                "edge_index":
                    [
                        [],
                        [],
                    ],

                "edge_type_ids":
                    [],
            }


        nodes = (
            subgraph.get(
                "nodes",
                [],
            )
        )


        edges = (
            subgraph.get(
                "edges",
                [],
            )
        )


        # ========================================================
        # NODE INDEX
        # ========================================================

        node_index = {

            node[
                "node_id"
            ]:
                index

            for (
                index,
                node,
            )
            in enumerate(
                nodes
            )
        }


        node_ids = [

            node[
                "node_id"
            ]

            for node in nodes
        ]


        # ========================================================
        # NODE TYPES
        # ========================================================

        node_type_ids = []


        for node in nodes:

            node_type = (
                node.get(
                    "node_type",
                    "UNKNOWN",
                )
            )


            node_type_ids.append(

                self.NODE_TYPE_IDS.get(
                    node_type,
                    -1,
                )
            )


        # ========================================================
        # EDGE INDEX
        #
        # PyTorch-Geometric style:
        #
        # [
        #   [source indices],
        #   [target indices]
        # ]
        # ========================================================

        edge_sources = []

        edge_targets = []

        edge_type_ids = []


        for edge in edges:

            source = (
                edge.get(
                    "source_node_id"
                )
            )


            target = (
                edge.get(
                    "target_node_id"
                )
            )


            if (
                source not in node_index

                or

                target not in node_index
            ):

                continue


            edge_sources.append(
                node_index[
                    source
                ]
            )


            edge_targets.append(
                node_index[
                    target
                ]
            )


            edge_type_ids.append(

                self.EDGE_TYPE_IDS.get(

                    edge.get(
                        "edge_type",
                        "",
                    ),

                    -1,
                )
            )


        center_index = (
            node_index.get(
                subgraph.get(
                    "center_node_id"
                )
            )
        )


        return {
            "found":
                True,

            "pid":
                subgraph.get(
                    "pid"
                ),

            "process_name":
                subgraph.get(
                    "process_name"
                ),

            "center_node_id":
                subgraph.get(
                    "center_node_id"
                ),

            "center_node_index":
                center_index,

            "node_index":
                node_index,

            "node_ids":
                node_ids,

            "node_type_ids":
                node_type_ids,

            "edge_index": [
                edge_sources,
                edge_targets,
            ],

            "edge_type_ids":
                edge_type_ids,

            "node_type_mapping":
                dict(
                    self.NODE_TYPE_IDS
                ),

            "edge_type_mapping":
                dict(
                    self.EDGE_TYPE_IDS
                ),

            "node_count":
                len(
                    node_ids
                ),

            "edge_count":
                len(
                    edge_type_ids
                ),
        }


    # ============================================================
    # EXPORT TO JSON
    # ============================================================

    def save_subgraph_json(
        self,
        *,
        subgraph: Dict[str, Any],
        output_path,
    ) -> Path:

        output_path = Path(
            output_path
        )


        output_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )


        with open(
            output_path,
            "w",
            encoding="utf-8",
        ) as file:

            json.dump(
                subgraph,
                file,
                indent=2,
                ensure_ascii=False,
                default=str,
            )


        return output_path


    # ============================================================
    # CLOSE
    # ============================================================

    def close(
        self,
    ) -> None:

        self.store.close()