import networkx as nx
from datetime import datetime, timezone


class AttackGraphAgent:

    def __init__(self):

        self.name = "AttackGraphAgent"


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
    # SAFE LIST
    # ============================================================

    def safe_list(
        self,
        value,
    ) -> list:

        if isinstance(
            value,
            list,
        ):

            return value

        return []


    # ============================================================
    # SAFE DICT
    # ============================================================

    def safe_dict(
        self,
        value,
    ) -> dict:

        if isinstance(
            value,
            dict,
        ):

            return value

        return {}


    # ============================================================
    # PROCESS NODE ID
    # ============================================================

    def process_node_id(
        self,
        process: dict,
    ) -> str:

        pid = (
            process.get(
                "pid"
            )
        )

        name = (
            process.get(
                "name"
            )
            or "unknown"
        )

        return (
            f"PROCESS::{pid}::{name}"
        )


    # ============================================================
    # FILE NODE ID
    # ============================================================

    def file_node_id(
        self,
        file_item: dict,
    ) -> str:

        path = (
            file_item.get(
                "path"
            )
            or file_item.get(
                "name"
            )
            or "unknown"
        )

        return (
            f"FILE::{path}"
        )


    # ============================================================
    # NETWORK NODE ID
    # ============================================================

    def network_node_id(
        self,
        connection: dict,
    ) -> str:

        ip = (
            connection.get(
                "remote_ip"
            )
            or "unknown"
        )

        port = (
            connection.get(
                "remote_port"
            )
        )

        return (
            f"NETWORK::{ip}:{port}"
        )


    # ============================================================
    # REGISTRY NODE ID
    # ============================================================

    def registry_node_id(
        self,
        registry: dict,
    ) -> str:

        key = (
            registry.get(
                "key"
            )
            or "unknown"
        )

        value_name = (
            registry.get(
                "value_name"
            )
            or ""
        )

        return (
            f"REGISTRY::{key}::{value_name}"
        )


    # ============================================================
    # ADD PROCESS NODES
    # ============================================================

    def add_process_nodes(
        self,
        graph,
        processes,
    ):

        for process in processes:

            node_id = (
                self.process_node_id(
                    process
                )
            )

            graph.add_node(

                node_id,

                type="PROCESS",

                label=(
                    process.get(
                        "name"
                    )
                    or "Unknown Process"
                ),

                pid=(
                    process.get(
                        "pid"
                    )
                ),

                exe=(
                    process.get(
                        "exe"
                    )
                ),

                behavior_score=(
                    process.get(
                        "behavior_score"
                    )
                ),

                anomaly_score=(
                    process.get(
                        "anomaly_score"
                    )
                ),

                combined_threat_score=(
                    process.get(
                        "combined_threat_score"
                    )
                ),
            )


    # ============================================================
    # ADD FILE NODES
    # ============================================================

    def add_file_nodes(
        self,
        graph,
        files,
    ):

        for file_item in files:

            node_id = (
                self.file_node_id(
                    file_item
                )
            )

            graph.add_node(

                node_id,

                type="FILE",

                label=(
                    file_item.get(
                        "name"
                    )
                    or file_item.get(
                        "path"
                    )
                    or "Unknown File"
                ),

                path=(
                    file_item.get(
                        "path"
                    )
                ),

                sha256=(
                    file_item.get(
                        "sha256"
                    )
                ),

                malware_probability=(
                    file_item.get(
                        "malware_probability"
                    )
                ),

                static_risk_score=(
                    file_item.get(
                        "static_risk_score"
                    )
                ),
            )


    # ============================================================
    # ADD NETWORK NODES
    # ============================================================

    def add_network_nodes(
        self,
        graph,
        network_connections,
    ):

        for connection in network_connections:

            node_id = (
                self.network_node_id(
                    connection
                )
            )

            graph.add_node(

                node_id,

                type="NETWORK",

                label=(
                    f"{connection.get('remote_ip')}:{connection.get('remote_port')}"
                ),

                remote_ip=(
                    connection.get(
                        "remote_ip"
                    )
                ),

                remote_port=(
                    connection.get(
                        "remote_port"
                    )
                ),

                protocol=(
                    connection.get(
                        "protocol"
                    )
                ),
            )


    # ============================================================
    # ADD REGISTRY NODES
    # ============================================================

    def add_registry_nodes(
        self,
        graph,
        registry_items,
    ):

        for registry in registry_items:

            node_id = (
                self.registry_node_id(
                    registry
                )
            )

            graph.add_node(

                node_id,

                type="REGISTRY",

                label=(
                    registry.get(
                        "key"
                    )
                    or "Unknown Registry"
                ),

                key=(
                    registry.get(
                        "key"
                    )
                ),

                value_name=(
                    registry.get(
                        "value_name"
                    )
                ),

                value_data=(
                    registry.get(
                        "value_data"
                    )
                ),
            )


    # ============================================================
    # FIND PROCESS NODE
    # ============================================================

    def find_process_node(
        self,
        graph,
        process_name=None,
        pid=None,
    ):

        for node_id, data in graph.nodes(
            data=True
        ):

            if (
                data.get(
                    "type"
                )
                != "PROCESS"
            ):

                continue


            if (
                pid is not None
                and data.get(
                    "pid"
                )
                == pid
            ):

                return node_id


            if (
                process_name
                and str(
                    data.get(
                        "label"
                    )
                    or ""
                ).lower()
                == str(
                    process_name
                ).lower()
            ):

                return node_id


        return None


    # ============================================================
    # FIND FILE NODE
    # ============================================================

    def find_file_node(
        self,
        graph,
        path=None,
    ):

        for node_id, data in graph.nodes(
            data=True
        ):

            if (
                data.get(
                    "type"
                )
                != "FILE"
            ):

                continue


            if (
                path
                and str(
                    data.get(
                        "path"
                    )
                    or ""
                ).lower()
                == str(
                    path
                ).lower()
            ):

                return node_id


        return None


    # ============================================================
    # FIND NETWORK NODE
    # ============================================================

    def find_network_node(
        self,
        graph,
        target=None,
    ):

        for node_id, data in graph.nodes(
            data=True
        ):

            if (
                data.get(
                    "type"
                )
                != "NETWORK"
            ):

                continue


            if (
                target
                and str(
                    data.get(
                        "remote_ip"
                    )
                    or ""
                )
                == str(
                    target
                )
            ):

                return node_id


        return None


    # ============================================================
    # FIND REGISTRY NODE
    # ============================================================

    def find_registry_node(
        self,
        graph,
        key=None,
    ):

        for node_id, data in graph.nodes(
            data=True
        ):

            if (
                data.get(
                    "type"
                )
                != "REGISTRY"
            ):

                continue


            if (
                key
                and str(
                    data.get(
                        "key"
                    )
                    or ""
                ).lower()
                == str(
                    key
                ).lower()
            ):

                return node_id


        return None


    # ============================================================
    # ADD RELATIONSHIP EDGES
    # ============================================================

    def add_relationship_edges(
        self,
        graph,
        relationships,
    ):

        for relationship in relationships:

            source_type = (
                relationship.get(
                    "source_type"
                )
            )

            target_type = (
                relationship.get(
                    "target_type"
                )
            )

            source = (
                relationship.get(
                    "source"
                )
            )

            target = (
                relationship.get(
                    "target"
                )
            )

            relation = (
                relationship.get(
                    "relationship"
                )
                or "RELATED_TO"
            )

            confidence = (
                relationship.get(
                    "confidence",
                    0,
                )
            )


            source_node = None

            target_node = None


            # ----------------------------------------------------
            # SOURCE NODE
            # ----------------------------------------------------

            if source_type == "PROCESS":

                source_node = (
                    self.find_process_node(
                        graph,
                        process_name=source,
                    )
                )


            elif source_type == "FILE":

                source_node = (
                    self.find_file_node(
                        graph,
                        path=source,
                    )
                )


            elif source_type == "REGISTRY":

                source_node = (
                    self.find_registry_node(
                        graph,
                        key=source,
                    )
                )


            # ----------------------------------------------------
            # TARGET NODE
            # ----------------------------------------------------

            if target_type == "PROCESS":

                target_node = (
                    self.find_process_node(
                        graph,
                        process_name=target,
                    )
                )


            elif target_type == "FILE":

                target_node = (
                    self.find_file_node(
                        graph,
                        path=target,
                    )
                )


            elif target_type == "NETWORK":

                target_node = (
                    self.find_network_node(
                        graph,
                        target=target,
                    )
                )


            elif target_type == "REGISTRY":

                target_node = (
                    self.find_registry_node(
                        graph,
                        key=target,
                    )
                )


            # ----------------------------------------------------
            # ADD EDGE
            # ----------------------------------------------------

            if (
                source_node
                and target_node
            ):

                graph.add_edge(

                    source_node,

                    target_node,

                    relationship=relation,

                    confidence=confidence,
                )


    # ============================================================
    # BUILD GRAPH
    # ============================================================

    def build_graph(
        self,
        enriched_evidence: dict,
    ):

        graph = (
            nx.DiGraph()
        )


        processes = (
            self.safe_list(
                enriched_evidence.get(
                    "processes"
                )
            )
        )

        files = (
            self.safe_list(
                enriched_evidence.get(
                    "files"
                )
            )
        )

        network_connections = (
            self.safe_list(
                enriched_evidence.get(
                    "network_connections"
                )
            )
        )

        registry_items = (
            self.safe_list(
                enriched_evidence.get(
                    "registry_artifacts"
                )
            )
        )

        relationships = (
            self.safe_list(
                enriched_evidence.get(
                    "relationships"
                )
            )
        )


        # --------------------------------------------------------
        # ADD NODES
        # --------------------------------------------------------

        self.add_process_nodes(
            graph,
            processes,
        )

        self.add_file_nodes(
            graph,
            files,
        )

        self.add_network_nodes(
            graph,
            network_connections,
        )

        self.add_registry_nodes(
            graph,
            registry_items,
        )


        # --------------------------------------------------------
        # ADD EDGES
        # --------------------------------------------------------

        self.add_relationship_edges(
            graph,
            relationships,
        )


        return graph


    # ============================================================
    # EXPORT GRAPH TO DICTIONARY
    # ============================================================

    def export_graph(
        self,
        graph,
    ) -> dict:

        nodes = []

        edges = []


        for node_id, data in graph.nodes(
            data=True
        ):

            node = {

                "id":
                    node_id,

                **data,
            }

            nodes.append(
                node
            )


        for source, target, data in graph.edges(
            data=True
        ):

            edge = {

                "source":
                    source,

                "target":
                    target,

                **data,
            }

            edges.append(
                edge
            )


        return {

            "nodes":
                nodes,

            "edges":
                edges,

            "node_count":
                graph.number_of_nodes(),

            "edge_count":
                graph.number_of_edges(),
        }


    # ============================================================
    # GRAPH SUMMARY
    # ============================================================

    def summarize_graph(
        self,
        graph,
    ) -> dict:

        type_counts = {

            "PROCESS":
                0,

            "FILE":
                0,

            "NETWORK":
                0,

            "REGISTRY":
                0,
        }


        for _, data in graph.nodes(
            data=True
        ):

            node_type = (
                data.get(
                    "type"
                )
            )


            if node_type in type_counts:

                type_counts[
                    node_type
                ] += 1


        return {

            "nodes":
                graph.number_of_nodes(),

            "edges":
                graph.number_of_edges(),

            "node_types":
                type_counts,
        }


    # ============================================================
    # GENERATE ATTACK GRAPH
    # ============================================================

    def generate(
        self,
        enriched_evidence: dict,
    ) -> dict:

        enriched_evidence = (
            self.safe_dict(
                enriched_evidence
            )
        )


        graph = (
            self.build_graph(
                enriched_evidence
            )
        )


        exported = (
            self.export_graph(
                graph
            )
        )


        summary = (
            self.summarize_graph(
                graph
            )
        )


        return {

            "incident_id":
                enriched_evidence.get(
                    "incident_id"
                ),

            "agent":
                self.name,

            "generated_at":
                self.now_iso(),

            "graph":
                exported,

            "summary":
                summary,
        }