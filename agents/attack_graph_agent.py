
import networkx as nx

from datetime import datetime, timezone


class AttackGraphAgent:

    def __init__(self):
        self.name = "AttackGraphAgent"

    # ============================================================
    # CURRENT TIME
    # ============================================================

    def now_iso(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    # ============================================================
    # SAFE HELPERS
    # ============================================================

    def safe_list(self, value) -> list:
        return value if isinstance(value, list) else []

    def safe_dict(self, value) -> dict:
        return value if isinstance(value, dict) else {}

    def valid_pid(self, value) -> bool:
        try:
            if value is None or isinstance(value, bool):
                return False

            pid = int(value)

            return pid > 0 and pid != 4

        except (TypeError, ValueError, OverflowError):
            return False

    def explicit_device(self, item) -> str:
        item = self.safe_dict(item)

        return str(
            item.get("device_id") or ""
        ).strip()

    # ============================================================
    # PROCESS NODE ID
    # ============================================================

    def process_node_id(self, process: dict) -> str:
        process = self.safe_dict(process)

        device = self.explicit_device(process)
        pid = process.get("pid")

        create_time = (
            process.get("create_time")
            or process.get("process_create_time")
        )

        if (
            device
            and self.valid_pid(pid)
            and create_time is not None
            and str(create_time).strip()
        ):
            return (
                f"PROCESS::{device}::"
                f"{int(pid)}::{create_time}"
            )

        # Incomplete identity: this is a display hint,
        # not a unique process identity.
        name = process.get("name") or "unknown"

        return (
            f"PROCESS::UNSCOPED::{pid}::{name}"
        )

    # ============================================================
    # FILE NODE ID
    # ============================================================

    def file_node_id(self, file_item: dict) -> str:
        file_item = self.safe_dict(file_item)

        device = self.explicit_device(file_item)

        path = (
            file_item.get("path")
            or file_item.get("name")
            or "unknown"
        )

        if device:
            return f"FILE::{device}::{path}"

        return f"FILE::{path}"

    # ============================================================
    # NETWORK NODE ID
    # ============================================================

    def network_node_id(self, connection: dict) -> str:
        connection = self.safe_dict(connection)

        device = self.explicit_device(connection)

        ip = (
            connection.get("remote_ip")
            or "unknown"
        )

        port = connection.get("remote_port")
        protocol = connection.get("protocol") or ""

        if device:
            return (
                f"NETWORK::{device}::"
                f"{ip}:{port}::{protocol}"
            )

        return f"NETWORK::{ip}:{port}::{protocol}"

    # ============================================================
    # REGISTRY NODE ID
    # ============================================================

    def registry_node_id(self, registry: dict) -> str:
        registry = self.safe_dict(registry)

        device = self.explicit_device(registry)

        key = registry.get("key") or "unknown"
        value_name = registry.get("value_name") or ""

        if device:
            return (
                f"REGISTRY::{device}::"
                f"{key}::{value_name}"
            )

        return f"REGISTRY::{key}::{value_name}"

    # ============================================================
    # ADD PROCESS NODES
    # ============================================================

    def add_process_nodes(
        self,
        graph,
        processes,
    ):
        for index, raw in enumerate(
            self.safe_list(processes)
        ):
            process = self.safe_dict(raw)

            if not process:
                continue

            node_id = self.process_node_id(process)

            device = self.explicit_device(process)
            create_time = (
                process.get("create_time")
                or process.get("process_create_time")
            )

            complete_identity = (
                bool(device)
                and self.valid_pid(
                    process.get("pid")
                )
                and create_time is not None
                and bool(str(create_time).strip())
            )

            if not complete_identity:
                # Avoid joining distinct records because
                # they reused a PID or process name.
                node_id = (
                    f"{node_id}::OBS::{index}"
                )

            graph.add_node(
                node_id,
                type="PROCESS",
                label=(
                    process.get("name")
                    or "Unknown Process"
                ),
                pid=process.get("pid"),
                exe=process.get("exe"),
                device_id=device or None,
                process_create_time=create_time,
                identity_complete=complete_identity,
                identity_verified=False,
                behavior_score=process.get(
                    "behavior_score"
                ),
                anomaly_score=process.get(
                    "anomaly_score"
                ),
                combined_threat_score=process.get(
                    "combined_threat_score"
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
        for index, raw in enumerate(
            self.safe_list(files)
        ):
            file_item = self.safe_dict(raw)

            if not file_item:
                continue

            node_id = self.file_node_id(file_item)

            if not self.explicit_device(file_item):
                node_id += f"::OBS::{index}"

            graph.add_node(
                node_id,
                type="FILE",
                label=(
                    file_item.get("name")
                    or file_item.get("path")
                    or "Unknown File"
                ),
                path=file_item.get("path"),
                sha256=file_item.get("sha256"),
                device_id=(
                    self.explicit_device(file_item)
                    or None
                ),
                malware_probability=file_item.get(
                    "malware_probability"
                ),
                malware_model_authoritative=False,
                static_risk_score=file_item.get(
                    "static_risk_score"
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
        for index, raw in enumerate(
            self.safe_list(network_connections)
        ):
            connection = self.safe_dict(raw)

            if not connection:
                continue

            node_id = self.network_node_id(
                connection
            )

            if not self.explicit_device(connection):
                node_id += f"::OBS::{index}"

            graph.add_node(
                node_id,
                type="NETWORK",
                label=(
                    f"{connection.get('remote_ip')}:"
                    f"{connection.get('remote_port')}"
                ),
                remote_ip=connection.get(
                    "remote_ip"
                ),
                remote_port=connection.get(
                    "remote_port"
                ),
                protocol=connection.get("protocol"),
                pid=connection.get("pid"),
                device_id=(
                    self.explicit_device(connection)
                    or None
                ),
                identity_verified=False,
            )

    # ============================================================
    # ADD REGISTRY NODES
    # ============================================================

    def add_registry_nodes(
        self,
        graph,
        registry_items,
    ):
        for index, raw in enumerate(
            self.safe_list(registry_items)
        ):
            registry = self.safe_dict(raw)

            if not registry:
                continue

            node_id = self.registry_node_id(
                registry
            )

            if not self.explicit_device(registry):
                node_id += f"::OBS::{index}"

            graph.add_node(
                node_id,
                type="REGISTRY",
                label=(
                    registry.get("key")
                    or "Unknown Registry"
                ),
                key=registry.get("key"),
                value_name=registry.get(
                    "value_name"
                ),
                value_data=registry.get(
                    "value_data"
                ),
                device_id=(
                    self.explicit_device(registry)
                    or None
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
        candidates = []

        for node_id, data in graph.nodes(
            data=True
        ):
            if data.get("type") != "PROCESS":
                continue

            if pid is not None:
                if not self.valid_pid(pid):
                    return None

                if data.get("pid") != pid:
                    continue

            if process_name:
                if str(
                    data.get("label") or ""
                ).lower() != str(
                    process_name
                ).lower():
                    continue

            if pid is None and not process_name:
                continue

            candidates.append(node_id)

        # Never silently select the first process
        # when multiple records match.
        if len(candidates) == 1:
            return candidates[0]

        return None

    # ============================================================
    # FIND FILE NODE
    # ============================================================

    def find_file_node(
        self,
        graph,
        path=None,
    ):
        if not path:
            return None

        candidates = []

        for node_id, data in graph.nodes(
            data=True
        ):
            if data.get("type") != "FILE":
                continue

            if str(
                data.get("path") or ""
            ).lower() == str(path).lower():
                candidates.append(node_id)

        return (
            candidates[0]
            if len(candidates) == 1
            else None
        )

    # ============================================================
    # FIND NETWORK NODE
    # ============================================================

    def find_network_node(
        self,
        graph,
        target=None,
    ):
        if not target:
            return None

        candidates = []

        for node_id, data in graph.nodes(
            data=True
        ):
            if data.get("type") != "NETWORK":
                continue

            if str(
                data.get("remote_ip") or ""
            ) == str(target):
                candidates.append(node_id)

        # Same IP on several endpoints is ambiguous.
        return (
            candidates[0]
            if len(candidates) == 1
            else None
        )

    # ============================================================
    # FIND REGISTRY NODE
    # ============================================================

    def find_registry_node(
        self,
        graph,
        key=None,
    ):
        if not key:
            return None

        candidates = []

        for node_id, data in graph.nodes(
            data=True
        ):
            if data.get("type") != "REGISTRY":
                continue

            if str(
                data.get("key") or ""
            ).lower() == str(key).lower():
                candidates.append(node_id)

        return (
            candidates[0]
            if len(candidates) == 1
            else None
        )

    # ============================================================
    # ADD INFERRED RELATIONSHIP EDGES
    # ============================================================

    def add_relationship_edges(
        self,
        graph,
        relationships,
    ):
        for raw in self.safe_list(relationships):
            relationship = self.safe_dict(raw)

            if not relationship:
                continue

            source_type = str(
                relationship.get("source_type")
                or ""
            ).upper()

            target_type = str(
                relationship.get("target_type")
                or ""
            ).upper()

            source = relationship.get("source")
            target = relationship.get("target")

            relation = (
                relationship.get("relationship")
                or "RELATED_TO"
            )

            # Important:
            # The old builder linked process -> network
            # using PID alone, sometimes even PID 0.
            # Do not create an attribution edge from it.
            # Valid identity-link observations are handled
            # separately below.
            if (
                source_type == "PROCESS"
                and target_type == "NETWORK"
            ):
                continue

            source_node = None
            target_node = None

            # ----------------------------------------------------
            # SOURCE NODE
            # ----------------------------------------------------

            if source_type == "PROCESS":
                source_node = self.find_process_node(
                    graph,
                    process_name=source,
                )

            elif source_type == "FILE":
                source_node = self.find_file_node(
                    graph,
                    path=source,
                )

            elif source_type == "REGISTRY":
                source_node = self.find_registry_node(
                    graph,
                    key=source,
                )

            # ----------------------------------------------------
            # TARGET NODE
            # ----------------------------------------------------

            if target_type == "PROCESS":
                target_node = self.find_process_node(
                    graph,
                    process_name=target,
                )

            elif target_type == "FILE":
                target_node = self.find_file_node(
                    graph,
                    path=target,
                )

            elif target_type == "NETWORK":
                target_node = self.find_network_node(
                    graph,
                    target=target,
                )

            elif target_type == "REGISTRY":
                target_node = self.find_registry_node(
                    graph,
                    key=target,
                )

            if not source_node or not target_node:
                continue

            # Preserve multiple inferred labels without
            # overwriting an existing graph edge.
            if graph.has_edge(
                source_node,
                target_node,
            ):
                data = graph.edges[
                    source_node,
                    target_node
                ]

                labels = list(
                    data.get("relationships", [])
                )

                if relation not in labels:
                    labels.append(relation)

                data["relationships"] = labels
                continue

            graph.add_edge(
                source_node,
                target_node,
                relationship=relation,
                relationships=[relation],
                confidence=0,
                match_score=relationship.get(
                    "match_score",
                    relationship.get(
                        "confidence", 0
                    ),
                ),
                verified=False,
                provenance_status="INFERRED",
                requires_validation=True,
                source_event_id=relationship.get(
                    "source_event_id"
                ),
                target_event_id=relationship.get(
                    "target_event_id"
                ),
            )

    # ============================================================
    # ADD IDENTITY-LINK OBSERVATION EDGES
    # ============================================================

    def add_identity_link_edges(
        self,
        graph,
        identity_links,
    ):
        """
        Identity-linked edges connect event observations,
        not ambiguous historical aggregate entities.

        All such edges remain unverified.
        """

        for raw in self.safe_list(identity_links):
            link = self.safe_dict(raw)

            if not link:
                continue

            if link.get("identity_match") is not True:
                continue

            device = str(
                link.get("device_id") or ""
            ).strip()

            source_event = str(
                link.get("source_event_id") or ""
            ).strip()

            target_event = str(
                link.get("target_event_id") or ""
            ).strip()

            create_time = str(
                link.get("process_create_time")
                or ""
            ).strip()

            pid = link.get("pid")

            if not (
                device
                and source_event
                and target_event
                and create_time
            ):
                continue

            if source_event == target_event:
                continue

            if not self.valid_pid(pid):
                continue

            # Keep the event references in the ID to avoid
            # collapsing different observations of a PID.
            process_node = (
                f"PROCESS_EVENT::{device}::"
                f"{source_event}"
            )

            network_node = (
                f"NETWORK_EVENT::{device}::"
                f"{target_event}"
            )

            if graph.has_node(process_node):
                existing = graph.nodes[process_node]

                if (
                    existing.get("pid") != pid
                    or existing.get(
                        "process_create_time"
                    ) != create_time
                ):
                    continue

            if graph.has_node(network_node):
                existing = graph.nodes[network_node]

                if (
                    existing.get("pid") != pid
                    or existing.get(
                        "process_create_time"
                    ) != create_time
                ):
                    continue

            graph.add_node(
                process_node,
                type="PROCESS_OBSERVATION",
                label=(
                    link.get("process_name")
                    or "Process observation"
                ),
                event_id=source_event,
                device_id=device,
                pid=pid,
                process_create_time=create_time,
                identity_verified=False,
            )

            graph.add_node(
                network_node,
                type="NETWORK_OBSERVATION",
                label=(
                    f"{link.get('remote_ip')}:"
                    f"{link.get('remote_port')}"
                ),
                event_id=target_event,
                device_id=device,
                pid=pid,
                process_create_time=create_time,
                remote_ip=link.get("remote_ip"),
                remote_port=link.get(
                    "remote_port"
                ),
                identity_verified=False,
            )

            graph.add_edge(
                process_node,
                network_node,
                relationship="OBSERVED_CONNECTION",
                confidence=0,
                verified=False,
                identity_match=True,
                source_event_id=source_event,
                target_event_id=target_event,
                observation_gap_seconds=link.get(
                    "observation_gap_seconds"
                ),
                provenance_status=(
                    "MATCHED_IDENTIFIERS_UNVERIFIED"
                ),
                requires_validation=True,
            )

    # ============================================================
    # BUILD GRAPH
    # ============================================================

    def build_graph(
        self,
        enriched_evidence: dict,
    ):
        enriched_evidence = self.safe_dict(
            enriched_evidence
        )

        graph = nx.DiGraph()

        processes = self.safe_list(
            enriched_evidence.get("processes")
        )

        files = self.safe_list(
            enriched_evidence.get("files")
        )

        network_connections = self.safe_list(
            enriched_evidence.get(
                "network_connections"
            )
        )

        registry_items = self.safe_list(
            enriched_evidence.get(
                "registry_artifacts"
            )
        )

        relationships = self.safe_list(
            enriched_evidence.get(
                "relationships"
            )
        )

        identity_links = self.safe_list(
            enriched_evidence.get(
                "identity_links"
            )
        )

        self.add_process_nodes(
            graph, processes
        )

        self.add_file_nodes(
            graph, files
        )

        self.add_network_nodes(
            graph, network_connections
        )

        self.add_registry_nodes(
            graph, registry_items
        )

        self.add_relationship_edges(
            graph, relationships
        )

        self.add_identity_link_edges(
            graph, identity_links
        )

        return graph

    # ============================================================
    # EXPORT GRAPH TO DICTIONARY
    # ============================================================

    def export_graph(self, graph) -> dict:
        nodes = []
        edges = []

        for node_id, data in graph.nodes(
            data=True
        ):
            nodes.append({
                "id": node_id,
                **data,
            })

        for source, target, data in graph.edges(
            data=True
        ):
            edges.append({
                "source": source,
                "target": target,
                **data,
            })

        return {
            "nodes": nodes,
            "edges": edges,
            "node_count":
                graph.number_of_nodes(),
            "edge_count":
                graph.number_of_edges(),
        }

    # ============================================================
    # GRAPH SUMMARY
    # ============================================================

    def summarize_graph(self, graph) -> dict:
        type_counts = {
            "PROCESS": 0,
            "FILE": 0,
            "NETWORK": 0,
            "REGISTRY": 0,
            "PROCESS_OBSERVATION": 0,
            "NETWORK_OBSERVATION": 0,
        }

        for _, data in graph.nodes(
            data=True
        ):
            node_type = data.get("type")

            if node_type in type_counts:
                type_counts[node_type] += 1

        inferred = 0
        identity_matched = 0
        verified = 0

        for _, _, data in graph.edges(
            data=True
        ):
            provenance = data.get(
                "provenance_status",
                "INFERRED",
            )

            if provenance == "INFERRED":
                inferred += 1

            elif provenance == (
                "MATCHED_IDENTIFIERS_UNVERIFIED"
            ):
                identity_matched += 1

            if data.get("verified") is True:
                # Do not trust externally supplied verified
                # flags here. All edges generated by this
                # implementation are unverified.
                verified += 1

        return {
            "nodes": graph.number_of_nodes(),
            "edges": graph.number_of_edges(),
            "node_types": type_counts,
            "inferred_edge_count": inferred,
            "identity_matched_edge_count":
                identity_matched,
            "verified_relationship_count":
                verified,
        }

    # ============================================================
    # GENERATE ATTACK GRAPH
    # ============================================================

    def generate(
        self,
        enriched_evidence: dict,
    ) -> dict:
        enriched_evidence = self.safe_dict(
            enriched_evidence
        )

        graph = self.build_graph(
            enriched_evidence
        )

        exported = self.export_graph(
            graph
        )

        summary = self.summarize_graph(
            graph
        )

        identity_links = self.safe_list(
            enriched_evidence.get(
                "identity_links"
            )
        )

        summary["identity_link_count"] = len(
            identity_links
        )

        # No relationship is independently authenticated
        # by this graph construction stage.
        summary["verified_relationship_count"] = 0

        return {
            "incident_id":
                enriched_evidence.get(
                    "incident_id"
                ),
            "agent": self.name,
            "generated_at": self.now_iso(),
            "graph": exported,
            "summary": summary,

            # Preserve the candidate evidence separately
            # for the AI Investigation page.
            "identity_links": identity_links,
            "provenance_policy":
                "UNVERIFIED_GRAPH_V2",
        }
