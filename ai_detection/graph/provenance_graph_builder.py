from __future__ import annotations

import hashlib
import os

from typing import (
    Any,
    Dict,
    Optional,
)


from ai_detection.graph.provenance_graph_store import (
    ProvenanceGraphStore,
)


# ================================================================
# SENTINEL-X PROVENANCE GRAPH BUILDER
#
# Converts SecurityEvent dictionaries into a persistent graph.
#
# NODE TYPES
# ----------
# EVENT
# PROCESS
# FILE
# NETWORK_ENDPOINT
# REGISTRY
#
# EDGE TYPES
# ----------
# OBSERVED_PROCESS
# SPAWNED
# OBSERVED_FILE
# TOUCHED_FILE
# OBSERVED_NETWORK
# CONNECTED_TO
# OBSERVED_REGISTRY
# MODIFIED_REGISTRY
#
# ================================================================


class ProvenanceGraphBuilder:

    # ============================================================
    # INITIALIZATION
    #
    # IMPORTANT:
    #
    # database_path is intentionally supported because tests can
    # use an isolated temporary SQLite database.
    #
    # Production code may omit database_path and use the default
    # sentinel_endpoint.db handled by ProvenanceGraphStore.
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
    # HASHED NODE ID
    # ============================================================

    def hashed_node_id(
        self,
        node_type: str,
        identity: str,
    ) -> str:

        digest = (
            hashlib.sha256(

                identity.encode(
                    "utf-8",
                    errors="ignore",
                )

            )
            .hexdigest()
            [:24]
        )


        return (
            f"{node_type}:{digest}"
        )


    # ============================================================
    # DEVICE ID
    # ============================================================

    def get_device_id(
        self,
        event: Dict[str, Any],
    ) -> str:

        metadata = (
            self.safe_dict(
                event.get(
                    "metadata"
                )
            )
        )


        return (
            self.normalize_text(

                event.get(
                    "device_id"
                )

                or

                metadata.get(
                    "device_id"
                )

                or

                "local-device"
            )
        )


    # ============================================================
    # EVENT NODE ID
    # ============================================================

    def event_node_id(
        self,
        event: Dict[str, Any],
    ) -> str:

        event_id = (
            self.normalize_text(
                event.get(
                    "event_id"
                )
            )
        )


        if not event_id:

            raise ValueError(
                "SecurityEvent requires event_id."
            )


        return (
            self.hashed_node_id(
                "EVENT",
                event_id,
            )
        )


    # ============================================================
    # PROCESS IDENTITY
    #
    # For the current provenance foundation PID + name + device are
    # used as the stable identity.
    #
    # This allows:
    #
    # process event
    #       PID 42420
    #
    # and later network event
    #       PID 42420
    #
    # to resolve to the SAME process node.
    #
    # Later Graph-v2 can strengthen this with create_time/session ID.
    # ============================================================

    def process_node_id(
        self,
        *,
        process: Dict[str, Any],
        device_id: str,
    ) -> str:

        pid = (
            process.get(
                "pid"
            )
        )


        name = (
            self.normalize_text(

                process.get(
                    "name"
                )

                or

                process.get(
                    "process_name"
                )

                or

                "unknown"
            )
            .lower()
        )


        identity = (
            f"{device_id.lower()}|"
            f"{pid}|"
            f"{name}"
        )


        return (
            self.hashed_node_id(
                "PROCESS",
                identity,
            )
        )


    # ============================================================
    # FILE NODE ID
    # ============================================================

    def file_node_id(
        self,
        *,
        file_data: Dict[str, Any],
        device_id: str,
    ) -> str:

        path = (
            self.normalize_text(

                file_data.get(
                    "path"
                )

                or

                file_data.get(
                    "file_path"
                )

                or

                file_data.get(
                    "name"
                )

                or

                "unknown-file"
            )
        )


        normalized_path = (
            os.path.normcase(
                os.path.normpath(
                    path
                )
            )
        )


        identity = (
            f"{device_id.lower()}|"
            f"{normalized_path.lower()}"
        )


        return (
            self.hashed_node_id(
                "FILE",
                identity,
            )
        )


    # ============================================================
    # NETWORK ENDPOINT NODE ID
    # ============================================================

    def network_node_id(
        self,
        network: Dict[str, Any],
    ) -> str:

        remote_ip = (
            self.normalize_text(

                network.get(
                    "remote_ip"
                )

                or

                network.get(
                    "destination_ip"
                )

                or

                "unknown"
            )
        )


        remote_port = (

            network.get(
                "remote_port"
            )

            or

            network.get(
                "destination_port"
            )

            or

            ""
        )


        protocol = (
            self.normalize_text(

                network.get(
                    "protocol"
                )

                or

                "UNKNOWN"
            )
            .upper()
        )


        identity = (
            f"{protocol}|"
            f"{remote_ip.lower()}|"
            f"{remote_port}"
        )


        return (
            self.hashed_node_id(
                "NETWORK_ENDPOINT",
                identity,
            )
        )


    # ============================================================
    # REGISTRY NODE ID
    # ============================================================

    def registry_node_id(
        self,
        *,
        registry: Dict[str, Any],
        device_id: str,
    ) -> str:

        key = (
            self.normalize_text(

                registry.get(
                    "key"
                )

                or

                registry.get(
                    "registry_key"
                )

                or

                registry.get(
                    "path"
                )

                or

                "unknown"
            )
            .lower()
        )


        value_name = (
            self.normalize_text(

                registry.get(
                    "value_name"
                )

                or

                ""
            )
            .lower()
        )


        identity = (
            f"{device_id.lower()}|"
            f"{key}|"
            f"{value_name}"
        )


        return (
            self.hashed_node_id(
                "REGISTRY",
                identity,
            )
        )


    # ============================================================
    # ADD EDGE
    # ============================================================

    def add_edge(
        self,
        *,
        source_node_id: str,
        target_node_id: str,
        edge_type: str,
        event_id: str,
        properties: Optional[
            Dict[str, Any]
        ] = None,
    ) -> Dict[str, Any]:

        properties = (
            properties

            if isinstance(
                properties,
                dict,
            )

            else {}
        )


        edge_id = (
            self.store.save_edge(

                source_node_id=
                    source_node_id,

                target_node_id=
                    target_node_id,

                edge_type=
                    edge_type,

                event_id=
                    event_id,

                properties=
                    properties,
            )
        )


        return {
            "edge_id":
                edge_id,

            "source":
                source_node_id,

            "target":
                target_node_id,

            "edge_type":
                edge_type,

            "event_id":
                event_id,

            "properties":
                properties,
        }


    # ============================================================
    # EXTRACT PROCESS FROM NETWORK EVENT
    # ============================================================

    def process_from_network(
        self,
        network: Dict[str, Any],
    ) -> Dict[str, Any]:

        pid = (
            network.get(
                "pid"
            )
        )


        process_name = (

            network.get(
                "process_name"
            )

            or

            network.get(
                "name"
            )
        )


        if (
            pid is None

            and

            not process_name
        ):

            return {}


        return {
            "pid":
                pid,

            "name":
                (
                    process_name
                    or
                    "unknown"
                ),
        }


    # ============================================================
    # EVENT CATEGORY
    # ============================================================

    def get_event_category(
        self,
        event: Dict[str, Any],
    ) -> str:

        metadata = (
            self.safe_dict(
                event.get(
                    "metadata"
                )
            )
        )


        explicit = (

            event.get(
                "event_category"
            )

            or

            metadata.get(
                "event_category"
            )
        )


        if explicit:

            return (
                self.normalize_text(
                    explicit
                )
                .upper()
            )


        event_type = (
            self.normalize_text(
                event.get(
                    "event_type"
                )
            )
            .lower()
        )


        if event_type.startswith(
            "process"
        ):

            return "PROCESS"


        if event_type.startswith(
            "file"
        ):

            return "FILE"


        if event_type.startswith(
            "network"
        ):

            return "NETWORK"


        if event_type.startswith(
            "registry"
        ):

            return "REGISTRY"


        return "SYSTEM"


    # ============================================================
    # BUILD PROVENANCE FROM SECURITY EVENT
    # ============================================================

    def build_from_event(
        self,
        event: Dict[str, Any],
    ) -> Dict[str, Any]:

        if not isinstance(
            event,
            dict,
        ):

            raise TypeError(
                "event must be a dictionary."
            )


        # ========================================================
        # EVENT ID
        # ========================================================

        event_id = (
            self.normalize_text(
                event.get(
                    "event_id"
                )
            )
        )


        if not event_id:

            raise ValueError(
                "event_id is required."
            )


        # ========================================================
        # DEVICE
        # ========================================================

        device_id = (
            self.get_device_id(
                event
            )
        )


        # ========================================================
        # EVENT SECTIONS
        # ========================================================

        process = (
            self.safe_dict(
                event.get(
                    "process"
                )
            )
        )


        file_data = (
            self.safe_dict(
                event.get(
                    "file"
                )
            )
        )


        network = (
            self.safe_dict(
                event.get(
                    "network"
                )
            )
        )


        registry = (
            self.safe_dict(
                event.get(
                    "registry"
                )
            )
        )


        # ========================================================
        # EVENT METADATA
        # ========================================================

        event_type = (
            self.normalize_text(

                event.get(
                    "event_type"
                )

                or

                "unknown"
            )
        )


        category = (
            self.get_event_category(
                event
            )
        )


        # ========================================================
        # SAVE PROVENANCE EVENT
        # ========================================================

        self.store.save_event(
            event
        )


        # ========================================================
        # CREATE EVENT NODE
        # ========================================================

        event_node = (
            self.event_node_id(
                event
            )
        )


        self.store.upsert_node(

            node_id=
                event_node,

            node_type=
                "EVENT",

            label=
                event_type,

            properties={
                "event_id":
                    event_id,

                "event_type":
                    event_type,

                "event_category":
                    category,

                "source":
                    event.get(
                        "source"
                    ),

                "severity":
                    event.get(
                        "severity"
                    ),

                "timestamp":
                    event.get(
                        "timestamp"
                    ),

                "device_id":
                    device_id,
            },
        )


        nodes = {
            "event":
                event_node,
        }


        edges = []


        # ========================================================
        # PROCESS
        # ========================================================

        if process:

            process_node = (
                self.process_node_id(

                    process=
                        process,

                    device_id=
                        device_id,
                )
            )


            self.store.upsert_node(

                node_id=
                    process_node,

                node_type=
                    "PROCESS",

                label=(

                    process.get(
                        "name"
                    )

                    or

                    process.get(
                        "process_name"
                    )

                    or

                    "Unknown Process"
                ),

                properties={
                    **process,

                    "device_id":
                        device_id,
                },
            )


            nodes[
                "process"
            ] = (
                process_node
            )


            edges.append(

                self.add_edge(

                    source_node_id=
                        event_node,

                    target_node_id=
                        process_node,

                    edge_type=
                        "OBSERVED_PROCESS",

                    event_id=
                        event_id,
                )
            )


            # ====================================================
            # PARENT PROCESS
            # ====================================================

            ppid = (
                process.get(
                    "ppid"
                )
            )


            parent_name = (

                process.get(
                    "parent_name"
                )

                or

                process.get(
                    "parent_process_name"
                )
            )


            if (
                ppid is not None

                or

                parent_name
            ):

                parent_process = {
                    "pid":
                        ppid,

                    "name":
                        (
                            parent_name
                            or
                            "unknown-parent"
                        ),
                }


                parent_node = (
                    self.process_node_id(

                        process=
                            parent_process,

                        device_id=
                            device_id,
                    )
                )


                self.store.upsert_node(

                    node_id=
                        parent_node,

                    node_type=
                        "PROCESS",

                    label=
                        parent_process[
                            "name"
                        ],

                    properties={
                        **parent_process,

                        "device_id":
                            device_id,

                        "parent_reference":
                            True,
                    },
                )


                nodes[
                    "parent_process"
                ] = (
                    parent_node
                )


                edges.append(

                    self.add_edge(

                        source_node_id=
                            parent_node,

                        target_node_id=
                            process_node,

                        edge_type=
                            "SPAWNED",

                        event_id=
                            event_id,
                    )
                )


        # ========================================================
        # FILE
        # ========================================================

        if file_data:

            file_node = (
                self.file_node_id(

                    file_data=
                        file_data,

                    device_id=
                        device_id,
                )
            )


            self.store.upsert_node(

                node_id=
                    file_node,

                node_type=
                    "FILE",

                label=(

                    file_data.get(
                        "name"
                    )

                    or

                    file_data.get(
                        "path"
                    )

                    or

                    "Unknown File"
                ),

                properties={
                    **file_data,

                    "device_id":
                        device_id,
                },
            )


            nodes[
                "file"
            ] = (
                file_node
            )


            edges.append(

                self.add_edge(

                    source_node_id=
                        event_node,

                    target_node_id=
                        file_node,

                    edge_type=
                        "OBSERVED_FILE",

                    event_id=
                        event_id,
                )
            )


            # ====================================================
            # PROCESS -> FILE
            # ====================================================

            process_node = (
                nodes.get(
                    "process"
                )
            )


            if process_node:

                edges.append(

                    self.add_edge(

                        source_node_id=
                            process_node,

                        target_node_id=
                            file_node,

                        edge_type=
                            "TOUCHED_FILE",

                        event_id=
                            event_id,

                        properties={
                            "event_type":
                                event_type,
                        },
                    )
                )


        # ========================================================
        # NETWORK
        # ========================================================

        if network:

            network_node = (
                self.network_node_id(
                    network
                )
            )


            remote_ip = (

                network.get(
                    "remote_ip"
                )

                or

                network.get(
                    "destination_ip"
                )

                or

                "unknown"
            )


            remote_port = (

                network.get(
                    "remote_port"
                )

                or

                network.get(
                    "destination_port"
                )

                or

                ""
            )


            self.store.upsert_node(

                node_id=
                    network_node,

                node_type=
                    "NETWORK_ENDPOINT",

                label=(
                    f"{remote_ip}:"
                    f"{remote_port}"
                ),

                properties={
                    **network,
                },
            )


            nodes[
                "network_endpoint"
            ] = (
                network_node
            )


            edges.append(

                self.add_edge(

                    source_node_id=
                        event_node,

                    target_node_id=
                        network_node,

                    edge_type=
                        "OBSERVED_NETWORK",

                    event_id=
                        event_id,
                )
            )


            # ====================================================
            # PROCESS ATTRIBUTION FROM NETWORK PID
            # ====================================================

            network_process = (
                self.process_from_network(
                    network
                )
            )


            if network_process:

                network_process_node = (
                    self.process_node_id(

                        process=
                            network_process,

                        device_id=
                            device_id,
                    )
                )


                self.store.upsert_node(

                    node_id=
                        network_process_node,

                    node_type=
                        "PROCESS",

                    label=(

                        network_process.get(
                            "name"
                        )

                        or

                        "Unknown Process"
                    ),

                    properties={
                        **network_process,

                        "device_id":
                            device_id,
                    },
                )


                nodes[
                    "network_process"
                ] = (
                    network_process_node
                )


                edges.append(

                    self.add_edge(

                        source_node_id=
                            network_process_node,

                        target_node_id=
                            network_node,

                        edge_type=
                            "CONNECTED_TO",

                        event_id=
                            event_id,

                        properties={
                            "protocol":
                                network.get(
                                    "protocol"
                                ),

                            "local_ip":
                                network.get(
                                    "local_ip"
                                ),

                            "local_port":
                                network.get(
                                    "local_port"
                                ),

                            "remote_ip":
                                remote_ip,

                            "remote_port":
                                remote_port,

                            "status":
                                network.get(
                                    "status"
                                ),
                        },
                    )
                )


        # ========================================================
        # REGISTRY
        # ========================================================

        if registry:

            registry_node = (
                self.registry_node_id(

                    registry=
                        registry,

                    device_id=
                        device_id,
                )
            )


            self.store.upsert_node(

                node_id=
                    registry_node,

                node_type=
                    "REGISTRY",

                label=(

                    registry.get(
                        "key"
                    )

                    or

                    registry.get(
                        "registry_key"
                    )

                    or

                    registry.get(
                        "path"
                    )

                    or

                    "Unknown Registry Key"
                ),

                properties={
                    **registry,

                    "device_id":
                        device_id,
                },
            )


            nodes[
                "registry"
            ] = (
                registry_node
            )


            edges.append(

                self.add_edge(

                    source_node_id=
                        event_node,

                    target_node_id=
                        registry_node,

                    edge_type=
                        "OBSERVED_REGISTRY",

                    event_id=
                        event_id,
                )
            )


            # ====================================================
            # PROCESS -> REGISTRY
            # ====================================================

            process_node = (
                nodes.get(
                    "process"
                )
            )


            if process_node:

                edges.append(

                    self.add_edge(

                        source_node_id=
                            process_node,

                        target_node_id=
                            registry_node,

                        edge_type=
                            "MODIFIED_REGISTRY",

                        event_id=
                            event_id,

                        properties={
                            "event_type":
                                event_type,
                        },
                    )
                )


        # ========================================================
        # RESULT
        # ========================================================

        return {
            "event_id":
                event_id,

            "category":
                category,

            "nodes":
                nodes,

            "edges":
                edges,

            "edge_count":
                len(
                    edges
                ),
        }


    # ============================================================
    # COMPATIBILITY METHOD
    # ============================================================

    def process_event(
        self,
        event: Dict[str, Any],
    ) -> Dict[str, Any]:

        return (
            self.build_from_event(
                event
            )
        )


    # ============================================================
    # SUMMARY
    # ============================================================

    def get_summary(
        self,
    ) -> Dict[str, Any]:

        return (
            self.store
            .get_summary()
        )


    # ============================================================
    # CLOSE
    # ============================================================

    def close(
        self,
    ) -> None:

        self.store.close()