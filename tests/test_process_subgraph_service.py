from __future__ import annotations

import json
import sys
import tempfile

from pathlib import Path


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
        str(PROJECT_ROOT),
    )


# ================================================================
# IMPORTS
# ================================================================

from ai_detection.graph.provenance_graph_builder import (
    ProvenanceGraphBuilder,
)


from ai_detection.graph.process_subgraph_service import (
    ProcessSubgraphService,
)


# ================================================================
# DISPLAY
# ================================================================

def heading(
    title: str,
):

    print()

    print(
        "=" * 100
    )

    print(
        title
    )

    print(
        "=" * 100
    )


# ================================================================
# MAIN
# ================================================================

def main():

    heading(
        "SENTINEL-X PROCESS-CENTERED SUBGRAPH TEST"
    )


    with tempfile.TemporaryDirectory() as directory:

        database_path = (

            Path(
                directory
            )

            / "process_subgraph_test.db"
        )


        # ========================================================
        # BUILDER
        # ========================================================

        builder = (
            ProvenanceGraphBuilder(

                database_path=
                    database_path
            )
        )


        # ========================================================
        # DEVICE / PROCESS
        # ========================================================

        device_id = (
            "sentinelx-subgraph-device"
        )


        pid = 42420


        process_name = (
            "sentinelx_graph_demo.exe"
        )


        # ========================================================
        # 1. PROCESS START
        # ========================================================

        builder.build_from_event(
            {
                "event_id":
                    "subgraph-process-001",

                "timestamp":
                    "2026-09-29T09:00:00+00:00",

                "event_type":
                    "process_start",

                "source":
                    "process_monitor",

                "severity":
                    "HIGH",

                "device_id":
                    device_id,

                "process": {
                    "pid":
                        pid,

                    "ppid":
                        2000,

                    "name":
                        process_name,

                    "exe":
                        (
                            r"C:\Temp"
                            r"\sentinelx_graph_demo.exe"
                        ),

                    "parent_name":
                        "explorer.exe",
                },

                "file":
                    {},

                "network":
                    {},

                "registry":
                    {},

                "metadata": {
                    "event_category":
                        "PROCESS",

                    "device_id":
                        device_id,
                },
            }
        )


        # ========================================================
        # 2. NETWORK CONNECTION
        # ========================================================

        builder.build_from_event(
            {
                "event_id":
                    "subgraph-network-001",

                "timestamp":
                    "2026-09-29T09:00:05+00:00",

                "event_type":
                    "network_connect",

                "source":
                    "network_monitor",

                "severity":
                    "INFO",

                "device_id":
                    device_id,

                "process":
                    {},

                "file":
                    {},

                "network": {
                    "pid":
                        pid,

                    "process_name":
                        process_name,

                    "protocol":
                        "TCP",

                    "local_ip":
                        "192.168.1.20",

                    "local_port":
                        54000,

                    "remote_ip":
                        "203.0.113.50",

                    "remote_port":
                        443,

                    "status":
                        "ESTABLISHED",
                },

                "registry":
                    {},

                "metadata": {
                    "event_category":
                        "NETWORK",

                    "device_id":
                        device_id,
                },
            }
        )


        # ========================================================
        # 3. FILE ACTIVITY
        # ========================================================

        builder.build_from_event(
            {
                "event_id":
                    "subgraph-file-001",

                "timestamp":
                    "2026-09-29T09:00:10+00:00",

                "event_type":
                    "file_modify",

                "source":
                    "file_monitor",

                "severity":
                    "MEDIUM",

                "device_id":
                    device_id,

                "process": {
                    "pid":
                        pid,

                    "name":
                        process_name,
                },

                "file": {
                    "name":
                        "payload.bin",

                    "path":
                        r"C:\Temp\payload.bin",

                    "extension":
                        ".bin",

                    "size":
                        4096,
                },

                "network":
                    {},

                "registry":
                    {},

                "metadata": {
                    "event_category":
                        "FILE",

                    "device_id":
                        device_id,
                },
            }
        )


        # ========================================================
        # 4. REGISTRY ACTIVITY
        # ========================================================

        builder.build_from_event(
            {
                "event_id":
                    "subgraph-registry-001",

                "timestamp":
                    "2026-09-29T09:00:15+00:00",

                "event_type":
                    "registry_change",

                "source":
                    "registry_monitor",

                "severity":
                    "MEDIUM",

                "device_id":
                    device_id,

                "process": {
                    "pid":
                        pid,

                    "name":
                        process_name,
                },

                "file":
                    {},

                "network":
                    {},

                "registry": {
                    "key":
                        (
                            r"HKCU\Software\Microsoft"
                            r"\Windows\CurrentVersion"
                            r"\Run"
                        ),

                    "value_name":
                        "SentinelXDemo",

                    "value_data":
                        (
                            r"C:\Temp"
                            r"\sentinelx_graph_demo.exe"
                        ),
                },

                "metadata": {
                    "event_category":
                        "REGISTRY",

                    "device_id":
                        device_id,
                },
            }
        )


        # ========================================================
        # 5. CHILD PROCESS
        # ========================================================

        builder.build_from_event(
            {
                "event_id":
                    "subgraph-child-001",

                "timestamp":
                    "2026-09-29T09:00:20+00:00",

                "event_type":
                    "process_start",

                "source":
                    "process_monitor",

                "severity":
                    "INFO",

                "device_id":
                    device_id,

                "process": {
                    "pid":
                        50000,

                    "ppid":
                        pid,

                    "name":
                        "child_process.exe",

                    "parent_name":
                        process_name,
                },

                "file":
                    {},

                "network":
                    {},

                "registry":
                    {},

                "metadata": {
                    "event_category":
                        "PROCESS",

                    "device_id":
                        device_id,
                },
            }
        )


        # ========================================================
        # SERVICE
        # ========================================================

        service = (
            ProcessSubgraphService(

                database_path=
                    database_path
            )
        )


        # ========================================================
        # QUERY CENTER PROCESS
        # ========================================================

        subgraph = (
            service.get_process_subgraph(

                pid=
                    pid,

                device_id=
                    device_id,

                process_name=
                    process_name,

                max_hops=
                    2,

                include_event_nodes=
                    True,
            )
        )


        heading(
            "PROCESS RESOLUTION"
        )


        print()

        print(
            "Found:",
            subgraph[
                "found"
            ],
        )


        print(
            "PID:",
            subgraph[
                "pid"
            ],
        )


        print(
            "Process:",
            subgraph[
                "process_name"
            ],
        )


        print(
            "Center Node:",
            subgraph[
                "center_node_id"
            ],
        )


        assert (
            subgraph[
                "found"
            ]
            is True
        )


        assert (
            subgraph[
                "pid"
            ]
            == pid
        )


        # ========================================================
        # SUMMARY
        # ========================================================

        summary = (
            subgraph[
                "summary"
            ]
        )


        heading(
            "SUBGRAPH SUMMARY"
        )


        print()

        print(
            "Nodes:",
            summary[
                "node_count"
            ],
        )


        print(
            "Edges:",
            summary[
                "edge_count"
            ],
        )


        print()

        print(
            "Node types:"
        )


        for (
            node_type,
            count,
        ) in sorted(
            summary[
                "node_types"
            ].items()
        ):

            print(
                f"{node_type:<22}: "
                f"{count}"
            )


        print()

        print(
            "Edge types:"
        )


        for (
            edge_type,
            count,
        ) in sorted(
            summary[
                "edge_types"
            ].items()
        ):

            print(
                f"{edge_type:<26}: "
                f"{count}"
            )


        # ========================================================
        # EXPECTED 2-HOP SUBGRAPH
        # ========================================================

        assert (
            summary[
                "node_count"
            ]
            == 11
        )


        assert (
            summary[
                "edge_count"
            ]
            == 12
        )


        # ========================================================
        # NODE TYPES
        # ========================================================

        assert (
            summary[
                "node_types"
            ].get(
                "EVENT"
            )
            == 5
        )


        assert (
            summary[
                "node_types"
            ].get(
                "PROCESS"
            )
            == 3
        )


        assert (
            summary[
                "node_types"
            ].get(
                "FILE"
            )
            == 1
        )


        assert (
            summary[
                "node_types"
            ].get(
                "NETWORK_ENDPOINT"
            )
            == 1
        )


        assert (
            summary[
                "node_types"
            ].get(
                "REGISTRY"
            )
            == 1
        )


        # ========================================================
        # IMPORTANT RELATIONSHIPS
        # ========================================================

        edge_types = (
            summary[
                "edge_types"
            ]
        )


        required_edges = {

            "SPAWNED",

            "CONNECTED_TO",

            "TOUCHED_FILE",

            "MODIFIED_REGISTRY",
        }


        for edge_type in required_edges:

            assert (
                edge_types.get(
                    edge_type,
                    0,
                )
                > 0
            ), (
                f"Missing relationship: "
                f"{edge_type}"
            )


        print()

        print(
            "Parent/child relationship : PASS"
        )


        print(
            "Process/file relationship  : PASS"
        )


        print(
            "Process/network relation   : PASS"
        )


        print(
            "Process/registry relation  : PASS"
        )


        # ========================================================
        # GNN STRUCTURAL EXPORT
        # ========================================================

        gnn = (
            service.export_gnn_structure(
                subgraph
            )
        )


        heading(
            "GNN STRUCTURAL EXPORT"
        )


        print()

        print(
            "Nodes:",
            gnn[
                "node_count"
            ],
        )


        print(
            "Edges:",
            gnn[
                "edge_count"
            ],
        )


        print(
            "Center node index:",
            gnn[
                "center_node_index"
            ],
        )


        print()

        print(
            "Node type IDs:"
        )


        print(
            gnn[
                "node_type_ids"
            ]
        )


        print()

        print(
            "Edge index:"
        )


        print(
            gnn[
                "edge_index"
            ]
        )


        print()

        print(
            "Edge type IDs:"
        )


        print(
            gnn[
                "edge_type_ids"
            ]
        )


        assert (
            gnn[
                "node_count"
            ]
            ==
            summary[
                "node_count"
            ]
        )


        assert (
            gnn[
                "edge_count"
            ]
            ==
            summary[
                "edge_count"
            ]
        )


        assert (
            gnn[
                "center_node_index"
            ]
            is not None
        )


        assert (
            len(
                gnn[
                    "edge_index"
                ][
                    0
                ]
            )
            ==
            len(
                gnn[
                    "edge_index"
                ][
                    1
                ]
            )
            ==
            gnn[
                "edge_count"
            ]
        )


        # ========================================================
        # JSON EXPORT
        # ========================================================

        output_path = (

            Path(
                directory
            )

            / "process_subgraph.json"
        )


        saved_path = (
            service.save_subgraph_json(

                subgraph=
                    subgraph,

                output_path=
                    output_path,
            )
        )


        assert (
            saved_path.exists()
        )


        with open(
            saved_path,
            "r",
            encoding="utf-8",
        ) as file:

            exported = (
                json.load(
                    file
                )
            )


        assert (
            exported[
                "center_node_id"
            ]
            ==
            subgraph[
                "center_node_id"
            ]
        )


        print()

        print(
            "JSON export:",
            saved_path,
        )


        print(
            "JSON export validation: PASS"
        )


        # ========================================================
        # QUERY WITHOUT EVENT NODES
        # ========================================================

        artifact_only = (
            service.get_process_subgraph(

                pid=
                    pid,

                device_id=
                    device_id,

                process_name=
                    process_name,

                max_hops=
                    2,

                include_event_nodes=
                    False,
            )
        )


        assert (

            "EVENT"

            not in

            artifact_only[
                "summary"
            ][
                "node_types"
            ]
        )


        print()

        print(
            "Event-node filtering: PASS"
        )


        # ========================================================
        # UNKNOWN PID
        # ========================================================

        missing = (
            service.get_process_subgraph(

                pid=
                    99999999,

                max_hops=
                    2,
            )
        )


        assert (
            missing[
                "found"
            ]
            is False
        )


        print(
            "Unknown PID handling: PASS"
        )


        # ========================================================
        # CLEANUP
        # ========================================================

        service.close()

        builder.close()


    # ============================================================
    # TEMP DIRECTORY SUCCESSFULLY REMOVED
    # ============================================================

    heading(
        "PROCESS-CENTERED SUBGRAPH TEST: PASS"
    )


if __name__ == "__main__":

    main()