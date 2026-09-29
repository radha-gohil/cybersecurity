from __future__ import annotations

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
        str(
            PROJECT_ROOT
        ),
    )


# ================================================================
# IMPORTS
# ================================================================

from ai_detection.graph.provenance_graph_builder import (
    ProvenanceGraphBuilder,
)


# ================================================================
# HELPERS
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
# MAIN TEST
# ================================================================

def main():

    heading(
        "SENTINEL-X PROVENANCE GRAPH BUILDER TEST"
    )


    # ============================================================
    # TEMPORARY DATABASE
    #
    # IMPORTANT:
    #
    # Every SQLite connection in ProvenanceGraphStore now uses:
    #
    #     contextlib.closing(...)
    #
    # Therefore Windows can remove this directory when the test
    # exits.
    # ============================================================

    with tempfile.TemporaryDirectory() as directory:

        database_path = (

            Path(
                directory
            )

            / "provenance_test.db"
        )


        builder = (
            ProvenanceGraphBuilder(
                database_path=
                    database_path
            )
        )


        # ========================================================
        # COMMON PROCESS
        # ========================================================

        process_pid = 42420


        process_name = (
            "sentinelx_demo.exe"
        )


        device_id = (
            "sentinelx-test-device"
        )


        # ========================================================
        # 1. PROCESS EVENT
        # ========================================================

        process_event = {

            "event_id":
                "prov-process-001",

            "timestamp":
                "2026-09-29T08:00:00+00:00",

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
                    process_pid,

                "ppid":
                    2000,

                "name":
                    process_name,

                "exe":
                    r"C:\Temp\sentinelx_demo.exe",

                "cmdline":
                    r"C:\Temp\sentinelx_demo.exe",

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


        process_result = (
            builder.build_from_event(
                process_event
            )
        )


        print()

        print(
            "[1] PROCESS EVENT"
        )


        print(
            "Nodes:",
            process_result[
                "nodes"
            ],
        )


        print(
            "Edges:",
            process_result[
                "edge_count"
            ],
        )


        assert (
            process_result[
                "edge_count"
            ]
            == 2
        )


        assert (
            "event"
            in process_result[
                "nodes"
            ]
        )


        assert (
            "process"
            in process_result[
                "nodes"
            ]
        )


        assert (
            "parent_process"
            in process_result[
                "nodes"
            ]
        )


        original_process_node = (
            process_result[
                "nodes"
            ][
                "process"
            ]
        )


        # ========================================================
        # 2. NETWORK EVENT
        # ========================================================

        network_event = {

            "event_id":
                "prov-network-001",

            "timestamp":
                "2026-09-29T08:00:05+00:00",

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
                    process_pid,

                "process_name":
                    process_name,

                "protocol":
                    "TCP",

                "local_ip":
                    "192.168.1.50",

                "local_port":
                    53000,

                "remote_ip":
                    "203.0.113.10",

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


        network_result = (
            builder.build_from_event(
                network_event
            )
        )


        print()

        print(
            "[2] NETWORK EVENT"
        )


        print(
            "Nodes:",
            network_result[
                "nodes"
            ],
        )


        print(
            "Edges:",
            network_result[
                "edge_count"
            ],
        )


        assert (
            network_result[
                "edge_count"
            ]
            == 2
        )


        assert (
            "network_endpoint"
            in network_result[
                "nodes"
            ]
        )


        assert (
            "network_process"
            in network_result[
                "nodes"
            ]
        )


        # ========================================================
        # NETWORK PROCESS MUST RESOLVE TO THE ORIGINAL PROCESS
        # ========================================================

        network_process_node = (
            network_result[
                "nodes"
            ][
                "network_process"
            ]
        )


        assert (
            network_process_node
            ==
            original_process_node
        )


        # ========================================================
        # 3. FILE EVENT
        #
        # No process attribution.
        #
        # Expected:
        #
        # EVENT -> FILE
        # ========================================================

        file_event = {

            "event_id":
                "prov-file-001",

            "timestamp":
                "2026-09-29T08:00:10+00:00",

            "event_type":
                "file_modify",

            "source":
                "file_monitor",

            "severity":
                "MEDIUM",

            "device_id":
                device_id,

            "process":
                {},

            "file": {

                "name":
                    "config.json",

                "path":
                    r"C:\Temp\config.json",

                "extension":
                    ".json",

                "size":
                    1500,

                "sha256":
                    "FILE_TEST_HASH_001",
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


        file_result = (
            builder.build_from_event(
                file_event
            )
        )


        print()

        print(
            "[3] FILE EVENT"
        )


        print(
            "Nodes:",
            file_result[
                "nodes"
            ],
        )


        print(
            "Edges:",
            file_result[
                "edge_count"
            ],
        )


        assert (
            file_result[
                "edge_count"
            ]
            == 1
        )


        # ========================================================
        # 4. REGISTRY EVENT
        # ========================================================

        registry_event = {

            "event_id":
                "prov-registry-001",

            "timestamp":
                "2026-09-29T08:00:15+00:00",

            "event_type":
                "registry_change",

            "source":
                "registry_monitor",

            "severity":
                "MEDIUM",

            "device_id":
                device_id,

            "process":
                {},

            "file":
                {},

            "network":
                {},

            "registry": {

                "key":
                    (
                        r"HKCU\Software\Microsoft"
                        r"\Windows\CurrentVersion\Run"
                    ),

                "value_name":
                    "SentinelXDemo",

                "value_data":
                    r"C:\Temp\sentinelx_demo.exe",
            },

            "metadata": {

                "event_category":
                    "REGISTRY",

                "device_id":
                    device_id,
            },
        }


        registry_result = (
            builder.build_from_event(
                registry_event
            )
        )


        print()

        print(
            "[4] REGISTRY EVENT"
        )


        print(
            "Nodes:",
            registry_result[
                "nodes"
            ],
        )


        print(
            "Edges:",
            registry_result[
                "edge_count"
            ],
        )


        assert (
            registry_result[
                "edge_count"
            ]
            == 1
        )


        # ========================================================
        # 5. PROCESS-ATTRIBUTED FILE EVENT
        #
        # Expected:
        #
        # EVENT   -> PROCESS
        # EVENT   -> FILE
        # PROCESS -> FILE
        #
        # therefore 3 edges.
        # ========================================================

        attributed_file_event = {

            "event_id":
                "prov-file-002",

            "timestamp":
                "2026-09-29T08:00:20+00:00",

            "event_type":
                "file_create",

            "source":
                "file_monitor",

            "severity":
                "HIGH",

            "device_id":
                device_id,

            "process": {

                "pid":
                    process_pid,

                "name":
                    process_name,

                "exe":
                    r"C:\Temp\sentinelx_demo.exe",
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

                "sha256":
                    "FILE_TEST_HASH_002",
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


        attributed_result = (
            builder.build_from_event(
                attributed_file_event
            )
        )


        print()

        print(
            "[5] ATTRIBUTED PROCESS → FILE EVENT"
        )


        print(
            "Edges:",
            attributed_result[
                "edge_count"
            ],
        )


        assert (
            attributed_result[
                "edge_count"
            ]
            == 3
        )


        assert (
            attributed_result[
                "nodes"
            ][
                "process"
            ]
            ==
            original_process_node
        )


        # ========================================================
        # SUMMARY
        # ========================================================

        summary = (
            builder.get_summary()
        )


        heading(
            "GRAPH COUNTS"
        )


        print()

        print(
            "Events:",
            summary[
                "event_count"
            ],
        )


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
        ) in summary[
            "node_types"
        ].items():

            print(

                f"{node_type:<20}: "
                f"{count}"
            )


        print()

        print(
            "Edge types:"
        )


        for (
            edge_type,
            count,
        ) in summary[
            "edge_types"
        ].items():

            print(

                f"{edge_type:<24}: "
                f"{count}"
            )


        # ========================================================
        # EXPECTED COUNTS
        # ========================================================

        assert (
            summary[
                "event_count"
            ]
            == 5
        )


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
            == 9
        )


        # ========================================================
        # NODE TYPES
        # ========================================================

        assert (
            summary[
                "node_types"
            ][
                "EVENT"
            ]
            == 5
        )


        assert (
            summary[
                "node_types"
            ][
                "PROCESS"
            ]
            == 2
        )


        assert (
            summary[
                "node_types"
            ][
                "FILE"
            ]
            == 2
        )


        assert (
            summary[
                "node_types"
            ][
                "NETWORK_ENDPOINT"
            ]
            == 1
        )


        assert (
            summary[
                "node_types"
            ][
                "REGISTRY"
            ]
            == 1
        )


        # ========================================================
        # EDGE TYPES
        # ========================================================

        expected_edges = {

            "OBSERVED_PROCESS":
                2,

            "SPAWNED":
                1,

            "OBSERVED_NETWORK":
                1,

            "CONNECTED_TO":
                1,

            "OBSERVED_FILE":
                2,

            "TOUCHED_FILE":
                1,

            "OBSERVED_REGISTRY":
                1,
        }


        for (
            edge_type,
            expected,
        ) in expected_edges.items():

            actual = (

                summary[
                    "edge_types"
                ].get(
                    edge_type,
                    0,
                )
            )


            assert (
                actual
                == expected
            ), (
                f"{edge_type}: "
                f"expected={expected}, "
                f"actual={actual}"
            )


        print()

        print(
            "Network PID resolved to existing "
            "process node: PASS"
        )


        # ========================================================
        # EXPLICIT CLEANUP
        #
        # Store has no persistent DB handle, but retain explicit
        # close call for future compatibility.
        # ========================================================

        builder.close()


        # ========================================================
        # IMPORTANT WINDOWS CHECK
        #
        # If SQLite connections are properly closed, execution can
        # leave this `with TemporaryDirectory()` block without:
        #
        # PermissionError [WinError 32]
        #
        # ========================================================


    # ============================================================
    # THIS LINE IS ONLY REACHED AFTER TEMP DIRECTORY WAS REMOVED
    # ============================================================

    heading(
        "PROVENANCE GRAPH BUILDER TEST: PASS"
    )


if __name__ == "__main__":

    main()