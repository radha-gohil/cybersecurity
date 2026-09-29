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
# IMPORT MODULE ITSELF
#
# We temporarily replace save_event so this integration test does
# NOT write synthetic events into the normal endpoint event table.
# ================================================================

import endpoint.agent.telemetry_manager as telemetry_module


from endpoint.agent.telemetry_manager import (
    TelemetryManager,
)


from ai_detection.graph.provenance_graph_builder import (
    ProvenanceGraphBuilder,
)


# ================================================================
# CONTROLLED CORRELATION MANAGER
#
# Provenance integration is the thing under test here.
#
# We therefore avoid modifying the real correlation/incident store.
# ================================================================


class TestCorrelationManager:

    def process_event(
        self,
        event,
    ):

        return {
            "correlation": {
                "correlated":
                    False,

                "correlation_score":
                    0,

                "related_event_count":
                    0,
            },

            "incident_created":
                False,

            "incident_updated":
                False,
        }


# ================================================================
# HEADING
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
# MAIN
# ================================================================


def main():

    heading(
        "SENTINEL-X TELEMETRY → PROVENANCE GRAPH INTEGRATION TEST"
    )


    # ============================================================
    # PRESERVE ORIGINAL save_event()
    # ============================================================

    original_save_event = (
        telemetry_module.save_event
    )


    # ============================================================
    # TEST RAW EVENT CAPTURE
    # ============================================================

    raw_events = []


    def controlled_save_event(
        event,
    ):

        raw_events.append(
            event.to_dict()
        )


    telemetry_module.save_event = (
        controlled_save_event
    )


    try:

        with tempfile.TemporaryDirectory() as directory:

            database_path = (

                Path(
                    directory
                )

                / "telemetry_provenance_test.db"
            )


            # ====================================================
            # ISOLATED GRAPH
            # ====================================================

            builder = (
                ProvenanceGraphBuilder(

                    database_path=
                        database_path
                )
            )


            # ====================================================
            # ISOLATED TELEMETRY MANAGER
            # ====================================================

            telemetry = (
                TelemetryManager(

                    device_id=
                        "sentinelx-provenance-device",

                    provenance_builder=
                        builder,

                    correlation_manager=
                        TestCorrelationManager(),
                )
            )


            # ====================================================
            # PROCESS
            # ====================================================

            print()

            print(
                "[1] PROCESS TELEMETRY"
            )


            process_event = (
                telemetry.emit(

                    event_type=
                        "process_start",

                    source=
                        "test_process_monitor",

                    severity=
                        "HIGH",

                    process={
                        "pid":
                            42420,

                        "ppid":
                            1000,

                        "name":
                            "sentinelx_graph_demo.exe",

                        "parent_name":
                            "explorer.exe",

                        "exe":
                            (
                                r"C:\Temp"
                                r"\sentinelx_graph_demo.exe"
                            ),
                    },

                    metadata={
                        "synthetic_test":
                            True,
                    },
                )
            )


            print(
                "Event ID:",
                process_event.event_id,
            )


            print(
                "Graph:",
                process_event.metadata.get(
                    "provenance_graph"
                ),
            )


            assert (
                process_event.metadata[
                    "provenance_graph"
                ][
                    "processed"
                ]
                is True
            )


            assert (
                process_event.metadata[
                    "provenance_graph"
                ][
                    "edge_count"
                ]
                == 2
            )


            # ====================================================
            # NETWORK
            # ====================================================

            print()

            print(
                "[2] NETWORK TELEMETRY"
            )


            network_event = (
                telemetry.emit(

                    event_type=
                        "network_connect",

                    source=
                        "test_network_monitor",

                    severity=
                        "INFO",

                    network={
                        "pid":
                            42420,

                        "process_name":
                            "sentinelx_graph_demo.exe",

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

                    metadata={
                        "synthetic_test":
                            True,
                    },
                )
            )


            print(
                "Event ID:",
                network_event.event_id,
            )


            print(
                "Graph:",
                network_event.metadata.get(
                    "provenance_graph"
                ),
            )


            assert (
                network_event.metadata[
                    "provenance_graph"
                ][
                    "edge_count"
                ]
                == 2
            )


            # ====================================================
            # FILE WITH PROCESS ATTRIBUTION
            # ====================================================

            print()

            print(
                "[3] FILE TELEMETRY"
            )


            file_event = (
                telemetry.emit(

                    event_type=
                        "file_modify",

                    source=
                        "test_file_monitor",

                    severity=
                        "MEDIUM",

                    process={
                        "pid":
                            42420,

                        "name":
                            "sentinelx_graph_demo.exe",
                    },

                    file={
                        "name":
                            "graph_test.bin",

                        "path":
                            (
                                r"C:\Temp"
                                r"\graph_test.bin"
                            ),

                        "extension":
                            ".bin",

                        "size":
                            4096,
                    },

                    metadata={
                        "synthetic_test":
                            True,
                    },
                )
            )


            print(
                "Event ID:",
                file_event.event_id,
            )


            print(
                "Graph:",
                file_event.metadata.get(
                    "provenance_graph"
                ),
            )


            assert (
                file_event.metadata[
                    "provenance_graph"
                ][
                    "edge_count"
                ]
                == 3
            )


            # ====================================================
            # REGISTRY WITH PROCESS ATTRIBUTION
            # ====================================================

            print()

            print(
                "[4] REGISTRY TELEMETRY"
            )


            registry_event = (
                telemetry.emit(

                    event_type=
                        "registry_change",

                    source=
                        "test_registry_monitor",

                    severity=
                        "MEDIUM",

                    process={
                        "pid":
                            42420,

                        "name":
                            "sentinelx_graph_demo.exe",
                    },

                    registry={
                        "key":
                            (
                                r"HKCU\Software\Microsoft"
                                r"\Windows\CurrentVersion"
                                r"\Run"
                            ),

                        "value_name":
                            "SentinelXGraphDemo",

                        "value_data":
                            (
                                r"C:\Temp"
                                r"\sentinelx_graph_demo.exe"
                            ),
                    },

                    metadata={
                        "synthetic_test":
                            True,
                    },
                )
            )


            print(
                "Event ID:",
                registry_event.event_id,
            )


            print(
                "Graph:",
                registry_event.metadata.get(
                    "provenance_graph"
                ),
            )


            assert (
                registry_event.metadata[
                    "provenance_graph"
                ][
                    "edge_count"
                ]
                == 3
            )


            # ====================================================
            # VERIFY RAW TELEMETRY PATH
            # ====================================================

            heading(
                "RAW TELEMETRY"
            )


            print(
                "SecurityEvents emitted:",
                len(
                    raw_events
                ),
            )


            assert (
                len(
                    raw_events
                )
                == 4
            )


            # ====================================================
            # GRAPH SUMMARY
            # ====================================================

            summary = (
                builder.get_summary()
            )


            heading(
                "PROVENANCE GRAPH SUMMARY"
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


            # ====================================================
            # GRAPH COUNTS
            # ====================================================

            assert (
                summary[
                    "event_count"
                ]
                == 4
            )


            assert (
                summary[
                    "node_count"
                ]
                == 9
            )


            assert (
                summary[
                    "edge_count"
                ]
                == 10
            )


            # ====================================================
            # NODE TYPES
            # ====================================================

            assert (
                summary[
                    "node_types"
                ].get(
                    "EVENT"
                )
                == 4
            )


            assert (
                summary[
                    "node_types"
                ].get(
                    "PROCESS"
                )
                == 2
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


            # ====================================================
            # EDGE TYPES
            # ====================================================

            expected_edges = {

                "OBSERVED_PROCESS":
                    3,

                "SPAWNED":
                    1,

                "OBSERVED_NETWORK":
                    1,

                "CONNECTED_TO":
                    1,

                "OBSERVED_FILE":
                    1,

                "TOUCHED_FILE":
                    1,

                "OBSERVED_REGISTRY":
                    1,

                "MODIFIED_REGISTRY":
                    1,
            }


            for (
                edge_type,
                expected_count,
            ) in expected_edges.items():

                actual_count = (
                    summary[
                        "edge_types"
                    ].get(
                        edge_type,
                        0,
                    )
                )


                assert (
                    actual_count
                    == expected_count
                ), (
                    f"{edge_type}: "
                    f"expected="
                    f"{expected_count}, "
                    f"actual="
                    f"{actual_count}"
                )


            # ====================================================
            # PROCESS IDENTITY RESOLUTION
            # ====================================================

            nodes = (
                builder.store
                .get_nodes(
                    limit=100
                )
            )


            process_nodes = [

                node

                for node in nodes

                if (
                    node.get(
                        "node_type"
                    )
                    == "PROCESS"
                )
            ]


            # One explorer parent + one demo process.
            assert (
                len(
                    process_nodes
                )
                == 2
            )


            demo_nodes = [

                node

                for node in process_nodes

                if (
                    node.get(
                        "properties",
                        {},
                    ).get(
                        "pid"
                    )
                    == 42420
                )
            ]


            assert (
                len(
                    demo_nodes
                )
                == 1
            )


            print()

            print(
                "Cross-event process identity "
                "resolution: PASS"
            )


            # ====================================================
            # CLEANUP
            # ====================================================

            builder.close()


        # Temporary database has now been successfully deleted.


    finally:

        # ========================================================
        # RESTORE REAL EVENT PERSISTENCE
        # ========================================================

        telemetry_module.save_event = (
            original_save_event
        )


    heading(
        "TELEMETRY → PROVENANCE GRAPH INTEGRATION TEST: PASS"
    )


if __name__ == "__main__":

    main()