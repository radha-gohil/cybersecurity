from __future__ import annotations

import json
import sys
import tempfile

from pathlib import Path


import numpy as np


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


from ai_detection.graph.graph_dataset_builder import (
    GraphDatasetBuilder,
)


# ================================================================
# DISPLAY
# ================================================================

def heading(
    title,
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
        "SENTINEL-X GRAPH FEATURE + DATASET BUILDER TEST"
    )


    # ============================================================
    # TEMPORARY TEST DIRECTORY
    #
    # Everything used by this test is placed inside this temporary
    # directory:
    #
    #   graph_dataset_test.db
    #   graph_dataset.npz
    #   graph_dataset.manifest.json
    #
    # All resources MUST therefore be closed before leaving this
    # block, especially SQLite and np.load() handles on Windows.
    # ============================================================

    with tempfile.TemporaryDirectory() as directory:

        directory_path = Path(
            directory
        )


        database_path = (

            directory_path
            / "graph_dataset_test.db"
        )


        # ========================================================
        # PROVENANCE GRAPH BUILDER
        # ========================================================

        builder = (
            ProvenanceGraphBuilder(

                database_path=
                    database_path
            )
        )


        # ========================================================
        # TEST IDENTITY
        # ========================================================

        device_id = (
            "sentinelx-graph-ai-device"
        )


        pid = 42420


        process_name = (
            "sentinelx_graph_ai.exe"
        )


        # ========================================================
        # 1. PROCESS EVENT
        #
        # Includes behavioral + AI evidence so the graph feature
        # encoder can validate the process feature positions.
        # ========================================================

        builder.build_from_event(
            {
                "event_id":
                    "graph-ai-process",

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
                            r"\sentinelx_graph_ai.exe"
                        ),

                    "parent_name":
                        "explorer.exe",

                    # --------------------------------------------
                    # Runtime telemetry
                    # --------------------------------------------

                    "cpu_percent":
                        35,

                    "memory_percent":
                        12,

                    "network_connection_count":
                        4,

                    "file_activity_count":
                        3,

                    "registry_activity_count":
                        1,

                    # --------------------------------------------
                    # Rule / statistical evidence
                    # --------------------------------------------

                    "behavior_score":
                        85,

                    "anomaly_score":
                        70,

                    "combined_threat_score":
                        88,

                    # --------------------------------------------
                    # Behavioral AI
                    # --------------------------------------------

                    "isolation_forest_score":
                        72,

                    "autoencoder_score":
                        68,

                    "dual_ai_consensus_score":
                        70,

                    # --------------------------------------------
                    # Temporal AI
                    # --------------------------------------------

                    "temporal_ai_score":
                        77,

                    # --------------------------------------------
                    # Fusion
                    # --------------------------------------------

                    "fusion_score":
                        82,

                    # --------------------------------------------
                    # Behavioral flags
                    # --------------------------------------------

                    "is_script_interpreter":
                        True,

                    "has_encoded_command":
                        True,
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

                    "synthetic_test":
                        True,
                },
            }
        )


        # ========================================================
        # 2. NETWORK EVENT
        # ========================================================

        builder.build_from_event(
            {
                "event_id":
                    "graph-ai-network",

                "timestamp":
                    "2026-09-29T09:00:05+00:00",

                "event_type":
                    "network_connect",

                "source":
                    "network_monitor",

                "severity":
                    "MEDIUM",

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

                    "synthetic_test":
                        True,
                },
            }
        )


        # ========================================================
        # 3. FILE EVENT
        # ========================================================

        builder.build_from_event(
            {
                "event_id":
                    "graph-ai-file",

                "timestamp":
                    "2026-09-29T09:00:10+00:00",

                "event_type":
                    "file_modify",

                "source":
                    "file_monitor",

                "severity":
                    "HIGH",

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
                        "payload.exe",

                    "path":
                        r"C:\Temp\payload.exe",

                    "extension":
                        ".exe",

                    "size":
                        250000,

                    "static_risk_score":
                        80,

                    "malware_probability":
                        0.92,

                    "entropy":
                        7.2,

                    "is_pe":
                        True,

                    "sha256":
                        "GRAPH_AI_TEST_SHA256",
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

                    "synthetic_test":
                        True,
                },
            }
        )


        # ========================================================
        # 4. REGISTRY EVENT
        # ========================================================

        builder.build_from_event(
            {
                "event_id":
                    "graph-ai-registry",

                "timestamp":
                    "2026-09-29T09:00:15+00:00",

                "event_type":
                    "registry_change",

                "source":
                    "registry_monitor",

                "severity":
                    "HIGH",

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
                            r"\Windows\CurrentVersion\Run"
                        ),

                    "value_name":
                        "GraphAI",

                    "value_data":
                        r"C:\Temp\payload.exe",
                },

                "metadata": {

                    "event_category":
                        "REGISTRY",

                    "device_id":
                        device_id,

                    "synthetic_test":
                        True,
                },
            }
        )


        # ========================================================
        # 5. CHILD PROCESS EVENT
        #
        # This creates:
        #
        # center process -> child process
        #
        # through the SPAWNED relationship.
        # ========================================================

        builder.build_from_event(
            {
                "event_id":
                    "graph-ai-child",

                "timestamp":
                    "2026-09-29T09:00:20+00:00",

                "event_type":
                    "process_start",

                "source":
                    "process_monitor",

                "severity":
                    "MEDIUM",

                "device_id":
                    device_id,

                "process": {

                    "pid":
                        50000,

                    "ppid":
                        pid,

                    "name":
                        "child.exe",

                    "exe":
                        r"C:\Temp\child.exe",

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

                    "synthetic_test":
                        True,
                },
            }
        )


        # ========================================================
        # GRAPH DATASET BUILDER
        # ========================================================

        dataset_builder = (
            GraphDatasetBuilder(

                database_path=
                    database_path,

                max_hops=
                    2,

                include_event_nodes=
                    True,
            )
        )


        # ========================================================
        # BUILD ONE PROCESS-CENTERED GRAPH
        # ========================================================

        dataset = (
            dataset_builder.build_dataset(

                process_queries=[
                    {
                        "pid":
                            pid,

                        "process_name":
                            process_name,

                        "device_id":
                            device_id,
                    }
                ]
            )
        )


        # ========================================================
        # DATASET SUMMARY
        # ========================================================

        heading(
            "DATASET SUMMARY"
        )


        print()

        print(
            "Graphs:",
            dataset[
                "graph_count"
            ],
        )


        print(
            "Nodes:",
            dataset[
                "node_count"
            ],
        )


        print(
            "Edges:",
            dataset[
                "edge_count"
            ],
        )


        print(
            "Feature count:",
            dataset[
                "x"
            ].shape[
                1
            ],
        )


        print(
            "X shape:",
            dataset[
                "x"
            ].shape,
        )


        print(
            "Edge index shape:",
            dataset[
                "edge_index"
            ].shape,
        )


        print(
            "Node type shape:",
            dataset[
                "node_type_ids"
            ].shape,
        )


        print(
            "Edge type shape:",
            dataset[
                "edge_type_ids"
            ].shape,
        )


        # ========================================================
        # EXPECTED GRAPH STRUCTURE
        # ========================================================

        assert (
            dataset[
                "graph_count"
            ]
            == 1
        )


        assert (
            dataset[
                "node_count"
            ]
            == 11
        )


        assert (
            dataset[
                "edge_count"
            ]
            == 12
        )


        # ========================================================
        # FEATURE MATRIX
        # ========================================================

        assert (
            dataset[
                "x"
            ].shape
            ==
            (
                11,
                32,
            )
        )


        # ========================================================
        # NODE TYPE IDS
        # ========================================================

        assert (
            dataset[
                "node_type_ids"
            ].shape
            ==
            (
                11,
            )
        )


        # ========================================================
        # EDGE INDEX
        # ========================================================

        assert (
            dataset[
                "edge_index"
            ].shape
            ==
            (
                2,
                12,
            )
        )


        # ========================================================
        # EDGE TYPES
        # ========================================================

        assert (
            dataset[
                "edge_type_ids"
            ].shape
            ==
            (
                12,
            )
        )


        # ========================================================
        # NUMERICAL SAFETY
        # ========================================================

        assert (
            np.isfinite(
                dataset[
                    "x"
                ]
            ).all()
        )


        assert (
            (
                dataset[
                    "x"
                ]
                >= 0
            ).all()
        )


        assert (
            (
                dataset[
                    "x"
                ]
                <= 1
            ).all()
        )


        print()

        print(
            "No NaN / Inf: PASS"
        )


        print(
            "Feature range [0,1]: PASS"
        )


        # ========================================================
        # CENTER NODE
        # ========================================================

        assert (
            len(
                dataset[
                    "center_node_indices"
                ]
            )
            == 1
        )


        center_index = int(

            dataset[
                "center_node_indices"
            ][
                0
            ]
        )


        print(
            "Center process index:",
            center_index,
        )


        assert (
            0
            <= center_index
            <
            dataset[
                "node_count"
            ]
        )


        # ========================================================
        # FEATURE 0
        #
        # type_process
        # ========================================================

        assert (
            dataset[
                "x"
            ][
                center_index,
                0,
            ]
            == 1.0
        )


        # ========================================================
        # FEATURE 5
        #
        # is_center_process
        # ========================================================

        assert (
            dataset[
                "x"
            ][
                center_index,
                5,
            ]
            == 1.0
        )


        print(
            "Center-process encoding: PASS"
        )


        # ========================================================
        # PROCESS AI FEATURES
        # ========================================================

        center_features = (
            dataset[
                "x"
            ][
                center_index
            ]
        )


        # --------------------------------------------------------
        # behavior_score
        # --------------------------------------------------------

        assert (
            center_features[
                7
            ]
            > 0
        )


        # --------------------------------------------------------
        # anomaly_score
        # --------------------------------------------------------

        assert (
            center_features[
                8
            ]
            > 0
        )


        # --------------------------------------------------------
        # combined threat
        # --------------------------------------------------------

        assert (
            center_features[
                9
            ]
            > 0
        )


        # --------------------------------------------------------
        # Isolation Forest
        # --------------------------------------------------------

        assert (
            center_features[
                10
            ]
            > 0
        )


        # --------------------------------------------------------
        # Autoencoder
        # --------------------------------------------------------

        assert (
            center_features[
                11
            ]
            > 0
        )


        # --------------------------------------------------------
        # Dual-AI consensus
        # --------------------------------------------------------

        assert (
            center_features[
                12
            ]
            > 0
        )


        # --------------------------------------------------------
        # Temporal AI
        # --------------------------------------------------------

        assert (
            center_features[
                13
            ]
            > 0
        )


        # --------------------------------------------------------
        # Fusion
        # --------------------------------------------------------

        assert (
            center_features[
                14
            ]
            > 0
        )


        print(
            "Behavioral AI features: PASS"
        )


        print(
            "Temporal AI feature: PASS"
        )


        print(
            "Fusion feature: PASS"
        )


        # ========================================================
        # CENTER TELEMETRY FEATURES
        # ========================================================

        assert (
            center_features[
                15
            ]
            > 0
        )


        assert (
            center_features[
                16
            ]
            > 0
        )


        assert (
            center_features[
                17
            ]
            > 0
        )


        assert (
            center_features[
                18
            ]
            > 0
        )


        assert (
            center_features[
                19
            ]
            > 0
        )


        assert (
            center_features[
                20
            ]
            == 1.0
        )


        assert (
            center_features[
                21
            ]
            == 1.0
        )


        print(
            "Process telemetry features: PASS"
        )


        # ========================================================
        # EDGE INDEX SAFETY
        # ========================================================

        if (
            dataset[
                "edge_count"
            ]
            > 0
        ):

            assert (
                dataset[
                    "edge_index"
                ].min()
                >= 0
            )


            assert (
                dataset[
                    "edge_index"
                ].max()
                <
                dataset[
                    "node_count"
                ]
            )


        print(
            "Edge index validation: PASS"
        )


        # ========================================================
        # UNKNOWN TYPE IDs
        #
        # Our controlled graph should contain only defined node
        # and edge types.
        # ========================================================

        assert (
            (
                dataset[
                    "node_type_ids"
                ]
                >= 0
            ).all()
        )


        assert (
            (
                dataset[
                    "edge_type_ids"
                ]
                >= 0
            ).all()
        )


        print(
            "Node/edge type mapping: PASS"
        )


        # ========================================================
        # GRAPH POINTERS
        #
        # One graph:
        #
        # node range:
        #     [0, 11)
        #
        # edge range:
        #     [0, 12)
        # ========================================================

        assert (
            dataset[
                "graph_ptr"
            ].tolist()
            ==
            [
                0,
                11,
            ]
        )


        assert (
            dataset[
                "edge_ptr"
            ].tolist()
            ==
            [
                0,
                12,
            ]
        )


        print(
            "Graph pointer validation: PASS"
        )


        # ========================================================
        # GRAPH IDENTIFIERS
        # ========================================================

        assert (
            len(
                dataset[
                    "graph_ids"
                ]
            )
            == 1
        )


        assert (
            dataset[
                "pids"
            ][
                0
            ]
            ==
            str(
                pid
            )
        )


        assert (
            dataset[
                "process_names"
            ][
                0
            ]
            ==
            process_name
        )


        assert (
            dataset[
                "device_ids"
            ][
                0
            ]
            ==
            device_id
        )


        print(
            "Graph metadata validation: PASS"
        )


        # ========================================================
        # SAVE DATASET
        # ========================================================

        output_path = (

            directory_path
            / "graph_dataset.npz"
        )


        result = (
            dataset_builder.save_dataset(

                dataset,

                output_path=
                    output_path,
            )
        )


        print()

        print(
            "Dataset:",
            result[
                "dataset_path"
            ],
        )


        print(
            "Manifest:",
            result[
                "manifest_path"
            ],
        )


        assert (
            result[
                "dataset_path"
            ].exists()
        )


        assert (
            result[
                "manifest_path"
            ].exists()
        )


        # ========================================================
        # RELOAD DATASET
        #
        # CRITICAL WINDOWS FIX
        # --------------------
        #
        # np.load() on .npz returns an NpzFile backed by an open
        # ZIP file.
        #
        # If we write:
        #
        #     loaded = np.load(...)
        #
        # and do not explicitly close it, Windows continues to
        # hold graph_dataset.npz open.
        #
        # TemporaryDirectory then fails with:
        #
        #     PermissionError: [WinError 32]
        #
        # Using `with np.load(...) as loaded:` guarantees the
        # underlying file is closed before directory cleanup.
        # ========================================================

        with np.load(
            result[
                "dataset_path"
            ],
            allow_pickle=False,
        ) as loaded:

            # ====================================================
            # FEATURE MATRIX
            # ====================================================

            assert (
                loaded[
                    "x"
                ].shape
                ==
                (
                    11,
                    32,
                )
            )


            # ====================================================
            # NODE TYPES
            # ====================================================

            assert (
                loaded[
                    "node_type_ids"
                ].shape
                ==
                (
                    11,
                )
            )


            # ====================================================
            # EDGE INDEX
            # ====================================================

            assert (
                loaded[
                    "edge_index"
                ].shape
                ==
                (
                    2,
                    12,
                )
            )


            # ====================================================
            # EDGE TYPES
            # ====================================================

            assert (
                loaded[
                    "edge_type_ids"
                ].shape
                ==
                (
                    12,
                )
            )


            # ====================================================
            # GRAPH POINTER
            # ====================================================

            assert (
                loaded[
                    "graph_ptr"
                ].tolist()
                ==
                [
                    0,
                    11,
                ]
            )


            # ====================================================
            # EDGE POINTER
            # ====================================================

            assert (
                loaded[
                    "edge_ptr"
                ].tolist()
                ==
                [
                    0,
                    12,
                ]
            )


            # ====================================================
            # CENTER NODE
            # ====================================================

            assert (
                loaded[
                    "center_node_indices"
                ].tolist()
                ==
                [
                    center_index
                ]
            )


            # ====================================================
            # FEATURE NAMES
            # ====================================================

            assert (
                len(
                    loaded[
                        "feature_names"
                    ]
                )
                == 32
            )


            # ====================================================
            # NUMERICAL SAFETY AFTER RELOAD
            # ====================================================

            assert (
                np.isfinite(
                    loaded[
                        "x"
                    ]
                ).all()
            )


        # ========================================================
        # At this point the NpzFile has definitely been CLOSED.
        # ========================================================

        print(
            "NPZ reload: PASS"
        )


        print(
            "NPZ file handle closed: PASS"
        )


        # ========================================================
        # MANIFEST
        # ========================================================

        with open(
            result[
                "manifest_path"
            ],
            "r",
            encoding="utf-8",
        ) as file:

            manifest = (
                json.load(
                    file
                )
            )


        # ========================================================
        # MANIFEST VERSION
        # ========================================================

        assert (
            manifest[
                "dataset_version"
            ]
            ==
            "sentinelx_graph_dataset_v1"
        )


        # ========================================================
        # FEATURE COUNT
        # ========================================================

        assert (
            manifest[
                "feature_count"
            ]
            == 32
        )


        assert (
            len(
                manifest[
                    "feature_names"
                ]
            )
            == 32
        )


        # ========================================================
        # DATASET COUNTS
        # ========================================================

        assert (
            manifest[
                "graph_count"
            ]
            == 1
        )


        assert (
            manifest[
                "node_count"
            ]
            == 11
        )


        assert (
            manifest[
                "edge_count"
            ]
            == 12
        )


        # ========================================================
        # LABEL POLICY
        #
        # We DO NOT currently have ground-truth malicious/benign
        # labels for these process provenance graphs.
        # ========================================================

        assert (
            manifest[
                "labels_available"
            ]
            is False
        )


        # ========================================================
        # LEARNING MODE
        # ========================================================

        assert (
            manifest[
                "learning_mode"
            ]
            ==
            (
                "SELF_SUPERVISED_"
                "REPRESENTATION_LEARNING"
            )
        )


        print(
            "Manifest validation: PASS"
        )


        print(
            "No fabricated graph labels: PASS"
        )


        # ========================================================
        # CLOSE GRAPH SERVICES
        #
        # ProvenanceGraphStore currently uses short-lived SQLite
        # connections, but these close() calls are retained for
        # clean lifecycle management and future compatibility.
        # ========================================================

        dataset_builder.close()

        builder.close()


        print(
            "Graph resources closed: PASS"
        )


    # ============================================================
    # IMPORTANT
    #
    # Reaching this point proves Windows successfully deleted:
    #
    #   graph_dataset_test.db
    #   graph_dataset.npz
    #   graph_dataset.manifest.json
    #
    # Therefore there are no lingering SQLite / NPZ handles.
    # ============================================================

    heading(
        "GRAPH FEATURE + DATASET BUILDER TEST: PASS"
    )


if __name__ == "__main__":

    main()