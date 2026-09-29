from __future__ import annotations

import math
import sys

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

from ai_detection.graph.provenance_graph_store import (
    ProvenanceGraphStore,
)

from ai_detection.graph.process_graph_anomaly_predictor import (
    ProcessGraphAnomalyPredictor,
)


# ================================================================
# DISPLAY
# ================================================================

def heading(
    value,
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
# FIND REAL PROCESS
# ================================================================

def find_latest_real_process():

    store = (
        ProvenanceGraphStore()
    )


    try:

        nodes = (
            store.get_nodes(
                limit=100000
            )
        )


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
                    "properties",
                    {}
                )

                or {}
            )


            pid = (
                properties.get(
                    "pid"
                )
            )


            if pid is None:

                continue


            return {
                "pid":
                    pid,

                "process_name":
                    (
                        properties.get(
                            "name"
                        )

                        or

                        node.get(
                            "label"
                        )
                    ),

                "device_id":
                    properties.get(
                        "device_id"
                    ),
            }


    finally:

        store.close()


    return None


# ================================================================
# MAIN
# ================================================================

def main():

    heading(
        "SENTINEL-X REAL GRAPH RUNTIME PREDICTOR TEST"
    )


    process = (
        find_latest_real_process()
    )


    if process is None:

        raise RuntimeError(
            (
                "No real PROCESS node exists in the "
                "provenance graph."
            )
        )


    print()

    print(
        "PID:",
        process[
            "pid"
        ],
    )


    print(
        "Process:",
        process[
            "process_name"
        ],
    )


    print(
        "Device:",
        process[
            "device_id"
        ],
    )


    predictor = (
        ProcessGraphAnomalyPredictor()
    )


    try:

        result = (
            predictor.predict(

                pid=
                    process[
                        "pid"
                    ],

                process_name=
                    process[
                        "process_name"
                    ],

                device_id=
                    process[
                        "device_id"
                    ],
            )
        )


    finally:

        predictor.close()


    heading(
        "GRAPH AI RESULT"
    )


    print()

    print(
        "Available:",
        result[
            "available"
        ],
    )


    print(
        "State:",
        result[
            "state"
        ],
    )


    assert (
        result[
            "available"
        ]
        is True
    )


    assert (
        result[
            "state"
        ]
        ==
        "GRAPH_INFERENCE_COMPLETE"
    )


    print()

    print(
        "Graph nodes:",
        result[
            "graph_node_count"
        ],
    )


    print(
        "Graph edges:",
        result[
            "graph_edge_count"
        ],
    )


    print()

    print(
        "Raw reconstruction error:",
        result[
            "raw_reconstruction_error"
        ],
    )


    print(
        "Center reconstruction error:",
        result[
            "center_reconstruction_error"
        ],
    )


    print(
        "Graph anomaly score:",
        result[
            "graph_anomaly_score"
        ],
    )


    print(
        "Graph anomaly band:",
        result[
            "graph_anomaly_band"
        ],
    )


    # ============================================================
    # NUMERICAL CHECKS
    # ============================================================

    assert math.isfinite(
        result[
            "raw_reconstruction_error"
        ]
    )


    assert math.isfinite(
        result[
            "center_reconstruction_error"
        ]
    )


    assert (
        0.0
        <=
        result[
            "graph_anomaly_score"
        ]
        <=
        100.0
    )


    print()

    print(
        "Graph anomaly numerical safety: PASS"
    )


    # ============================================================
    # EMBEDDING
    # ============================================================

    embedding = np.asarray(

        result[
            "embedding"
        ],

        dtype=np.float32,
    )


    assert (
        embedding.shape
        ==
        (
            64,
        )
    )


    assert (
        np.isfinite(
            embedding
        ).all()
    )


    assert (
        np.linalg.norm(
            embedding
        )
        > 0
    )


    print(
        "64-D graph embedding: PASS"
    )


    # ============================================================
    # CALIBRATION
    # ============================================================

    assert (
        result[
            "calibration_version"
        ]
        == "v1"
    )


    print(
        "Graph calibration v1: PASS"
    )


    # ============================================================
    # SAFETY
    # ============================================================

    assert (
        result[
            "authoritative_alert"
        ]
        is False
    )


    assert (
        result[
            "operating_mode"
        ]
        ==
        "SHADOW_GRAPH_AI"
    )


    print(
        "Shadow-mode safety: PASS"
    )


    # ============================================================
    # EVIDENCE COVERAGE
    # ============================================================

    coverage = (
        result[
            "ai_evidence_coverage"
        ]
    )


    print()

    print(
        "Upstream AI evidence:"
    )


    for (
        key,
        value,
    ) in coverage[
        "availability"
    ].items():

        print(
            f"{key:<24}: "
            f"{value}"
        )


    print()

    print(
        "Coverage:",
        coverage[
            "coverage"
        ],
    )


    # ============================================================
    # FINAL
    # ============================================================

    heading(
        "REAL GRAPH RUNTIME PREDICTOR: PASS"
    )


if __name__ == "__main__":

    main()