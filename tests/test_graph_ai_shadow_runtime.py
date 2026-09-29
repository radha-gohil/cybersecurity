from __future__ import annotations

import sys

from pathlib import Path


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


from endpoint.collectors.graph_ai_process_monitor import (
    GraphAIProcessMonitor,
)


from ai_detection.graph.process_graph_result_store import (
    ProcessGraphResultStore,
)


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


def main():

    heading(
        "SENTINEL-X GRAPH AI SHADOW RUNTIME TEST"
    )


    monitor = (
        GraphAIProcessMonitor(
            poll_interval=2.0
        )
    )


    try:

        status = (
            monitor.get_graph_ai_status()
        )


        print()

        print(
            "Available:",
            status[
                "available"
            ],
        )


        print(
            "Predictor:",
            status[
                "predictor"
            ],
        )


        print(
            "Predictor version:",
            status[
                "predictor_version"
            ],
        )


        print(
            "Model version:",
            status[
                "model_version"
            ],
        )


        print(
            "Calibration:",
            status[
                "calibration_version"
            ],
        )


        print(
            "Calibration quality:",
            status[
                "calibration_quality"
            ],
        )


        print(
            "Mode:",
            status[
                "operating_mode"
            ],
        )


        print(
            "Primary influence:",
            status[
                "primary_influence"
            ],
        )


        assert (
            status[
                "available"
            ]
            is True
        )


        assert (
            status[
                "predictor_version"
            ]
            == "v1"
        )


        assert (
            status[
                "model_version"
            ]
            == "v1"
        )


        assert (
            status[
                "calibration_version"
            ]
            == "v1"
        )


        assert (
            status[
                "operating_mode"
            ]
            ==
            "SHADOW_GRAPH_AI"
        )


        assert (
            status[
                "primary_influence"
            ]
            is False
        )


        assert (
            status[
                "authoritative_alert"
            ]
            is False
        )


        print()

        print(
            "Graph-AI primary isolation: PASS"
        )


        # ========================================================
        # RESULT STORE
        # ========================================================

        store = (
            ProcessGraphResultStore()
        )


        try:

            print()

            print(
                "Persisted graph results:",
                store.count(),
            )


            print(
                "Active graph results:",
                store.count_active(),
            )


            print(
                "Strong graph results:",
                store.count_strong(),
            )


            recent = (
                store.get_recent(
                    limit=5
                )
            )


            print()

            print(
                "Recent rows:",
                len(
                    recent
                ),
            )


            if recent:

                latest = (
                    recent[
                        0
                    ]
                )


                print(
                    "Latest PID:",
                    latest.get(
                        "pid"
                    ),
                )


                print(
                    "Latest score:",
                    latest.get(
                        "graph_anomaly_score"
                    ),
                )


                print(
                    "Latest band:",
                    latest.get(
                        "graph_anomaly_band"
                    ),
                )


                assert (
                    latest.get(
                        "authoritative_alert"
                    )
                    is False
                )


        finally:

            store.close()


    finally:

        monitor.stop()


    heading(
        "GRAPH AI SHADOW RUNTIME TEST: PASS"
    )


if __name__ == "__main__":

    main()