from __future__ import annotations

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
        str(PROJECT_ROOT),
    )


# ================================================================
# SENTINEL-X IMPORT
# ================================================================

from ai_detection.temporal.process_temporal_buffer import (
    ProcessTemporalBuffer,
)


# ================================================================
# SENTINEL-X TEMPORAL BUFFER E2E TEST
# ================================================================

PID = 4321

CREATE_TIME = 1700000000.0

FEATURE_COUNT = 27

SEQUENCE_LENGTH = 8


# ================================================================
# MAIN
# ================================================================

def main():

    print()

    print(
        "=" * 80
    )

    print(
        "SENTINEL-X TEMPORAL BUFFER E2E TEST"
    )

    print(
        "=" * 80
    )


    # ============================================================
    # CREATE BUFFER
    # ============================================================

    buffer = (
        ProcessTemporalBuffer(

            sequence_length=
                SEQUENCE_LENGTH,

            expected_feature_count=
                FEATURE_COUNT,

            max_observation_gap_seconds=
                180.0,
        )
    )


    base_timestamp = (
        1800000000.0
    )


    # ============================================================
    # TEST 1
    # ADD 8 CONTIGUOUS OBSERVATIONS
    # ============================================================

    print()

    print(
        "[1] Adding 8 continuous observations..."
    )


    for index in range(
        SEQUENCE_LENGTH
    ):

        vector = np.full(

            FEATURE_COUNT,

            float(
                index + 1
            ),

            dtype=np.float64,
        )


        result = (
            buffer.add_observation(

                pid=
                    PID,

                create_time=
                    CREATE_TIME,

                vector=
                    vector,

                timestamp=
                    (
                        base_timestamp
                        + (
                            index
                            * 60.0
                        )
                    ),

                feature_record_id=
                    (
                        1000
                        + index
                    ),

                process_name=
                    "test.exe",
            )
        )


        print(

            f"Observation {index + 1} | "
            f"Depth={result['depth']} | "
            f"Ready={result['ready']} | "
            f"Reset={result['reset_due_to_gap']}"
        )


    # ============================================================
    # TEST 2
    # READY STATE
    # ============================================================

    print()

    print(
        "[2] Checking sequence readiness..."
    )


    assert buffer.is_ready(

        pid=
            PID,

        create_time=
            CREATE_TIME,

    ) is True


    sequence = (
        buffer.get_sequence(

            pid=
                PID,

            create_time=
                CREATE_TIME,
        )
    )


    assert sequence is not None


    assert sequence.shape == (

        SEQUENCE_LENGTH,

        FEATURE_COUNT,
    )


    record_ids = (
        buffer.get_feature_record_ids(

            pid=
                PID,

            create_time=
                CREATE_TIME,
        )
    )


    expected_record_ids = [

        1000,
        1001,
        1002,
        1003,
        1004,
        1005,
        1006,
        1007,
    ]


    assert record_ids == (
        expected_record_ids
    )


    print(
        "Sequence shape:",
        sequence.shape,
    )


    print(
        "Record IDs:",
        record_ids,
    )


    print(
        "Sequence readiness: PASS"
    )


    # ============================================================
    # TEST 3
    # ROLLING WINDOW
    # ============================================================

    print()

    print(
        "[3] Testing rolling window..."
    )


    ninth_vector = np.full(

        FEATURE_COUNT,

        9.0,

        dtype=np.float64,
    )


    result = (
        buffer.add_observation(

            pid=
                PID,

            create_time=
                CREATE_TIME,

            vector=
                ninth_vector,

            timestamp=
                (
                    base_timestamp
                    + (
                        8
                        * 60.0
                    )
                ),

            feature_record_id=
                1008,

            process_name=
                "test.exe",
        )
    )


    assert result[
        "depth"
    ] == SEQUENCE_LENGTH


    assert result[
        "ready"
    ] is True


    record_ids = (
        buffer.get_feature_record_ids(

            pid=
                PID,

            create_time=
                CREATE_TIME,
        )
    )


    expected_rolling_ids = [

        1001,
        1002,
        1003,
        1004,
        1005,
        1006,
        1007,
        1008,
    ]


    assert record_ids == (
        expected_rolling_ids
    )


    print(
        "Rolling record IDs:",
        record_ids,
    )


    print(
        "Rolling-window test: PASS"
    )


    # ============================================================
    # TEST 4
    # LARGE GAP RESET
    # ============================================================

    print()

    print(
        "[4] Testing temporal-gap reset..."
    )


    result = (
        buffer.add_observation(

            pid=
                PID,

            create_time=
                CREATE_TIME,

            vector=
                np.full(

                    FEATURE_COUNT,

                    10.0,

                    dtype=np.float64,
                ),

            timestamp=
                (
                    base_timestamp
                    + 2000.0
                ),

            feature_record_id=
                2000,

            process_name=
                "test.exe",
        )
    )


    assert result[
        "reset_due_to_gap"
    ] is True


    assert result[
        "depth"
    ] == 1


    assert result[
        "ready"
    ] is False


    print(
        "Depth after gap:",
        result[
            "depth"
        ],
    )


    print(
        "Large-gap reset: PASS"
    )


    # ============================================================
    # TEST 5
    # PID REUSE
    # ============================================================

    print()

    print(
        "[5] Testing PID reuse protection..."
    )


    new_create_time = (

        CREATE_TIME

        + 5000.0
    )


    result = (
        buffer.add_observation(

            pid=
                PID,

            create_time=
                new_create_time,

            vector=
                np.ones(

                    FEATURE_COUNT,

                    dtype=np.float64,
                ),

            timestamp=
                (
                    base_timestamp
                    + 2010.0
                ),

            feature_record_id=
                3000,

            process_name=
                "different.exe",
        )
    )


    assert result[
        "depth"
    ] == 1


    states = (
        buffer.list_states()
    )


    assert len(
        states
    ) == 2


    print(
        "Stored process instances:",
        len(
            states
        ),
    )


    print(
        "PID reuse protection: PASS"
    )


    # ============================================================
    # TEST 6
    # BUFFER STATUS
    # ============================================================

    print()

    print(
        "[6] Checking buffer status..."
    )


    status = (
        buffer.get_status()
    )


    for (
        key,
        value,
    ) in status.items():

        print(
            f"{key:<35}: {value}"
        )


    assert status[
        "process_instances"
    ] == 2


    # ============================================================
    # TEST 7
    # REMOVE PID
    # ============================================================

    print()

    print(
        "[7] Testing PID cleanup..."
    )


    removed = (
        buffer.remove_pid(
            PID
        )
    )


    assert removed == 2


    final_status = (
        buffer.get_status()
    )


    assert final_status[
        "process_instances"
    ] == 0


    print(
        "Removed states:",
        removed,
    )


    print(
        "PID cleanup: PASS"
    )


    # ============================================================
    # FINAL
    # ============================================================

    print()

    print(
        "=" * 80
    )

    print(
        "TEMPORAL BUFFER E2E TEST: PASS"
    )

    print(
        "=" * 80
    )


# ================================================================
# ENTRY
# ================================================================

if __name__ == "__main__":

    main()