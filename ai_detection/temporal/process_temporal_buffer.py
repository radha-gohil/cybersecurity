from __future__ import annotations

import threading
import time

from collections import (
    deque,
)

from dataclasses import (
    dataclass,
    field,
)

from typing import (
    Any,
    Deque,
    Dict,
    List,
    Optional,
    Tuple,
)

import numpy as np


# ================================================================
# SENTINEL-X LIVE TEMPORAL PROCESS BUFFER V1
#
# Maintains a rolling sequence of endpoint observations for each
# real process instance.
#
# Process identity:
#
#       PID + process create_time
#
# NOT PID alone.
#
# Why:
#
# Windows can reuse a PID after a process terminates.
#
#
# Buffer:
#
#       observation 1
#       observation 2
#       ...
#       observation 8
#
#               ↓
#
#       Transformer-ready sequence
#
#
# Every observation must already contain the complete RAW temporal
# 27-feature vector:
#
#       19 behavior model features
#        4 Autoencoder embedding dimensions
#        1 Isolation Forest score
#        1 Autoencoder score
#        1 Dual-AI consensus score
#        1 delta_seconds
#       --------------------------------
#       27
#
# The temporal predictor performs normalization itself.
# ================================================================


# ================================================================
# CONFIGURATION
# ================================================================

BUFFER_VERSION = "v1"


SEQUENCE_LENGTH = 8


EXPECTED_FEATURE_COUNT = 27


# If two observations for the same process are separated by more
# than this, reset its temporal history.
#
# Your measured endpoint cadence was approximately 60 seconds.
# 180 seconds gives reasonable scheduling tolerance while still
# protecting temporal continuity.

MAX_OBSERVATION_GAP_SECONDS = 180.0


# Remove dead/stale process buffers eventually.

STALE_BUFFER_SECONDS = 900.0


# ================================================================
# PROCESS KEY
# ================================================================

@dataclass(
    frozen=True
)
class ProcessTemporalKey:

    pid: int

    create_time: float


# ================================================================
# OBSERVATION
# ================================================================

@dataclass
class TemporalObservation:

    timestamp: float

    feature_record_id: Optional[int]

    vector: List[float]

    process_name: str = "UNKNOWN"

    metadata: Dict[str, Any] = field(
        default_factory=dict
    )


# ================================================================
# PROCESS BUFFER STATE
# ================================================================

@dataclass
class ProcessTemporalState:

    key: ProcessTemporalKey

    process_name: str

    observations: Deque[
        TemporalObservation
    ] = field(
        default_factory=lambda:
            deque(
                maxlen=SEQUENCE_LENGTH
            )
    )

    first_seen: float = field(
        default_factory=time.time
    )

    last_seen: float = field(
        default_factory=time.time
    )

    sequence_generation: int = 0


# ================================================================
# TEMPORAL BUFFER
# ================================================================

class ProcessTemporalBuffer:

    def __init__(
        self,
        sequence_length: int = SEQUENCE_LENGTH,
        expected_feature_count: int = EXPECTED_FEATURE_COUNT,
        max_observation_gap_seconds: float = MAX_OBSERVATION_GAP_SECONDS,
        stale_buffer_seconds: float = STALE_BUFFER_SECONDS,
    ):

        self.sequence_length = int(
            sequence_length
        )


        self.expected_feature_count = int(
            expected_feature_count
        )


        self.max_observation_gap_seconds = float(
            max_observation_gap_seconds
        )


        self.stale_buffer_seconds = float(
            stale_buffer_seconds
        )


        self._states: Dict[
            ProcessTemporalKey,
            ProcessTemporalState,
        ] = {}


        self._lock = (
            threading.RLock()
        )


    # ============================================================
    # PROCESS KEY
    # ============================================================

    def build_key(
        self,
        pid: Any,
        create_time: Any,
    ) -> ProcessTemporalKey:

        try:

            pid_value = int(
                pid
            )


        except (
            TypeError,
            ValueError,
        ) as error:

            raise ValueError(
                f"Invalid PID: {pid}"
            ) from error


        try:

            create_time_value = float(
                create_time
            )


        except (
            TypeError,
            ValueError,
        ) as error:

            raise ValueError(
                f"Invalid process create_time: {create_time}"
            ) from error


        if not np.isfinite(
            create_time_value
        ):

            raise ValueError(
                "Process create_time must be finite."
            )


        return ProcessTemporalKey(

            pid=
                pid_value,

            create_time=
                create_time_value,
        )


    # ============================================================
    # VECTOR VALIDATION
    # ============================================================

    def validate_vector(
        self,
        vector: Any,
    ) -> List[float]:

        array = np.asarray(

            vector,

            dtype=np.float64,
        )


        if array.ndim != 1:

            raise ValueError(

                "Temporal observation must be "
                "a one-dimensional feature vector."
            )


        if (

            array.shape[
                0
            ]

            != self.expected_feature_count

        ):

            raise ValueError(

                "Temporal observation feature count mismatch. "
                f"Expected {self.expected_feature_count}, "
                f"received {array.shape[0]}."
            )


        if not np.all(
            np.isfinite(
                array
            )
        ):

            raise ValueError(

                "Temporal observation contains "
                "NaN or infinity."
            )


        return (

            array
            .astype(
                np.float64
            )
            .tolist()
        )


    # ============================================================
    # ADD OBSERVATION
    # ============================================================

    def add_observation(
        self,
        *,
        pid: Any,
        create_time: Any,
        vector: Any,
        timestamp: Optional[float] = None,
        feature_record_id: Optional[int] = None,
        process_name: Optional[str] = None,
        metadata: Optional[
            Dict[str, Any]
        ] = None,
    ) -> Dict[str, Any]:

        timestamp_value = (

            float(
                timestamp
            )

            if timestamp is not None

            else time.time()
        )


        if not np.isfinite(
            timestamp_value
        ):

            raise ValueError(
                "Observation timestamp must be finite."
            )


        key = (
            self.build_key(

                pid=
                    pid,

                create_time=
                    create_time,
            )
        )


        parsed_vector = (
            self.validate_vector(
                vector
            )
        )


        process_name_value = (

            str(
                process_name
                or "UNKNOWN"
            )
            .strip()

            or "UNKNOWN"
        )


        observation_metadata = dict(
            metadata
            or {}
        )


        with self._lock:

            state = (
                self._states.get(
                    key
                )
            )


            reset_due_to_gap = False


            if state is None:

                state = (
                    ProcessTemporalState(

                        key=
                            key,

                        process_name=
                            process_name_value,

                        observations=
                            deque(
                                maxlen=
                                    self.sequence_length
                            ),

                        first_seen=
                            timestamp_value,

                        last_seen=
                            timestamp_value,
                    )
                )


                self._states[
                    key
                ] = state


            else:

                # =================================================
                # CONTINUITY CHECK
                # =================================================

                if state.observations:

                    previous_timestamp = (

                        state
                        .observations[
                            -1
                        ]
                        .timestamp
                    )


                    gap = (

                        timestamp_value

                        - previous_timestamp
                    )


                    if (

                        gap <= 0.0

                        or

                        gap
                        > self.max_observation_gap_seconds

                    ):

                        state.observations.clear()

                        state.sequence_generation += 1

                        state.first_seen = (
                            timestamp_value
                        )

                        reset_due_to_gap = True


                state.process_name = (
                    process_name_value
                )


                state.last_seen = (
                    timestamp_value
                )


            observation = (
                TemporalObservation(

                    timestamp=
                        timestamp_value,

                    feature_record_id=
                        feature_record_id,

                    vector=
                        parsed_vector,

                    process_name=
                        process_name_value,

                    metadata=
                        observation_metadata,
                )
            )


            state.observations.append(
                observation
            )


            depth = len(
                state.observations
            )


            ready = (

                depth

                >= self.sequence_length
            )


            return {
                "pid":
                    key.pid,

                "create_time":
                    key.create_time,

                "process_name":
                    state.process_name,

                "depth":
                    depth,

                "required_depth":
                    self.sequence_length,

                "ready":
                    ready,

                "reset_due_to_gap":
                    reset_due_to_gap,

                "sequence_generation":
                    state.sequence_generation,

                "oldest_timestamp":
                    (
                        state
                        .observations[
                            0
                        ]
                        .timestamp

                        if state.observations

                        else None
                    ),

                "latest_timestamp":
                    (
                        state
                        .observations[
                            -1
                        ]
                        .timestamp

                        if state.observations

                        else None
                    ),
            }


    # ============================================================
    # GET RAW SEQUENCE
    # ============================================================

    def get_sequence(
        self,
        *,
        pid: Any,
        create_time: Any,
    ) -> Optional[np.ndarray]:

        key = (
            self.build_key(

                pid=
                    pid,

                create_time=
                    create_time,
            )
        )


        with self._lock:

            state = (
                self._states.get(
                    key
                )
            )


            if state is None:

                return None


            if (

                len(
                    state.observations
                )

                < self.sequence_length

            ):

                return None


            observations = list(
                state.observations
            )[
                -self.sequence_length:
            ]


            matrix = np.asarray(

                [
                    observation.vector

                    for observation
                    in observations
                ],

                dtype=np.float64,
            )


            expected_shape = (

                self.sequence_length,

                self.expected_feature_count,
            )


            if matrix.shape != expected_shape:

                raise RuntimeError(

                    "Internal temporal-buffer "
                    "shape corruption detected. "
                    f"Expected {expected_shape}, "
                    f"found {matrix.shape}."
                )


            return matrix


    # ============================================================
    # GET RECORD IDS
    # ============================================================

    def get_feature_record_ids(
        self,
        *,
        pid: Any,
        create_time: Any,
    ) -> Optional[
        List[
            Optional[int]
        ]
    ]:

        key = (
            self.build_key(

                pid=
                    pid,

                create_time=
                    create_time,
            )
        )


        with self._lock:

            state = (
                self._states.get(
                    key
                )
            )


            if state is None:

                return None


            if (

                len(
                    state.observations
                )

                < self.sequence_length

            ):

                return None


            observations = list(
                state.observations
            )[
                -self.sequence_length:
            ]


            return [

                observation.feature_record_id

                for observation
                in observations
            ]


    # ============================================================
    # GET OBSERVATION METADATA
    # ============================================================

    def get_observation_metadata(
        self,
        *,
        pid: Any,
        create_time: Any,
    ) -> Optional[
        List[
            Dict[str, Any]
        ]
    ]:

        key = (
            self.build_key(

                pid=
                    pid,

                create_time=
                    create_time,
            )
        )


        with self._lock:

            state = (
                self._states.get(
                    key
                )
            )


            if state is None:

                return None


            return [

                {
                    "timestamp":
                        observation.timestamp,

                    "feature_record_id":
                        observation.feature_record_id,

                    "process_name":
                        observation.process_name,

                    "metadata":
                        dict(
                            observation.metadata
                        ),
                }

                for observation
                in state.observations
            ]


    # ============================================================
    # DEPTH
    # ============================================================

    def get_depth(
        self,
        *,
        pid: Any,
        create_time: Any,
    ) -> int:

        key = (
            self.build_key(

                pid=
                    pid,

                create_time=
                    create_time,
            )
        )


        with self._lock:

            state = (
                self._states.get(
                    key
                )
            )


            if state is None:

                return 0


            return len(
                state.observations
            )


    # ============================================================
    # READY
    # ============================================================

    def is_ready(
        self,
        *,
        pid: Any,
        create_time: Any,
    ) -> bool:

        return (

            self.get_depth(

                pid=
                    pid,

                create_time=
                    create_time,
            )

            >= self.sequence_length
        )


    # ============================================================
    # REMOVE PROCESS INSTANCE
    # ============================================================

    def remove(
        self,
        *,
        pid: Any,
        create_time: Any,
    ) -> bool:

        key = (
            self.build_key(

                pid=
                    pid,

                create_time=
                    create_time,
            )
        )


        with self._lock:

            return (

                self._states.pop(
                    key,
                    None,
                )

                is not None
            )


    # ============================================================
    # REMOVE ALL STATES FOR PID
    #
    # Useful when ProcessMonitor observes a process stop.
    # ============================================================

    def remove_pid(
        self,
        pid: Any,
    ) -> int:

        try:

            pid_value = int(
                pid
            )

        except (
            TypeError,
            ValueError,
        ):

            return 0


        with self._lock:

            keys = [

                key

                for key
                in self._states

                if key.pid == pid_value
            ]


            for key in keys:

                self._states.pop(
                    key,
                    None,
                )


            return len(
                keys
            )


    # ============================================================
    # STALE CLEANUP
    # ============================================================

    def cleanup_stale(
        self,
        now: Optional[float] = None,
    ) -> int:

        current_time = (

            float(
                now
            )

            if now is not None

            else time.time()
        )


        with self._lock:

            stale_keys = [

                key

                for (
                    key,
                    state,
                ) in self._states.items()

                if (

                    current_time

                    - state.last_seen

                    > self.stale_buffer_seconds
                )
            ]


            for key in stale_keys:

                self._states.pop(
                    key,
                    None,
                )


            return len(
                stale_keys
            )


    # ============================================================
    # STATUS
    # ============================================================

    def get_status(
        self,
    ) -> Dict[str, Any]:

        with self._lock:

            depths = [

                len(
                    state.observations
                )

                for state
                in self._states.values()
            ]


            ready_count = sum(

                1

                for depth
                in depths

                if depth >= self.sequence_length
            )


            return {
                "buffer_version":
                    BUFFER_VERSION,

                "sequence_length":
                    self.sequence_length,

                "expected_feature_count":
                    self.expected_feature_count,

                "max_observation_gap_seconds":
                    self.max_observation_gap_seconds,

                "process_instances":
                    len(
                        self._states
                    ),

                "ready_process_instances":
                    ready_count,

                "maximum_depth":
                    (
                        max(
                            depths
                        )

                        if depths

                        else 0
                    ),
            }


    # ============================================================
    # ALL PROCESS STATES
    # ============================================================

    def list_states(
        self,
    ) -> List[
        Dict[str, Any]
    ]:

        with self._lock:

            output = []


            for (
                key,
                state,
            ) in self._states.items():

                output.append(
                    {
                        "pid":
                            key.pid,

                        "create_time":
                            key.create_time,

                        "process_name":
                            state.process_name,

                        "depth":
                            len(
                                state.observations
                            ),

                        "ready":
                            (
                                len(
                                    state.observations
                                )

                                >= self.sequence_length
                            ),

                        "first_seen":
                            state.first_seen,

                        "last_seen":
                            state.last_seen,

                        "sequence_generation":
                            state.sequence_generation,
                    }
                )


            output.sort(

                key=lambda item:
                    item[
                        "depth"
                    ],

                reverse=True,
            )


            return output


# ================================================================
# SHARED LIVE BUFFER
# ================================================================

shared_process_temporal_buffer = (
    ProcessTemporalBuffer()
)