from __future__ import annotations

import threading
import time

from collections import (
    defaultdict,
    deque,
)

from typing import (
    Any,
    Deque,
    Dict,
    Optional,
    Set,
    Tuple,
)


# ================================================================
# PROCESS BEHAVIOR CONTEXT TRACKER
#
# Maintains a rolling behavioral history for every process PID.
#
# Current reliable attribution:
#
#   PROCESS  -> PID
#   NETWORK  -> PID
#
# Future attribution:
#
#   FILE     -> PID using Sysmon / ETW
#   REGISTRY -> PID using Sysmon / ETW
#
# The object is shared by multiple collector threads, therefore
# access is protected by a re-entrant lock.
# ================================================================


class ProcessBehaviorContextTracker:

    def __init__(
        self,
        window_seconds: float = 300.0,
    ):

        self.window_seconds = float(
            window_seconds
        )

        self.lock = threading.RLock()

        # ========================================================
        # PROCESS ACTIVITY
        # ========================================================

        self.process_events: Dict[
            int,
            Deque[float],
        ] = defaultdict(
            deque
        )

        # ========================================================
        # NETWORK ACTIVITY
        #
        # Structure:
        #
        # PID -> deque([
        #     (
        #         timestamp,
        #         remote_ip
        #     )
        # ])
        # ========================================================

        self.network_events: Dict[
            int,
            Deque[
                Tuple[
                    float,
                    Optional[str],
                ]
            ],
        ] = defaultdict(
            deque
        )

        # ========================================================
        # FILE ACTIVITY
        #
        # PID attribution will be used later when a Windows-native
        # telemetry source such as Sysmon / ETW is integrated.
        # ========================================================

        self.file_events: Dict[
            int,
            Deque[float],
        ] = defaultdict(
            deque
        )

        # ========================================================
        # REGISTRY ACTIVITY
        # ========================================================

        self.registry_events: Dict[
            int,
            Deque[float],
        ] = defaultdict(
            deque
        )

        # ========================================================
        # CHILD PROCESS ACTIVITY
        #
        # Stored under the parent's PID.
        # ========================================================

        self.child_process_events: Dict[
            int,
            Deque[float],
        ] = defaultdict(
            deque
        )

        # ========================================================
        # UNATTRIBUTED ACTIVITY
        #
        # Watchdog and polling-based registry monitoring currently
        # do not reliably identify the originating PID.
        #
        # We intentionally keep those events separate rather than
        # assigning them to an incorrect process.
        # ========================================================

        self.unattributed_file_events: Deque[
            float
        ] = deque()

        self.unattributed_registry_events: Deque[
            float
        ] = deque()


    # ============================================================
    # CURRENT TIME
    # ============================================================

    def _now(
        self,
    ) -> float:

        return time.time()


    # ============================================================
    # NORMALIZE PID
    # ============================================================

    def _normalize_pid(
        self,
        pid: Any,
    ) -> Optional[int]:

        if pid is None:

            return None

        try:

            normalized = int(
                pid
            )

        except (
            TypeError,
            ValueError,
        ):

            return None

        if normalized <= 0:

            return None

        return normalized


    # ============================================================
    # PRUNE TIMESTAMP DEQUE
    # ============================================================

    def _prune_timestamp_deque(
        self,
        values: Deque[float],
        now: float,
    ) -> None:

        cutoff = (
            now
            - self.window_seconds
        )

        while (
            values
            and values[0] < cutoff
        ):

            values.popleft()


    # ============================================================
    # PRUNE NETWORK DEQUE
    # ============================================================

    def _prune_network_deque(
        self,
        values: Deque[
            Tuple[
                float,
                Optional[str],
            ]
        ],
        now: float,
    ) -> None:

        cutoff = (
            now
            - self.window_seconds
        )

        while (
            values
            and values[0][0] < cutoff
        ):

            values.popleft()


    # ============================================================
    # RECORD PROCESS ACTIVITY
    # ============================================================

    def record_process_activity(
        self,
        pid: Any,
    ) -> None:

        normalized_pid = (
            self._normalize_pid(
                pid
            )
        )

        if normalized_pid is None:

            return

        now = (
            self._now()
        )

        with self.lock:

            events = (
                self.process_events[
                    normalized_pid
                ]
            )

            events.append(
                now
            )

            self._prune_timestamp_deque(
                events,
                now,
            )


    # ============================================================
    # RECORD CHILD PROCESS
    # ============================================================

    def record_child_process(
        self,
        parent_pid: Any,
    ) -> None:

        normalized_pid = (
            self._normalize_pid(
                parent_pid
            )
        )

        if normalized_pid is None:

            return

        now = (
            self._now()
        )

        with self.lock:

            events = (
                self.child_process_events[
                    normalized_pid
                ]
            )

            events.append(
                now
            )

            self._prune_timestamp_deque(
                events,
                now,
            )


    # ============================================================
    # RECORD NETWORK ACTIVITY
    # ============================================================

    def record_network_activity(
        self,
        pid: Any,
        remote_ip: Optional[str] = None,
    ) -> None:

        normalized_pid = (
            self._normalize_pid(
                pid
            )
        )

        if normalized_pid is None:

            return

        normalized_remote_ip = (

            str(
                remote_ip
            ).strip()

            if remote_ip
            else None
        )

        now = (
            self._now()
        )

        with self.lock:

            events = (
                self.network_events[
                    normalized_pid
                ]
            )

            events.append(
                (
                    now,
                    normalized_remote_ip,
                )
            )

            self._prune_network_deque(
                events,
                now,
            )


    # ============================================================
    # RECORD FILE ACTIVITY
    # ============================================================

    def record_file_activity(
        self,
        pid: Any = None,
    ) -> None:

        normalized_pid = (
            self._normalize_pid(
                pid
            )
        )

        now = (
            self._now()
        )

        with self.lock:

            # ----------------------------------------------------
            # NO RELIABLE PID
            # ----------------------------------------------------

            if normalized_pid is None:

                self.unattributed_file_events.append(
                    now
                )

                self._prune_timestamp_deque(
                    self.unattributed_file_events,
                    now,
                )

                return

            # ----------------------------------------------------
            # PID-ATTRIBUTED EVENT
            # ----------------------------------------------------

            events = (
                self.file_events[
                    normalized_pid
                ]
            )

            events.append(
                now
            )

            self._prune_timestamp_deque(
                events,
                now,
            )


    # ============================================================
    # RECORD REGISTRY ACTIVITY
    # ============================================================

    def record_registry_activity(
        self,
        pid: Any = None,
    ) -> None:

        normalized_pid = (
            self._normalize_pid(
                pid
            )
        )

        now = (
            self._now()
        )

        with self.lock:

            # ----------------------------------------------------
            # NO RELIABLE PID
            # ----------------------------------------------------

            if normalized_pid is None:

                self.unattributed_registry_events.append(
                    now
                )

                self._prune_timestamp_deque(
                    self.unattributed_registry_events,
                    now,
                )

                return

            # ----------------------------------------------------
            # PID-ATTRIBUTED EVENT
            # ----------------------------------------------------

            events = (
                self.registry_events[
                    normalized_pid
                ]
            )

            events.append(
                now
            )

            self._prune_timestamp_deque(
                events,
                now,
            )


    # ============================================================
    # GET PROCESS CONTEXT
    # ============================================================

    def get_context(
        self,
        pid: Any,
    ) -> Dict[
        str,
        float,
    ]:

        normalized_pid = (
            self._normalize_pid(
                pid
            )
        )

        # --------------------------------------------------------
        # INVALID PID
        # --------------------------------------------------------

        if normalized_pid is None:

            return {

                "child_process_count":
                    0.0,

                "network_connection_count":
                    0.0,

                "unique_remote_ip_count":
                    0.0,

                "file_activity_count":
                    0.0,

                "registry_activity_count":
                    0.0,

                "recent_event_count":
                    0.0,
            }

        now = (
            self._now()
        )

        with self.lock:

            process_events = (
                self.process_events[
                    normalized_pid
                ]
            )

            network_events = (
                self.network_events[
                    normalized_pid
                ]
            )

            file_events = (
                self.file_events[
                    normalized_pid
                ]
            )

            registry_events = (
                self.registry_events[
                    normalized_pid
                ]
            )

            child_events = (
                self.child_process_events[
                    normalized_pid
                ]
            )

            # ----------------------------------------------------
            # REMOVE OLD ACTIVITY
            # ----------------------------------------------------

            self._prune_timestamp_deque(
                process_events,
                now,
            )

            self._prune_network_deque(
                network_events,
                now,
            )

            self._prune_timestamp_deque(
                file_events,
                now,
            )

            self._prune_timestamp_deque(
                registry_events,
                now,
            )

            self._prune_timestamp_deque(
                child_events,
                now,
            )

            # ----------------------------------------------------
            # UNIQUE NETWORK DESTINATIONS
            # ----------------------------------------------------

            remote_ips: Set[str] = {

                remote_ip

                for (
                    _,
                    remote_ip,
                )
                in network_events

                if remote_ip
            }

            # ----------------------------------------------------
            # TOTAL RECENT ACTIVITY
            # ----------------------------------------------------

            recent_event_count = (

                len(
                    process_events
                )

                + len(
                    network_events
                )

                + len(
                    file_events
                )

                + len(
                    registry_events
                )

                + len(
                    child_events
                )
            )

            return {

                "child_process_count":
                    float(
                        len(
                            child_events
                        )
                    ),

                "network_connection_count":
                    float(
                        len(
                            network_events
                        )
                    ),

                "unique_remote_ip_count":
                    float(
                        len(
                            remote_ips
                        )
                    ),

                "file_activity_count":
                    float(
                        len(
                            file_events
                        )
                    ),

                "registry_activity_count":
                    float(
                        len(
                            registry_events
                        )
                    ),

                "recent_event_count":
                    float(
                        recent_event_count
                    ),
            }


    # ============================================================
    # GET GLOBAL UNATTRIBUTED CONTEXT
    # ============================================================

    def get_global_context(
        self,
    ) -> Dict[
        str,
        float,
    ]:

        now = (
            self._now()
        )

        with self.lock:

            self._prune_timestamp_deque(
                self.unattributed_file_events,
                now,
            )

            self._prune_timestamp_deque(
                self.unattributed_registry_events,
                now,
            )

            return {

                "unattributed_file_activity_count":
                    float(
                        len(
                            self.unattributed_file_events
                        )
                    ),

                "unattributed_registry_activity_count":
                    float(
                        len(
                            self.unattributed_registry_events
                        )
                    ),
            }


    # ============================================================
    # REMOVE PROCESS CONTEXT
    # ============================================================

    def remove_process(
        self,
        pid: Any,
    ) -> None:

        normalized_pid = (
            self._normalize_pid(
                pid
            )
        )

        if normalized_pid is None:

            return

        with self.lock:

            self.process_events.pop(
                normalized_pid,
                None,
            )

            self.network_events.pop(
                normalized_pid,
                None,
            )

            self.file_events.pop(
                normalized_pid,
                None,
            )

            self.registry_events.pop(
                normalized_pid,
                None,
            )

            self.child_process_events.pop(
                normalized_pid,
                None,
            )


# ================================================================
# SHARED INSTANCE
# ================================================================

shared_process_behavior_context = (
    ProcessBehaviorContextTracker(
        window_seconds=300.0
    )
)


# ================================================================
# MANUAL TEST
# ================================================================

if __name__ == "__main__":

    tracker = (
        ProcessBehaviorContextTracker(
            window_seconds=300.0
        )
    )

    tracker.record_process_activity(
        4242
    )

    tracker.record_child_process(
        4242
    )

    tracker.record_network_activity(
        pid=4242,
        remote_ip="203.0.113.25",
    )

    tracker.record_network_activity(
        pid=4242,
        remote_ip="203.0.113.25",
    )

    tracker.record_network_activity(
        pid=4242,
        remote_ip="198.51.100.10",
    )

    print(
        tracker.get_context(
            4242
        )
    )