from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import List

from detection.fusion.entity_linker import (
    EntityLinker,
)


class EventCorrelator:

    def __init__(
        self,
        correlation_window_seconds: int = 120,
        max_events_per_entity: int = 100,
        entity_link_threshold: int = 40,
    ):

        self.correlation_window_seconds = (
            correlation_window_seconds
        )

        self.max_events_per_entity = (
            max_events_per_entity
        )

        self.events = deque(
            maxlen=2000
        )

        # ========================================================
        # ENTITY INDEXES
        # ========================================================

        self.events_by_pid = defaultdict(
            lambda: deque(
                maxlen=self.max_events_per_entity
            )
        )

        self.events_by_hash = defaultdict(
            lambda: deque(
                maxlen=self.max_events_per_entity
            )
        )

        self.events_by_file = defaultdict(
            lambda: deque(
                maxlen=self.max_events_per_entity
            )
        )

        self.events_by_ip = defaultdict(
            lambda: deque(
                maxlen=self.max_events_per_entity
            )
        )

        # ========================================================
        # CONFIDENCE-BASED ENTITY LINKER
        # ========================================================

        self.entity_linker = (
            EntityLinker(
                minimum_confidence=
                    entity_link_threshold
            )
        )


    # ============================================================
    # CURRENT TIME
    # ============================================================

    def now_timestamp(
        self,
    ) -> float:

        return (
            datetime.now(
                timezone.utc
            ).timestamp()
        )


    # ============================================================
    # NORMALIZE EVENT
    # ============================================================

    def normalize_event(
        self,
        event: dict,
    ) -> dict:

        normalized = dict(
            event
        )

        if (
            "timestamp_unix"
            not in normalized
            or normalized.get(
                "timestamp_unix"
            )
            is None
        ):

            normalized[
                "timestamp_unix"
            ] = self.now_timestamp()


        normalized.setdefault(
            "event_type",
            "unknown",
        )

        normalized.setdefault(
            "source",
            "unknown",
        )

        normalized.setdefault(
            "severity",
            "INFO",
        )

        normalized.setdefault(
            "process",
            {},
        )

        normalized.setdefault(
            "file",
            {},
        )

        normalized.setdefault(
            "network",
            {},
        )

        normalized.setdefault(
            "registry",
            {},
        )

        normalized.setdefault(
            "metadata",
            {},
        )

        return normalized


    # ============================================================
    # EXTRACT PID
    # ============================================================

    def extract_pid(
        self,
        event: dict,
    ):

        process = (
            event.get(
                "process"
            )
            or {}
        )

        network = (
            event.get(
                "network"
            )
            or {}
        )

        registry = (
            event.get(
                "registry"
            )
            or {}
        )

        metadata = (
            event.get(
                "metadata"
            )
            or {}
        )


        pid = process.get(
            "pid"
        )

        if pid is not None:
            return pid


        pid = network.get(
            "pid"
        )

        if pid is not None:
            return pid


        pid = registry.get(
            "pid"
        )

        if pid is not None:
            return pid


        pid = metadata.get(
            "pid"
        )

        if pid is not None:
            return pid


        return None


    # ============================================================
    # EXTRACT SHA256
    # ============================================================

    def extract_sha256(
        self,
        event: dict,
    ):

        file_data = (
            event.get(
                "file"
            )
            or {}
        )

        return (
            file_data.get(
                "sha256"
            )
        )


    # ============================================================
    # EXTRACT FILE PATH
    # ============================================================

    def extract_file_path(
        self,
        event: dict,
    ):

        file_data = (
            event.get(
                "file"
            )
            or {}
        )

        return (
            file_data.get(
                "path"
            )
        )


    # ============================================================
    # EXTRACT REMOTE IP
    # ============================================================

    def extract_remote_ip(
        self,
        event: dict,
    ):

        network = (
            event.get(
                "network"
            )
            or {}
        )

        return (
            network.get(
                "remote_ip"
            )
            or network.get(
                "raddr_ip"
            )
        )


    # ============================================================
    # EVENT CATEGORY
    # ============================================================

    def get_event_category(
        self,
        event: dict,
    ) -> str:

        event_type = str(
            event.get(
                "event_type",
                ""
            )
        ).lower()


        if event_type.startswith(
            "process"
        ):
            return "process"


        if event_type.startswith(
            "file"
        ):
            return "file"


        if event_type.startswith(
            "network"
        ):
            return "network"


        if (
            event_type.startswith(
                "registry"
            )
            or event_type.startswith(
                "startup"
            )
        ):
            return "registry"


        return "other"


    # ============================================================
    # TIME WINDOW
    # ============================================================

    def within_window(
        self,
        event_a: dict,
        event_b: dict,
    ) -> bool:

        try:

            timestamp_a = float(
                event_a.get(
                    "timestamp_unix",
                    0,
                )
            )

        except (
            TypeError,
            ValueError,
        ):

            timestamp_a = 0.0


        try:

            timestamp_b = float(
                event_b.get(
                    "timestamp_unix",
                    0,
                )
            )

        except (
            TypeError,
            ValueError,
        ):

            timestamp_b = 0.0


        difference = abs(
            timestamp_a
            - timestamp_b
        )


        return (
            difference
            <= self.correlation_window_seconds
        )


    # ============================================================
    # ADD EVENT
    # ============================================================

    def add_event(
        self,
        event: dict,
    ) -> dict:

        normalized = (
            self.normalize_event(
                event
            )
        )

        # --------------------------------------------------------
        # CORRELATE BEFORE/AFTER INDEXING IS SAFE BECAUSE
        # get_related_events explicitly ignores the current object.
        # --------------------------------------------------------

        self.events.append(
            normalized
        )


        pid = (
            self.extract_pid(
                normalized
            )
        )

        sha256 = (
            self.extract_sha256(
                normalized
            )
        )

        file_path = (
            self.extract_file_path(
                normalized
            )
        )

        remote_ip = (
            self.extract_remote_ip(
                normalized
            )
        )


        # --------------------------------------------------------
        # PID INDEX
        # --------------------------------------------------------

        if pid is not None:

            self.events_by_pid[
                pid
            ].append(
                normalized
            )


        # --------------------------------------------------------
        # HASH INDEX
        # --------------------------------------------------------

        if sha256:

            self.events_by_hash[
                str(
                    sha256
                ).lower()
            ].append(
                normalized
            )


        # --------------------------------------------------------
        # FILE PATH INDEX
        # --------------------------------------------------------

        if file_path:

            self.events_by_file[
                str(
                    file_path
                ).lower()
            ].append(
                normalized
            )


        # --------------------------------------------------------
        # REMOTE IP INDEX
        # --------------------------------------------------------

        if remote_ip:

            self.events_by_ip[
                str(
                    remote_ip
                )
            ].append(
                normalized
            )


        return (
            self.correlate_event(
                normalized
            )
        )


    # ============================================================
    # ADD UNIQUE RELATED EVENT
    # ============================================================

    def add_related_event(
        self,
        related: list,
        seen_ids: set,
        current_event: dict,
        candidate: dict,
    ):

        if candidate is current_event:

            return


        candidate_id = (
            candidate.get(
                "event_id"
            )
            or id(
                candidate
            )
        )


        if candidate_id in seen_ids:

            return


        if not self.within_window(
            current_event,
            candidate,
        ):

            return


        seen_ids.add(
            candidate_id
        )

        related.append(
            candidate
        )


    # ============================================================
    # GET DIRECT ENTITY CANDIDATES
    # ============================================================

    def get_direct_candidate_groups(
        self,
        event: dict,
    ) -> list:

        groups = []


        pid = (
            self.extract_pid(
                event
            )
        )

        sha256 = (
            self.extract_sha256(
                event
            )
        )

        file_path = (
            self.extract_file_path(
                event
            )
        )

        remote_ip = (
            self.extract_remote_ip(
                event
            )
        )


        if pid is not None:

            groups.append(
                self.events_by_pid[
                    pid
                ]
            )


        if sha256:

            groups.append(
                self.events_by_hash[
                    str(
                        sha256
                    ).lower()
                ]
            )


        if file_path:

            groups.append(
                self.events_by_file[
                    str(
                        file_path
                    ).lower()
                ]
            )


        if remote_ip:

            groups.append(
                self.events_by_ip[
                    str(
                        remote_ip
                    )
                ]
            )


        return groups


    # ============================================================
    # GET RELATED EVENTS
    # ============================================================

    def get_related_events(
        self,
        event: dict,
    ) -> List[dict]:

        related = []

        seen_ids = set()


        # ========================================================
        # 1. DIRECT ENTITY MATCHING
        #
        # PID / hash / path / remote IP
        # ========================================================

        candidate_groups = (
            self.get_direct_candidate_groups(
                event
            )
        )


        for group in candidate_groups:

            for candidate in group:

                self.add_related_event(
                    related,
                    seen_ids,
                    event,
                    candidate,
                )


        # ========================================================
        # 2. CONFIDENCE-BASED ENTITY LINKING
        #
        # Used mainly when a file or registry event does not
        # contain PID information.
        #
        # Time is only used as a search window.
        # It is NOT sufficient to create a link.
        # ========================================================

        for candidate in self.events:

            if candidate is event:

                continue


            candidate_id = (
                candidate.get(
                    "event_id"
                )
                or id(
                    candidate
                )
            )


            if candidate_id in seen_ids:

                continue


            if not self.within_window(
                event,
                candidate,
            ):

                continue


            # ----------------------------------------------------
            # Avoid comparing same event category unless
            # there is useful entity evidence.
            # ----------------------------------------------------

            current_category = (
                self.get_event_category(
                    event
                )
            )

            candidate_category = (
                self.get_event_category(
                    candidate
                )
            )


            if (
                current_category
                == "other"
                or candidate_category
                == "other"
            ):

                continue


            # ----------------------------------------------------
            # ENTITY LINK CONFIDENCE
            # ----------------------------------------------------

            link_result = (
                self.entity_linker.score_pair(
                    event,
                    candidate,
                )
            )


            if not link_result.get(
                "linked",
                False,
            ):

                continue


            # ----------------------------------------------------
            # Store link information on a copy of candidate
            # so original telemetry is not modified.
            # ----------------------------------------------------

            linked_candidate = dict(
                candidate
            )


            linked_candidate[
                "_entity_link"
            ] = {

                "confidence":
                    link_result.get(
                        "confidence",
                        0,
                    ),

                "reasons":
                    link_result.get(
                        "reasons",
                        [],
                    ),
            }


            self.add_related_event(
                related,
                seen_ids,
                event,
                linked_candidate,
            )


        return related


    # ============================================================
    # GET ENTITY LINK CONFIDENCE
    # ============================================================

    def get_max_entity_link_confidence(
        self,
        related_events: List[dict],
    ) -> int:

        max_confidence = 0


        for event in related_events:

            link_data = (
                event.get(
                    "_entity_link"
                )
                or {}
            )


            confidence = (
                link_data.get(
                    "confidence",
                    0,
                )
            )


            try:

                confidence = int(
                    confidence
                )

            except (
                TypeError,
                ValueError,
            ):

                confidence = 0


            max_confidence = max(
                max_confidence,
                confidence,
            )


        return max_confidence


    # ============================================================
    # CORRELATION SCORE
    # ============================================================

    def calculate_correlation_score(
        self,
        event: dict,
        related_events: List[dict],
    ) -> int:

        score = 0


        current_type = str(
            event.get(
                "event_type",
                ""
            )
        ).lower()


        related_types = {

            str(
                related.get(
                    "event_type",
                    ""
                )
            ).lower()

            for related in related_events
        }


        all_events = (
            [event]
            + related_events
        )


        # ========================================================
        # CATEGORY DIVERSITY
        # ========================================================

        categories = set()


        for item in all_events:

            category = (
                self.get_event_category(
                    item
                )
            )

            if category != "other":

                categories.add(
                    category
                )


        if len(
            categories
        ) >= 2:

            score += 20


        if len(
            categories
        ) >= 3:

            score += 20


        if len(
            categories
        ) >= 4:

            score += 20


        # ========================================================
        # PROCESS + FILE
        # ========================================================

        if (
            current_type.startswith(
                "process"
            )
            and any(
                event_type.startswith(
                    "file"
                )
                for event_type in related_types
            )
        ):

            score += 15


        if (
            current_type.startswith(
                "file"
            )
            and any(
                event_type.startswith(
                    "process"
                )
                for event_type in related_types
            )
        ):

            score += 15


        # ========================================================
        # PROCESS + NETWORK
        # ========================================================

        if (
            current_type.startswith(
                "process"
            )
            and any(
                event_type.startswith(
                    "network"
                )
                for event_type in related_types
            )
        ):

            score += 20


        if (
            current_type.startswith(
                "network"
            )
            and any(
                event_type.startswith(
                    "process"
                )
                for event_type in related_types
            )
        ):

            score += 20


        # ========================================================
        # REGISTRY + PROCESS
        # ========================================================

        has_registry = any(

            (
                event_type.startswith(
                    "registry"
                )
                or event_type.startswith(
                    "startup"
                )
            )

            for event_type in related_types
        )


        has_process = any(

            event_type.startswith(
                "process"
            )

            for event_type in related_types
        )


        if (
            (
                current_type.startswith(
                    "registry"
                )
                or current_type.startswith(
                    "startup"
                )
            )
            and has_process
        ):

            score += 25


        if (
            current_type.startswith(
                "process"
            )
            and has_registry
        ):

            score += 25


        # ========================================================
        # SAME PID
        # ========================================================

        current_pid = (
            self.extract_pid(
                event
            )
        )


        if current_pid is not None:

            same_pid_count = 0


            for related_event in related_events:

                related_pid = (
                    self.extract_pid(
                        related_event
                    )
                )


                if (
                    related_pid
                    == current_pid
                ):

                    same_pid_count += 1


            if same_pid_count >= 1:

                score += 10


            if same_pid_count >= 2:

                score += 5


        # ========================================================
        # SAME HASH
        # ========================================================

        current_hash = (
            self.extract_sha256(
                event
            )
        )


        if current_hash:

            current_hash = str(
                current_hash
            ).lower()


            same_hash_found = any(

                str(
                    self.extract_sha256(
                        related_event
                    )
                    or ""
                ).lower()
                == current_hash

                for related_event
                in related_events
            )


            if same_hash_found:

                score += 15


        # ========================================================
        # SAME FILE PATH
        # ========================================================

        current_file = (
            self.extract_file_path(
                event
            )
        )


        if current_file:

            current_file = str(
                current_file
            ).lower()


            same_file_found = any(

                str(
                    self.extract_file_path(
                        related_event
                    )
                    or ""
                ).lower()
                == current_file

                for related_event
                in related_events
            )


            if same_file_found:

                score += 10


        # ========================================================
        # ENTITY LINK CONFIDENCE
        # ========================================================

        max_link_confidence = (
            self.get_max_entity_link_confidence(
                related_events
            )
        )


        if max_link_confidence >= 80:

            score += 25


        elif max_link_confidence >= 60:

            score += 20


        elif max_link_confidence >= 40:

            score += 10


        # ========================================================
        # SEVERITY CONTRIBUTION
        # ========================================================

        severity_scores = {
            "INFO": 0,
            "LOW": 5,
            "MEDIUM": 10,
            "HIGH": 20,
            "CRITICAL": 30,
        }


        max_severity_score = max(

            severity_scores.get(

                str(
                    item.get(
                        "severity",
                        "INFO",
                    )
                ).upper(),

                0,
            )

            for item in all_events
        )


        score += (
            max_severity_score
        )


        return min(
            int(
                score
            ),
            100,
        )


    # ============================================================
    # SCORE TO SEVERITY
    # ============================================================

    def score_to_severity(
        self,
        score: int,
    ) -> str:

        if score >= 80:
            return "CRITICAL"

        if score >= 60:
            return "HIGH"

        if score >= 35:
            return "MEDIUM"

        if score >= 15:
            return "LOW"

        return "INFO"


    # ============================================================
    # COLLECT ENTITY LINKS
    # ============================================================

    def collect_entity_links(
        self,
        related_events: List[dict],
    ) -> list:

        links = []


        for event in related_events:

            link_data = (
                event.get(
                    "_entity_link"
                )
            )


            if not link_data:

                continue


            links.append(
                {
                    "event_id":
                        event.get(
                            "event_id"
                        ),

                    "confidence":
                        link_data.get(
                            "confidence",
                            0,
                        ),

                    "reasons":
                        link_data.get(
                            "reasons",
                            [],
                        ),
                }
            )


        return links


    # ============================================================
    # CORRELATE EVENT
    # ============================================================

    def correlate_event(
        self,
        event: dict,
    ) -> dict:

        related_events = (
            self.get_related_events(
                event
            )
        )


        correlation_score = (
            self.calculate_correlation_score(
                event,
                related_events,
            )
        )


        severity = (
            self.score_to_severity(
                correlation_score
            )
        )


        correlated = (
            correlation_score
            >= 35
        )


        entity_links = (
            self.collect_entity_links(
                related_events
            )
        )


        return {

            "correlated":
                correlated,

            "correlation_score":
                correlation_score,

            "severity":
                severity,

            "related_event_count":
                len(
                    related_events
                ),

            "related_events":
                related_events,

            "entity_links":
                entity_links,

            "current_event":
                event,

            "entities": {

                "pid":
                    self.extract_pid(
                        event
                    ),

                "sha256":
                    self.extract_sha256(
                        event
                    ),

                "file_path":
                    self.extract_file_path(
                        event
                    ),

                "remote_ip":
                    self.extract_remote_ip(
                        event
                    ),
            },
        }