import uuid
from datetime import datetime, timezone

from detection.fusion.event_correlator import (
    EventCorrelator,
)

from detection.fusion.incident_store import (
    IncidentStore,
)


class CorrelationManager:

    def __init__(
        self,
        correlation_window_seconds: int = 120,
        incident_threshold: int = 35,
    ):

        self.correlator = EventCorrelator(
            correlation_window_seconds=
                correlation_window_seconds
        )

        self.incident_threshold = (
            incident_threshold
        )

        self.incidents = {}

        self.incident_store = (
            IncidentStore()
        )


    # ============================================================
    # CURRENT UTC TIME
    # ============================================================

    def current_timestamp(
        self,
    ) -> str:

        return (
            datetime.now(
                timezone.utc
            ).isoformat()
        )


    # ============================================================
    # NORMALIZE EVENT
    # ============================================================

    def normalize_event_input(
        self,
        event,
    ) -> dict:

        if hasattr(
            event,
            "to_dict",
        ):

            event = (
                event.to_dict()
            )

        if not isinstance(
            event,
            dict,
        ):

            raise TypeError(
                "CorrelationManager expects "
                "a SecurityEvent or dictionary."
            )

        normalized = dict(
            event
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
    # EVENT CATEGORY
    # ============================================================

    def get_event_category(
        self,
        event_type: str,
    ) -> str:

        event_type = (
            event_type
            or ""
        ).lower()

        if event_type.startswith(
            "process"
        ):
            return "PROCESS"

        if event_type.startswith(
            "file"
        ):
            return "FILE"

        if event_type.startswith(
            "network"
        ):
            return "NETWORK"

        if event_type.startswith(
            "registry"
        ):
            return "REGISTRY"

        if event_type.startswith(
            "startup"
        ):
            return "STARTUP"

        # ============================================================
        # SECURITY
        # ============================================================

        if event_type.startswith(
            "security"
        ):
            return "SECURITY"

        return "OTHER"


    # ============================================================
    # COLLECT CATEGORIES
    # ============================================================

    def collect_categories(
        self,
        correlation_result: dict,
    ) -> list:

        categories = set()

        current_event = (
            correlation_result.get(
                "current_event"
            )
            or {}
        )

        related_events = (
            correlation_result.get(
                "related_events"
            )
            or []
        )

        all_events = [
            current_event,
            *related_events,
        ]

        for event in all_events:

            category = (
                self.get_event_category(
                    event.get(
                        "event_type",
                        ""
                    )
                )
            )

            if category != "OTHER":

                categories.add(
                    category
                )

        return sorted(
            categories
        )


    # ============================================================
    # COLLECT EVENT IDS
    # ============================================================

    def collect_event_ids(
        self,
        correlation_result: dict,
    ) -> list:

        event_ids = []

        current_event = (
            correlation_result.get(
                "current_event"
            )
            or {}
        )

        related_events = (
            correlation_result.get(
                "related_events"
            )
            or []
        )

        all_events = [
            current_event,
            *related_events,
        ]

        for event in all_events:

            event_id = (
                event.get(
                    "event_id"
                )
            )

            if (
                event_id
                and event_id not in event_ids
            ):

                event_ids.append(
                    event_id
                )

        return event_ids


    # ============================================================
    # BUILD TIMELINE
    # ============================================================

    def build_timeline(
        self,
        correlation_result: dict,
    ) -> list:

        current_event = (
            correlation_result.get(
                "current_event"
            )
            or {}
        )

        related_events = (
            correlation_result.get(
                "related_events"
            )
            or []
        )

        all_events = [
            current_event,
            *related_events,
        ]

        timeline = []

        seen = set()

        for event in all_events:

            event_id = (
                event.get(
                    "event_id"
                )
            )

            if (
                event_id
                and event_id in seen
            ):

                continue

            if event_id:

                seen.add(
                    event_id
                )

            timeline.append(
                {
                    "event_id":
                        event_id,

                    "event_type":
                        event.get(
                            "event_type"
                        ),

                    "source":
                        event.get(
                            "source"
                        ),

                    "severity":
                        event.get(
                            "severity"
                        ),

                    "timestamp":
                        event.get(
                            "timestamp"
                        ),

                    "timestamp_unix":
                        event.get(
                            "timestamp_unix"
                        ),
                }
            )

        timeline.sort(
            key=lambda item:
                item.get(
                    "timestamp_unix"
                )
                or 0
        )

        return timeline


    # ============================================================
    # INCIDENT TITLE
    # ============================================================

    def build_incident_title(
        self,
        categories: list,
    ) -> str:

        if not categories:

            return (
                "Correlated Security Activity"
            )

        return (
            "Correlated "
            + " + ".join(
                categories
            )
            + " Activity"
        )


    # ============================================================
    # FIND EXISTING INCIDENT
    # ============================================================

    def find_matching_incident(
        self,
        event_ids: list,
    ):

        incoming_ids = set(
            event_ids
        )

        if not incoming_ids:

            return None


        best_incident = None

        best_overlap = 0


        for incident in (
            self.incidents.values()
        ):

            existing_ids = set(
                incident.get(
                    "event_ids",
                    [],
                )
            )


            overlap = len(
                incoming_ids.intersection(
                    existing_ids
                )
            )


            if overlap > best_overlap:

                best_overlap = (
                    overlap
                )

                best_incident = (
                    incident
                )


        if best_overlap > 0:

            return best_incident

        return None


    # ============================================================
    # MERGE TIMELINE
    # ============================================================

    def merge_timelines(
        self,
        existing_timeline: list,
        new_timeline: list,
    ) -> list:

        combined = []

        seen_ids = set()


        for item in (
            existing_timeline
            + new_timeline
        ):

            event_id = (
                item.get(
                    "event_id"
                )
            )


            if (
                event_id
                and event_id in seen_ids
            ):

                continue


            if event_id:

                seen_ids.add(
                    event_id
                )


            combined.append(
                item
            )


        combined.sort(
            key=lambda item:
                item.get(
                    "timestamp_unix"
                )
                or 0
        )


        return combined


    # ============================================================
    # SAVE INCIDENT TO DATABASE
    # ============================================================

    def persist_incident(
        self,
        incident: dict,
    ):

        self.incident_store.save_incident(
            incident
        )


    # ============================================================
    # UPDATE INCIDENT
    # ============================================================

    def update_incident(
        self,
        incident: dict,
        correlation_result: dict,
    ) -> dict:

        new_event_ids = (
            self.collect_event_ids(
                correlation_result
            )
        )


        existing_event_ids = (
            incident.get(
                "event_ids",
                []
            )
        )


        merged_event_ids = list(
            dict.fromkeys(
                existing_event_ids
                + new_event_ids
            )
        )


        new_categories = (
            self.collect_categories(
                correlation_result
            )
        )


        existing_categories = (
            incident.get(
                "categories",
                []
            )
        )


        merged_categories = sorted(
            set(
                existing_categories
                + new_categories
            )
        )


        new_timeline = (
            self.build_timeline(
                correlation_result
            )
        )


        merged_timeline = (
            self.merge_timelines(

                incident.get(
                    "timeline",
                    [],
                ),

                new_timeline,
            )
        )


        old_score = (
            incident.get(
                "correlation_score",
                0,
            )
        )


        new_score = (
            correlation_result.get(
                "correlation_score",
                0,
            )
        )


        final_score = max(
            old_score,
            new_score,
        )


        severity_order = {
            "INFO": 0,
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4,
        }


        old_severity = (
            incident.get(
                "severity",
                "INFO",
            )
        )


        new_severity = (
            correlation_result.get(
                "severity",
                "INFO",
            )
        )


        final_severity = max(
            [
                old_severity,
                new_severity,
            ],
            key=lambda value:
                severity_order.get(
                    value,
                    0,
                ),
        )


        incident.update(
            {
                "title":
                    self.build_incident_title(
                        merged_categories
                    ),

                "correlation_score":
                    final_score,

                "severity":
                    final_severity,

                "categories":
                    merged_categories,

                "event_ids":
                    merged_event_ids,

                "event_count":
                    len(
                        merged_event_ids
                    ),

                "timeline":
                    merged_timeline,

                "updated_at":
                    self.current_timestamp(),

                "requires_investigation":
                    final_score
                    >= self.incident_threshold,
            }
        )


        # --------------------------------------------------------
        # PERSIST UPDATED INCIDENT
        # --------------------------------------------------------

        self.persist_incident(
            incident
        )


        return incident


    # ============================================================
    # CREATE INCIDENT
    # ============================================================

    def create_incident_candidate(
        self,
        correlation_result: dict,
    ) -> dict:

        score = (
            correlation_result.get(
                "correlation_score",
                0,
            )
        )


        categories = (
            self.collect_categories(
                correlation_result
            )
        )


        event_ids = (
            self.collect_event_ids(
                correlation_result
            )
        )


        timeline = (
            self.build_timeline(
                correlation_result
            )
        )


        incident_id = str(
            uuid.uuid4()
        )


        created_at = (
            self.current_timestamp()
        )


        incident = {

            "incident_id":
                incident_id,

            "title":
                self.build_incident_title(
                    categories
                ),

            "status":
                "NEW",

            "correlation_score":
                score,

            "severity":
                correlation_result.get(
                    "severity",
                    "INFO",
                ),

            "categories":
                categories,

            "event_ids":
                event_ids,

            "event_count":
                len(
                    event_ids
                ),

            "timeline":
                timeline,

            "created_at":
                created_at,

            "updated_at":
                created_at,

            "source":
                "CorrelationManager",

            "requires_investigation":
                score
                >= self.incident_threshold,
        }


        self.incidents[
            incident_id
        ] = incident


        # --------------------------------------------------------
        # PERSIST NEW INCIDENT
        # --------------------------------------------------------

        self.persist_incident(
            incident
        )


        return incident


    # ============================================================
    # CREATE OR UPDATE INCIDENT
    # ============================================================

    def create_or_update_incident(
        self,
        correlation_result: dict,
    ) -> tuple:

        event_ids = (
            self.collect_event_ids(
                correlation_result
            )
        )


        existing_incident = (
            self.find_matching_incident(
                event_ids
            )
        )


        if existing_incident:

            incident = (
                self.update_incident(
                    existing_incident,
                    correlation_result,
                )
            )

            return (
                incident,
                False,
                True,
            )


        incident = (
            self.create_incident_candidate(
                correlation_result
            )
        )


        return (
            incident,
            True,
            False,
        )


    # ============================================================
    # PROCESS EVENT
    # ============================================================

    def process_event(
        self,
        event,
    ) -> dict:

        normalized_event = (
            self.normalize_event_input(
                event
            )
        )


        correlation_result = (
            self.correlator.add_event(
                normalized_event
            )
        )


        incident = None

        incident_created = False

        incident_updated = False


        if (
            correlation_result.get(
                "correlated",
                False,
            )
            and
            correlation_result.get(
                "correlation_score",
                0,
            )
            >= self.incident_threshold
        ):

            (
                incident,
                incident_created,
                incident_updated,
            ) = (
                self.create_or_update_incident(
                    correlation_result
                )
            )


        return {

            "correlation":
                correlation_result,

            "incident_created":
                incident_created,

            "incident_updated":
                incident_updated,

            "incident":
                incident,
        }


    # ============================================================
    # GET INCIDENT
    # ============================================================

    def get_incident(
        self,
        incident_id: str,
    ):

        incident = (
            self.incidents.get(
                incident_id
            )
        )


        if incident:

            return incident


        return (
            self.incident_store.get_incident(
                incident_id
            )
        )


    # ============================================================
    # GET ALL INCIDENTS
    # ============================================================

    def get_incidents(
        self,
    ) -> list:

        return list(
            self.incidents.values()
        )


    # ============================================================
    # GET DATABASE INCIDENTS
    # ============================================================

    def get_persisted_incidents(
        self,
    ) -> list:

        return (
            self.incident_store.get_incidents()
        )