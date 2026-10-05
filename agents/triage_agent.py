
from datetime import datetime, timezone
import math


class TriageAgent:
    """
    Evidence-grounded triage.

    Existing public method names and downstream result fields
    are preserved.

    Scores are heuristic review priorities, not calibrated
    attack probabilities.
    """

    VALID_CATEGORIES = {
        "PROCESS", "FILE", "NETWORK", "REGISTRY"
    }

    QUALIFYING_SEVERITIES = {
        "MEDIUM", "HIGH", "CRITICAL"
    }

    def __init__(self):
        self.name = "TriageAgent"

    def now_iso(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def safe_int(self, value, default=0):
        try:
            number = float(value)
            if not math.isfinite(number):
                return default
            return int(number)
        except (TypeError, ValueError, OverflowError):
            return default

    def safe_float(self, value, default=0.0):
        try:
            number = float(value)
            return number if math.isfinite(number) else default
        except (TypeError, ValueError, OverflowError):
            return default

    def safe_dict(self, value):
        return value if isinstance(value, dict) else {}

    def severity_score(self, severity) -> int:
        mapping = {
            "INFO": 0,
            "LOW": 0,
            "MEDIUM": 12,
            "HIGH": 22,
            "CRITICAL": 30,
        }
        return mapping.get(str(severity).upper(), 0)

    def get_timeline(self, incident: dict) -> list:
        if not isinstance(incident, dict):
            return []

        timeline = incident.get("timeline")
        return timeline if isinstance(timeline, list) else []

    def event_category(self, event: dict) -> str:
        metadata = self.safe_dict(event.get("metadata"))

        category = str(
            event.get("event_category")
            or metadata.get("event_category")
            or ""
        ).upper()

        if category in self.VALID_CATEGORIES:
            return category

        event_type = str(
            event.get("event_type") or ""
        ).lower()

        if event_type.startswith("process"):
            return "PROCESS"
        if event_type.startswith("file"):
            return "FILE"
        if event_type.startswith("network"):
            return "NETWORK"
        if event_type.startswith(("registry", "startup")):
            return "REGISTRY"

        return "UNKNOWN"

    @staticmethod
    def valid_pid(value):
        try:
            if value is None or isinstance(value, bool):
                return False

            pid = int(value)
            return pid > 0 and pid != 4
        except (TypeError, ValueError, OverflowError):
            return False

    def authoritative_events(self, incident: dict) -> list:
        accepted = []
        seen = set()

        for event in self.get_timeline(incident):
            if not isinstance(event, dict):
                continue

            event_id = str(
                event.get("event_id") or ""
            ).strip()

            if not event_id or event_id in seen:
                continue

            seen.add(event_id)

            severity = str(
                event.get("severity") or "INFO"
            ).upper()

            if severity not in self.QUALIFYING_SEVERITIES:
                continue

            metadata = self.safe_dict(
                event.get("metadata")
            )

            mode = str(
                event.get("detection_mode")
                or event.get("mode")
                or metadata.get("detection_mode")
                or metadata.get("operating_mode")
                or metadata.get("mode")
                or ""
            ).upper()

            if (
                "SHADOW" in mode
                or mode in {
                    "OFF", "DISABLED", "SIMULATION"
                }
            ):
                continue

            if (
                event.get("simulation_mode") is True
                or metadata.get("simulation_mode") is True
                or metadata.get("synthetic") is True
            ):
                continue

            device_id = str(
                event.get("device_id")
                or metadata.get("device_id")
                or ""
            ).strip()

            if not device_id:
                continue

            category = self.event_category(event)

            if category not in self.VALID_CATEGORIES:
                continue

            if category in {"PROCESS", "NETWORK"}:
                data = self.safe_dict(
                    event.get(
                        "process"
                        if category == "PROCESS"
                        else "network"
                    )
                )

                if not self.valid_pid(data.get("pid")):
                    continue

            accepted.append({
                "event_id": event_id,
                "category": category,
                "severity": severity,
                "device_id": device_id,
                "event": event,
            })

        return accepted

    def get_categories(self, incident: dict) -> set:
        return {
            item["category"]
            for item in self.authoritative_events(incident)
        }

    def get_max_malware_probability(
        self,
        incident: dict,
    ) -> float:
        # Historical EMBER malware inference remains OFF.
        return 0.0

    def get_max_behavior_score(
        self,
        incident: dict,
    ) -> int:
        maximum = 0

        for item in self.authoritative_events(incident):
            if item["category"] != "PROCESS":
                continue

            event = item["event"]
            process = self.safe_dict(event.get("process"))
            metadata = self.safe_dict(event.get("metadata"))

            for value in (
                process.get("behavior_score"),
                metadata.get("behavior_score"),
                metadata.get("rule_score"),
            ):
                maximum = max(
                    maximum,
                    self.safe_int(value),
                )

        return max(0, min(100, maximum))

    def get_max_anomaly_score(
        self,
        incident: dict,
    ) -> int:
        maximum = 0

        for item in self.authoritative_events(incident):
            if item["category"] != "PROCESS":
                continue

            event = item["event"]
            process = self.safe_dict(event.get("process"))
            metadata = self.safe_dict(event.get("metadata"))

            for value in (
                process.get("anomaly_score"),
                metadata.get("anomaly_score"),
            ):
                maximum = max(
                    maximum,
                    self.safe_int(value),
                )

        return max(0, min(100, maximum))

    def has_persistence_activity(
        self,
        incident: dict,
    ) -> bool:
        for item in self.authoritative_events(incident):
            if item["category"] != "REGISTRY":
                continue

            event = item["event"]
            metadata = self.safe_dict(event.get("metadata"))

            reason = " ".join(
                str(value or "")
                for value in (
                    event.get("reason"),
                    event.get("detection_reason"),
                    metadata.get("reason"),
                    metadata.get("detection_reason"),
                )
            ).lower()

            if any(
                keyword in reason
                for keyword in (
                    "persistence",
                    "autorun",
                    "startup modification",
                )
            ):
                return True

        return False

    def has_network_activity(
        self,
        incident: dict,
    ) -> bool:
        return any(
            item["category"] == "NETWORK"
            for item in self.authoritative_events(incident)
        )

    def calculate_triage_score(
        self,
        incident: dict,
    ) -> dict:
        incident = self.safe_dict(incident)
        qualifying = self.authoritative_events(incident)

        score = 0
        reasons = []

        categories = {
            item["category"]
            for item in qualifying
        }

        # Strongest distinct detection counts once.
        strongest = max(
            (
                self.severity_score(item["severity"])
                for item in qualifying
            ),
            default=0,
        )

        score += strongest

        if strongest:
            reasons.append(
                "Strongest qualifying detection severity "
                "counted once."
            )

        # Count diversity within a device, not globally.
        by_device = {}

        for item in qualifying:
            by_device.setdefault(
                item["device_id"], set()
            ).add(item["category"])

        diversity = max(
            (
                len(device_categories)
                for device_categories in by_device.values()
            ),
            default=0,
        )

        if diversity >= 3:
            score += 15
            reasons.append(
                "Three or more qualifying event categories "
                "occur on one device."
            )
        elif diversity == 2:
            score += 8
            reasons.append(
                "Two qualifying event categories occur "
                "on one device."
            )

        behavior_score = self.get_max_behavior_score(
            incident
        )

        anomaly_score = self.get_max_anomaly_score(
            incident
        )

        if behavior_score >= 70:
            score += 12
            reasons.append(
                "Elevated recorded process behavior score."
            )
        elif behavior_score >= 35:
            score += 6
            reasons.append(
                "Moderate recorded process behavior score."
            )

        # Anomaly scores remain visible but are not added
        # again without independent calibration.
        persistence = self.has_persistence_activity(
            incident
        )

        if persistence:
            score += 8
            reasons.append(
                "A qualifying registry detection explicitly "
                "indicates possible persistence."
            )

        network_activity = self.has_network_activity(
            incident
        )

        # Presence of ordinary network communication:
        # ZERO additional risk points.

        if not qualifying:
            reasons.append(
                "No qualifying authoritative event evidence."
            )

        score = max(0, min(100, score))

        return {
            "triage_score": score,
            "reasons": reasons,
            "categories": sorted(categories),
            "malware_probability": 0.0,
            "behavior_score": behavior_score,
            "anomaly_score": anomaly_score,
            "persistence_detected": persistence,
            "network_activity": network_activity,
            "authoritative_event_count": len(qualifying),
            "evidence_policy": "EVIDENCE_TRIAGE_V2",
        }

    def score_to_priority(self, score: int) -> str:
        if score >= 80:
            return "P1"
        if score >= 60:
            return "P2"
        if score >= 35:
            return "P3"
        return "P4"

    def priority_description(
        self,
        priority: str,
    ) -> str:
        mapping = {
            "P1": "Urgent analyst investigation recommended.",
            "P2": "High-priority analyst review recommended.",
            "P3": "Further investigation recommended.",
            "P4": "Monitoring and evidence review recommended.",
        }

        return mapping.get(
            priority,
            "Continue evidence review.",
        )

    def triage(
        self,
        incident: dict,
    ) -> dict:
        incident = self.safe_dict(incident)

        analysis = self.calculate_triage_score(
            incident
        )

        score = analysis["triage_score"]
        priority = self.score_to_priority(score)

        return {
            "incident_id": incident.get("incident_id"),
            "agent": self.name,
            "triaged_at": self.now_iso(),
            "triage_score": score,
            "priority": priority,
            "recommendation":
                self.priority_description(priority),
            "reasons": analysis["reasons"],
            "categories": analysis["categories"],
            "malware_probability":
                analysis["malware_probability"],
            "behavior_score": analysis["behavior_score"],
            "anomaly_score": analysis["anomaly_score"],
            "persistence_detected":
                analysis["persistence_detected"],
            "network_activity":
                analysis["network_activity"],
            "authoritative_event_count":
                analysis["authoritative_event_count"],
            "evidence_policy":
                analysis["evidence_policy"],
            "requires_investigation": (
                priority in {"P1", "P2", "P3"}
            ),
        }

    def triage_incidents(
        self,
        incidents: list,
    ) -> list:
        results = [
            self.triage(item)
            for item in incidents
        ]

        return sorted(
            results,
            key=lambda result: result["triage_score"],
            reverse=True,
        )
