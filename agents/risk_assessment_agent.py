
from datetime import datetime, timezone
import math

from agents.investigation_agent import InvestigationAgent


class RiskAssessmentAgent:
    """
    Evidence-grounded risk assessment.

    Preserves original helper method names, component
    names, and assess() interface.

    Risk scores represent provisional review priority,
    not calibrated attack probabilities.
    """

    def __init__(self):
        self.name = "RiskAssessmentAgent"
        self.investigator = InvestigationAgent()

    # ============================================================
    # CURRENT TIME
    # ============================================================

    def now_iso(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    # ============================================================
    # SAFE HELPERS
    # ============================================================

    def safe_list(self, value) -> list:
        return value if isinstance(value, list) else []

    def safe_dict(self, value) -> dict:
        return value if isinstance(value, dict) else {}

    def safe_int(self, value, default=0) -> int:
        try:
            number = float(value)
            if not math.isfinite(number):
                return default
            return int(number)
        except (TypeError, ValueError, OverflowError):
            return default

    def safe_float(self, value, default=0.0) -> float:
        try:
            number = float(value)
            return number if math.isfinite(number) else default
        except (TypeError, ValueError, OverflowError):
            return default

    # ============================================================
    # GET MAX MALWARE PROBABILITY
    # ============================================================

    def get_max_malware_probability(
        self,
        enriched_evidence: dict,
    ) -> float:
        # Old EMBER inference is disabled.
        # Retain the interface without trusting old values.
        return 0.0

    # ============================================================
    # GET MAX STATIC RISK
    # ============================================================

    def get_max_static_risk(
        self,
        enriched_evidence: dict,
    ) -> int:
        maximum = 0

        for item in self.safe_list(
            enriched_evidence.get("files")
        ):
            if not isinstance(item, dict):
                continue

            # Retain a descriptive value for review.
            maximum = max(
                maximum,
                self.safe_int(
                    item.get("static_risk_score")
                ),
            )

        return max(0, min(100, maximum))

    # ============================================================
    # GET MAX BEHAVIOR SCORE
    # ============================================================

    def get_max_behavior_score(
        self,
        enriched_evidence: dict,
    ) -> int:
        maximum = 0

        for item in self.safe_list(
            enriched_evidence.get("processes")
        ):
            if not isinstance(item, dict):
                continue

            maximum = max(
                maximum,
                self.safe_int(
                    item.get("behavior_score")
                ),
            )

        return max(0, min(100, maximum))

    # ============================================================
    # GET MAX ANOMALY SCORE
    # ============================================================

    def get_max_anomaly_score(
        self,
        enriched_evidence: dict,
    ) -> int:
        maximum = 0

        for item in self.safe_list(
            enriched_evidence.get("processes")
        ):
            if not isinstance(item, dict):
                continue

            maximum = max(
                maximum,
                self.safe_int(
                    item.get("anomaly_score")
                ),
            )

        return max(0, min(100, maximum))

    # ============================================================
    # GET MAX COMBINED PROCESS SCORE
    # ============================================================

    def get_max_combined_process_score(
        self,
        enriched_evidence: dict,
    ) -> int:
        maximum = 0

        for item in self.safe_list(
            enriched_evidence.get("processes")
        ):
            if not isinstance(item, dict):
                continue

            maximum = max(
                maximum,
                self.safe_int(
                    item.get("combined_threat_score")
                ),
            )

        return max(0, min(100, maximum))

    # ============================================================
    # CHECK NETWORK ACTIVITY
    # ============================================================

    def has_network_activity(
        self,
        enriched_evidence: dict,
    ) -> bool:
        network = self.safe_list(
            enriched_evidence.get(
                "network_connections"
            )
        )

        # Observational only; no points by itself.
        return len(network) > 0

    # ============================================================
    # CHECK PERSISTENCE
    # ============================================================

    def has_persistence(
        self,
        enriched_evidence: dict,
        attack_timeline: dict,
    ) -> bool:
        # Inferred timeline labels and registry paths
        # are insufficient to confirm persistence.
        # Keep this False until artifact provenance and
        # detection criteria are independently validated.
        return False

    # ============================================================
    # GET CATEGORY COUNT
    # ============================================================

    def get_category_count(
        self,
        investigation: dict,
        enriched_evidence: dict,
    ) -> int:
        assessment = self.safe_dict(
            investigation.get(
                "evidence_assessment"
            )
        )

        return max(
            0,
            self.safe_int(
                assessment.get(
                    "qualifying_category_count"
                ),
                0,
            ),
        )

    # ============================================================
    # GET RELATIONSHIP STRENGTH
    # ============================================================

    def get_relationship_strength(
        self,
        enriched_evidence: dict,
    ) -> dict:
        relationships = [
            item
            for item in self.safe_list(
                enriched_evidence.get(
                    "relationships"
                )
            )
            if isinstance(item, dict)
        ]

        maximum = 0
        high_count = 0

        for relationship in relationships:
            confidence = max(
                0,
                min(
                    100,
                    self.safe_int(
                        relationship.get(
                            "confidence"
                        )
                    ),
                ),
            )

            maximum = max(maximum, confidence)

            if confidence >= 80:
                high_count += 1

        return {
            "count": len(relationships),
            "max_confidence": maximum,
            "high_confidence_count": high_count,
            "verified_count": 0,
        }

    # ============================================================
    # SEVERITY BONUS
    # ============================================================

    def severity_points(self, severity) -> int:
        # Used only with qualifying event severity,
        # not inherited incident severity.
        mapping = {
            "INFO": 0,
            "LOW": 0,
            "MEDIUM": 12,
            "HIGH": 22,
            "CRITICAL": 30,
        }

        return mapping.get(
            str(severity).upper(),
            0,
        )

    # ============================================================
    # RISK LEVEL
    # ============================================================

    def score_to_risk_level(
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
    # RECOMMENDED ACTION
    # ============================================================

    def recommended_action(
        self,
        risk_level: str,
    ) -> str:
        mapping = {
            "CRITICAL":
                "Urgent analyst review before considering containment.",
            "HIGH":
                "High-priority evidence and attribution review.",
            "MEDIUM":
                "Investigate related evidence and verify relationships.",
            "LOW":
                "Continue monitoring and retain supporting evidence.",
            "INFO":
                "No immediate response required.",
        }

        return mapping.get(
            risk_level,
            "Continue evidence review.",
        )

    # ============================================================
    # ASSESS RISK
    # ============================================================

    def assess(
        self,
        incident: dict,
        investigation: dict,
        enriched_evidence: dict,
        attack_timeline: dict,
        attack_graph: dict,
    ) -> dict:

        incident = self.safe_dict(incident)
        investigation = self.safe_dict(investigation)
        enriched_evidence = self.safe_dict(
            enriched_evidence
        )
        attack_timeline = self.safe_dict(
            attack_timeline
        )
        attack_graph = self.safe_dict(
            attack_graph
        )

        score = 0
        reasons = []
        components = {}

        qualifying = (
            self.investigator.get_qualifying_events(
                incident
            )
        )

        evidence_assessment = (
            self.investigator.evidence_assessment(
                incident
            )
        )

        corroborated = bool(
            evidence_assessment.get(
                "basic_corroboration",
                False,
            )
        )

        category_count = self.safe_int(
            evidence_assessment.get(
                "qualifying_category_count"
            ),
            0,
        )

        # ========================================================
        # 1. INCIDENT CORRELATION
        # ========================================================

        correlation_score = self.safe_int(
            incident.get("correlation_score")
        )

        # Historical correlation score is context only.
        correlation_points = 0

        components["correlation"] = {
            "value": correlation_score,
            "points": correlation_points,
            "status": "HISTORICAL_CONTEXT",
        }

        # ========================================================
        # 2. MALWARE PROBABILITY
        # ========================================================

        malware_probability = (
            self.get_max_malware_probability(
                enriched_evidence
            )
        )

        malware_points = 0

        components["malware_probability"] = {
            "value": None,
            "points": malware_points,
            "status": "DISABLED",
        }

        # ========================================================
        # 3. STATIC FILE RISK
        # ========================================================

        static_risk = self.get_max_static_risk(
            enriched_evidence
        )

        static_points = 0

        components["static_file_risk"] = {
            "value": static_risk,
            "points": static_points,
            "status": "NOT_INDEPENDENTLY_VERIFIED",
        }

        # ========================================================
        # 4. PROCESS BEHAVIOR
        # ========================================================

        behavior_score = self.get_max_behavior_score(
            enriched_evidence
        )

        behavior_points = 0

        components["behavior"] = {
            "value": behavior_score,
            "points": behavior_points,
            "status": "PROVENANCE_NOT_VERIFIED",
        }

        # ========================================================
        # 5. PROCESS ANOMALY
        # ========================================================

        anomaly_score = self.get_max_anomaly_score(
            enriched_evidence
        )

        anomaly_points = 0

        components["anomaly"] = {
            "value": anomaly_score,
            "points": anomaly_points,
            "status": "NOT_CALIBRATED",
        }

        # ========================================================
        # 6. PERSISTENCE
        # ========================================================

        persistence = self.has_persistence(
            enriched_evidence,
            attack_timeline,
        )

        persistence_points = 0

        components["persistence"] = {
            "value": persistence,
            "points": persistence_points,
            "status": "NOT_VERIFIED",
        }

        # ========================================================
        # 7. NETWORK ACTIVITY
        # ========================================================

        network_activity = self.has_network_activity(
            enriched_evidence
        )

        network_points = 0

        components["network_activity"] = {
            "value": network_activity,
            "points": network_points,
            "status": "OBSERVATION_ONLY",
        }

        # ========================================================
        # 8. TELEMETRY DIVERSITY
        # ========================================================

        # Calculate directly from qualifying incident
        # evidence, never from raw enriched entity counts.
        category_points = (
            8 if corroborated else 0
        )

        components["telemetry_diversity"] = {
            "value": category_count,
            "points": category_points,
            "status": (
                "PRELIMINARY_CROSS_CATEGORY"
                if corroborated
                else "INSUFFICIENT"
            ),
        }

        if corroborated:
            score += category_points
            reasons.append(
                "Qualifying events in different categories "
                "occur on the same device. A causal link "
                "has not been verified."
            )

        # ========================================================
        # 9. RELATIONSHIP CONFIDENCE
        # ========================================================

        relationship_info = (
            self.get_relationship_strength(
                enriched_evidence
            )
        )

        relationship_points = 0

        components["entity_relationships"] = {
            "value": relationship_info,
            "points": relationship_points,
            "status": "NOT_INDEPENDENTLY_VERIFIED",
        }

        # ========================================================
        # 10. INCIDENT SEVERITY
        # ========================================================

        incident_severity = incident.get(
            "severity", "INFO"
        )

        components["incident_severity"] = {
            "value": incident_severity,
            "points": 0,
            "status": "HISTORICAL_CONTEXT",
        }

        # ========================================================
        # 11. QUALIFYING EVENT SEVERITY
        # ========================================================

        strongest_event_score = max(
            (
                self.severity_points(
                    event.get("severity")
                )
                for event in qualifying
            ),
            default=0,
        )

        score += strongest_event_score

        components["qualifying_event_severity"] = {
            "value": strongest_event_score,
            "points": strongest_event_score,
        }

        if qualifying:
            reasons.append(
                "The strongest qualifying event severity "
                "was counted once, without multiplying "
                "repeated event observations."
            )
        else:
            reasons.append(
                "No qualifying authoritative detection "
                "evidence was found."
            )

        # ========================================================
        # 12. CONSERVATIVE RISK CAP
        # ========================================================

        # Current evidence does not establish attack
        # confirmation or verified causal relationships.
        # Restrict unverified scores to analyst-review levels.
        score = max(0, min(int(score), 34))

        risk_level = self.score_to_risk_level(
            score
        )

        reasons.append(
            "Stored severity, correlation, INFO network "
            "activity, unverified relationships, and "
            "disabled malware predictions were not "
            "counted as independent risk evidence."
        )

        # ========================================================
        # FINAL RESULT
        # ========================================================

        return {
            "incident_id": incident.get(
                "incident_id"
            ),
            "agent": self.name,
            "assessed_at": self.now_iso(),

            "risk_score": score,
            "risk_level": risk_level,
            "recommended_action":
                self.recommended_action(
                    risk_level
                ),

            # No autonomous response authorization.
            "requires_response": False,

            "components": components,
            "reasons": reasons,

            "evidence_summary": {
                "malware_probability": None,
                "static_risk": static_risk,
                "behavior_score": behavior_score,
                "anomaly_score": anomaly_score,
                "combined_process_score":
                    self.get_max_combined_process_score(
                        enriched_evidence
                    ),
                "persistence": persistence,
                "network_activity": network_activity,
                "telemetry_categories": category_count,
                "relationship_count":
                    relationship_info["count"],
                "high_confidence_relationships":
                    relationship_info[
                        "high_confidence_count"
                    ],
                "qualifying_event_count": len(
                    qualifying
                ),
                "basic_corroboration": corroborated,
                "causal_relationship_verified": False,
                "attack_confirmed": False,
                "scoring_policy":
                    "CONSERVATIVE_RISK_V2",
            },

            "confidence_calibrated": False,
            "execution_allowed": False,
        }
