
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
        """
        Calculate review priority from persisted detector evidence.

        IMPORTANT:
        - This score is NOT an attack probability.
        - A HIGH/CRITICAL score can require response review without
          claiming that the attack is independently confirmed.
        - Real response execution remains disabled.
        """

        incident = self.safe_dict(incident)
        investigation = self.safe_dict(investigation)
        enriched_evidence = self.safe_dict(enriched_evidence)
        attack_timeline = self.safe_dict(attack_timeline)
        attack_graph = self.safe_dict(attack_graph)

        score = 0
        reasons = []
        components = {}

        analysis_context = self.safe_dict(
            incident.get("analysis_context")
        )
        validation_only = bool(
            analysis_context.get("validation_mode", False)
        )

        qualifying = self.investigator.get_qualifying_events(
            incident
        )
        evidence_assessment = (
            self.investigator.evidence_assessment(
                incident
            )
        )

        corroborated = bool(
            evidence_assessment.get(
                "cross_category_corroboration",
                False,
            )
        )
        category_count = self.safe_int(
            evidence_assessment.get(
                "qualifying_category_count"
            ),
            0,
        )

        detections = [
            item
            for item in self.safe_list(
                enriched_evidence.get("detections")
                or incident.get("detections")
            )
            if isinstance(item, dict)
            and item.get("detected") is not False
            and item.get("stored_detection_record") is True
        ]

        strong_detections = []

        for detection in detections:
            detection_risk = self.safe_float(
                detection.get("risk_score")
                or detection.get("fusion_score"),
                0.0,
            )
            detection_severity = str(
                detection.get("severity") or "INFO"
            ).upper()
            signal_count = self.safe_int(
                detection.get("independent_signal_count"),
                0,
            )

            if (
                detection_risk >= 60
                and detection_severity in {"HIGH", "CRITICAL"}
                and signal_count >= 2
            ):
                strong_detections.append(detection)

        strongest_detection = None
        if strong_detections:
            strongest_detection = max(
                strong_detections,
                key=lambda item: self.safe_float(
                    item.get("risk_score")
                    or item.get("fusion_score"),
                    0.0,
                ),
            )

        max_detection_risk = (
            self.safe_float(
                strongest_detection.get("risk_score")
                or strongest_detection.get("fusion_score"),
                0.0,
            )
            if strongest_detection
            else 0.0
        )
        strongest_detection_severity = (
            str(
                strongest_detection.get("severity") or "INFO"
            ).upper()
            if strongest_detection
            else "INFO"
        )
        max_signal_count = (
            self.safe_int(
                strongest_detection.get("independent_signal_count"),
                0,
            )
            if strongest_detection
            else 0
        )

        # ========================================================
        # 1. PERSISTED DETECTOR EVIDENCE
        # ========================================================
        detection_points = (
            min(45, round(max_detection_risk * 0.45))
            if strongest_detection
            else 0
        )
        score += detection_points

        components["persisted_detection"] = {
            "value": max_detection_risk,
            "points": detection_points,
            "engine": (
                strongest_detection.get("engine")
                if strongest_detection
                else None
            ),
            "threat_type": (
                strongest_detection.get("threat_type")
                if strongest_detection
                else None
            ),
            "status": (
                "STRONG_STORED_DETECTION"
                if strongest_detection
                else "NOT_AVAILABLE"
            ),
        }

        if strongest_detection:
            reasons.append(
                "Persisted detector output contributes to review "
                "priority because it is linked to the incident event."
            )

        # ========================================================
        # 2. DETECTION SEVERITY
        # ========================================================
        detection_severity_points = {
            "MEDIUM": 6,
            "HIGH": 12,
            "CRITICAL": 15,
        }.get(strongest_detection_severity, 0)
        score += detection_severity_points

        components["detection_severity"] = {
            "value": strongest_detection_severity,
            "points": detection_severity_points,
            "status": "DETECTOR_REVIEW_PRIORITY",
        }

        # ========================================================
        # 3. MULTI-SIGNAL DETECTOR CORROBORATION
        # ========================================================
        signal_points = (
            10 if max_signal_count >= 2
            else 5 if max_signal_count == 1
            else 0
        )
        score += signal_points

        components["detector_signal_corroboration"] = {
            "value": max_signal_count,
            "points": signal_points,
            "status": (
                "MULTI_SIGNAL"
                if max_signal_count >= 2
                else "LIMITED"
            ),
        }

        # ========================================================
        # 4. QUALIFYING EVENT SEVERITY
        # ========================================================
        qualifying_event_points = min(
            10,
            max(
                (
                    self.severity_points(
                        event.get("severity")
                    )
                    for event in qualifying
                ),
                default=0,
            ),
        )
        score += qualifying_event_points

        components["qualifying_event_severity"] = {
            "value": qualifying_event_points,
            "points": qualifying_event_points,
            "qualifying_event_count": len(qualifying),
        }

        # ========================================================
        # 5. INCIDENT CORRELATION SUPPORT
        # ========================================================
        correlation_score = self.safe_int(
            incident.get("correlation_score")
        )
        correlation_points = (
            min(5, round(correlation_score / 20))
            if strongest_detection
            else 0
        )
        score += correlation_points

        components["correlation"] = {
            "value": correlation_score,
            "points": correlation_points,
            "status": (
                "SUPPORTING_CONTEXT"
                if strongest_detection
                else "HISTORICAL_CONTEXT"
            ),
        }

        # ========================================================
        # 6. CROSS-CATEGORY TELEMETRY DIVERSITY
        # ========================================================
        category_points = 10 if corroborated else 0
        score += category_points

        components["telemetry_diversity"] = {
            "value": category_count,
            "points": category_points,
            "status": (
                "CROSS_CATEGORY_CORROBORATION"
                if corroborated
                else "NOT_PRESENT"
            ),
        }

        # ========================================================
        # CONTEXT-ONLY COMPONENTS
        # ========================================================
        static_risk = self.get_max_static_risk(
            enriched_evidence
        )
        behavior_score = self.get_max_behavior_score(
            enriched_evidence
        )
        anomaly_score = self.get_max_anomaly_score(
            enriched_evidence
        )
        persistence = self.has_persistence(
            enriched_evidence,
            attack_timeline,
        )
        network_activity = self.has_network_activity(
            enriched_evidence
        )
        relationship_info = self.get_relationship_strength(
            enriched_evidence
        )

        components["behavior"] = {
            "value": behavior_score,
            "points": 0,
            "status": "ALREADY_REPRESENTED_IN_DETECTOR_EVIDENCE",
        }
        components["anomaly"] = {
            "value": anomaly_score,
            "points": 0,
            "status": "CONTEXT_ONLY",
        }
        components["static_file_risk"] = {
            "value": static_risk,
            "points": 0,
            "status": "CONTEXT_ONLY",
        }
        components["persistence"] = {
            "value": persistence,
            "points": 0,
            "status": "NOT_VERIFIED",
        }
        components["network_activity"] = {
            "value": network_activity,
            "points": 0,
            "status": "OBSERVATION_ONLY",
        }
        components["entity_relationships"] = {
            "value": relationship_info,
            "points": 0,
            "status": "NOT_INDEPENDENTLY_VERIFIED",
        }
        components["incident_severity"] = {
            "value": incident.get("severity", "INFO"),
            "points": 0,
            "status": "ANALYSIS_CONTEXT",
        }
        components["malware_probability"] = {
            "value": None,
            "points": 0,
            "status": "DISABLED",
        }

        # Without a strong persisted detector result, preserve the
        # conservative review-only ceiling from the previous policy.
        if not strongest_detection:
            score = min(score, 34)

        score = max(0, min(int(score), 100))
        risk_level = self.score_to_risk_level(score)

        response_review_supported = bool(
            strongest_detection
            and score >= 60
        )

        if response_review_supported:
            reasons.append(
                "High review priority warrants simulated response "
                "planning and analyst review. It does not authorize "
                "real containment."
            )
        else:
            reasons.append(
                "Evidence remains below the response-review threshold."
            )

        return {
            "incident_id": incident.get("incident_id"),
            "agent": self.name,
            "assessed_at": self.now_iso(),
            "risk_score": score,
            "risk_level": risk_level,
            "recommended_action": self.recommended_action(
                risk_level
            ),
            "requires_response": response_review_supported,
            "requires_response_review": response_review_supported,
            "components": components,
            "reasons": reasons,
            "evidence_summary": {
                "malware_probability": None,
                "static_risk": static_risk,
                "behavior_score": behavior_score,
                "anomaly_score": anomaly_score,
                "combined_process_score": (
                    self.get_max_combined_process_score(
                        enriched_evidence
                    )
                ),
                "persistence": persistence,
                "network_activity": network_activity,
                "telemetry_categories": category_count,
                "relationship_count": relationship_info["count"],
                "high_confidence_relationships": relationship_info[
                    "high_confidence_count"
                ],
                "qualifying_event_count": len(qualifying),
                "stored_detection_count": len(detections),
                "strong_detection_count": len(strong_detections),
                "max_detection_risk": max_detection_risk,
                "max_detection_signal_count": max_signal_count,
                "detection_supported": bool(strongest_detection),
                "basic_corroboration": bool(
                    evidence_assessment.get(
                        "basic_corroboration",
                        False,
                    )
                ),
                "cross_category_corroboration": corroborated,
                "causal_relationship_verified": False,
                "attack_confirmed": False,
                "validation_only": validation_only,
                "production_eligible": not validation_only,
                "scoring_policy": "DETECTION_GROUNDED_REVIEW_RISK_V3",
            },
            "confidence_calibrated": False,
            "execution_allowed": False,
            "validation_only": validation_only,
            "production_eligible": not validation_only,
        }

