from datetime import datetime, timezone


class RiskAssessmentAgent:

    def __init__(self):

        self.name = "RiskAssessmentAgent"


    # ============================================================
    # CURRENT TIME
    # ============================================================

    def now_iso(
        self,
    ) -> str:

        return (
            datetime.now(
                timezone.utc
            ).isoformat()
        )


    # ============================================================
    # SAFE HELPERS
    # ============================================================

    def safe_list(
        self,
        value,
    ) -> list:

        if isinstance(
            value,
            list,
        ):

            return value

        return []


    def safe_dict(
        self,
        value,
    ) -> dict:

        if isinstance(
            value,
            dict,
        ):

            return value

        return {}


    def safe_int(
        self,
        value,
        default=0,
    ) -> int:

        try:

            return int(
                value
            )

        except (
            TypeError,
            ValueError,
        ):

            return default


    def safe_float(
        self,
        value,
        default=0.0,
    ) -> float:

        try:

            return float(
                value
            )

        except (
            TypeError,
            ValueError,
        ):

            return default


    # ============================================================
    # GET MAX MALWARE PROBABILITY
    # ============================================================

    def get_max_malware_probability(
        self,
        enriched_evidence: dict,
    ) -> float:

        maximum = 0.0


        files = (
            self.safe_list(
                enriched_evidence.get(
                    "files"
                )
            )
        )


        for file_item in files:

            probability = (
                self.safe_float(
                    file_item.get(
                        "malware_probability"
                    ),
                    0.0,
                )
            )


            maximum = max(
                maximum,
                probability,
            )


        return maximum


    # ============================================================
    # GET MAX STATIC RISK
    # ============================================================

    def get_max_static_risk(
        self,
        enriched_evidence: dict,
    ) -> int:

        maximum = 0


        files = (
            self.safe_list(
                enriched_evidence.get(
                    "files"
                )
            )
        )


        for file_item in files:

            risk = (
                self.safe_int(
                    file_item.get(
                        "static_risk_score"
                    ),
                    0,
                )
            )


            maximum = max(
                maximum,
                risk,
            )


        return maximum


    # ============================================================
    # GET MAX BEHAVIOR SCORE
    # ============================================================

    def get_max_behavior_score(
        self,
        enriched_evidence: dict,
    ) -> int:

        maximum = 0


        processes = (
            self.safe_list(
                enriched_evidence.get(
                    "processes"
                )
            )
        )


        for process in processes:

            value = (
                self.safe_int(
                    process.get(
                        "behavior_score"
                    ),
                    0,
                )
            )


            maximum = max(
                maximum,
                value,
            )


        return maximum


    # ============================================================
    # GET MAX ANOMALY SCORE
    # ============================================================

    def get_max_anomaly_score(
        self,
        enriched_evidence: dict,
    ) -> int:

        maximum = 0


        processes = (
            self.safe_list(
                enriched_evidence.get(
                    "processes"
                )
            )
        )


        for process in processes:

            value = (
                self.safe_int(
                    process.get(
                        "anomaly_score"
                    ),
                    0,
                )
            )


            maximum = max(
                maximum,
                value,
            )


        return maximum


    # ============================================================
    # GET MAX COMBINED PROCESS SCORE
    # ============================================================

    def get_max_combined_process_score(
        self,
        enriched_evidence: dict,
    ) -> int:

        maximum = 0


        processes = (
            self.safe_list(
                enriched_evidence.get(
                    "processes"
                )
            )
        )


        for process in processes:

            value = (
                self.safe_int(
                    process.get(
                        "combined_threat_score"
                    ),
                    0,
                )
            )


            maximum = max(
                maximum,
                value,
            )


        return maximum


    # ============================================================
    # CHECK NETWORK ACTIVITY
    # ============================================================

    def has_network_activity(
        self,
        enriched_evidence: dict,
    ) -> bool:

        network = (
            self.safe_list(
                enriched_evidence.get(
                    "network_connections"
                )
            )
        )


        return (
            len(
                network
            )
            > 0
        )


    # ============================================================
    # CHECK PERSISTENCE
    # ============================================================

    def has_persistence(
        self,
        enriched_evidence: dict,
        attack_timeline: dict,
    ) -> bool:

        # --------------------------------------------------------
        # First use attack timeline stages
        # --------------------------------------------------------

        attack_stages = (
            self.safe_list(
                attack_timeline.get(
                    "attack_stages"
                )
            )
        )


        if "PERSISTENCE" in attack_stages:

            return True


        # --------------------------------------------------------
        # Fallback to registry content
        # --------------------------------------------------------

        registry_items = (
            self.safe_list(
                enriched_evidence.get(
                    "registry_artifacts"
                )
            )
        )


        persistence_keywords = [

            "\\run",

            "\\runonce",

            "startup",

            "winlogon",

            "services",
        ]


        for item in registry_items:

            text = " ".join(

                str(
                    value
                )

                for value
                in item.values()

                if value is not None
            ).lower()


            for keyword in persistence_keywords:

                if keyword in text:

                    return True


        return False


    # ============================================================
    # GET CATEGORY COUNT
    # ============================================================

    def get_category_count(
        self,
        investigation: dict,
        enriched_evidence: dict,
    ) -> int:

        category_counts = (
            self.safe_dict(
                investigation.get(
                    "category_counts"
                )
            )
        )


        if category_counts:

            return len(
                [
                    key
                    for key, value
                    in category_counts.items()
                    if value
                ]
            )


        count = 0


        if self.safe_list(
            enriched_evidence.get(
                "processes"
            )
        ):

            count += 1


        if self.safe_list(
            enriched_evidence.get(
                "files"
            )
        ):

            count += 1


        if self.safe_list(
            enriched_evidence.get(
                "network_connections"
            )
        ):

            count += 1


        if self.safe_list(
            enriched_evidence.get(
                "registry_artifacts"
            )
        ):

            count += 1


        return count


    # ============================================================
    # GET RELATIONSHIP STRENGTH
    # ============================================================

    def get_relationship_strength(
        self,
        enriched_evidence: dict,
    ) -> dict:

        relationships = (
            self.safe_list(
                enriched_evidence.get(
                    "relationships"
                )
            )
        )


        if not relationships:

            return {

                "count":
                    0,

                "max_confidence":
                    0,

                "high_confidence_count":
                    0,
            }


        max_confidence = 0

        high_confidence_count = 0


        for relationship in relationships:

            confidence = (
                self.safe_int(
                    relationship.get(
                        "confidence"
                    ),
                    0,
                )
            )


            max_confidence = max(
                max_confidence,
                confidence,
            )


            if confidence >= 80:

                high_confidence_count += 1


        return {

            "count":
                len(
                    relationships
                ),

            "max_confidence":
                max_confidence,

            "high_confidence_count":
                high_confidence_count,
        }


    # ============================================================
    # SEVERITY BONUS
    # ============================================================

    def severity_points(
        self,
        severity,
    ) -> int:

        mapping = {

            "INFO":
                0,

            "LOW":
                2,

            "MEDIUM":
                5,

            "HIGH":
                8,

            "CRITICAL":
                10,
        }


        return mapping.get(
            str(
                severity
            ).upper(),
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
                "Immediate analyst review and containment recommendation.",

            "HIGH":
                "High-priority investigation and containment review recommended.",

            "MEDIUM":
                "Continue investigation and monitor related activity.",

            "LOW":
                "Monitor the activity and retain evidence.",

            "INFO":
                "No immediate response required.",
        }


        return mapping.get(
            risk_level,
            "Monitor the incident.",
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

        incident = (
            self.safe_dict(
                incident
            )
        )

        investigation = (
            self.safe_dict(
                investigation
            )
        )

        enriched_evidence = (
            self.safe_dict(
                enriched_evidence
            )
        )

        attack_timeline = (
            self.safe_dict(
                attack_timeline
            )
        )

        attack_graph = (
            self.safe_dict(
                attack_graph
            )
        )


        score = 0

        reasons = []

        components = {}


        # ========================================================
        # 1. INCIDENT CORRELATION
        # max 15 points
        # ========================================================

        correlation_score = (
            self.safe_int(
                incident.get(
                    "correlation_score"
                ),
                0,
            )
        )


        correlation_points = 0


        if correlation_score >= 80:

            correlation_points = 15

            reasons.append(
                "Very high cross-event correlation."
            )


        elif correlation_score >= 60:

            correlation_points = 12

            reasons.append(
                "High cross-event correlation."
            )


        elif correlation_score >= 35:

            correlation_points = 7

            reasons.append(
                "Moderate cross-event correlation."
            )


        score += correlation_points

        components[
            "correlation"
        ] = {

            "value":
                correlation_score,

            "points":
                correlation_points,
        }


        # ========================================================
        # 2. MALWARE PROBABILITY
        # max 20 points
        # ========================================================

        malware_probability = (
            self.get_max_malware_probability(
                enriched_evidence
            )
        )


        malware_points = 0


        if malware_probability >= 0.90:

            malware_points = 20

            reasons.append(
                "Very high malware-model probability."
            )


        elif malware_probability >= 0.70:

            malware_points = 15

            reasons.append(
                "Elevated malware-model probability."
            )


        elif malware_probability >= 0.40:

            malware_points = 7

            reasons.append(
                "Moderate malware-model probability."
            )


        score += malware_points

        components[
            "malware_probability"
        ] = {

            "value":
                malware_probability,

            "points":
                malware_points,
        }


        # ========================================================
        # 3. STATIC FILE RISK
        # max 10 points
        # ========================================================

        static_risk = (
            self.get_max_static_risk(
                enriched_evidence
            )
        )


        static_points = 0


        if static_risk >= 70:

            static_points = 10

            reasons.append(
                "High static file risk."
            )


        elif static_risk >= 40:

            static_points = 6

            reasons.append(
                "Moderate static file risk."
            )


        elif static_risk >= 20:

            static_points = 3


        score += static_points

        components[
            "static_file_risk"
        ] = {

            "value":
                static_risk,

            "points":
                static_points,
        }


        # ========================================================
        # 4. PROCESS BEHAVIOR
        # max 15 points
        # ========================================================

        behavior_score = (
            self.get_max_behavior_score(
                enriched_evidence
            )
        )


        behavior_points = 0


        if behavior_score >= 70:

            behavior_points = 15

            reasons.append(
                "Strong suspicious process behavior."
            )


        elif behavior_score >= 35:

            behavior_points = 8

            reasons.append(
                "Suspicious process behavior."
            )


        score += behavior_points

        components[
            "behavior"
        ] = {

            "value":
                behavior_score,

            "points":
                behavior_points,
        }


        # ========================================================
        # 5. PROCESS ANOMALY
        # max 10 points
        # ========================================================

        anomaly_score = (
            self.get_max_anomaly_score(
                enriched_evidence
            )
        )


        anomaly_points = 0


        if anomaly_score >= 70:

            anomaly_points = 10

            reasons.append(
                "Strong process anomaly."
            )


        elif anomaly_score >= 35:

            anomaly_points = 5

            reasons.append(
                "Process anomaly observed."
            )


        score += anomaly_points

        components[
            "anomaly"
        ] = {

            "value":
                anomaly_score,

            "points":
                anomaly_points,
        }


        # ========================================================
        # 6. PERSISTENCE
        # max 10 points
        # ========================================================

        persistence = (
            self.has_persistence(
                enriched_evidence,
                attack_timeline,
            )
        )


        persistence_points = (
            10
            if persistence
            else 0
        )


        if persistence:

            reasons.append(
                "Persistence-related activity is present."
            )


        score += persistence_points

        components[
            "persistence"
        ] = {

            "value":
                persistence,

            "points":
                persistence_points,
        }


        # ========================================================
        # 7. NETWORK ACTIVITY
        # max 5 points
        # ========================================================

        network_activity = (
            self.has_network_activity(
                enriched_evidence
            )
        )


        network_points = (
            5
            if network_activity
            else 0
        )


        if network_activity:

            reasons.append(
                "Network communication is associated with the incident."
            )


        score += network_points

        components[
            "network_activity"
        ] = {

            "value":
                network_activity,

            "points":
                network_points,
        }


        # ========================================================
        # 8. TELEMETRY DIVERSITY
        # max 5 points
        # ========================================================

        category_count = (
            self.get_category_count(
                investigation,
                enriched_evidence,
            )
        )


        category_points = 0


        if category_count >= 4:

            category_points = 5

            reasons.append(
                "Activity spans four telemetry categories."
            )


        elif category_count >= 3:

            category_points = 4


        elif category_count >= 2:

            category_points = 2


        score += category_points

        components[
            "telemetry_diversity"
        ] = {

            "value":
                category_count,

            "points":
                category_points,
        }


        # ========================================================
        # 9. RELATIONSHIP CONFIDENCE
        # max 5 points
        # ========================================================

        relationship_info = (
            self.get_relationship_strength(
                enriched_evidence
            )
        )


        relationship_points = 0


        if (
            relationship_info[
                "high_confidence_count"
            ]
            >= 3
        ):

            relationship_points = 5

            reasons.append(
                "Multiple high-confidence entity relationships support the incident."
            )


        elif (
            relationship_info[
                "high_confidence_count"
            ]
            >= 1
        ):

            relationship_points = 3


        score += relationship_points

        components[
            "entity_relationships"
        ] = {

            "value":
                relationship_info,

            "points":
                relationship_points,
        }


        # ========================================================
        # 10. INCIDENT SEVERITY
        # max 10 points
        # ========================================================

        incident_severity = (
            incident.get(
                "severity",
                "INFO",
            )
        )


        severity_points = (
            self.severity_points(
                incident_severity
            )
        )


        score += severity_points

        components[
            "incident_severity"
        ] = {

            "value":
                incident_severity,

            "points":
                severity_points,
        }


        # ========================================================
        # CAP FINAL RISK
        # ========================================================

        score = min(
            int(
                score
            ),
            100,
        )


        risk_level = (
            self.score_to_risk_level(
                score
            )
        )


        return {

            "incident_id":
                incident.get(
                    "incident_id"
                ),

            "agent":
                self.name,

            "assessed_at":
                self.now_iso(),

            "risk_score":
                score,

            "risk_level":
                risk_level,

            "recommended_action":
                self.recommended_action(
                    risk_level
                ),

            "requires_response":
                risk_level
                in [
                    "CRITICAL",
                    "HIGH",
                ],

            "components":
                components,

            "reasons":
                reasons,

            "evidence_summary": {

                "malware_probability":
                    malware_probability,

                "static_risk":
                    static_risk,

                "behavior_score":
                    behavior_score,

                "anomaly_score":
                    anomaly_score,

                "combined_process_score":
                    self.get_max_combined_process_score(
                        enriched_evidence
                    ),

                "persistence":
                    persistence,

                "network_activity":
                    network_activity,

                "telemetry_categories":
                    category_count,

                "relationship_count":
                    relationship_info[
                        "count"
                    ],

                "high_confidence_relationships":
                    relationship_info[
                        "high_confidence_count"
                    ],
            },
        }