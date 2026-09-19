from datetime import datetime, timezone


class TriageAgent:

    def __init__(self):

        self.name = "TriageAgent"


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
    # SAFE INTEGER
    # ============================================================

    def safe_int(
        self,
        value,
        default=0,
    ):

        try:

            return int(
                value
            )

        except (
            TypeError,
            ValueError,
        ):

            return default


    # ============================================================
    # SAFE FLOAT
    # ============================================================

    def safe_float(
        self,
        value,
        default=0.0,
    ):

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
    # SEVERITY SCORE
    # ============================================================

    def severity_score(
        self,
        severity,
    ) -> int:

        mapping = {

            "INFO":
                0,

            "LOW":
                5,

            "MEDIUM":
                15,

            "HIGH":
                25,

            "CRITICAL":
                35,
        }


        return mapping.get(
            str(
                severity
            ).upper(),
            0,
        )


    # ============================================================
    # GET TIMELINE
    # ============================================================

    def get_timeline(
        self,
        incident: dict,
    ) -> list:

        timeline = (
            incident.get(
                "timeline"
            )
            or []
        )


        if not isinstance(
            timeline,
            list,
        ):

            return []


        return timeline


    # ============================================================
    # GET EVENT CATEGORIES
    # ============================================================

    def get_categories(
        self,
        incident: dict,
    ) -> set:

        categories = set()


        timeline = (
            self.get_timeline(
                incident
            )
        )


        for event in timeline:

            event_type = str(
                event.get(
                    "event_type",
                    ""
                )
            ).lower()


            if event_type.startswith(
                "process"
            ):

                categories.add(
                    "PROCESS"
                )


            elif event_type.startswith(
                "file"
            ):

                categories.add(
                    "FILE"
                )


            elif event_type.startswith(
                "network"
            ):

                categories.add(
                    "NETWORK"
                )


            elif (
                event_type.startswith(
                    "registry"
                )
                or event_type.startswith(
                    "startup"
                )
            ):

                categories.add(
                    "REGISTRY"
                )


        # --------------------------------------------------------
        # FALLBACK TO INCIDENT CATEGORIES
        # --------------------------------------------------------

        if not categories:

            stored_categories = (
                incident.get(
                    "categories"
                )
                or []
            )


            if isinstance(
                stored_categories,
                list,
            ):

                for category in stored_categories:

                    categories.add(
                        str(
                            category
                        ).upper()
                    )


        return categories


    # ============================================================
    # FIND MAX MALWARE PROBABILITY
    # ============================================================

    def get_max_malware_probability(
        self,
        incident: dict,
    ) -> float:

        max_probability = 0.0


        for event in self.get_timeline(
            incident
        ):

            file_data = (
                event.get(
                    "file"
                )
                or {}
            )


            probability = (
                file_data.get(
                    "malware_probability"
                )
            )


            probability = (
                self.safe_float(
                    probability,
                    0.0,
                )
            )


            max_probability = max(
                max_probability,
                probability,
            )


        return max_probability


    # ============================================================
    # FIND MAX BEHAVIOR SCORE
    # ============================================================

    def get_max_behavior_score(
        self,
        incident: dict,
    ) -> int:

        maximum = 0


        for event in self.get_timeline(
            incident
        ):

            process = (
                event.get(
                    "process"
                )
                or {}
            )


            metadata = (
                event.get(
                    "metadata"
                )
                or {}
            )


            values = [

                process.get(
                    "behavior_score"
                ),

                metadata.get(
                    "behavior_score"
                ),
            ]


            for value in values:

                maximum = max(

                    maximum,

                    self.safe_int(
                        value,
                        0,
                    ),
                )


        return maximum


    # ============================================================
    # FIND MAX ANOMALY SCORE
    # ============================================================

    def get_max_anomaly_score(
        self,
        incident: dict,
    ) -> int:

        maximum = 0


        for event in self.get_timeline(
            incident
        ):

            process = (
                event.get(
                    "process"
                )
                or {}
            )


            metadata = (
                event.get(
                    "metadata"
                )
                or {}
            )


            values = [

                process.get(
                    "anomaly_score"
                ),

                metadata.get(
                    "anomaly_score"
                ),
            ]


            for value in values:

                maximum = max(

                    maximum,

                    self.safe_int(
                        value,
                        0,
                    ),
                )


        return maximum


    # ============================================================
    # CHECK REGISTRY PERSISTENCE
    # ============================================================

    def has_persistence_activity(
        self,
        incident: dict,
    ) -> bool:

        persistence_keywords = [

            "\\run",

            "\\runonce",

            "startup",

            "winlogon",

            "services",

            "scheduled task",
        ]


        for event in self.get_timeline(
            incident
        ):

            registry = (
                event.get(
                    "registry"
                )
                or {}
            )


            registry_text = " ".join(

                str(
                    value
                )

                for value
                in registry.values()

                if value is not None
            ).lower()


            for keyword in persistence_keywords:

                if keyword in registry_text:

                    return True


        return False


    # ============================================================
    # CHECK NETWORK ACTIVITY
    # ============================================================

    def has_network_activity(
        self,
        incident: dict,
    ) -> bool:

        categories = (
            self.get_categories(
                incident
            )
        )


        return (
            "NETWORK"
            in categories
        )


    # ============================================================
    # CALCULATE TRIAGE SCORE
    # ============================================================

    def calculate_triage_score(
        self,
        incident: dict,
    ) -> dict:

        score = 0

        reasons = []


        # ========================================================
        # 1. INCIDENT SEVERITY
        # ========================================================

        severity = (
            incident.get(
                "severity",
                "INFO",
            )
        )


        severity_points = (
            self.severity_score(
                severity
            )
        )


        score += (
            severity_points
        )


        if severity_points > 0:

            reasons.append(
                f"Incident severity is {str(severity).upper()}."
            )


        # ========================================================
        # 2. CORRELATION SCORE
        # ========================================================

        correlation_score = (
            self.safe_int(
                incident.get(
                    "correlation_score"
                ),
                0,
            )
        )


        if correlation_score >= 80:

            score += 25

            reasons.append(
                "Very high multi-event correlation score."
            )


        elif correlation_score >= 60:

            score += 20

            reasons.append(
                "High multi-event correlation score."
            )


        elif correlation_score >= 35:

            score += 10

            reasons.append(
                "Moderate correlation score."
            )


        # ========================================================
        # 3. TELEMETRY CATEGORY DIVERSITY
        # ========================================================

        categories = (
            self.get_categories(
                incident
            )
        )


        category_count = len(
            categories
        )


        if category_count >= 4:

            score += 15

            reasons.append(
                "Activity spans process, file, network and registry telemetry."
            )


        elif category_count >= 3:

            score += 10

            reasons.append(
                "Activity spans at least three telemetry categories."
            )


        elif category_count >= 2:

            score += 5

            reasons.append(
                "Activity spans multiple telemetry categories."
            )


        # ========================================================
        # 4. MALWARE PROBABILITY
        # ========================================================

        malware_probability = (
            self.get_max_malware_probability(
                incident
            )
        )


        if malware_probability >= 0.90:

            score += 20

            reasons.append(
                "File has very high malware probability."
            )


        elif malware_probability >= 0.70:

            score += 15

            reasons.append(
                "File has elevated malware probability."
            )


        elif malware_probability >= 0.40:

            score += 5

            reasons.append(
                "File has moderate malware probability."
            )


        # ========================================================
        # 5. BEHAVIOR SCORE
        # ========================================================

        behavior_score = (
            self.get_max_behavior_score(
                incident
            )
        )


        if behavior_score >= 70:

            score += 15

            reasons.append(
                "Strong suspicious process behavior detected."
            )


        elif behavior_score >= 35:

            score += 8

            reasons.append(
                "Suspicious process behavior detected."
            )


        # ========================================================
        # 6. ANOMALY SCORE
        # ========================================================

        anomaly_score = (
            self.get_max_anomaly_score(
                incident
            )
        )


        if anomaly_score >= 70:

            score += 10

            reasons.append(
                "Strong process anomaly detected."
            )


        elif anomaly_score >= 35:

            score += 5

            reasons.append(
                "Process anomaly detected."
            )


        # ========================================================
        # 7. REGISTRY PERSISTENCE
        # ========================================================

        persistence = (
            self.has_persistence_activity(
                incident
            )
        )


        if persistence:

            score += 15

            reasons.append(
                "Possible persistence-related registry activity detected."
            )


        # ========================================================
        # 8. NETWORK ACTIVITY
        # ========================================================

        network_activity = (
            self.has_network_activity(
                incident
            )
        )


        if network_activity:

            score += 5

            reasons.append(
                "Network communication is associated with the incident."
            )


        # ========================================================
        # CAP SCORE
        # ========================================================

        score = min(
            score,
            100,
        )


        return {

            "triage_score":
                score,

            "reasons":
                reasons,

            "categories":
                sorted(
                    categories
                ),

            "malware_probability":
                malware_probability,

            "behavior_score":
                behavior_score,

            "anomaly_score":
                anomaly_score,

            "persistence_detected":
                persistence,

            "network_activity":
                network_activity,
        }


    # ============================================================
    # SCORE -> PRIORITY
    # ============================================================

    def score_to_priority(
        self,
        score: int,
    ) -> str:

        if score >= 80:

            return "P1"


        if score >= 60:

            return "P2"


        if score >= 35:

            return "P3"


        return "P4"


    # ============================================================
    # PRIORITY DESCRIPTION
    # ============================================================

    def priority_description(
        self,
        priority: str,
    ) -> str:

        mapping = {

            "P1":
                "Immediate investigation required.",

            "P2":
                "High-priority investigation recommended.",

            "P3":
                "Standard investigation required.",

            "P4":
                "Low-priority monitoring recommended.",
        }


        return mapping.get(
            priority,
            "Monitoring recommended.",
        )


    # ============================================================
    # TRIAGE INCIDENT
    # ============================================================

    def triage(
        self,
        incident: dict,
    ) -> dict:

        analysis = (
            self.calculate_triage_score(
                incident
            )
        )


        triage_score = (
            analysis[
                "triage_score"
            ]
        )


        priority = (
            self.score_to_priority(
                triage_score
            )
        )


        return {

            "incident_id":
                incident.get(
                    "incident_id"
                ),

            "agent":
                self.name,

            "triaged_at":
                self.now_iso(),

            "triage_score":
                triage_score,

            "priority":
                priority,

            "recommendation":
                self.priority_description(
                    priority
                ),

            "reasons":
                analysis[
                    "reasons"
                ],

            "categories":
                analysis[
                    "categories"
                ],

            "malware_probability":
                analysis[
                    "malware_probability"
                ],

            "behavior_score":
                analysis[
                    "behavior_score"
                ],

            "anomaly_score":
                analysis[
                    "anomaly_score"
                ],

            "persistence_detected":
                analysis[
                    "persistence_detected"
                ],

            "network_activity":
                analysis[
                    "network_activity"
                ],

            "requires_investigation":
                priority
                in [
                    "P1",
                    "P2",
                    "P3",
                ],
        }


    # ============================================================
    # TRIAGE MULTIPLE INCIDENTS
    # ============================================================

    def triage_incidents(
        self,
        incidents: list,
    ) -> list:

        results = []


        for incident in incidents:

            result = (
                self.triage(
                    incident
                )
            )

            results.append(
                result
            )


        # --------------------------------------------------------
        # Highest triage score first
        # --------------------------------------------------------

        results.sort(

            key=lambda item:
                item.get(
                    "triage_score",
                    0,
                ),

            reverse=True,
        )


        return results