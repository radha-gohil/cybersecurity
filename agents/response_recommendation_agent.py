from datetime import datetime, timezone


class ResponseRecommendationAgent:

    def __init__(self):

        self.name = "ResponseRecommendationAgent"


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
        evidence: dict,
    ) -> float:

        maximum = 0.0


        for file_item in self.safe_list(
            evidence.get(
                "files"
            )
        ):

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
    # GET MAX PROCESS THREAT SCORE
    # ============================================================

    def get_max_process_score(
        self,
        evidence: dict,
    ) -> int:

        maximum = 0


        for process in self.safe_list(
            evidence.get(
                "processes"
            )
        ):

            values = [

                self.safe_int(
                    process.get(
                        "behavior_score"
                    ),
                    0,
                ),

                self.safe_int(
                    process.get(
                        "anomaly_score"
                    ),
                    0,
                ),

                self.safe_int(
                    process.get(
                        "combined_threat_score"
                    ),
                    0,
                ),
            ]


            maximum = max(
                maximum,
                *values,
            )


        return maximum


    # ============================================================
    # CHECK NETWORK ACTIVITY
    # ============================================================

    def has_network_activity(
        self,
        evidence: dict,
    ) -> bool:

        return bool(
            self.safe_list(
                evidence.get(
                    "network_connections"
                )
            )
        )


    # ============================================================
    # CHECK POSSIBLE PERSISTENCE
    # ============================================================

    def has_persistence_activity(
        self,
        evidence: dict,
        attack_timeline: dict,
    ) -> bool:

        attack_stages = (
            self.safe_list(
                attack_timeline.get(
                    "attack_stages"
                )
            )
        )


        if "PERSISTENCE" in attack_stages:

            return True


        registry_items = (
            self.safe_list(
                evidence.get(
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

                for value in item.values()

                if value is not None
            ).lower()


            for keyword in persistence_keywords:

                if keyword in text:

                    return True


        return False


    # ============================================================
    # ADD UNIQUE RECOMMENDATION
    # ============================================================

    def add_recommendation(
        self,
        recommendations: list,
        action: str,
        priority: str,
        reason: str,
        requires_approval: bool = True,
        target: dict = None,
    ):

        for existing in recommendations:

            if existing.get(
                "action"
            ) == action:

                return


        recommendations.append(
            {

                "action":
                    action,

                "priority":
                    priority,

                "reason":
                    reason,

                "requires_approval":
                    requires_approval,

                "target":
                    target
                    if isinstance(
                        target,
                        dict,
                    )
                    else {},
            }
        )


    # ============================================================
    # DETERMINE OVERALL RESPONSE LEVEL
    # ============================================================

    def determine_response_level(
        self,
        consensus_decision: str,
        risk_level: str,
    ) -> str:

        consensus_decision = str(
            consensus_decision
        ).upper()


        risk_level = str(
            risk_level
        ).upper()


        if (
            consensus_decision
            == "CONTAINMENT_RECOMMENDED"

            or risk_level
            == "CRITICAL"
        ):

            return "CONTAINMENT_REVIEW"


        if consensus_decision in [

            "RESPONSE_RECOMMENDED",

            "RESPONSE_REVIEW",
        ]:

            return "RESPONSE_REVIEW"


        if consensus_decision in [

            "INVESTIGATE",

            "CONTINUE_ANALYSIS",
        ]:

            return "INVESTIGATION"


        return "MONITORING"


    # ============================================================
    # GENERATE RECOMMENDATIONS
    # ============================================================

    def generate(
        self,
        consensus: dict,
        risk: dict,
        evidence: dict,
        attack_timeline: dict,
    ) -> dict:

        consensus = (
            self.safe_dict(
                consensus
            )
        )

        risk = (
            self.safe_dict(
                risk
            )
        )

        evidence = (
            self.safe_dict(
                evidence
            )
        )

        attack_timeline = (
            self.safe_dict(
                attack_timeline
            )
        )


        recommendations = []


        consensus_decision = str(
            consensus.get(
                "final_decision",
                "MONITOR",
            )
        ).upper()


        consensus_confidence = (
            self.safe_int(
                consensus.get(
                    "consensus_confidence"
                ),
                0,
            )
        )


        risk_score = (
            self.safe_int(
                risk.get(
                    "risk_score"
                ),
                0,
            )
        )


        risk_level = str(
            risk.get(
                "risk_level",
                "INFO",
            )
        ).upper()


        malware_probability = (
            self.get_max_malware_probability(
                evidence
            )
        )


        process_score = (
            self.get_max_process_score(
                evidence
            )
        )


        network_activity = (
            self.has_network_activity(
                evidence
            )
        )


        persistence_activity = (
            self.has_persistence_activity(
                evidence,
                attack_timeline,
            )
        )


        # ========================================================
        # ALWAYS RETAIN / MONITOR EVIDENCE
        # ========================================================

        self.add_recommendation(

            recommendations,

            action=
                "MONITOR_INCIDENT",

            priority=
                "LOW",

            reason=
                "Continue monitoring and retain incident evidence.",

            requires_approval=
                False,
        )


        # ========================================================
        # INVESTIGATION
        # ========================================================

        if (
            risk_score >= 35

            or consensus_decision in [

                "INVESTIGATE",

                "CONTINUE_ANALYSIS",

                "RESPONSE_REVIEW",

                "RESPONSE_RECOMMENDED",

                "CONTAINMENT_RECOMMENDED",
            ]
        ):

            self.add_recommendation(

                recommendations,

                action=
                    "INVESTIGATE_INCIDENT",

                priority=
                    (
                        "HIGH"
                        if risk_score >= 60
                        else "MEDIUM"
                    ),

                reason=
                    "The incident has sufficient risk or agent support for further investigation.",

                requires_approval=
                    False,
            )


        # ========================================================
        # FILE QUARANTINE REVIEW
        # ========================================================

        if malware_probability >= 0.70:

            suspicious_files = []


            for file_item in self.safe_list(
                evidence.get(
                    "files"
                )
            ):

                probability = (
                    self.safe_float(
                        file_item.get(
                            "malware_probability"
                        ),
                        0.0,
                    )
                )


                if probability >= 0.70:

                    suspicious_files.append(
                        {

                            "path":
                                file_item.get(
                                    "path"
                                ),

                            "sha256":
                                file_item.get(
                                    "sha256"
                                ),

                            "malware_probability":
                                probability,
                        }
                    )


            self.add_recommendation(

                recommendations,

                action=
                    "QUARANTINE_REVIEW",

                priority=
                    (
                        "CRITICAL"
                        if malware_probability >= 0.90
                        else "HIGH"
                    ),

                reason=
                    (
                        "One or more files have elevated malware-model probability. "
                        "Analyst validation is required before quarantine."
                    ),

                requires_approval=
                    True,

                target={

                    "files":
                        suspicious_files,
                },
            )


        # ========================================================
        # PROCESS TERMINATION REVIEW
        # ========================================================

        if process_score >= 60:

            suspicious_processes = []


            for process in self.safe_list(
                evidence.get(
                    "processes"
                )
            ):

                combined_score = max(

                    self.safe_int(
                        process.get(
                            "behavior_score"
                        ),
                        0,
                    ),

                    self.safe_int(
                        process.get(
                            "anomaly_score"
                        ),
                        0,
                    ),

                    self.safe_int(
                        process.get(
                            "combined_threat_score"
                        ),
                        0,
                    ),
                )


                if combined_score >= 60:

                    suspicious_processes.append(
                        {

                            "pid":
                                process.get(
                                    "pid"
                                ),

                            "name":
                                process.get(
                                    "name"
                                ),

                            "exe":
                                process.get(
                                    "exe"
                                ),

                            "threat_score":
                                combined_score,
                        }
                    )


            self.add_recommendation(

                recommendations,

                action=
                    "PROCESS_TERMINATION_REVIEW",

                priority=
                    (
                        "CRITICAL"
                        if process_score >= 80
                        else "HIGH"
                    ),

                reason=
                    (
                        "High process behavior or anomaly score observed. "
                        "Review the process before termination."
                    ),

                requires_approval=
                    True,

                target={

                    "processes":
                        suspicious_processes,
                },
            )


        # ========================================================
        # NETWORK BLOCK REVIEW
        # ========================================================

        if (
            network_activity

            and risk_score >= 60
        ):

            remote_endpoints = []


            for item in self.safe_list(
                evidence.get(
                    "network_connections"
                )
            ):

                remote_ip = (
                    item.get(
                        "remote_ip"
                    )
                )


                if remote_ip:

                    entry = {

                        "remote_ip":
                            remote_ip,

                        "remote_port":
                            item.get(
                                "remote_port"
                            ),

                        "pid":
                            item.get(
                                "pid"
                            ),

                        "process_name":
                            item.get(
                                "process_name"
                            ),
                    }


                    if entry not in remote_endpoints:

                        remote_endpoints.append(
                            entry
                        )


            self.add_recommendation(

                recommendations,

                action=
                    "NETWORK_BLOCK_REVIEW",

                priority=
                    (
                        "CRITICAL"
                        if risk_level
                        == "CRITICAL"
                        else "HIGH"
                    ),

                reason=
                    (
                        "Network communication is associated with a high-risk incident. "
                        "Validate the destination before applying any block."
                    ),

                requires_approval=
                    True,

                target={

                    "connections":
                        remote_endpoints,
                },
            )


        # ========================================================
        # PERSISTENCE REMEDIATION REVIEW
        # ========================================================

        if (
            persistence_activity

            and risk_score >= 60
        ):

            self.add_recommendation(

                recommendations,

                action=
                    "PERSISTENCE_REMEDIATION_REVIEW",

                priority=
                    (
                        "CRITICAL"
                        if risk_level
                        == "CRITICAL"
                        else "HIGH"
                    ),

                reason=
                    (
                        "Possible persistence-related activity is associated with "
                        "the incident. Review the artifact before removal."
                    ),

                requires_approval=
                    True,

                target={

                    "registry_artifacts":
                        self.safe_list(
                            evidence.get(
                                "registry_artifacts"
                            )
                        ),
                },
            )


        # ========================================================
        # ENDPOINT ISOLATION REVIEW
        # ========================================================

        if (
            consensus_decision
            == "CONTAINMENT_RECOMMENDED"

            and risk_score >= 80

            and consensus_confidence >= 70
        ):

            self.add_recommendation(

                recommendations,

                action=
                    "ENDPOINT_ISOLATION_REVIEW",

                priority=
                    "CRITICAL",

                reason=
                    (
                        "Agents recommend containment and the incident has a "
                        "critical risk score. Human approval is required before "
                        "endpoint isolation."
                    ),

                requires_approval=
                    True,
            )


        # ========================================================
        # RESPONSE LEVEL
        # ========================================================

        response_level = (
            self.determine_response_level(
                consensus_decision,
                risk_level,
            )
        )


        return {

            "agent":
                self.name,

            "generated_at":
                self.now_iso(),

            "response_level":
                response_level,

            "consensus_decision":
                consensus_decision,

            "consensus_confidence":
                consensus_confidence,

            "risk_score":
                risk_score,

            "risk_level":
                risk_level,

            "recommendation_count":
                len(
                    recommendations
                ),

            "recommendations":
                recommendations,

            "execution_allowed":
                False,

            "note":
                (
                    "Recommendations are advisory only. "
                    "No containment or remediation action was executed."
                ),
        }