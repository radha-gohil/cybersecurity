class DigitalTwinRiskPredictor:

    def __init__(self):

        self.name = "DigitalTwinRiskPredictor"


    # ============================================================
    # SAFE HELPERS
    # ============================================================

    def safe_int(
        self,
        value,
        default=0,
    ) -> int:

        try:
            return int(value)

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
            return float(value)

        except (
            TypeError,
            ValueError,
        ):
            return default


    # ============================================================
    # SCORE -> LEVEL
    # ============================================================

    def score_to_level(
        self,
        score: int,
    ) -> str:

        score = max(
            0,
            min(
                int(score),
                100,
            ),
        )


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
    # ACTIVE HIGH-RISK PROCESS SCORE
    # ============================================================

    def process_risk(
        self,
        twin,
    ) -> float:

        risk = 0.0


        for process in twin.processes:

            if process.get(
                "terminated_in_twin",
                False,
            ):
                continue


            threat_score = max(

                self.safe_int(
                    process.get(
                        "combined_threat_score"
                    ),
                    0,
                ),

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
            )


            risk = max(
                risk,
                threat_score * 0.30,
            )


        return risk


    # ============================================================
    # ACTIVE FILE RISK
    # ============================================================

    def file_risk(
        self,
        twin,
    ) -> float:

        risk = 0.0


        for file_item in twin.files:

            if file_item.get(
                "quarantined_in_twin",
                False,
            ):
                continue


            malware_probability = (
                self.safe_float(
                    file_item.get(
                        "malware_probability"
                    ),
                    0.0,
                )
            )


            static_risk = (
                self.safe_int(
                    file_item.get(
                        "static_risk_score"
                    ),
                    0,
                )
            )


            probability_component = (
                malware_probability
                * 100
                * 0.25
            )


            static_component = (
                static_risk
                * 0.10
            )


            risk = max(
                risk,
                probability_component
                + static_component,
            )


        return risk


    # ============================================================
    # ACTIVE NETWORK RISK
    # ============================================================

    def network_risk(
        self,
        twin,
    ) -> float:

        active_connections = [

            connection

            for connection
            in twin.network_connections

            if not connection.get(
                "blocked_in_twin",
                False,
            )
        ]


        if not active_connections:
            return 0.0


        # Network presence alone is only supporting evidence.
        return min(
            15.0,
            5.0
            + (
                len(
                    active_connections
                )
                - 1
            )
            * 2.0,
        )


    # ============================================================
    # ACTIVE PERSISTENCE RISK
    # ============================================================

    def persistence_risk(
        self,
        twin,
    ) -> float:

        active_artifacts = [

            artifact

            for artifact
            in twin.persistence_artifacts

            if not artifact.get(
                "removed_in_twin",
                False,
            )
        ]


        if not active_artifacts:
            return 0.0


        return min(
            20.0,
            12.0
            + (
                len(
                    active_artifacts
                )
                - 1
            )
            * 3.0,
        )


    # ============================================================
    # ENDPOINT ISOLATION EFFECT
    # ============================================================

    def isolation_adjustment(
        self,
        twin,
    ) -> float:

        if twin.endpoint_state.get(
            "isolated",
            False,
        ):

            return -10.0


        return 0.0


    # ============================================================
    # CALCULATE PREDICTED RISK
    # ============================================================

    def calculate_predicted_risk(
        self,
        twin,
    ) -> dict:

        process_component = (
            self.process_risk(
                twin
            )
        )


        file_component = (
            self.file_risk(
                twin
            )
        )


        network_component = (
            self.network_risk(
                twin
            )
        )


        persistence_component = (
            self.persistence_risk(
                twin
            )
        )


        isolation_component = (
            self.isolation_adjustment(
                twin
            )
        )


        score = (

            process_component
            + file_component
            + network_component
            + persistence_component
            + isolation_component
        )


        score = max(
            0,
            min(
                round(score),
                100,
            ),
        )


        return {

            "predicted_risk_score":
                score,

            "predicted_risk_level":
                self.score_to_level(
                    score
                ),

            "components": {

                "process":
                    round(
                        process_component,
                        2,
                    ),

                "file":
                    round(
                        file_component,
                        2,
                    ),

                "network":
                    round(
                        network_component,
                        2,
                    ),

                "persistence":
                    round(
                        persistence_component,
                        2,
                    ),

                "isolation_adjustment":
                    round(
                        isolation_component,
                        2,
                    ),
            },
        }


    # ============================================================
    # RESPONSE EFFECTIVENESS
    # ============================================================

    def response_effectiveness(
        self,
        reduction_percentage,
    ) -> str:

        if reduction_percentage >= 70:
            return "VERY_HIGH"

        if reduction_percentage >= 50:
            return "HIGH"

        if reduction_percentage >= 25:
            return "MODERATE"

        if reduction_percentage > 0:
            return "LOW"

        return "NONE"


    # ============================================================
    # OPERATIONAL IMPACT
    # ============================================================

    def operational_impact(
        self,
        twin,
    ) -> dict:

        impact_score = 0

        reasons = []


        terminated_processes = sum(

            1

            for process in twin.processes

            if process.get(
                "terminated_in_twin",
                False,
            )
        )


        quarantined_files = sum(

            1

            for file_item in twin.files

            if file_item.get(
                "quarantined_in_twin",
                False,
            )
        )


        blocked_connections = sum(

            1

            for connection
            in twin.network_connections

            if connection.get(
                "blocked_in_twin",
                False,
            )
        )


        removed_persistence = sum(

            1

            for artifact
            in twin.persistence_artifacts

            if artifact.get(
                "removed_in_twin",
                False,
            )
        )


        # --------------------------------------------------------
        # PROCESS IMPACT
        # --------------------------------------------------------

        if terminated_processes:

            impact_score += min(
                30,
                terminated_processes * 15,
            )

            reasons.append(
                f"{terminated_processes} process(es) would be terminated."
            )


        # --------------------------------------------------------
        # FILE IMPACT
        # --------------------------------------------------------

        if quarantined_files:

            impact_score += min(
                25,
                quarantined_files * 12,
            )

            reasons.append(
                f"{quarantined_files} file(s) would be quarantined."
            )


        # --------------------------------------------------------
        # NETWORK IMPACT
        # --------------------------------------------------------

        if blocked_connections:

            impact_score += min(
                20,
                blocked_connections * 8,
            )

            reasons.append(
                f"{blocked_connections} network connection(s) would be restricted."
            )


        # --------------------------------------------------------
        # PERSISTENCE IMPACT
        # --------------------------------------------------------

        if removed_persistence:

            impact_score += min(
                15,
                removed_persistence * 8,
            )

            reasons.append(
                f"{removed_persistence} persistence artifact(s) would be remediated."
            )


        # --------------------------------------------------------
        # ENDPOINT ISOLATION
        # --------------------------------------------------------

        if twin.endpoint_state.get(
            "isolated",
            False,
        ):

            impact_score += 35

            reasons.append(
                "Endpoint isolation would significantly restrict normal connectivity."
            )


        impact_score = min(
            impact_score,
            100,
        )


        if impact_score >= 70:

            level = "HIGH"

        elif impact_score >= 35:

            level = "MEDIUM"

        elif impact_score > 0:

            level = "LOW"

        else:

            level = "MINIMAL"


        return {

            "impact_score":
                impact_score,

            "impact_level":
                level,

            "reasons":
                reasons,
        }


    # ============================================================
    # RECOMMENDED DECISION
    # ============================================================

    def recommended_decision(
        self,
        residual_risk: int,
        risk_reduction_percentage: float,
        impact_level: str,
    ) -> str:

        if (
            residual_risk >= 60
            and risk_reduction_percentage < 25
        ):

            return "REASSESS_RESPONSE_PLAN"


        if impact_level == "HIGH":

            return "ANALYST_REVIEW_REQUIRED"


        if (
            residual_risk < 35
            and risk_reduction_percentage >= 50
        ):

            return "RESPONSE_PLAN_EFFECTIVE"


        return "RESPONSE_PLAN_REVIEW"


    # ============================================================
    # PREDICT
    # ============================================================

    def predict(
        self,
        twin,
    ) -> dict:

        initial_risk = (
            self.safe_int(
                twin.initial_risk_score,
                0,
            )
        )


        predicted = (
            self.calculate_predicted_risk(
                twin
            )
        )


        residual_risk = (
            predicted[
                "predicted_risk_score"
            ]
        )


        risk_reduction = max(
            0,
            initial_risk
            - residual_risk,
        )


        if initial_risk > 0:

            risk_reduction_percentage = (
                risk_reduction
                / initial_risk
                * 100
            )

        else:

            risk_reduction_percentage = 0.0


        impact = (
            self.operational_impact(
                twin
            )
        )


        effectiveness = (
            self.response_effectiveness(
                risk_reduction_percentage
            )
        )


        decision = (
            self.recommended_decision(

                residual_risk=
                    residual_risk,

                risk_reduction_percentage=
                    risk_reduction_percentage,

                impact_level=
                    impact[
                        "impact_level"
                    ],
            )
        )


        twin.update_risk(
            residual_risk
        )


        return {

            "predictor":
                self.name,

            "twin_id":
                twin.twin_id,

            "incident_id":
                twin.incident_id,

            "initial_risk_score":
                initial_risk,

            "initial_risk_level":
                twin.initial_risk_level,

            "predicted_residual_risk":
                residual_risk,

            "predicted_residual_level":
                predicted[
                    "predicted_risk_level"
                ],

            "risk_reduction":
                risk_reduction,

            "risk_reduction_percentage":
                round(
                    risk_reduction_percentage,
                    2,
                ),

            "response_effectiveness":
                effectiveness,

            "operational_impact":
                impact,

            "risk_components":
                predicted[
                    "components"
                ],

            "recommended_decision":
                decision,

            "real_endpoint_modified":
                False,
        }