
"""
SENTINEL-X Digital Twin Risk Predictor

HEURISTIC ONLY:
- Scores represent virtual-model components.
- Scores are NOT attack probabilities.
- Reductions are NOT verified mitigation efficacy.
- Network presence alone is supporting context.
- No endpoint actions or persistence operations.
"""

class DigitalTwinRiskPredictor:

    MODEL_TYPE = "HEURISTIC_DIGITAL_TWIN_V1"

    def __init__(self):
        self.name = "DigitalTwinRiskPredictor"

    def safe_int(self, value, default=0):
        try:
            return int(float(value))
        except (TypeError, ValueError, OverflowError):
            return default

    def safe_float(self, value, default=0.0):
        try:
            result = float(value)
            if result != result or result in (
                float("inf"), float("-inf")
            ):
                return default
            return result
        except (TypeError, ValueError, OverflowError):
            return default

    def clamp(self, value, minimum=0, maximum=100):
        return max(minimum, min(maximum, value))

    def score_to_level(self, score):
        score = self.clamp(self.safe_int(score))
        if score >= 80:
            return "CRITICAL"
        if score >= 60:
            return "HIGH"
        if score >= 35:
            return "MEDIUM"
        if score >= 15:
            return "LOW"
        return "INFO"

    def process_risk(self, twin):
        risk = 0.0

        for process in twin.processes:
            if process.get("terminated_in_twin", False):
                continue

            score = max(
                self.safe_float(
                    process.get("combined_threat_score")
                ),
                self.safe_float(
                    process.get("behavior_score")
                ),
                self.safe_float(
                    process.get("anomaly_score")
                ),
                0.0,
            )

            # Historical heuristic, not a learned risk weight.
            risk = max(risk, self.clamp(score) * 0.30)

        return round(risk, 2)

    def file_risk(self, twin):
        risk = 0.0

        for file_item in twin.files:
            if file_item.get("quarantined_in_twin", False):
                continue

            # Only compute legacy-compatible scores from
            # explicitly supplied features. The preview
            # removes incompatible malware probabilities.
            probability = self.clamp(
                self.safe_float(
                    file_item.get("malware_probability")
                ),
                0,
                1,
            )

            static_score = self.clamp(
                self.safe_float(
                    file_item.get("static_risk_score")
                )
            )

            component = (
                probability * 100 * 0.25
                + static_score * 0.10
            )
            risk = max(risk, component)

        return round(risk, 2)

    def network_risk(self, twin):
        active = [
            item
            for item in twin.network_connections
            if not item.get("blocked_in_twin", False)
        ]

        if not active:
            return 0.0

        # This is a context score, not proof of
        # malicious network activity.
        return round(
            min(15.0, 5.0 + (len(active) - 1) * 2.0),
            2,
        )

    def persistence_risk(self, twin):
        active = [
            item
            for item in twin.persistence_artifacts
            if not item.get("removed_in_twin", False)
        ]

        if not active:
            return 0.0

        return round(
            min(20.0, 12.0 + (len(active) - 1) * 3.0),
            2,
        )

    def isolation_adjustment(self, twin):
        return (
            -10.0
            if twin.endpoint_state.get("isolated", False)
            else 0.0
        )

    def calculate_predicted_risk(self, twin):
        components = {
            "process": self.process_risk(twin),
            "file": self.file_risk(twin),
            "network": self.network_risk(twin),
            "persistence": self.persistence_risk(twin),
            "isolation_adjustment":
                self.isolation_adjustment(twin),
        }

        raw = sum(components.values())
        score = int(self.clamp(round(raw)))

        # Diagnostic details are informational, not
        # authoritative evidence or eligibility.
        active_processes = sum(
            not item.get("terminated_in_twin", False)
            for item in twin.processes
        )
        active_files = sum(
            not item.get("quarantined_in_twin", False)
            for item in twin.files
        )
        active_network = sum(
            not item.get("blocked_in_twin", False)
            for item in twin.network_connections
        )
        active_persistence = sum(
            not item.get("removed_in_twin", False)
            for item in twin.persistence_artifacts
        )

        limitations = [
            "Heuristic projection, not a calibrated probability.",
            "No learned causal intervention-outcome model.",
            "Virtual action success is not real containment.",
        ]

        if active_network:
            limitations.append(
                "Network presence contributes contextual "
                "risk without proving malicious communication."
            )

        if score == 0:
            limitations.append(
                "Zero modeled risk does not establish "
                "that the endpoint is safe."
            )

        return {
            "predicted_risk_score": score,
            "predicted_risk_level":
                self.score_to_level(score),
            "components": components,
            "component_explanation": {
                "process":
                    "Maximum available process score x 0.30.",
                "file":
                    "Maximum available file feature contribution.",
                "network":
                    "Context from active virtual connections.",
                "persistence":
                    "Context from virtual persistence artifacts.",
                "isolation_adjustment":
                    "Fixed virtual isolation adjustment.",
            },
            "active_entity_counts": {
                "processes": active_processes,
                "files": active_files,
                "network_connections": active_network,
                "registry_artifacts": active_persistence,
            },
            "risk_semantics": "MODELED_HEURISTIC_COMPONENTS",
            "limitations": limitations,
        }

    def response_effectiveness(self, reduction_percentage):
        """
        Legacy descriptor used by the existing planner.
        It describes modeled reduction, NOT actual
        response effectiveness.
        """
        if reduction_percentage >= 70:
            return "VERY_HIGH"
        if reduction_percentage >= 50:
            return "HIGH"
        if reduction_percentage >= 25:
            return "MODERATE"
        if reduction_percentage > 0:
            return "LOW"
        return "NONE"

    def operational_impact(self, twin):
        reasons = []
        score = 0

        terminated = sum(
            bool(item.get("terminated_in_twin", False))
            for item in twin.processes
        )
        quarantined = sum(
            bool(item.get("quarantined_in_twin", False))
            for item in twin.files
        )
        blocked = sum(
            bool(item.get("blocked_in_twin", False))
            for item in twin.network_connections
        )
        removed = sum(
            bool(item.get("removed_in_twin", False))
            for item in twin.persistence_artifacts
        )

        if terminated:
            score += min(30, terminated * 15)
            reasons.append(
                f"{terminated} process(es) virtually terminated."
            )

        if quarantined:
            score += min(25, quarantined * 12)
            reasons.append(
                f"{quarantined} file(s) virtually quarantined."
            )

        if blocked:
            score += min(20, blocked * 8)
            reasons.append(
                f"{blocked} connection(s) virtually blocked."
            )

        if removed:
            score += min(15, removed * 8)
            reasons.append(
                f"{removed} persistence artifact(s) "
                "virtually removed."
            )

        if twin.endpoint_state.get("isolated", False):
            score += 35
            reasons.append(
                "Virtual endpoint isolation may interrupt "
                "normal connectivity."
            )

        score = min(score, 100)

        if score >= 70:
            level = "HIGH"
        elif score >= 35:
            level = "MEDIUM"
        elif score > 0:
            level = "LOW"
        else:
            level = "MINIMAL"

        return {
            "impact_score": score,
            "impact_level": level,
            "reasons": reasons,
        }

    def recommended_decision(
        self,
        residual_risk,
        risk_reduction_percentage,
        impact_level,
    ):
        """
        Preserved for planner compatibility.
        Consumers MUST NOT treat the output as
        authorization or proven effectiveness.
        """
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

    def predict(self, twin):
        initial = self.safe_int(
            twin.initial_risk_score, 0
        )
        projected = self.calculate_predicted_risk(twin)

        residual = projected["predicted_risk_score"]
        reduction = max(0, initial - residual)

        percentage = (
            reduction / initial * 100.0
            if initial > 0
            else 0.0
        )

        impact = self.operational_impact(twin)

        decision = self.recommended_decision(
            residual,
            percentage,
            impact["impact_level"],
        )

        twin.update_risk(residual)

        return {
            "predictor": self.name,
            "model_type": self.MODEL_TYPE,
            "twin_id": twin.twin_id,
            "incident_id": twin.incident_id,
            "initial_risk_score": initial,
            "initial_risk_level":
                twin.initial_risk_level,
            "predicted_residual_risk": residual,
            "predicted_residual_level":
                projected["predicted_risk_level"],
            "risk_reduction": reduction,
            "risk_reduction_percentage":
                round(percentage, 2),
            "response_effectiveness":
                self.response_effectiveness(percentage),
            "operational_impact": impact,
            "risk_components": projected["components"],
            "component_explanation":
                projected["component_explanation"],
            "active_entity_counts":
                projected["active_entity_counts"],
            "recommended_decision": decision,
            "decision_is_authorization": False,
            "risk_semantics":
                projected["risk_semantics"],
            "limitations": projected["limitations"],
            "real_endpoint_modified": False,
        }
