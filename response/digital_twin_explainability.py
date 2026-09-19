from datetime import datetime, timezone


class DigitalTwinExplainability:

    def __init__(self):

        self.name = "DigitalTwinExplainability"


    # ============================================================
    # TIME
    # ============================================================

    def now_iso(self):

        return datetime.now(
            timezone.utc
        ).isoformat()


    # ============================================================
    # SAFE HELPERS
    # ============================================================

    def safe_dict(
        self,
        value,
    ):

        if isinstance(
            value,
            dict,
        ):
            return value

        return {}


    def safe_list(
        self,
        value,
    ):

        if isinstance(
            value,
            list,
        ):
            return value

        return []


    # ============================================================
    # ACTION LABEL
    # ============================================================

    def action_label(
        self,
        action_type,
    ):

        labels = {

            "QUARANTINE_FILE":
                "Quarantine suspicious file",

            "TERMINATE_PROCESS":
                "Terminate suspicious process",

            "BLOCK_NETWORK":
                "Restrict suspicious network connection",

            "REMEDIATE_PERSISTENCE":
                "Remediate persistence artifact",

            "ISOLATE_ENDPOINT":
                "Isolate endpoint",
        }


        return labels.get(
            action_type,
            action_type,
        )


    # ============================================================
    # BUILD SELECTED PLAN REASONS
    # ============================================================

    def selected_plan_reasons(
        self,
        result,
    ):

        best = self.safe_dict(
            result.get(
                "best_plan"
            )
        )


        reasons = []


        initial_risk = result.get(
            "initial_risk_score",
            0,
        )


        residual_risk = best.get(
            "predicted_residual_risk",
            initial_risk,
        )


        reduction = best.get(
            "risk_reduction_percentage",
            0,
        )


        impact = self.safe_dict(
            best.get(
                "operational_impact"
            )
        )


        impact_level = impact.get(
            "impact_level",
            "UNKNOWN",
        )


        reasons.append(
            (
                f"Predicted incident risk decreases "
                f"from {initial_risk} to {residual_risk}."
            )
        )


        reasons.append(
            (
                f"Predicted risk reduction is "
                f"{reduction}%."
            )
        )


        reasons.append(
            (
                f"Operational impact is estimated "
                f"as {impact_level}."
            )
        )


        actions = self.safe_list(
            best.get(
                "actions"
            )
        )


        if actions:

            action_names = [

                self.action_label(
                    item.get(
                        "action_type"
                    )
                )

                for item in actions
            ]


            reasons.append(
                (
                    "Selected controls: "
                    + ", ".join(
                        action_names
                    )
                    + "."
                )
            )


        if not any(

            item.get(
                "action_type"
            )
            == "ISOLATE_ENDPOINT"

            for item in actions

        ):

            reasons.append(
                (
                    "Endpoint-wide isolation is avoided "
                    "because targeted remediation provides "
                    "a strong predicted security benefit "
                    "with lower disruption."
                )
            )


        return reasons


    # ============================================================
    # EXPLAIN ALTERNATIVE
    # ============================================================

    def explain_alternative(
        self,
        best,
        alternative,
    ):

        best_score = best.get(
            "plan_score",
            0,
        )


        alternative_score = alternative.get(
            "plan_score",
            0,
        )


        best_risk = best.get(
            "predicted_residual_risk",
            100,
        )


        alternative_risk = alternative.get(
            "predicted_residual_risk",
            100,
        )


        best_impact = self.safe_dict(
            best.get(
                "operational_impact"
            )
        ).get(
            "impact_level",
            "UNKNOWN",
        )


        alternative_impact = self.safe_dict(
            alternative.get(
                "operational_impact"
            )
        ).get(
            "impact_level",
            "UNKNOWN",
        )


        reasons = []


        if alternative_risk > best_risk:

            reasons.append(
                (
                    f"Higher predicted residual risk "
                    f"({alternative_risk} vs {best_risk})."
                )
            )


        if (
            alternative_risk
            == best_risk
            and alternative_impact
            != best_impact
        ):

            reasons.append(
                (
                    f"Provides similar predicted security "
                    f"benefit but has {alternative_impact} "
                    f"operational impact instead of "
                    f"{best_impact}."
                )
            )


        if alternative_score < best_score:

            reasons.append(
                (
                    f"Lower overall response-plan score "
                    f"({alternative_score} vs {best_score})."
                )
            )


        if not reasons:

            reasons.append(
                (
                    "The selected plan achieved a better "
                    "overall balance between predicted "
                    "security benefit and operational impact."
                )
            )


        return {

            "plan_id":
                alternative.get(
                    "plan_id"
                ),

            "plan_name":
                alternative.get(
                    "plan_name"
                ),

            "predicted_residual_risk":
                alternative_risk,

            "operational_impact":
                alternative_impact,

            "plan_score":
                alternative_score,

            "reasons_not_selected":
                reasons,
        }


    # ============================================================
    # GENERATE EXPLANATION
    # ============================================================

    def generate(
        self,
        decision_result,
    ):

        decision_result = self.safe_dict(
            decision_result
        )


        best = self.safe_dict(
            decision_result.get(
                "best_plan"
            )
        )


        ranked_plans = self.safe_list(
            decision_result.get(
                "ranked_plans"
            )
        )


        if not best:

            return {

                "explainability":
                    self.name,

                "incident_id":
                    decision_result.get(
                        "incident_id"
                    ),

                "generated_at":
                    self.now_iso(),

                "status":
                    "NO_SELECTED_PLAN",

                "summary":
                    (
                        "No digital-twin response plan "
                        "was selected."
                    ),

                "real_endpoint_modified":
                    False,
            }


        reasons = (
            self.selected_plan_reasons(
                decision_result
            )
        )


        alternatives = []


        for plan in ranked_plans:

            if (
                plan.get(
                    "plan_id"
                )
                == best.get(
                    "plan_id"
                )
            ):
                continue


            alternatives.append(
                self.explain_alternative(
                    best,
                    plan,
                )
            )


        initial_risk = (
            decision_result.get(
                "initial_risk_score",
                0,
            )
        )


        residual_risk = (
            best.get(
                "predicted_residual_risk",
                initial_risk,
            )
        )


        impact = self.safe_dict(
            best.get(
                "operational_impact"
            )
        )


        summary = (

            f"SENTINEL-X selected "
            f"'{best.get('plan_name')}' because it "
            f"provides the strongest modeled balance "
            f"between security improvement and "
            f"operational disruption. The digital twin "
            f"predicts the modeled risk score decreasing "
            f"from {initial_risk} to {residual_risk}, "
            f"with {impact.get('impact_level', 'UNKNOWN')} "
            f"operational impact."
        )


        return {

            "explainability":
                self.name,

            "incident_id":
                decision_result.get(
                    "incident_id"
                ),

            "twin_id":
                decision_result.get(
                    "twin_id"
                ),

            "generated_at":
                self.now_iso(),

            "status":
                "EXPLANATION_GENERATED",

            "selected_plan": {

                "plan_id":
                    best.get(
                        "plan_id"
                    ),

                "plan_name":
                    best.get(
                        "plan_name"
                    ),

                "plan_score":
                    best.get(
                        "plan_score"
                    ),

                "predicted_residual_risk":
                    best.get(
                        "predicted_residual_risk"
                    ),

                "predicted_residual_level":
                    best.get(
                        "predicted_residual_level"
                    ),

                "risk_reduction_percentage":
                    best.get(
                        "risk_reduction_percentage"
                    ),

                "response_effectiveness":
                    best.get(
                        "response_effectiveness"
                    ),

                "operational_impact":
                    impact.get(
                        "impact_level"
                    ),
            },

            "why_selected":
                reasons,

            "alternative_plans":
                alternatives,

            "summary":
                summary,

            "requires_analyst_approval":
                decision_result.get(
                    "requires_analyst_approval",
                    False,
                ),

            "real_endpoint_modified":
                False,
        }