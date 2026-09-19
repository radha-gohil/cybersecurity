from datetime import datetime, timezone


class PolicyAutonomyGate:

    def __init__(
        self,
        autonomy_level: int = 2,
    ):

        self.name = "PolicyAutonomyGate"

        self.autonomy_level = (
            self.normalize_level(
                autonomy_level
            )
        )


    # ============================================================
    # TIME
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
    # NORMALIZE LEVEL
    # ============================================================

    def normalize_level(
        self,
        level,
    ) -> int:

        try:

            level = int(
                level
            )

        except (
            TypeError,
            ValueError,
        ):

            level = 2


        return max(
            0,
            min(
                level,
                4,
            ),
        )


    # ============================================================
    # AUTONOMY DESCRIPTION
    # ============================================================

    def autonomy_description(
        self,
    ) -> str:

        mapping = {

            0:
                "MONITOR_ONLY",

            1:
                "EXPLAIN_ONLY",

            2:
                "RECOMMEND_ONLY",

            3:
                "APPROVED_LOW_RISK_AUTOMATION",

            4:
                "POLICY_CONTROLLED_CONTAINMENT",
        }


        return mapping.get(
            self.autonomy_level,
            "RECOMMEND_ONLY",
        )


    # ============================================================
    # ACTION CLASSIFICATION
    # ============================================================

    def classify_action(
        self,
        action: str,
    ) -> str:

        action = str(
            action
        ).upper()


        # --------------------------------------------------------
        # OBSERVATION / ANALYSIS
        # --------------------------------------------------------

        if action in {

            "MONITOR_INCIDENT",

            "INVESTIGATE_INCIDENT",
        }:

            return "NON_DESTRUCTIVE"


        # --------------------------------------------------------
        # RESPONSE REVIEW
        # These are recommendations, not execution actions.
        # --------------------------------------------------------

        if action in {

            "QUARANTINE_REVIEW",

            "PROCESS_TERMINATION_REVIEW",

            "NETWORK_BLOCK_REVIEW",

            "PERSISTENCE_REMEDIATION_REVIEW",

            "ENDPOINT_ISOLATION_REVIEW",
        }:

            return "RESPONSE_REVIEW"


        return "UNKNOWN"


    # ============================================================
    # CHECK POLICY
    # ============================================================

    def evaluate_action(
        self,
        recommendation: dict,
    ) -> dict:

        action = str(
            recommendation.get(
                "action",
                "UNKNOWN"
            )
        ).upper()


        requires_approval = bool(
            recommendation.get(
                "requires_approval",
                False,
            )
        )


        classification = (
            self.classify_action(
                action
            )
        )


        decision = "DENY"

        execution_allowed = False

        approval_required = False

        reason = ""


        # ========================================================
        # LEVEL 0
        # Monitor only
        # ========================================================

        if self.autonomy_level == 0:

            if action == "MONITOR_INCIDENT":

                decision = "ALLOW"

                execution_allowed = True

                reason = (
                    "Autonomy level 0 permits monitoring only."
                )

            else:

                decision = "DENY"

                reason = (
                    "Autonomy level 0 does not permit analysis "
                    "or response actions."
                )


        # ========================================================
        # LEVEL 1
        # Explain only
        # ========================================================

        elif self.autonomy_level == 1:

            if classification == "NON_DESTRUCTIVE":

                decision = "ALLOW"

                execution_allowed = True

                reason = (
                    "Autonomy level 1 permits monitoring "
                    "and analysis."
                )

            else:

                decision = "DENY"

                reason = (
                    "Autonomy level 1 does not permit "
                    "response execution."
                )


        # ========================================================
        # LEVEL 2
        # Recommend only
        # ========================================================

        elif self.autonomy_level == 2:

            if classification == "NON_DESTRUCTIVE":

                decision = "ALLOW"

                execution_allowed = True

                reason = (
                    "Autonomy level 2 permits monitoring "
                    "and investigation."
                )

            elif classification == "RESPONSE_REVIEW":

                decision = "RECOMMEND_ONLY"

                execution_allowed = False

                approval_required = True

                reason = (
                    "Autonomy level 2 permits response "
                    "recommendations but not execution."
                )

            else:

                decision = "DENY"

                reason = (
                    "Unknown action is not permitted."
                )


        # ========================================================
        # LEVEL 3
        # Approved low-risk automation
        # ========================================================

        elif self.autonomy_level == 3:

            if classification == "NON_DESTRUCTIVE":

                decision = "ALLOW"

                execution_allowed = True

                reason = (
                    "Non-destructive action permitted."
                )

            elif classification == "RESPONSE_REVIEW":

                decision = "APPROVAL_REQUIRED"

                execution_allowed = False

                approval_required = True

                reason = (
                    "Response action requires explicit approval "
                    "before execution."
                )

            else:

                decision = "DENY"

                reason = (
                    "Unknown action is not permitted."
                )


        # ========================================================
        # LEVEL 4
        # Policy-controlled containment
        #
        # We STILL do not execute anything here yet.
        # This gate only decides eligibility.
        # ========================================================

        elif self.autonomy_level == 4:

            if classification == "NON_DESTRUCTIVE":

                decision = "ALLOW"

                execution_allowed = True

                reason = (
                    "Non-destructive action permitted."
                )

            elif classification == "RESPONSE_REVIEW":

                # In the current development build,
                # destructive containment is not executed.
                # The action becomes policy eligible,
                # but still requires approval/execution layer.

                decision = "POLICY_ELIGIBLE"

                execution_allowed = False

                approval_required = (
                    requires_approval
                    or True
                )

                reason = (
                    "Action is eligible for policy-controlled "
                    "containment, but execution is disabled "
                    "in the current development build."
                )

            else:

                decision = "DENY"

                reason = (
                    "Unknown action is not permitted."
                )


        return {

            "action":
                action,

            "classification":
                classification,

            "autonomy_level":
                self.autonomy_level,

            "autonomy_mode":
                self.autonomy_description(),

            "policy_decision":
                decision,

            "execution_allowed":
                execution_allowed,

            "approval_required":
                approval_required,

            "reason":
                reason,

            "evaluated_at":
                self.now_iso(),
        }


    # ============================================================
    # EVALUATE ALL RECOMMENDATIONS
    # ============================================================

    def evaluate_recommendations(
        self,
        response_result: dict,
    ) -> dict:

        recommendations = (
            response_result.get(
                "recommendations",
                []
            )
        )


        if not isinstance(
            recommendations,
            list,
        ):

            recommendations = []


        evaluations = []


        for recommendation in recommendations:

            if not isinstance(
                recommendation,
                dict,
            ):

                continue


            evaluations.append(
                self.evaluate_action(
                    recommendation
                )
            )


        allowed_count = sum(

            1
            for item in evaluations

            if item[
                "policy_decision"
            ]
            == "ALLOW"
        )


        recommendation_only_count = sum(

            1
            for item in evaluations

            if item[
                "policy_decision"
            ]
            in {

                "RECOMMEND_ONLY",

                "APPROVAL_REQUIRED",

                "POLICY_ELIGIBLE",
            }
        )


        denied_count = sum(

            1
            for item in evaluations

            if item[
                "policy_decision"
            ]
            == "DENY"
        )


        return {

            "gate":
                self.name,

            "autonomy_level":
                self.autonomy_level,

            "autonomy_mode":
                self.autonomy_description(),

            "evaluation_count":
                len(
                    evaluations
                ),

            "allowed_count":
                allowed_count,

            "review_or_recommendation_count":
                recommendation_only_count,

            "denied_count":
                denied_count,

            "evaluations":
                evaluations,

            "automatic_containment_enabled":
                False,

            "note":
                (
                    "Policy decisions do not execute containment "
                    "or remediation actions in the current build."
                ),
        }