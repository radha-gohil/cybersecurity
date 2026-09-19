from response.response_action import ResponseAction


class RecommendationActionMapper:

    def __init__(self):

        self.name = "RecommendationActionMapper"


    # ============================================================
    # ACTION MAPPING
    # ============================================================

    ACTION_MAP = {

        "MONITOR_INCIDENT":
            "MONITOR_INCIDENT",

        "INVESTIGATE_INCIDENT":
            "INVESTIGATE_INCIDENT",

        "QUARANTINE_REVIEW":
            "QUARANTINE_FILE",

        "PROCESS_TERMINATION_REVIEW":
            "TERMINATE_PROCESS",

        "NETWORK_BLOCK_REVIEW":
            "BLOCK_NETWORK",

        "PERSISTENCE_REMEDIATION_REVIEW":
            "REMEDIATE_PERSISTENCE",

        "ENDPOINT_ISOLATION_REVIEW":
            "ISOLATE_ENDPOINT",
    }


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


    # ============================================================
    # FIND POLICY RESULT
    # ============================================================

    def find_policy_result(
        self,
        recommendation_action: str,
        policy_result: dict,
    ) -> dict:

        evaluations = (
            self.safe_list(
                policy_result.get(
                    "evaluations"
                )
            )
        )


        for item in evaluations:

            if not isinstance(
                item,
                dict,
            ):

                continue


            action = str(
                item.get(
                    "action",
                    ""
                )
            ).upper()


            if (
                action
                == recommendation_action.upper()
            ):

                return item


        return {}


    # ============================================================
    # DETERMINE TARGET
    # ============================================================

    def build_target(
        self,
        recommendation: dict,
        mapped_action: str,
    ) -> dict:

        target = (
            self.safe_dict(
                recommendation.get(
                    "target"
                )
            )
        )


        # --------------------------------------------------------
        # MONITOR / INVESTIGATION
        # --------------------------------------------------------

        if mapped_action in {

            "MONITOR_INCIDENT",

            "INVESTIGATE_INCIDENT",
        }:

            return target


        # --------------------------------------------------------
        # QUARANTINE
        # --------------------------------------------------------

        if mapped_action == "QUARANTINE_FILE":

            files = (
                self.safe_list(
                    target.get(
                        "files"
                    )
                )
            )


            return {

                "files":
                    files,
            }


        # --------------------------------------------------------
        # PROCESS TERMINATION
        # --------------------------------------------------------

        if mapped_action == "TERMINATE_PROCESS":

            processes = (
                self.safe_list(
                    target.get(
                        "processes"
                    )
                )
            )


            return {

                "processes":
                    processes,
            }


        # --------------------------------------------------------
        # NETWORK BLOCK
        # --------------------------------------------------------

        if mapped_action == "BLOCK_NETWORK":

            connections = (
                self.safe_list(
                    target.get(
                        "connections"
                    )
                )
            )


            return {

                "connections":
                    connections,
            }


        # --------------------------------------------------------
        # PERSISTENCE REMEDIATION
        # --------------------------------------------------------

        if mapped_action == "REMEDIATE_PERSISTENCE":

            registry_artifacts = (
                self.safe_list(
                    target.get(
                        "registry_artifacts"
                    )
                )
            )


            return {

                "registry_artifacts":
                    registry_artifacts,
            }


        # --------------------------------------------------------
        # ENDPOINT ISOLATION
        # --------------------------------------------------------

        if mapped_action == "ISOLATE_ENDPOINT":

            return target


        return target


    # ============================================================
    # MAP ONE RECOMMENDATION
    # ============================================================

    def map_recommendation(
        self,
        incident_id: str,
        recommendation: dict,
        policy_result: dict,
        risk_level: str,
        requested_by: str = "ResponseRecommendationAgent",
    ):

        recommendation = (
            self.safe_dict(
                recommendation
            )
        )


        recommendation_action = str(
            recommendation.get(
                "action",
                ""
            )
        ).upper()


        if (
            recommendation_action
            not in self.ACTION_MAP
        ):

            return None


        mapped_action = (
            self.ACTION_MAP[
                recommendation_action
            ]
        )


        policy_evaluation = (
            self.find_policy_result(
                recommendation_action,
                policy_result,
            )
        )


        policy_decision = str(
            policy_evaluation.get(
                "policy_decision",
                "UNKNOWN",
            )
        ).upper()


        approval_required = bool(
            recommendation.get(
                "requires_approval",
                False,
            )
        )


        # --------------------------------------------------------
        # Any response-review action stays approval-controlled
        # --------------------------------------------------------

        if mapped_action in {

            "QUARANTINE_FILE",

            "TERMINATE_PROCESS",

            "BLOCK_NETWORK",

            "REMEDIATE_PERSISTENCE",

            "ISOLATE_ENDPOINT",
        }:

            approval_required = True


        target = (
            self.build_target(
                recommendation,
                mapped_action,
            )
        )


        action = ResponseAction(

            incident_id=
                incident_id,

            action_type=
                mapped_action,

            target=
                target,

            reason=
                recommendation.get(
                    "reason",
                    "No reason provided.",
                ),

            requested_by=
                requested_by,

            risk_level=
                risk_level,

            approval_required=
                approval_required,

            policy_decision=
                policy_decision,
        )


        return action


    # ============================================================
    # MAP ALL RECOMMENDATIONS
    # ============================================================

    def map_all(
        self,
        incident_id: str,
        response_result: dict,
        policy_result: dict,
        risk_level: str,
    ) -> dict:

        response_result = (
            self.safe_dict(
                response_result
            )
        )


        policy_result = (
            self.safe_dict(
                policy_result
            )
        )


        recommendations = (
            self.safe_list(
                response_result.get(
                    "recommendations"
                )
            )
        )


        actions = []


        for recommendation in recommendations:

            if not isinstance(
                recommendation,
                dict,
            ):

                continue


            action = (
                self.map_recommendation(
                    incident_id=
                        incident_id,

                    recommendation=
                        recommendation,

                    policy_result=
                        policy_result,

                    risk_level=
                        risk_level,
                )
            )


            if action is not None:

                actions.append(
                    action
                )


        return {

            "mapper":
                self.name,

            "incident_id":
                incident_id,

            "action_count":
                len(
                    actions
                ),

            "actions":
                actions,
        }