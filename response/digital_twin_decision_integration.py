from copy import deepcopy

from response.endpoint_digital_twin import EndpointDigitalTwin
from response.digital_twin_response_planner import DigitalTwinResponsePlanner


class DigitalTwinDecisionIntegration:

    def __init__(self):

        self.name = "DigitalTwinDecisionIntegration"

        self.planner = DigitalTwinResponsePlanner()


    # ============================================================
    # SAFE HELPERS
    # ============================================================

    def safe_list(self, value):

        if isinstance(value, list):
            return value

        return []


    def safe_dict(self, value):

        if isinstance(value, dict):
            return value

        return {}


    # ============================================================
    # BUILD TWIN FROM INTELLIGENCE OUTPUT
    # ============================================================

    def build_twin(
        self,
        incident_id,
        intelligence,
    ):

        intelligence = self.safe_dict(
            intelligence
        )


        risk = self.safe_dict(
            intelligence.get(
                "risk"
            )
        )


        coordinated = self.safe_dict(
            intelligence.get(
                "coordinated_analysis"
            )
        )


        evidence = self.safe_dict(
            coordinated.get(
                "evidence"
            )
        )


        # ========================================================
        # FALLBACK:
        # Some pipeline versions may store evidence inside context
        # ========================================================

        if not evidence:

            context = self.safe_dict(
                coordinated.get(
                    "context"
                )
            )


            evidence = self.safe_dict(
                context.get(
                    "evidence"
                )
            )


        initial_risk_score = risk.get(
            "risk_score",
            intelligence.get(
                "risk_score",
                0,
            ),
        )


        initial_risk_level = risk.get(
            "risk_level",
            intelligence.get(
                "risk_level",
                "INFO",
            ),
        )


        twin = EndpointDigitalTwin(

            incident_id=incident_id,

            initial_risk_score=
                initial_risk_score,

            initial_risk_level=
                initial_risk_level,
        )


        twin.load_evidence(
            evidence
        )


        return twin


    # ============================================================
    # EXTRACT RECOMMENDATIONS
    # ============================================================

    def extract_recommendations(
        self,
        intelligence,
    ):

        intelligence = self.safe_dict(
            intelligence
        )


        response = self.safe_dict(
            intelligence.get(
                "response"
            )
        )


        recommendations = response.get(
            "recommendations",
            [],
        )


        return self.safe_list(
            recommendations
        )


    # ============================================================
    # RECOMMENDATION -> DIGITAL TWIN ACTION
    # ============================================================

    def recommendation_to_action(
        self,
        recommendation,
        twin,
    ):

        recommendation = self.safe_dict(
            recommendation
        )


        rec_type = str(

            recommendation.get(
                "recommendation_type",

                recommendation.get(
                    "action",
                    "",
                ),
            )

        ).upper()


        target = self.safe_dict(
            recommendation.get(
                "target"
            )
        )


        # ========================================================
        # QUARANTINE
        # ========================================================

        if rec_type in {
            "QUARANTINE_REVIEW",
            "QUARANTINE_FILE",
        }:

            if target:

                return {
                    "action_type":
                        "QUARANTINE_FILE",

                    "target":
                        deepcopy(
                            target
                        ),
                }


            if twin.files:

                file_item = twin.files[0]


                return {
                    "action_type":
                        "QUARANTINE_FILE",

                    "target": {

                        "path":
                            file_item.get(
                                "path"
                            ),

                        "sha256":
                            file_item.get(
                                "sha256"
                            ),
                    },
                }


        # ========================================================
        # PROCESS
        # ========================================================

        if rec_type in {
            "PROCESS_TERMINATION_REVIEW",
            "TERMINATE_PROCESS",
        }:

            if target:

                return {
                    "action_type":
                        "TERMINATE_PROCESS",

                    "target":
                        deepcopy(
                            target
                        ),
                }


            if twin.processes:

                process = twin.processes[0]


                return {
                    "action_type":
                        "TERMINATE_PROCESS",

                    "target": {

                        "pid":
                            process.get(
                                "pid"
                            ),
                    },
                }


        # ========================================================
        # NETWORK
        # ========================================================

        if rec_type in {
            "NETWORK_BLOCK_REVIEW",
            "BLOCK_NETWORK",
        }:

            if target:

                return {
                    "action_type":
                        "BLOCK_NETWORK",

                    "target":
                        deepcopy(
                            target
                        ),
                }


            if twin.network_connections:

                connection = (
                    twin.network_connections[0]
                )


                return {
                    "action_type":
                        "BLOCK_NETWORK",

                    "target": {

                        "remote_ip":
                            connection.get(
                                "remote_ip"
                            ),

                        "remote_port":
                            connection.get(
                                "remote_port"
                            ),
                    },
                }


        # ========================================================
        # PERSISTENCE
        # ========================================================

        if rec_type in {
            "PERSISTENCE_REMEDIATION_REVIEW",
            "REMEDIATE_PERSISTENCE",
        }:

            if target:

                return {
                    "action_type":
                        "REMEDIATE_PERSISTENCE",

                    "target":
                        deepcopy(
                            target
                        ),
                }


            if twin.persistence_artifacts:

                artifact = (
                    twin.persistence_artifacts[0]
                )


                return {
                    "action_type":
                        "REMEDIATE_PERSISTENCE",

                    "target": {

                        "key":
                            artifact.get(
                                "key"
                            ),

                        "value_name":
                            artifact.get(
                                "value_name"
                            ),
                    },
                }


        # ========================================================
        # ENDPOINT ISOLATION
        # ========================================================

        if rec_type in {
            "ENDPOINT_ISOLATION_REVIEW",
            "ISOLATE_ENDPOINT",
        }:

            return {
                "action_type":
                    "ISOLATE_ENDPOINT",

                "target":
                    deepcopy(
                        target
                    ),
            }


        return None


    # ============================================================
    # BUILD CANDIDATE ACTIONS
    # ============================================================

    def build_candidate_actions(
        self,
        intelligence,
        twin,
    ):

        recommendations = (
            self.extract_recommendations(
                intelligence
            )
        )


        actions = []


        for recommendation in recommendations:

            action = (
                self.recommendation_to_action(

                    recommendation=
                        recommendation,

                    twin=
                        twin,
                )
            )


            if action is not None:

                actions.append(
                    action
                )


        # ========================================================
        # REMOVE DUPLICATE ACTION TYPES
        # ========================================================

        unique_actions = []

        seen = set()


        for action in actions:

            action_type = action.get(
                "action_type"
            )


            if action_type in seen:
                continue


            seen.add(
                action_type
            )


            unique_actions.append(
                action
            )


        return unique_actions


    # ============================================================
    # BUILD RESPONSE PLANS
    # ============================================================

    def build_response_plans(
        self,
        candidate_actions,
    ):

        candidate_actions = self.safe_list(
            candidate_actions
        )


        plans = []


        # ========================================================
        # PLAN 1
        # MINIMAL TARGETED RESPONSE
        # ========================================================

        if candidate_actions:

            plans.append(
                {
                    "plan_id":
                        "DT-PLAN-1",

                    "plan_name":
                        "Minimal Targeted Response",

                    "description":
                        (
                            "Apply the first targeted response "
                            "recommended by the intelligence layer."
                        ),

                    "actions": [
                        deepcopy(
                            candidate_actions[0]
                        )
                    ],
                }
            )


        # ========================================================
        # PLAN 2
        # TARGETED CONTAINMENT
        # ========================================================

        if len(
            candidate_actions
        ) >= 2:

            plans.append(
                {
                    "plan_id":
                        "DT-PLAN-2",

                    "plan_name":
                        "Targeted Containment",

                    "description":
                        (
                            "Apply two complementary "
                            "response actions."
                        ),

                    "actions":
                        deepcopy(
                            candidate_actions[:2]
                        ),
                }
            )


        # ========================================================
        # PLAN 3
        # ALL TARGETED REMEDIATION WITHOUT ISOLATION
        # ========================================================

        non_isolation_actions = [

            deepcopy(
                action
            )

            for action in candidate_actions

            if action.get(
                "action_type"
            )
            != "ISOLATE_ENDPOINT"
        ]


        if non_isolation_actions:

            plans.append(
                {
                    "plan_id":
                        "DT-PLAN-3",

                    "plan_name":
                        "Targeted Full Remediation",

                    "description":
                        (
                            "Apply all targeted remediation "
                            "actions without endpoint isolation."
                        ),

                    "actions":
                        non_isolation_actions,
                }
            )


        # ========================================================
        # PLAN 4
        # FULL CONTAINMENT
        # ========================================================

        isolation_present = any(

            action.get(
                "action_type"
            )
            == "ISOLATE_ENDPOINT"

            for action in candidate_actions
        )


        if isolation_present:

            plans.append(
                {
                    "plan_id":
                        "DT-PLAN-4",

                    "plan_name":
                        "Full Endpoint Containment",

                    "description":
                        (
                            "Apply all recommended controls "
                            "including endpoint isolation."
                        ),

                    "actions":
                        deepcopy(
                            candidate_actions
                        ),
                }
            )


        # ========================================================
        # REMOVE DUPLICATE PLANS
        # ========================================================

        final_plans = []

        seen_signatures = set()


        for plan in plans:

            signature = tuple(

                action.get(
                    "action_type"
                )

                for action in plan.get(
                    "actions",
                    []
                )
            )


            if signature in seen_signatures:
                continue


            seen_signatures.add(
                signature
            )


            final_plans.append(
                plan
            )


        return final_plans


    # ============================================================
    # APPROVAL DECISION
    # ============================================================

    def requires_analyst_approval(
        self,
        best_plan,
    ):

        if not best_plan:
            return False


        approval_actions = {

            "QUARANTINE_FILE",
            "TERMINATE_PROCESS",
            "BLOCK_NETWORK",
            "REMEDIATE_PERSISTENCE",
            "ISOLATE_ENDPOINT",
        }


        for action in best_plan.get(
            "actions",
            []
        ):

            if action.get(
                "action_type"
            ) in approval_actions:

                return True


        return False


    # ============================================================
    # MAIN EVALUATION
    # ============================================================

    def evaluate(
        self,
        incident_id,
        intelligence,
    ):

        twin = self.build_twin(

            incident_id=
                incident_id,

            intelligence=
                intelligence,
        )


        candidate_actions = (
            self.build_candidate_actions(

                intelligence=
                    intelligence,

                twin=
                    twin,
            )
        )


        plans = (
            self.build_response_plans(
                candidate_actions
            )
        )


        if not plans:

            return {
                "integration":
                    self.name,

                "incident_id":
                    incident_id,

                "twin_id":
                    twin.twin_id,

                "initial_risk_score":
                    twin.initial_risk_score,

                "initial_risk_level":
                    twin.initial_risk_level,

                "candidate_action_count":
                    0,

                "candidate_actions":
                    [],

                "plans_evaluated":
                    0,

                "ranked_plans":
                    [],

                "best_plan":
                    None,

                "requires_analyst_approval":
                    False,

                "decision":
                    "NO_RESPONSE_PLAN_AVAILABLE",

                "real_endpoint_modified":
                    False,
            }


        planner_result = (
            self.planner.compare_plans(

                source_twin=
                    twin,

                plans=
                    plans,
            )
        )


        best_plan = planner_result.get(
            "best_plan"
        )


        approval_required = (
            self.requires_analyst_approval(
                best_plan
            )
        )


        return {
            "integration":
                self.name,

            "incident_id":
                incident_id,

            "twin_id":
                twin.twin_id,

            "initial_risk_score":
                twin.initial_risk_score,

            "initial_risk_level":
                twin.initial_risk_level,

            "candidate_action_count":
                len(
                    candidate_actions
                ),

            "candidate_actions":
                candidate_actions,

            "plans_evaluated":
                planner_result.get(
                    "plans_evaluated",
                    0,
                ),

            "ranked_plans":
                planner_result.get(
                    "ranked_plans",
                    [],
                ),

            "best_plan":
                best_plan,

            "requires_analyst_approval":
                approval_required,

            "decision":
                (
                    "ANALYST_APPROVAL_REQUIRED"
                    if approval_required
                    else "SAFE_TO_CONTINUE"
                ),

            "real_endpoint_modified":
                False,
        }