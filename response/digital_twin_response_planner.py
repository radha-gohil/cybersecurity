from copy import deepcopy

from response.endpoint_digital_twin import (
    EndpointDigitalTwin,
)

from response.digital_twin_simulator import (
    DigitalTwinSimulator,
)

from response.digital_twin_risk_predictor import (
    DigitalTwinRiskPredictor,
)


class DigitalTwinResponsePlanner:

    def __init__(self):

        self.name = "DigitalTwinResponsePlanner"

        self.simulator = (
            DigitalTwinSimulator()
        )

        self.predictor = (
            DigitalTwinRiskPredictor()
        )


    # ============================================================
    # BUILD FRESH TWIN
    # ============================================================

    def build_twin(
        self,
        source_twin,
    ):

        if not isinstance(
            source_twin,
            EndpointDigitalTwin,
        ):
            raise TypeError(
                "source_twin must be an EndpointDigitalTwin."
            )


        new_twin = EndpointDigitalTwin(

            incident_id=
                source_twin.incident_id,

            initial_risk_score=
                source_twin.initial_risk_score,

            initial_risk_level=
                source_twin.initial_risk_level,
        )


        evidence = {

            "processes":
                deepcopy(
                    source_twin.processes
                ),

            "files":
                deepcopy(
                    source_twin.files
                ),

            "network_connections":
                deepcopy(
                    source_twin.network_connections
                ),

            "registry_artifacts":
                deepcopy(
                    source_twin.persistence_artifacts
                ),
        }


        # Reset any previous simulation state

        for process in evidence[
            "processes"
        ]:

            process[
                "terminated_in_twin"
            ] = False

            process[
                "twin_status"
            ] = "RUNNING"


        for file_item in evidence[
            "files"
        ]:

            file_item[
                "quarantined_in_twin"
            ] = False

            file_item[
                "twin_status"
            ] = "ACTIVE"


        for connection in evidence[
            "network_connections"
        ]:

            connection[
                "blocked_in_twin"
            ] = False

            connection[
                "twin_status"
            ] = "CONNECTED"


        for artifact in evidence[
            "registry_artifacts"
        ]:

            artifact[
                "removed_in_twin"
            ] = False

            artifact[
                "twin_status"
            ] = "ACTIVE"


        new_twin.load_evidence(
            evidence
        )


        return new_twin


    # ============================================================
    # APPLY RESPONSE PLAN
    # ============================================================

    def apply_plan(
        self,
        twin,
        actions,
    ):

        action_results = []


        for action in actions:

            action_type = (
                action.get(
                    "action_type"
                )
            )

            target = (
                action.get(
                    "target",
                    {},
                )
            )


            result = (
                self.simulator.simulate_action(

                    twin,

                    action_type=
                        action_type,

                    target=
                        target,
                )
            )


            action_results.append(
                {
                    "action_type":
                        action_type,

                    "result":
                        result,
                }
            )


        return action_results


    # ============================================================
    # SCORE PLAN
    # ============================================================

    def calculate_plan_score(
        self,
        prediction,
    ):

        residual_risk = (
            prediction[
                "predicted_residual_risk"
            ]
        )


        impact_score = (
            prediction[
                "operational_impact"
            ][
                "impact_score"
            ]
        )


        risk_reduction_percentage = (
            prediction[
                "risk_reduction_percentage"
            ]
        )


        # ========================================================
        # Higher score = better balanced response
        #
        # 50% residual risk control
        # 30% risk reduction
        # 20% operational safety
        # ========================================================

        security_score = (
            100
            - residual_risk
        )


        operational_safety = (
            100
            - impact_score
        )


        score = (

            security_score
            * 0.50

            +

            risk_reduction_percentage
            * 0.30

            +

            operational_safety
            * 0.20
        )


        return round(
            score,
            2,
        )


    # ============================================================
    # EVALUATE SINGLE PLAN
    # ============================================================

    def evaluate_plan(
        self,
        source_twin,
        plan,
    ):

        twin = (
            self.build_twin(
                source_twin
            )
        )


        actions = (
            plan.get(
                "actions",
                [],
            )
        )


        action_results = (
            self.apply_plan(
                twin,
                actions,
            )
        )


        prediction = (
            self.predictor.predict(
                twin
            )
        )


        plan_score = (
            self.calculate_plan_score(
                prediction
            )
        )


        return {

            "plan_id":
                plan.get(
                    "plan_id"
                ),

            "plan_name":
                plan.get(
                    "plan_name"
                ),

            "description":
                plan.get(
                    "description"
                ),

            "actions":
                deepcopy(
                    actions
                ),

            "action_results":
                action_results,

            "predicted_residual_risk":
                prediction[
                    "predicted_residual_risk"
                ],

            "predicted_residual_level":
                prediction[
                    "predicted_residual_level"
                ],

            "risk_reduction":
                prediction[
                    "risk_reduction"
                ],

            "risk_reduction_percentage":
                prediction[
                    "risk_reduction_percentage"
                ],

            "response_effectiveness":
                prediction[
                    "response_effectiveness"
                ],

            "operational_impact":
                prediction[
                    "operational_impact"
                ],

            "recommended_decision":
                prediction[
                    "recommended_decision"
                ],

            "plan_score":
                plan_score,

            "real_endpoint_modified":
                False,
        }


    # ============================================================
    # COMPARE PLANS
    # ============================================================

    def compare_plans(
        self,
        source_twin,
        plans,
    ):

        results = []


        for plan in plans:

            result = (
                self.evaluate_plan(
                    source_twin,
                    plan,
                )
            )

            results.append(
                result
            )


        results.sort(

            key=lambda item:
                item[
                    "plan_score"
                ],

            reverse=True,
        )


        best_plan = (
            results[
                0
            ]
            if results
            else None
        )


        return {

            "planner":
                self.name,

            "incident_id":
                source_twin.incident_id,

            "plans_evaluated":
                len(
                    results
                ),

            "ranked_plans":
                results,

            "best_plan":
                best_plan,

            "real_endpoint_modified":
                False,
        }