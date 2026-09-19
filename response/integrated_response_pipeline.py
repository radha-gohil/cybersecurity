from datetime import datetime, timezone

from agents.multi_agent_pipeline import (
    MultiAgentSecurityPipeline,
)

from response.recommendation_action_mapper import (
    RecommendationActionMapper,
)

from response.approval_workflow import (
    ApprovalWorkflow,
)

from response.response_orchestrator import (
    ResponseOrchestrator,
)


class IntegratedResponsePipeline:

    def __init__(
        self,
        autonomy_level=2,
        simulation_mode=True,
    ):

        self.name = "IntegratedResponsePipeline"

        self.autonomy_level = autonomy_level
        self.simulation_mode = simulation_mode

        self.multi_agent_pipeline = (
            MultiAgentSecurityPipeline(
                autonomy_level=autonomy_level
            )
        )

        self.mapper = (
            RecommendationActionMapper()
        )

        self.approval_workflow = (
            ApprovalWorkflow()
        )

        self.response_orchestrator = (
            ResponseOrchestrator(
                simulation_mode=simulation_mode
            )
        )


    # ============================================================
    # CURRENT TIME
    # ============================================================

    def now_iso(self):

        return datetime.now(
            timezone.utc
        ).isoformat()


    # ============================================================
    # PROCESS INCIDENT
    # ============================================================

    def process_incident(
        self,
        incident: dict,
    ) -> dict:

        if not isinstance(
            incident,
            dict,
        ):

            incident = {}


        incident_id = (
            incident.get(
                "incident_id"
            )
        )


        # ========================================================
        # STEP 1
        # MULTI-AGENT ANALYSIS
        # ========================================================

        intelligence = (
            self.multi_agent_pipeline.process_incident(
                incident
            )
        )


        # ========================================================
        # STEP 2
        # GET RESPONSE / POLICY
        # ========================================================

        response_result = (
            intelligence.get(
                "response",
                {},
            )
        )


        policy_result = (
            intelligence.get(
                "policy",
                {},
            )
        )


        risk_level = (
            intelligence.get(
                "risk_level",
                "INFO",
            )
        )


        # ========================================================
        # STEP 3
        # MAP RECOMMENDATIONS -> RESPONSE ACTIONS
        # ========================================================

        mapped = (
            self.mapper.map_all(

                incident_id=
                    incident_id,

                response_result=
                    response_result,

                policy_result=
                    policy_result,

                risk_level=
                    risk_level,
            )
        )


        actions = (
            mapped.get(
                "actions",
                []
            )
        )


        # ========================================================
        # STEP 4
        # CLASSIFY ACTIONS
        # ========================================================

        automatic_safe_actions = []

        approval_queue = []

        routed_results = []


        for action in actions:

            # ----------------------------------------------------
            # SAFE NON-DESTRUCTIVE ACTIONS
            # ----------------------------------------------------

            if not action.approval_required:

                action.mark_ready(
                    actor=self.name
                )


                route_result = (
                    self.response_orchestrator.execute(
                        action,
                        actor=self.name,
                    )
                )


                automatic_safe_actions.append(
                    action.to_dict()
                )


                routed_results.append(
                    route_result
                )


            # ----------------------------------------------------
            # APPROVAL-CONTROLLED ACTIONS
            # ----------------------------------------------------

            else:

                self.approval_workflow.request_approval(
                    action,
                    actor=self.name,
                )


                approval_queue.append(
                    action.to_dict()
                )


        # ========================================================
        # STEP 5
        # FINAL RESULT
        # ========================================================

        return {

            "pipeline":
                self.name,

            "processed_at":
                self.now_iso(),

            "incident_id":
                incident_id,

            "autonomy_level":
                self.autonomy_level,

            "simulation_mode":
                self.simulation_mode,

            "intelligence":
                intelligence,

            "mapped_action_count":
                len(
                    actions
                ),

            "automatic_safe_action_count":
                len(
                    automatic_safe_actions
                ),

            "approval_queue_count":
                len(
                    approval_queue
                ),

            "automatic_safe_actions":
                automatic_safe_actions,

            "approval_queue":
                approval_queue,

            "routed_results":
                routed_results,

            "active_containment_performed":
                False,

            "status":
                "COMPLETED",
        }