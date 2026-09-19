from response.digital_twin_decision_integration import (
    DigitalTwinDecisionIntegration,
)

from response.digital_twin_explainability import (
    DigitalTwinExplainability,
)

from response.automatic_ticket_generator import (
    AutomaticTicketGenerator,
)

from response.response_action import (
    ResponseAction,
)

from response.ticket_response_bridge import (
    TicketResponseBridge,
)

from response.response_orchestrator import (
    ResponseOrchestrator,
)


class UnifiedSOCWorkflow:

    def __init__(
        self,
        simulation_mode=True,
    ):

        self.name = "UnifiedSOCWorkflow"

        self.simulation_mode = bool(
            simulation_mode
        )

        self.decision_engine = (
            DigitalTwinDecisionIntegration()
        )

        self.explainer = (
            DigitalTwinExplainability()
        )

        self.ticket_generator = (
            AutomaticTicketGenerator()
        )

        self.bridge = (
            TicketResponseBridge(
                ticket_store=
                    self.ticket_generator.store
            )
        )

        self.orchestrator = (
            ResponseOrchestrator(
                simulation_mode=
                    self.simulation_mode
            )
        )


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
    # CONVERT BEST PLAN ACTION
    # INTO RESPONSE ACTION
    # ============================================================

    def build_response_action(
        self,
        incident_id,
        plan_action,
        risk_level,
    ):

        plan_action = self.safe_dict(
            plan_action
        )


        action_type = (
            plan_action.get(
                "action_type"
            )
        )


        target = self.safe_dict(
            plan_action.get(
                "target"
            )
        )


        # --------------------------------------------------------
        # ADAPT DIGITAL TWIN TARGET
        # TO RESPONSE ORCHESTRATOR TARGET FORMAT
        # --------------------------------------------------------

        if action_type == "QUARANTINE_FILE":

            mapped_target = {
                "files": [
                    target
                ]
            }


        elif action_type == "TERMINATE_PROCESS":

            mapped_target = {
                "processes": [
                    target
                ]
            }


        elif action_type == "BLOCK_NETWORK":

            mapped_target = {
                "connections": [
                    target
                ]
            }


        elif action_type == "REMEDIATE_PERSISTENCE":

            mapped_target = {
                "registry_artifacts": [
                    target
                ]
            }


        elif action_type == "ISOLATE_ENDPOINT":

            mapped_target = target


        else:

            mapped_target = target


        action = ResponseAction(

            incident_id=
                incident_id,

            action_type=
                action_type,

            target=
                mapped_target,

            reason=
                (
                    "Selected by SENTINEL-X "
                    "Digital Twin response planner."
                ),

            requested_by=
                self.name,

            risk_level=
                risk_level,

            approval_required=
                True,

            policy_decision=
                "RECOMMEND_ONLY",
        )


        return action


    # ============================================================
    # CREATE WORKFLOW
    # ============================================================

    def create_case(
        self,
        incident_id,
        intelligence,
    ):

        # --------------------------------------------------------
        # DIGITAL TWIN DECISION
        # --------------------------------------------------------

        decision = (
            self.decision_engine.evaluate(

                incident_id=
                    incident_id,

                intelligence=
                    intelligence,
            )
        )


        # --------------------------------------------------------
        # EXPLAINABILITY
        # --------------------------------------------------------

        explanation = (
            self.explainer.generate(
                decision
            )
        )


        # --------------------------------------------------------
        # AUTOMATIC SOC TICKET
        # --------------------------------------------------------

        ticket_result = (
            self.ticket_generator.generate(

                decision_result=
                    decision,

                explanation_result=
                    explanation,
            )
        )


        # --------------------------------------------------------
        # LOAD TICKET OBJECT DETAILS
        # --------------------------------------------------------

        ticket_data = (
            ticket_result[
                "ticket"
            ]
        )


        # --------------------------------------------------------
        # GET BEST PLAN
        # --------------------------------------------------------

        best_plan = self.safe_dict(
            decision.get(
                "best_plan"
            )
        )


        plan_actions = self.safe_list(
            best_plan.get(
                "actions"
            )
        )


        risk_level = (
            decision.get(
                "initial_risk_level",
                "INFO",
            )
        )


        # --------------------------------------------------------
        # BUILD RESPONSE ACTIONS
        # --------------------------------------------------------

        response_actions = []


        for plan_action in plan_actions:

            action = (
                self.build_response_action(

                    incident_id=
                        incident_id,

                    plan_action=
                        plan_action,

                    risk_level=
                        risk_level,
                )
            )


            self.bridge.approval_workflow.request_approval(
                action
            )


            response_actions.append(
                action
            )


        return {

            "workflow":
                self.name,

            "incident_id":
                incident_id,

            "decision":
                decision,

            "explanation":
                explanation,

            "ticket_result":
                ticket_result,

            "ticket_data":
                ticket_data,

            "response_actions":
                response_actions,

            "response_action_count":
                len(
                    response_actions
                ),

            "status":
                "AWAITING_ANALYST_REVIEW",

            "real_response_executed":
                False,
        }


    # ============================================================
    # APPROVE CASE
    # ============================================================

    def approve_case(
        self,
        case_result,
        ticket,
        analyst,
        comment="",
    ):

        actions = (
            case_result.get(
                "response_actions",
                []
            )
        )


        approval_results = []

        routing_results = []


        for action in actions:

            # ----------------------------------------------------
            # APPROVE TICKET + ACTION
            # ----------------------------------------------------

            approval_result = (
                self.bridge.approve(

                    ticket=
                        ticket,

                    action=
                        action,

                    analyst=
                        analyst,

                    comment=
                        comment,
                )
            )


            approval_results.append(
                approval_result
            )


            # ----------------------------------------------------
            # MARK ACTION READY
            # ----------------------------------------------------

            ready_result = (
                self.bridge.mark_action_ready(

                    ticket=
                        ticket,

                    action=
                        action,
                )
            )


            # ----------------------------------------------------
            # ROUTE THROUGH SAFE ORCHESTRATOR
            # ----------------------------------------------------

            if ready_result.get(
                "success",
                False,
            ):

                route_result = (
                    self.orchestrator.execute(

                        action=
                            action,

                        actor=
                            analyst,
                    )
                )


                routing_results.append(
                    route_result
                )


        return {

            "success":
                all(
                    result.get(
                        "success",
                        False,
                    )

                    for result
                    in approval_results
                ),

            "ticket_id":
                ticket.ticket_id,

            "incident_id":
                ticket.incident_id,

            "analyst":
                analyst,

            "approved_action_count":
                len(
                    approval_results
                ),

            "approval_results":
                approval_results,

            "routing_results":
                routing_results,

            "simulation_mode":
                self.simulation_mode,

            "real_response_executed":
                False,

            "status":
                "SIMULATED_RESPONSE_COMPLETED",
        }


    # ============================================================
    # REJECT CASE
    # ============================================================

    def reject_case(
        self,
        case_result,
        ticket,
        analyst,
        reason,
    ):

        actions = (
            case_result.get(
                "response_actions",
                []
            )
        )


        rejection_results = []


        for action in actions:

            result = (
                self.bridge.reject(

                    ticket=
                        ticket,

                    action=
                        action,

                    analyst=
                        analyst,

                    comment=
                        reason,
                )
            )


            rejection_results.append(
                result
            )


        return {

            "success":
                all(
                    result.get(
                        "success",
                        False,
                    )

                    for result
                    in rejection_results
                ),

            "ticket_id":
                ticket.ticket_id,

            "incident_id":
                ticket.incident_id,

            "rejected_action_count":
                len(
                    rejection_results
                ),

            "rejection_results":
                rejection_results,

            "routing_results":
                [],

            "real_response_executed":
                False,

            "status":
                "REJECTED",
        }