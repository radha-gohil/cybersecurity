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
    # ENDPOINT TARGET EXTRACTION
    # ============================================================

    def extract_endpoint_target(
        self,
        intelligence,
    ):

        intelligence = self.safe_dict(
            intelligence
        )

        source_incident = self.safe_dict(
            intelligence.get(
                "source_incident"
            )
        )

        source_timeline = self.safe_list(
            source_incident.get(
                "timeline"
            )
        )

        device_id = (
            source_incident.get(
                "device_id"
            )
        )

        hostname = (
            source_incident.get(
                "hostname"
            )
        )


        for event in source_timeline:

            event = self.safe_dict(
                event
            )

            metadata = self.safe_dict(
                event.get(
                    "metadata"
                )
            )


            if not device_id:

                device_id = (
                    event.get(
                        "device_id"
                    )
                    or metadata.get(
                        "device_id"
                    )
                )


            if not hostname:

                hostname = (
                    event.get(
                        "hostname"
                    )
                    or metadata.get(
                        "hostname"
                    )
                )


            if (
                device_id
                and hostname
            ):
                break


        endpoint_target = {}


        if device_id:

            endpoint_target[
                "device_id"
            ] = device_id


        if hostname:

            endpoint_target[
                "hostname"
            ] = hostname


        return endpoint_target


    # ============================================================
    # CONVERT DIGITAL TWIN ACTION
    # INTO RESPONSE ACTION
    # ============================================================

    def build_response_action(
        self,
        incident_id,
        plan_action,
        risk_level,
        endpoint_target=None,
    ):

        plan_action = self.safe_dict(
            plan_action
        )

        endpoint_target = self.safe_dict(
            endpoint_target
        )

        action_type = str(
            plan_action.get(
                "action_type",
                "",
            )
        ).upper()

        target = self.safe_dict(
            plan_action.get(
                "target"
            )
        )


        # ========================================================
        # IMPORTANT
        #
        # DigitalTwinDecisionIntegration already produces targets
        # in the structures expected by the response managers.
        #
        # Example:
        #
        # {
        #     "files": [...]
        # }
        #
        # Do NOT wrap this again as:
        #
        # {
        #     "files": [
        #         {
        #             "files": [...]
        #         }
        #     ]
        # }
        #
        # That was the cause of INVALID_TARGET during E2E.
        # ========================================================

        if action_type in {

            "QUARANTINE_FILE",

            "TERMINATE_PROCESS",

            "BLOCK_NETWORK",

            "REMEDIATE_PERSISTENCE",

        }:

            mapped_target = dict(
                target
            )


        elif (
            action_type
            == "ISOLATE_ENDPOINT"
        ):

            # Digital Twin may intentionally return an empty
            # isolation target because endpoint identity is not
            # part of risk evidence.
            #
            # For the persistent response layer, use endpoint
            # identity preserved from the source incident.

            if target:

                mapped_target = dict(
                    target
                )

            else:

                mapped_target = dict(
                    endpoint_target
                )


        else:

            mapped_target = dict(
                target
            )


        action = ResponseAction(

            incident_id=
                incident_id,

            action_type=
                action_type,

            target=
                mapped_target,

            reason=(
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

        intelligence = self.safe_dict(
            intelligence
        )


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
        # ENDPOINT IDENTITY
        # --------------------------------------------------------

        endpoint_target = (
            self.extract_endpoint_target(
                intelligence
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

                    endpoint_target=
                        endpoint_target,
                )
            )


            self.bridge.approval_workflow.request_approval(
                action
            )


            response_actions.append(
                action
            )


        # --------------------------------------------------------
        # CASE STATUS
        # --------------------------------------------------------

        if response_actions:

            case_status = (
                "AWAITING_ANALYST_REVIEW"
            )

        else:

            case_status = (
                "AWAITING_ANALYST_REVIEW"
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

            "endpoint_target":
                endpoint_target,

            "status":
                case_status,

            "simulation_mode":
                self.simulation_mode,

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
            # ROUTE THROUGH SAFE RESPONSE ORCHESTRATOR
            #
            # ResponseOrchestrator remains simulation-only.
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


        approval_success = all(

            result.get(
                "success",
                False,
            )

            for result
            in approval_results

        ) if approval_results else True


        return {

            "success":
                approval_success,

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


        rejection_success = all(

            result.get(
                "success",
                False,
            )

            for result
            in rejection_results

        ) if rejection_results else True


        return {

            "success":
                rejection_success,

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

            "simulation_mode":
                self.simulation_mode,

            "real_response_executed":
                False,

            "status":
                "REJECTED",
        }