from response.persistent_soc_workflow import (
    PersistentSOCWorkflow,
)

from response.soc_ticket_store import (
    SOCTicketStore,
)


class IncidentViewService:

    def __init__(
        self,
        workflow=None,
        ticket_store=None,
    ):

        self.name = (
            "IncidentViewService"
        )

        self.workflow = (
            workflow
            if workflow is not None
            else PersistentSOCWorkflow(
                simulation_mode=True
            )
        )

        self.ticket_store = (
            ticket_store
            if ticket_store is not None
            else SOCTicketStore()
        )


    # ============================================================
    # HELPERS
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


    def serialize(
        self,
        value,
    ):

        if value is None:

            return None


        if isinstance(
            value,
            (
                str,
                int,
                float,
                bool,
            ),
        ):

            return value


        if isinstance(
            value,
            dict,
        ):

            return {

                str(key):
                    self.serialize(
                        item
                    )

                for key, item
                in value.items()
            }


        if isinstance(
            value,
            (
                list,
                tuple,
                set,
            ),
        ):

            return [

                self.serialize(
                    item
                )

                for item in value
            ]


        if hasattr(
            value,
            "to_dict",
        ):

            return self.serialize(
                value.to_dict()
            )


        return str(
            value
        )


    # ============================================================
    # RISK
    # ============================================================

    def build_risk_section(
        self,
        case,
    ):

        decision = (
            self.safe_dict(
                case.get(
                    "decision"
                )
            )
        )


        ticket = (
            self.safe_dict(
                case.get(
                    "ticket_data"
                )
            )
        )


        best_plan = (
            self.safe_dict(
                decision.get(
                    "best_plan"
                )
            )
        )


        initial_score = (
            decision.get(
                "initial_risk_score"
            )
        )


        if initial_score is None:

            initial_score = (
                ticket.get(
                    "risk_score",
                    0,
                )
            )


        initial_level = (
            decision.get(
                "initial_risk_level"
            )
        )


        if not initial_level:

            initial_level = (
                ticket.get(
                    "risk_level",
                    "INFO",
                )
            )


        residual_risk = (
            best_plan.get(
                "predicted_residual_risk"
            )
        )


        if residual_risk is None:

            residual_risk = (
                ticket.get(
                    "predicted_residual_risk"
                )
            )


        return {

            "initial_risk_score":
                initial_score,

            "initial_risk_level":
                initial_level,

            "predicted_residual_risk":
                residual_risk,

            "modeled_risk_reduction":
                best_plan.get(
                    "risk_reduction"
                ),

            "modeled_risk_reduction_percentage":
                best_plan.get(
                    "risk_reduction_percentage"
                ),

            "model_type":
                "DETERMINISTIC_HEURISTIC",

            "calibrated_probability":
                False,
        }


    # ============================================================
    # EVIDENCE
    # ============================================================

    def build_evidence_section(
        self,
        case,
    ):

        evidence = (
            self.safe_dict(
                case.get(
                    "evidence"
                )
            )
        )


        return {

            "processes":
                self.safe_list(
                    evidence.get(
                        "processes"
                    )
                ),

            "files":
                self.safe_list(
                    evidence.get(
                        "files"
                    )
                ),

            "network_connections":
                self.safe_list(
                    evidence.get(
                        "network_connections"
                    )
                ),

            "registry_artifacts":
                self.safe_list(
                    evidence.get(
                        "registry_artifacts"
                    )
                ),

            "persistent":
                True,

            "raw_evidence_available":
                any(
                    [

                        bool(
                            evidence.get(
                                "processes"
                            )
                        ),

                        bool(
                            evidence.get(
                                "files"
                            )
                        ),

                        bool(
                            evidence.get(
                                "network_connections"
                            )
                        ),

                        bool(
                            evidence.get(
                                "registry_artifacts"
                            )
                        ),
                    ]
                ),
        }


    # ============================================================
    # TIMELINE
    # ============================================================

    def build_timeline_section(
        self,
        case,
    ):

        timeline = (
            self.safe_list(
                case.get(
                    "timeline"
                )
            )
        )


        return {

            "event_count":
                len(
                    timeline
                ),

            "events":
                self.serialize(
                    timeline
                ),

            "persistent":
                True,
        }


    # ============================================================
    # DIGITAL TWIN
    # ============================================================

    def build_digital_twin_section(
        self,
        case,
    ):

        decision = (
            self.safe_dict(
                case.get(
                    "decision"
                )
            )
        )


        best_plan = (
            self.safe_dict(
                decision.get(
                    "best_plan"
                )
            )
        )


        plans = (
            self.safe_list(
                decision.get(
                    "plans"
                )
            )
        )


        if not plans:

            plans = (
                self.safe_list(
                    decision.get(
                        "ranked_plans"
                    )
                )
            )


        return {

            "decision":
                decision.get(
                    "decision"
                ),

            "selected_plan":
                best_plan,

            "candidate_plans":
                plans,

            "candidate_plan_count":
                len(
                    plans
                ),

            "analyst_approval_required":
                (
                    decision.get(
                        "decision"
                    )
                    == "ANALYST_APPROVAL_REQUIRED"
                ),

            "real_endpoint_modified":
                False,
        }


    # ============================================================
    # RESPONSE
    # ============================================================

    def build_response_section(
        self,
        case,
    ):

        actions = (
            self.safe_list(
                case.get(
                    "response_actions"
                )
            )
        )


        serialized_actions = [

            self.serialize(
                action
            )

            for action
            in actions
        ]


        approval_counts = {

            "PENDING":
                0,

            "APPROVED":
                0,

            "REJECTED":
                0,

            "NOT_REQUIRED":
                0,
        }


        execution_counts = {

            "NOT_EXECUTED":
                0,

            "READY":
                0,

            "EXECUTING":
                0,

            "SUCCESS":
                0,

            "FAILED":
                0,

            "CANCELLED":
                0,
        }


        for action in serialized_actions:

            approval_status = (
                action.get(
                    "approval_status"
                )
            )


            if approval_status in approval_counts:

                approval_counts[
                    approval_status
                ] += 1


            execution_status = (
                action.get(
                    "execution_status"
                )
            )


            if execution_status in execution_counts:

                execution_counts[
                    execution_status
                ] += 1


        return {

            "action_count":
                len(
                    serialized_actions
                ),

            "actions":
                serialized_actions,

            "approval_counts":
                approval_counts,

            "execution_counts":
                execution_counts,

            "simulation_mode":
                True,

            "real_response_executed":
                False,
        }


    # ============================================================
    # TICKET
    # ============================================================

    def build_ticket_section(
        self,
        case,
    ):

        ticket_data = (
            self.safe_dict(
                case.get(
                    "ticket_data"
                )
            )
        )


        ticket_id = (
            ticket_data.get(
                "ticket_id"
            )
        )


        if ticket_id:

            stored_ticket = (
                self.ticket_store.get_ticket(
                    ticket_id
                )
            )


            if stored_ticket:

                ticket_data = (
                    stored_ticket
                )


        return ticket_data


    # ============================================================
    # INTELLIGENCE
    # ============================================================

    def build_intelligence_section(
        self,
        case,
    ):

        decision = (
            self.safe_dict(
                case.get(
                    "decision"
                )
            )
        )


        possible_keys = [

            "agent_analysis",
            "multi_agent_analysis",
            "coordinated_analysis",
            "consensus",
            "investigation",
            "risk",
            "response",
        ]


        result = {}


        for key in possible_keys:

            if key in decision:

                result[
                    key
                ] = self.serialize(
                    decision[
                        key
                    ]
                )


        return {

            "available":
                bool(
                    result
                ),

            "data":
                result,
        }


    # ============================================================
    # COMPLETE VIEW
    # ============================================================

    def get_full_incident(
        self,
        incident_id,
    ):

        case = (
            self.workflow.recover_case(
                incident_id
            )
        )


        if case is None:

            return None


        return {

            "service":
                self.name,

            "incident_id":
                incident_id,

            "case_status":
                case.get(
                    "status"
                ),

            "persistence": {

                "recovered_from_database":
                    case.get(
                        "recovered_from_database",
                        False,
                    ),

                "created_at":
                    case.get(
                        "created_at"
                    ),

                "updated_at":
                    case.get(
                        "updated_at"
                    ),
            },

            "risk":
                self.build_risk_section(
                    case
                ),

            "evidence":
                self.build_evidence_section(
                    case
                ),

            "timeline":
                self.build_timeline_section(
                    case
                ),

            "intelligence":
                self.build_intelligence_section(
                    case
                ),

            "digital_twin":
                self.build_digital_twin_section(
                    case
                ),

            "explanation":
                self.serialize(
                    case.get(
                        "explanation",
                        {},
                    )
                ),

            "ticket":
                self.build_ticket_section(
                    case
                ),

            "response":
                self.build_response_section(
                    case
                ),

            "safety": {

                "simulation_mode":
                    True,

                "real_endpoint_modified":
                    False,

                "real_response_executed":
                    False,
            },
        }