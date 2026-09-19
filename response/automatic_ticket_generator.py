from response.soc_ticket import (
    SOCTicket,
)

from response.soc_ticket_store import (
    SOCTicketStore,
)


class AutomaticTicketGenerator:

    def __init__(
        self,
        store=None,
    ):

        self.name = "AutomaticTicketGenerator"

        self.store = (
            store
            if store is not None
            else SOCTicketStore()
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


    def safe_int(
        self,
        value,
        default=0,
    ):

        try:
            return int(value)

        except (
            TypeError,
            ValueError,
        ):
            return default


    # ============================================================
    # PRIORITY MAPPING
    # ============================================================

    def risk_to_priority(
        self,
        risk_score,
    ) -> str:

        risk_score = max(
            0,
            min(
                self.safe_int(
                    risk_score
                ),
                100,
            ),
        )


        if risk_score >= 80:
            return "P1"

        if risk_score >= 60:
            return "P2"

        if risk_score >= 35:
            return "P3"

        return "P4"


    # ============================================================
    # TITLE
    # ============================================================

    def build_title(
        self,
        incident_id,
        risk_level,
    ) -> str:

        return (
            f"{risk_level} Security Incident "
            f"- {incident_id}"
        )


    # ============================================================
    # INITIAL TICKET STATUS
    # ============================================================

    def determine_status(
        self,
        approval_required,
    ) -> str:

        if approval_required:

            return "AWAITING_APPROVAL"

        return "OPEN"


    # ============================================================
    # APPROVAL STATUS
    # ============================================================

    def determine_approval_status(
        self,
        approval_required,
    ) -> str:

        if approval_required:

            return "PENDING"

        return "NOT_REQUIRED"


    # ============================================================
    # GENERATE FROM DIGITAL TWIN DECISION + EXPLANATION
    # ============================================================

    def generate(
        self,
        decision_result,
        explanation_result=None,
    ):

        decision_result = (
            self.safe_dict(
                decision_result
            )
        )


        explanation_result = (
            self.safe_dict(
                explanation_result
            )
        )


        incident_id = (
            decision_result.get(
                "incident_id",
                "UNKNOWN-INCIDENT",
            )
        )


        initial_risk_score = (
            self.safe_int(
                decision_result.get(
                    "initial_risk_score",
                    0,
                )
            )
        )


        initial_risk_level = str(
            decision_result.get(
                "initial_risk_level",
                "INFO",
            )
        ).upper()


        best_plan = (
            self.safe_dict(
                decision_result.get(
                    "best_plan"
                )
            )
        )


        selected_plan = (
            best_plan.get(
                "plan_name",
                "No Response Plan Selected",
            )
        )


        residual_risk = (
            self.safe_int(
                best_plan.get(
                    "predicted_residual_risk",
                    initial_risk_score,
                )
            )
        )


        operational_impact = (
            self.safe_dict(
                best_plan.get(
                    "operational_impact"
                )
            ).get(
                "impact_level",
                "UNKNOWN",
            )
        )


        approval_required = bool(
            decision_result.get(
                "requires_analyst_approval",
                False,
            )
        )


        explanation_text = (
            explanation_result.get(
                "summary",
                (
                    "Automatic SOC ticket created from "
                    "SENTINEL-X incident intelligence "
                    "and Digital Twin response analysis."
                ),
            )
        )


        priority = (
            self.risk_to_priority(
                initial_risk_score
            )
        )


        ticket = SOCTicket(

            incident_id=
                incident_id,

            title=
                self.build_title(
                    incident_id,
                    initial_risk_level,
                ),

            priority=
                priority,

            risk_score=
                initial_risk_score,

            risk_level=
                initial_risk_level,

            selected_plan=
                selected_plan,

            predicted_residual_risk=
                residual_risk,

            operational_impact=
                operational_impact,

            explanation=
                explanation_text,

            approval_required=
                approval_required,

            approval_status=
                self.determine_approval_status(
                    approval_required
                ),

            status=
                self.determine_status(
                    approval_required
                ),
        )


        ticket_id = (
            self.store.save_ticket(
                ticket
            )
        )


        return {

            "generator":
                self.name,

            "ticket_created":
                True,

            "ticket_id":
                ticket_id,

            "ticket":
                ticket.to_dict(),

            "real_endpoint_modified":
                False,
        }