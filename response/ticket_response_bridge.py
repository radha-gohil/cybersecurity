from response.response_action import (
    ResponseAction,
)

from response.approval_workflow import (
    ApprovalWorkflow,
)

from response.soc_ticket import (
    SOCTicket,
)

from response.soc_ticket_store import (
    SOCTicketStore,
)

from response.ticket_lifecycle_manager import (
    TicketLifecycleManager,
)


class TicketResponseBridge:

    def __init__(
        self,
        ticket_store=None,
        approval_workflow=None,
    ):

        self.name = "TicketResponseBridge"

        self.ticket_store = (
            ticket_store
            if ticket_store is not None
            else SOCTicketStore()
        )

        self.ticket_lifecycle = (
            TicketLifecycleManager(
                store=self.ticket_store
            )
        )

        self.approval_workflow = (
            approval_workflow
            if approval_workflow is not None
            else ApprovalWorkflow()
        )


    # ============================================================
    # VALIDATION
    # ============================================================

    def validate(
        self,
        ticket,
        action,
    ):

        if not isinstance(
            ticket,
            SOCTicket,
        ):

            raise TypeError(
                "ticket must be an SOCTicket."
            )


        if not isinstance(
            action,
            ResponseAction,
        ):

            raise TypeError(
                "action must be a ResponseAction."
            )


        if (
            ticket.incident_id
            != action.incident_id
        ):

            raise ValueError(
                "Ticket and ResponseAction incident IDs do not match."
            )


    # ============================================================
    # APPROVE TICKET + RESPONSE ACTION
    # ============================================================

    def approve(
        self,
        ticket: SOCTicket,
        action: ResponseAction,
        analyst: str,
        comment: str = "",
    ) -> dict:

        self.validate(
            ticket,
            action,
        )


        # --------------------------------------------------------
        # APPROVE SOC TICKET
        # --------------------------------------------------------

        ticket_result = (
            self.ticket_lifecycle.approve(

                ticket=
                    ticket,

                analyst=
                    analyst,
            )
        )


        # --------------------------------------------------------
        # APPROVE RESPONSE ACTION
        #
        # Your current ApprovalWorkflow.approve()
        # accepts action + analyst.
        # --------------------------------------------------------

        action_result = (
            self.approval_workflow.approve(

                action=
                    action,

                analyst=
                    analyst,
            )
        )


        success = (

            ticket_result.get(
                "success",
                False,
            )

            and

            action_result.get(
                "success",
                False,
            )
        )


        return {

            "bridge":
                self.name,

            "success":
                success,

            "decision":
                "APPROVED",

            "ticket_id":
                ticket.ticket_id,

            "action_id":
                action.action_id,

            "incident_id":
                ticket.incident_id,

            "analyst":
                analyst,

            "comment":
                comment,

            "ticket_status":
                ticket.status,

            "ticket_approval_status":
                ticket.approval_status,

            "action_approval_status":
                action.approval_status,

            "action_execution_status":
                action.execution_status,

            "ticket_result":
                ticket_result,

            "action_result":
                action_result,

            "real_response_executed":
                False,
        }


    # ============================================================
    # REJECT TICKET + RESPONSE ACTION
    # ============================================================

    def reject(
        self,
        ticket: SOCTicket,
        action: ResponseAction,
        analyst: str,
        comment: str = "",
    ) -> dict:

        self.validate(
            ticket,
            action,
        )


        # --------------------------------------------------------
        # REJECT SOC TICKET
        # --------------------------------------------------------

        ticket_result = (
            self.ticket_lifecycle.reject(

                ticket=
                    ticket,

                analyst=
                    analyst,
            )
        )


        # --------------------------------------------------------
        # REJECTION REASON
        #
        # ApprovalWorkflow.reject() requires:
        # action, analyst, reason
        # --------------------------------------------------------

        reason = str(
            comment
        ).strip()


        if not reason:

            reason = (
                "Rejected by SOC analyst."
            )


        # --------------------------------------------------------
        # REJECT RESPONSE ACTION
        # --------------------------------------------------------

        action_result = (
            self.approval_workflow.reject(

                action=
                    action,

                analyst=
                    analyst,

                reason=
                    reason,
            )
        )


        success = (

            ticket_result.get(
                "success",
                False,
            )

            and

            action_result.get(
                "success",
                False,
            )
        )


        return {

            "bridge":
                self.name,

            "success":
                success,

            "decision":
                "REJECTED",

            "ticket_id":
                ticket.ticket_id,

            "action_id":
                action.action_id,

            "incident_id":
                ticket.incident_id,

            "analyst":
                analyst,

            "reason":
                reason,

            "ticket_status":
                ticket.status,

            "ticket_approval_status":
                ticket.approval_status,

            "action_approval_status":
                action.approval_status,

            "action_execution_status":
                action.execution_status,

            "ticket_result":
                ticket_result,

            "action_result":
                action_result,

            "real_response_executed":
                False,
        }


    # ============================================================
    # MARK APPROVED ACTION READY
    # ============================================================

    def mark_action_ready(
        self,
        ticket: SOCTicket,
        action: ResponseAction,
        actor: str = "TicketResponseBridge",
    ) -> dict:

        self.validate(
            ticket,
            action,
        )


        # --------------------------------------------------------
        # TICKET MUST BE APPROVED
        # --------------------------------------------------------

        if (
            ticket.approval_status
            != "APPROVED"
        ):

            return {

                "success":
                    False,

                "status":
                    "BLOCKED",

                "reason":
                    "Ticket is not approved.",

                "ticket_id":
                    ticket.ticket_id,

                "action_id":
                    action.action_id,

                "ticket_approval_status":
                    ticket.approval_status,

                "action_approval_status":
                    action.approval_status,

                "action_execution_status":
                    action.execution_status,

                "real_response_executed":
                    False,
            }


        # --------------------------------------------------------
        # ACTION MUST BE APPROVED
        # --------------------------------------------------------

        if (
            action.approval_status
            != "APPROVED"
        ):

            return {

                "success":
                    False,

                "status":
                    "BLOCKED",

                "reason":
                    "ResponseAction is not approved.",

                "ticket_id":
                    ticket.ticket_id,

                "action_id":
                    action.action_id,

                "ticket_approval_status":
                    ticket.approval_status,

                "action_approval_status":
                    action.approval_status,

                "action_execution_status":
                    action.execution_status,

                "real_response_executed":
                    False,
            }


        # --------------------------------------------------------
        # MARK ACTION READY
        # --------------------------------------------------------

        ready_result = (
            self.approval_workflow.mark_ready(
                action
            )
        )


        return {

            "success":
                ready_result.get(
                    "success",
                    False,
                ),

            "status":
                action.execution_status,

            "ticket_id":
                ticket.ticket_id,

            "action_id":
                action.action_id,

            "actor":
                actor,

            "ticket_approval_status":
                ticket.approval_status,

            "action_approval_status":
                action.approval_status,

            "action_execution_status":
                action.execution_status,

            "ready_result":
                ready_result,

            "real_response_executed":
                False,
        }


    # ============================================================
    # GET CURRENT SYNCHRONIZED STATE
    # ============================================================

    def get_state(
        self,
        ticket: SOCTicket,
        action: ResponseAction,
    ) -> dict:

        self.validate(
            ticket,
            action,
        )


        return {

            "ticket_id":
                ticket.ticket_id,

            "action_id":
                action.action_id,

            "incident_id":
                ticket.incident_id,

            "ticket_status":
                ticket.status,

            "ticket_approval_status":
                ticket.approval_status,

            "action_approval_status":
                action.approval_status,

            "action_execution_status":
                action.execution_status,

            "synchronized_approval":
                (
                    ticket.approval_status
                    ==
                    action.approval_status
                ),

            "real_response_executed":
                False,
        }