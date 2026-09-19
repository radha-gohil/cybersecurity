from datetime import datetime, timezone

from response.soc_ticket import (
    SOCTicket,
)

from response.soc_ticket_store import (
    SOCTicketStore,
)


class TicketLifecycleManager:

    def __init__(
        self,
        store=None,
    ):

        self.name = "TicketLifecycleManager"

        self.store = (
            store
            if store is not None
            else SOCTicketStore()
        )


    # ============================================================
    # TIME
    # ============================================================

    def now_iso(
        self,
    ) -> str:

        return datetime.now(
            timezone.utc
        ).isoformat()


    # ============================================================
    # LOAD TICKET
    # ============================================================

    def get_ticket(
        self,
        ticket_id: str,
    ):

        return self.store.get_ticket(
            ticket_id
        )


    # ============================================================
    # ASSIGN ANALYST
    # ============================================================

    def assign_analyst(
        self,
        ticket: SOCTicket,
        analyst: str,
    ):

        if not isinstance(
            ticket,
            SOCTicket,
        ):

            raise TypeError(
                "ticket must be an SOCTicket."
            )


        analyst = str(
            analyst
        ).strip()


        if not analyst:

            raise ValueError(
                "Analyst name is required."
            )


        ticket.assign_analyst(
            analyst
        )


        if ticket.status == "OPEN":

            ticket.set_status(
                "IN_REVIEW"
            )


        self.store.save_ticket(
            ticket
        )


        return {

            "success":
                True,

            "event":
                "ANALYST_ASSIGNED",

            "ticket_id":
                ticket.ticket_id,

            "assigned_analyst":
                ticket.assigned_analyst,

            "status":
                ticket.status,

            "updated_at":
                ticket.updated_at,
        }


    # ============================================================
    # MOVE TO APPROVAL
    # ============================================================

    def request_approval(
        self,
        ticket: SOCTicket,
    ):

        if not isinstance(
            ticket,
            SOCTicket,
        ):

            raise TypeError(
                "ticket must be an SOCTicket."
            )


        if not ticket.approval_required:

            return {

                "success":
                    False,

                "event":
                    "APPROVAL_NOT_REQUIRED",

                "ticket_id":
                    ticket.ticket_id,

                "status":
                    ticket.status,
            }


        ticket.set_approval_status(
            "PENDING"
        )


        ticket.set_status(
            "AWAITING_APPROVAL"
        )


        self.store.save_ticket(
            ticket
        )


        return {

            "success":
                True,

            "event":
                "APPROVAL_REQUESTED",

            "ticket_id":
                ticket.ticket_id,

            "approval_status":
                ticket.approval_status,

            "status":
                ticket.status,
        }


    # ============================================================
    # APPROVE
    # ============================================================

    def approve(
        self,
        ticket: SOCTicket,
        analyst: str,
    ):

        if not isinstance(
            ticket,
            SOCTicket,
        ):

            raise TypeError(
                "ticket must be an SOCTicket."
            )


        analyst = str(
            analyst
        ).strip()


        if not analyst:

            raise ValueError(
                "Approving analyst is required."
            )


        if not ticket.approval_required:

            return {

                "success":
                    False,

                "event":
                    "APPROVAL_NOT_REQUIRED",

                "ticket_id":
                    ticket.ticket_id,
            }


        ticket.assign_analyst(
            analyst
        )


        ticket.set_approval_status(
            "APPROVED"
        )


        ticket.set_status(
            "APPROVED"
        )


        self.store.save_ticket(
            ticket
        )


        return {

            "success":
                True,

            "event":
                "TICKET_APPROVED",

            "ticket_id":
                ticket.ticket_id,

            "analyst":
                analyst,

            "approval_status":
                ticket.approval_status,

            "status":
                ticket.status,
        }


    # ============================================================
    # REJECT
    # ============================================================

    def reject(
        self,
        ticket: SOCTicket,
        analyst: str,
    ):

        if not isinstance(
            ticket,
            SOCTicket,
        ):

            raise TypeError(
                "ticket must be an SOCTicket."
            )


        analyst = str(
            analyst
        ).strip()


        if not analyst:

            raise ValueError(
                "Rejecting analyst is required."
            )


        ticket.assign_analyst(
            analyst
        )


        ticket.set_approval_status(
            "REJECTED"
        )


        ticket.set_status(
            "REJECTED"
        )


        self.store.save_ticket(
            ticket
        )


        return {

            "success":
                True,

            "event":
                "TICKET_REJECTED",

            "ticket_id":
                ticket.ticket_id,

            "analyst":
                analyst,

            "approval_status":
                ticket.approval_status,

            "status":
                ticket.status,
        }


    # ============================================================
    # RESOLVE
    # ============================================================

    def resolve(
        self,
        ticket: SOCTicket,
    ):

        if not isinstance(
            ticket,
            SOCTicket,
        ):

            raise TypeError(
                "ticket must be an SOCTicket."
            )


        if ticket.status not in {
            "APPROVED",
            "IN_REVIEW",
        }:

            return {

                "success":
                    False,

                "event":
                    "INVALID_RESOLUTION_STATE",

                "ticket_id":
                    ticket.ticket_id,

                "status":
                    ticket.status,
            }


        ticket.set_status(
            "RESOLVED"
        )


        self.store.save_ticket(
            ticket
        )


        return {

            "success":
                True,

            "event":
                "TICKET_RESOLVED",

            "ticket_id":
                ticket.ticket_id,

            "status":
                ticket.status,
        }


    # ============================================================
    # CLOSE
    # ============================================================

    def close(
        self,
        ticket: SOCTicket,
    ):

        if not isinstance(
            ticket,
            SOCTicket,
        ):

            raise TypeError(
                "ticket must be an SOCTicket."
            )


        if ticket.status != "RESOLVED":

            return {

                "success":
                    False,

                "event":
                    "INVALID_CLOSE_STATE",

                "ticket_id":
                    ticket.ticket_id,

                "status":
                    ticket.status,
            }


        ticket.set_status(
            "CLOSED"
        )


        self.store.save_ticket(
            ticket
        )


        return {

            "success":
                True,

            "event":
                "TICKET_CLOSED",

            "ticket_id":
                ticket.ticket_id,

            "status":
                ticket.status,
        }