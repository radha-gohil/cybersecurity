from response.soc_ticket import (
    SOCTicket,
)

from response.soc_ticket_store import (
    SOCTicketStore,
)

from response.ticket_lifecycle_manager import (
    TicketLifecycleManager,
)


def main():

    print()
    print("=" * 80)
    print(
        "SENTINEL-X TICKET LIFECYCLE MANAGER TEST"
    )
    print("=" * 80)


    store = (
        SOCTicketStore()
    )


    lifecycle = (
        TicketLifecycleManager(
            store=store
        )
    )


    # ============================================================
    # CREATE TEST TICKET
    # ============================================================

    ticket = SOCTicket(

        incident_id=
            "INC-LIFECYCLE-001",

        title=
            "Synthetic Critical Security Incident",

        priority=
            "P1",

        risk_score=
            96,

        risk_level=
            "CRITICAL",

        selected_plan=
            "Targeted Full Remediation",

        predicted_residual_risk=
            0,

        operational_impact=
            "MEDIUM",

        explanation=
            (
                "Synthetic ticket used to validate "
                "SOC analyst lifecycle handling."
            ),

        approval_required=
            True,

        approval_status=
            "PENDING",

        status=
            "OPEN",
    )


    store.save_ticket(
        ticket
    )


    # ============================================================
    # 1. ASSIGN ANALYST
    # ============================================================

    assign_result = (
        lifecycle.assign_analyst(

            ticket=
                ticket,

            analyst=
                "SOCAnalyst01",
        )
    )


    print()
    print(
        "After Analyst Assignment:"
    )

    print(
        "Analyst:",
        ticket.assigned_analyst,
    )

    print(
        "Status:",
        ticket.status,
    )


    # ============================================================
    # 2. REQUEST APPROVAL
    # ============================================================

    approval_request = (
        lifecycle.request_approval(
            ticket
        )
    )


    print()
    print(
        "After Approval Request:"
    )

    print(
        "Approval:",
        ticket.approval_status,
    )

    print(
        "Status:",
        ticket.status,
    )


    # ============================================================
    # 3. APPROVE
    # ============================================================

    approve_result = (
        lifecycle.approve(

            ticket=
                ticket,

            analyst=
                "SOCAnalyst01",
        )
    )


    print()
    print(
        "After Approval:"
    )

    print(
        "Approval:",
        ticket.approval_status,
    )

    print(
        "Status:",
        ticket.status,
    )


    # ============================================================
    # 4. RESOLVE
    # ============================================================

    resolve_result = (
        lifecycle.resolve(
            ticket
        )
    )


    print()
    print(
        "After Resolution:"
    )

    print(
        "Status:",
        ticket.status,
    )


    # ============================================================
    # 5. CLOSE
    # ============================================================

    close_result = (
        lifecycle.close(
            ticket
        )
    )


    print()
    print(
        "After Closure:"
    )

    print(
        "Status:",
        ticket.status,
    )


    # ============================================================
    # LOAD FROM DATABASE
    # ============================================================

    stored = (
        store.get_ticket(
            ticket.ticket_id
        )
    )


    # ============================================================
    # REJECTION TEST
    # ============================================================

    rejected_ticket = SOCTicket(

        incident_id=
            "INC-LIFECYCLE-002",

        title=
            "Synthetic Rejection Test",

        priority=
            "P2",

        risk_score=
            70,

        risk_level=
            "HIGH",

        selected_plan=
            "Targeted Containment",

        predicted_residual_risk=
            30,

        operational_impact=
            "LOW",

        explanation=
            "Synthetic rejection workflow test.",

        approval_required=
            True,

        approval_status=
            "PENDING",

        status=
            "AWAITING_APPROVAL",
    )


    store.save_ticket(
        rejected_ticket
    )


    reject_result = (
        lifecycle.reject(

            ticket=
                rejected_ticket,

            analyst=
                "SOCAnalyst02",
        )
    )


    # ============================================================
    # INVALID CLOSE TEST
    # ============================================================

    invalid_close_ticket = SOCTicket(

        incident_id=
            "INC-LIFECYCLE-003",

        title=
            "Invalid Close State Test",

        priority=
            "P3",

        risk_score=
            40,

        risk_level=
            "MEDIUM",

        approval_required=
            False,

        status=
            "OPEN",
    )


    invalid_close_result = (
        lifecycle.close(
            invalid_close_ticket
        )
    )


    # ============================================================
    # VALIDATION
    # ============================================================

    assign_pass = (

        assign_result[
            "success"
        ]
        is True

        and

        ticket.assigned_analyst
        == "SOCAnalyst01"
    )


    review_pass = (
        assign_result[
            "status"
        ]
        == "IN_REVIEW"
    )


    request_pass = (

        approval_request[
            "success"
        ]
        is True
    )


    approve_pass = (

        approve_result[
            "success"
        ]
        is True
    )


    resolve_pass = (

        resolve_result[
            "success"
        ]
        is True
    )


    close_pass = (

        close_result[
            "success"
        ]
        is True

        and

        ticket.status
        == "CLOSED"
    )


    persisted_pass = (

        stored
        is not None

        and

        stored[
            "status"
        ]
        == "CLOSED"
    )


    reject_pass = (

        reject_result[
            "success"
        ]
        is True

        and

        rejected_ticket.status
        == "REJECTED"

        and

        rejected_ticket.approval_status
        == "REJECTED"
    )


    invalid_close_pass = (

        invalid_close_result[
            "success"
        ]
        is False

        and

        invalid_close_result[
            "event"
        ]
        == "INVALID_CLOSE_STATE"
    )


    # ============================================================
    # FINAL OUTPUT
    # ============================================================

    print()
    print("=" * 80)
    print(
        "FINAL TICKET LIFECYCLE VALIDATION"
    )
    print("=" * 80)


    print(
        "Analyst assignment:",
        "PASS"
        if assign_pass
        else "FAIL",
    )


    print(
        "Ticket moved to IN_REVIEW:",
        "PASS"
        if review_pass
        else "FAIL",
    )


    print(
        "Approval requested:",
        "PASS"
        if request_pass
        else "FAIL",
    )


    print(
        "Ticket approved:",
        "PASS"
        if approve_pass
        else "FAIL",
    )


    print(
        "Ticket resolved:",
        "PASS"
        if resolve_pass
        else "FAIL",
    )


    print(
        "Ticket closed:",
        "PASS"
        if close_pass
        else "FAIL",
    )


    print(
        "Final state persisted:",
        "PASS"
        if persisted_pass
        else "FAIL",
    )


    print(
        "Ticket rejection workflow:",
        "PASS"
        if reject_pass
        else "FAIL",
    )


    print(
        "Invalid close prevented:",
        "PASS"
        if invalid_close_pass
        else "FAIL",
    )


    overall = all(
        [
            assign_pass,
            review_pass,
            request_pass,
            approve_pass,
            resolve_pass,
            close_pass,
            persisted_pass,
            reject_pass,
            invalid_close_pass,
        ]
    )


    print()

    print(
        "OVERALL:",
        "PASS"
        if overall
        else "FAIL",
    )

    print("=" * 80)


if __name__ == "__main__":

    main()