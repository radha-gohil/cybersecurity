from response.soc_ticket import (
    SOCTicket,
)

from response.soc_ticket_store import (
    SOCTicketStore,
)


def main():

    print()
    print("=" * 80)
    print(
        "SENTINEL-X SOC TICKET STORE TEST"
    )
    print("=" * 80)


    # ============================================================
    # STORE
    # ============================================================

    store = (
        SOCTicketStore()
    )


    count_before = (
        store.count()
    )


    # ============================================================
    # CREATE SYNTHETIC TICKET
    # ============================================================

    ticket = SOCTicket(

        incident_id=
            "INC-SOC-001",

        title=
            "Critical Synthetic Endpoint Threat",

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
                "Digital twin selected targeted remediation "
                "because it achieved strong modeled risk "
                "reduction with lower operational impact "
                "than full endpoint isolation."
            ),

        approval_required=
            True,

        approval_status=
            "PENDING",

        status=
            "AWAITING_APPROVAL",
    )


    # ============================================================
    # SAVE
    # ============================================================

    ticket_id = (
        store.save_ticket(
            ticket
        )
    )


    print()
    print(
        "Ticket ID:",
        ticket_id,
    )


    print(
        "Incident ID:",
        ticket.incident_id,
    )


    print(
        "Priority:",
        ticket.priority,
    )


    print(
        "Risk Score:",
        ticket.risk_score,
    )


    print(
        "Selected Plan:",
        ticket.selected_plan,
    )


    print(
        "Approval Status:",
        ticket.approval_status,
    )


    # ============================================================
    # READ BACK
    # ============================================================

    stored = (
        store.get_ticket(
            ticket_id
        )
    )


    incident_tickets = (
        store.get_by_incident(
            "INC-SOC-001"
        )
    )


    count_after = (
        store.count()
    )


    # ============================================================
    # ASSIGN ANALYST
    # ============================================================

    ticket.assign_analyst(
        "SyntheticSOCAnalyst"
    )


    ticket.set_status(
        "IN_REVIEW"
    )


    store.save_ticket(
        ticket
    )


    updated = (
        store.get_ticket(
            ticket_id
        )
    )


    # ============================================================
    # VALIDATION
    # ============================================================

    create_pass = (
        ticket_id.startswith(
            "TKT-"
        )
    )


    stored_pass = (
        stored
        is not None
    )


    incident_pass = (
        len(
            incident_tickets
        )
        >= 1
    )


    count_pass = (
        count_after
        >= count_before + 1
    )


    priority_pass = (
        stored[
            "priority"
        ]
        == "P1"
    )


    risk_pass = (
        stored[
            "risk_score"
        ]
        == 96
    )


    plan_pass = (
        stored[
            "selected_plan"
        ]
        == "Targeted Full Remediation"
    )


    residual_pass = (
        stored[
            "predicted_residual_risk"
        ]
        == 0
    )


    approval_pass = (

        stored[
            "approval_required"
        ]
        == 1

        and

        stored[
            "approval_status"
        ]
        == "PENDING"
    )


    analyst_pass = (
        updated[
            "assigned_analyst"
        ]
        == "SyntheticSOCAnalyst"
    )


    status_pass = (
        updated[
            "status"
        ]
        == "IN_REVIEW"
    )


    # ============================================================
    # OUTPUT
    # ============================================================

    print()
    print("=" * 80)
    print(
        "FINAL SOC TICKET STORE VALIDATION"
    )
    print("=" * 80)


    print(
        "Ticket created:",
        "PASS"
        if create_pass
        else "FAIL",
    )


    print(
        "Ticket persisted:",
        "PASS"
        if stored_pass
        else "FAIL",
    )


    print(
        "Incident lookup:",
        "PASS"
        if incident_pass
        else "FAIL",
    )


    print(
        "Ticket count increased:",
        "PASS"
        if count_pass
        else "FAIL",
    )


    print(
        "Priority stored:",
        "PASS"
        if priority_pass
        else "FAIL",
    )


    print(
        "Risk stored:",
        "PASS"
        if risk_pass
        else "FAIL",
    )


    print(
        "Digital Twin plan stored:",
        "PASS"
        if plan_pass
        else "FAIL",
    )


    print(
        "Residual risk stored:",
        "PASS"
        if residual_pass
        else "FAIL",
    )


    print(
        "Approval state stored:",
        "PASS"
        if approval_pass
        else "FAIL",
    )


    print(
        "Analyst assignment stored:",
        "PASS"
        if analyst_pass
        else "FAIL",
    )


    print(
        "Ticket status updated:",
        "PASS"
        if status_pass
        else "FAIL",
    )


    overall = all(
        [
            create_pass,
            stored_pass,
            incident_pass,
            count_pass,
            priority_pass,
            risk_pass,
            plan_pass,
            residual_pass,
            approval_pass,
            analyst_pass,
            status_pass,
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