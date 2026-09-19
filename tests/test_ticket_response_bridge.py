from response.response_action import (
    ResponseAction,
)

from response.soc_ticket import (
    SOCTicket,
)

from response.soc_ticket_store import (
    SOCTicketStore,
)

from response.ticket_response_bridge import (
    TicketResponseBridge,
)


def main():

    print()
    print("=" * 80)
    print(
        "SENTINEL-X TICKET -> RESPONSE APPROVAL BRIDGE TEST"
    )
    print("=" * 80)


    store = (
        SOCTicketStore()
    )


    bridge = (
        TicketResponseBridge(
            ticket_store=store
        )
    )


    # ============================================================
    # APPROVAL SCENARIO
    # ============================================================

    ticket = SOCTicket(

        incident_id=
            "INC-BRIDGE-001",

        title=
            "Synthetic Bridge Approval Incident",

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

        approval_required=
            True,

        approval_status=
            "PENDING",

        status=
            "AWAITING_APPROVAL",
    )


    store.save_ticket(
        ticket
    )


    action = ResponseAction(

        incident_id=
            "INC-BRIDGE-001",

        action_type=
            "QUARANTINE_FILE",

        target={
            "files": [
                {
                    "path":
                        r"C:\Temp\demo.exe",

                    "sha256":
                        "BRIDGE_TEST_SHA256",
                }
            ]
        },

        reason=
            "Synthetic ticket-response bridge test.",

        requested_by=
            "DigitalTwinDecisionIntegration",

        risk_level=
            "CRITICAL",

        approval_required=
            True,

        policy_decision=
            "RECOMMEND_ONLY",
    )


    bridge.approval_workflow.request_approval(
        action
    )


    approve_result = (
        bridge.approve(

            ticket=
                ticket,

            action=
                action,

            analyst=
                "SOCAnalyst01",

            comment=
                "Approved after reviewing Digital Twin plan.",
        )
    )


    ready_result = (
        bridge.mark_action_ready(

            ticket=
                ticket,

            action=
                action,
        )
    )


    print()
    print(
        "Approval Scenario"
    )

    print(
        "Ticket Approval:",
        ticket.approval_status,
    )

    print(
        "Ticket Status:",
        ticket.status,
    )

    print(
        "Action Approval:",
        action.approval_status,
    )

    print(
        "Action Execution Status:",
        action.execution_status,
    )


    # ============================================================
    # REJECTION SCENARIO
    # ============================================================

    rejected_ticket = SOCTicket(

        incident_id=
            "INC-BRIDGE-002",

        title=
            "Synthetic Bridge Rejection Incident",

        priority=
            "P2",

        risk_score=
            72,

        risk_level=
            "HIGH",

        selected_plan=
            "Targeted Containment",

        predicted_residual_risk=
            30,

        operational_impact=
            "LOW",

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


    rejected_action = ResponseAction(

        incident_id=
            "INC-BRIDGE-002",

        action_type=
            "BLOCK_NETWORK",

        target={
            "connections": [
                {
                    "remote_ip":
                        "203.0.113.200",

                    "remote_port":
                        443,
                }
            ]
        },

        reason=
            "Synthetic rejection bridge test.",

        requested_by=
            "DigitalTwinDecisionIntegration",

        risk_level=
            "HIGH",

        approval_required=
            True,

        policy_decision=
            "RECOMMEND_ONLY",
    )


    bridge.approval_workflow.request_approval(
        rejected_action
    )


    reject_result = (
        bridge.reject(

            ticket=
                rejected_ticket,

            action=
                rejected_action,

            analyst=
                "SOCAnalyst02",

            comment=
                "Rejected after analyst review.",
        )
    )


    rejected_ready = (
        bridge.mark_action_ready(

            ticket=
                rejected_ticket,

            action=
                rejected_action,
        )
    )


    # ============================================================
    # INCIDENT MISMATCH TEST
    # ============================================================

    mismatch_ticket = SOCTicket(

        incident_id=
            "INC-MISMATCH-A",

        title=
            "Mismatch Test",

        priority=
            "P3",

        risk_score=
            45,

        risk_level=
            "MEDIUM",
    )


    mismatch_action = ResponseAction(

        incident_id=
            "INC-MISMATCH-B",

        action_type=
            "MONITOR_INCIDENT",

        target={},

        reason=
            "Mismatch validation.",

        requested_by=
            "Test",

        risk_level=
            "MEDIUM",

        approval_required=
            False,

        policy_decision=
            "ALLOW",
    )


    mismatch_blocked = False


    try:

        bridge.validate(
            mismatch_ticket,
            mismatch_action,
        )

    except ValueError:

        mismatch_blocked = True


    # ============================================================
    # VALIDATION
    # ============================================================

    approval_bridge_pass = (

        approve_result[
            "success"
        ]
        is True
    )


    ticket_approved_pass = (

        ticket.approval_status
        == "APPROVED"

        and

        ticket.status
        == "APPROVED"
    )


    action_approved_pass = (
        action.approval_status
        == "APPROVED"
    )


    ready_pass = (

        ready_result[
            "success"
        ]
        is True

        and

        action.execution_status
        == "READY"
    )


    rejection_bridge_pass = (

        reject_result[
            "success"
        ]
        is True
    )


    ticket_rejected_pass = (

        rejected_ticket.approval_status
        == "REJECTED"

        and

        rejected_ticket.status
        == "REJECTED"
    )


    action_rejected_pass = (
        rejected_action.approval_status
        == "REJECTED"
    )


    rejected_ready_pass = (

        rejected_ready[
            "success"
        ]
        is False
    )


    mismatch_pass = (
        mismatch_blocked
        is True
    )


    stored_ticket = (
        store.get_ticket(
            ticket.ticket_id
        )
    )


    persistence_pass = (

        stored_ticket
        is not None

        and

        stored_ticket[
            "approval_status"
        ]
        == "APPROVED"
    )


    no_execution_pass = (

        approve_result[
            "real_response_executed"
        ]
        is False

        and

        reject_result[
            "real_response_executed"
        ]
        is False

        and

        ready_result[
            "real_response_executed"
        ]
        is False
    )


    # ============================================================
    # FINAL OUTPUT
    # ============================================================

    print()
    print("=" * 80)
    print(
        "FINAL TICKET -> RESPONSE BRIDGE VALIDATION"
    )
    print("=" * 80)


    print(
        "Approval synchronized:",
        "PASS"
        if approval_bridge_pass
        else "FAIL",
    )


    print(
        "Ticket approved:",
        "PASS"
        if ticket_approved_pass
        else "FAIL",
    )


    print(
        "ResponseAction approved:",
        "PASS"
        if action_approved_pass
        else "FAIL",
    )


    print(
        "Approved action marked READY:",
        "PASS"
        if ready_pass
        else "FAIL",
    )


    print(
        "Rejection synchronized:",
        "PASS"
        if rejection_bridge_pass
        else "FAIL",
    )


    print(
        "Ticket rejected:",
        "PASS"
        if ticket_rejected_pass
        else "FAIL",
    )


    print(
        "ResponseAction rejected:",
        "PASS"
        if action_rejected_pass
        else "FAIL",
    )


    print(
        "Rejected action cannot become READY:",
        "PASS"
        if rejected_ready_pass
        else "FAIL",
    )


    print(
        "Incident mismatch blocked:",
        "PASS"
        if mismatch_pass
        else "FAIL",
    )


    print(
        "Approved ticket persisted:",
        "PASS"
        if persistence_pass
        else "FAIL",
    )


    print(
        "No real response executed:",
        "PASS"
        if no_execution_pass
        else "FAIL",
    )


    overall = all(
        [
            approval_bridge_pass,
            ticket_approved_pass,
            action_approved_pass,
            ready_pass,
            rejection_bridge_pass,
            ticket_rejected_pass,
            action_rejected_pass,
            rejected_ready_pass,
            mismatch_pass,
            persistence_pass,
            no_execution_pass,
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