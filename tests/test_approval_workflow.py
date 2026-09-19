from response.response_action import (
    ResponseAction,
)

from response.approval_workflow import (
    ApprovalWorkflow,
)


def main():

    print()
    print("=" * 80)
    print(
        "SENTINEL-X APPROVAL WORKFLOW TEST"
    )
    print("=" * 80)


    workflow = (
        ApprovalWorkflow()
    )


    # ============================================================
    # ACTION 1 - APPROVAL SCENARIO
    # ============================================================

    action = ResponseAction(

        incident_id=
            "INC-APPROVAL-001",

        action_type=
            "QUARANTINE_FILE",

        target={

            "files": [

                {
                    "path":
                        r"C:\Temp\demo.exe",

                    "sha256":
                        "APPROVAL_TEST_SHA256",
                },
            ],
        },

        reason=
            "Synthetic quarantine approval test.",

        requested_by=
            "ResponseRecommendationAgent",

        risk_level=
            "CRITICAL",

        approval_required=
            True,

        policy_decision=
            "RECOMMEND_ONLY",
    )


    print()
    print(
        "Action ID:",
        action.action_id,
    )


    # ============================================================
    # REQUEST APPROVAL
    # ============================================================

    request_result = (
        workflow.request_approval(
            action
        )
    )


    request_pass = (
        request_result[
            "success"
        ]
        is True
    )


    # ============================================================
    # VERIFY EXECUTION BLOCKED
    # ============================================================

    before_approval_pass = (
        action.can_execute()
        is False
    )


    # ============================================================
    # APPROVE
    # ============================================================

    approve_result = (
        workflow.approve(

            action=
                action,

            analyst=
                "SyntheticSOCAnalyst",

            comment=
                "Evidence reviewed for test scenario.",
        )
    )


    approval_pass = (

        approve_result[
            "success"
        ]
        is True

        and

        action.approval_status
        == "APPROVED"
    )


    can_execute_pass = (
        action.can_execute()
        is True
    )


    # ============================================================
    # MARK READY
    #
    # NO REAL ACTION IS EXECUTED.
    # ============================================================

    ready_result = (
        workflow.mark_ready(
            action
        )
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


    # ============================================================
    # ACTION 2 - REJECTION SCENARIO
    # ============================================================

    rejected_action = ResponseAction(

        incident_id=
            "INC-APPROVAL-002",

        action_type=
            "BLOCK_NETWORK",

        target={

            "connections": [

                {
                    "remote_ip":
                        "203.0.113.50",

                    "remote_port":
                        443,
                },
            ],
        },

        reason=
            "Synthetic network response test.",

        requested_by=
            "ResponseRecommendationAgent",

        risk_level=
            "HIGH",

        approval_required=
            True,

        policy_decision=
            "RECOMMEND_ONLY",
    )


    workflow.request_approval(
        rejected_action
    )


    reject_result = (
        workflow.reject(

            action=
                rejected_action,

            analyst=
                "SyntheticSOCAnalyst",

            reason=
                "Insufficient evidence for blocking.",
        )
    )


    rejection_pass = (

        reject_result[
            "success"
        ]
        is True

        and

        rejected_action.approval_status
        == "REJECTED"

        and

        rejected_action.execution_status
        == "CANCELLED"
    )


    rejected_execution_pass = (
        rejected_action.can_execute()
        is False
    )


    # ============================================================
    # ACTION 3 - TRY READY WITHOUT APPROVAL
    # ============================================================

    pending_action = ResponseAction(

        incident_id=
            "INC-APPROVAL-003",

        action_type=
            "ISOLATE_ENDPOINT",

        target=
            {},

        reason=
            "Synthetic isolation test.",

        requested_by=
            "ResponseRecommendationAgent",

        risk_level=
            "CRITICAL",

        approval_required=
            True,

        policy_decision=
            "RECOMMEND_ONLY",
    )


    invalid_ready_result = (
        workflow.mark_ready(
            pending_action
        )
    )


    blocked_ready_pass = (

        invalid_ready_result[
            "success"
        ]
        is False

        and

        pending_action.execution_status
        == "NOT_EXECUTED"
    )


    # ============================================================
    # AUDIT VALIDATION
    # ============================================================

    audit_pass = (
        workflow.audit_log.log_path.exists()
    )


    internal_history_pass = (

        len(
            action.audit_history
        )
        >= 4

        and

        len(
            rejected_action.audit_history
        )
        >= 3
    )


    # ============================================================
    # PRINT RESULTS
    # ============================================================

    print()
    print("=" * 80)
    print(
        "FINAL APPROVAL WORKFLOW VALIDATION"
    )
    print("=" * 80)


    print(
        "Approval request recorded:",
        "PASS"
        if request_pass
        else "FAIL",
    )


    print(
        "Execution blocked before approval:",
        "PASS"
        if before_approval_pass
        else "FAIL",
    )


    print(
        "Analyst approval:",
        "PASS"
        if approval_pass
        else "FAIL",
    )


    print(
        "Action eligible after approval:",
        "PASS"
        if can_execute_pass
        else "FAIL",
    )


    print(
        "Ready state:",
        "PASS"
        if ready_pass
        else "FAIL",
    )


    print(
        "Analyst rejection:",
        "PASS"
        if rejection_pass
        else "FAIL",
    )


    print(
        "Rejected action cannot execute:",
        "PASS"
        if rejected_execution_pass
        else "FAIL",
    )


    print(
        "Pending action cannot become ready:",
        "PASS"
        if blocked_ready_pass
        else "FAIL",
    )


    print(
        "Internal audit history:",
        "PASS"
        if internal_history_pass
        else "FAIL",
    )


    print(
        "External audit log:",
        "PASS"
        if audit_pass
        else "FAIL",
    )


    overall = all(
        [
            request_pass,
            before_approval_pass,
            approval_pass,
            can_execute_pass,
            ready_pass,
            rejection_pass,
            rejected_execution_pass,
            blocked_ready_pass,
            internal_history_pass,
            audit_pass,
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


    print()
    print(
        "Audit log:",
        workflow.audit_log.log_path,
    )


if __name__ == "__main__":

    main()