from response.response_action import (
    ResponseAction,
)

from response.response_audit_log import (
    ResponseAuditLog,
)


def main():

    print()
    print("=" * 80)
    print(
        "SENTINEL-X RESPONSE ACTION MODEL TEST"
    )
    print("=" * 80)


    # ============================================================
    # CREATE SAFE SYNTHETIC RESPONSE ACTION
    # ============================================================

    action = ResponseAction(

        incident_id=
            "INC-RESPONSE-001",

        action_type=
            "QUARANTINE_FILE",

        target={
            "path":
                r"C:\Temp\demo.exe",

            "sha256":
                "SYNTHETIC_RESPONSE_SHA256",
        },

        reason=
            "Synthetic test action generated "
            "from a critical incident.",

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

    print(
        "Action Type:",
        action.action_type,
    )

    print(
        "Approval Status:",
        action.approval_status,
    )

    print(
        "Execution Status:",
        action.execution_status,
    )

    print(
        "Can Execute:",
        action.can_execute(),
    )


    # ============================================================
    # INITIAL VALIDATION
    # ============================================================

    created_pass = (
        action.action_id.startswith(
            "ACT-"
        )
    )


    pending_pass = (
        action.approval_status
        == "PENDING"
    )


    not_executed_pass = (
        action.execution_status
        == "NOT_EXECUTED"
    )


    initially_blocked_pass = (
        action.can_execute()
        is False
    )


    # ============================================================
    # AUDIT LOGGER
    # ============================================================

    audit = (
        ResponseAuditLog()
    )


    audit.write(

        event_type=
            "ACTION_CREATED",

        action=
            action.to_dict(),

        actor=
            "ResponseRecommendationAgent",
    )


    # ============================================================
    # SIMULATE APPROVAL
    #
    # No real response action occurs.
    # ============================================================

    action.approve(
        actor="SyntheticSOCAnalyst"
    )


    approved_pass = (
        action.approval_status
        == "APPROVED"
    )


    executable_after_approval_pass = (
        action.can_execute()
        is True
    )


    audit.write(

        event_type=
            "ACTION_APPROVED",

        action=
            action.to_dict(),

        actor=
            "SyntheticSOCAnalyst",
    )


    # ============================================================
    # MARK READY
    #
    # Still no action is executed.
    # ============================================================

    action.mark_ready(
        actor="ResponseController"
    )


    ready_pass = (
        action.execution_status
        == "READY"
    )


    audit.write(

        event_type=
            "ACTION_READY",

        action=
            action.to_dict(),

        actor=
            "ResponseController",
    )


    # ============================================================
    # AUDIT HISTORY
    # ============================================================

    history_pass = (
        len(
            action.audit_history
        )
        >= 3
    )


    # ============================================================
    # AUDIT FILE
    # ============================================================

    audit_file_pass = (
        audit.log_path.exists()
    )


    print()
    print("=" * 80)
    print(
        "ACTION AUDIT HISTORY"
    )
    print("=" * 80)


    for item in action.audit_history:

        print()

        print(
            item
        )


    # ============================================================
    # FINAL VALIDATION
    # ============================================================

    print()
    print("=" * 80)
    print(
        "FINAL RESPONSE ACTION VALIDATION"
    )
    print("=" * 80)


    print(
        "Action ID generated:",
        "PASS"
        if created_pass
        else "FAIL",
    )


    print(
        "Approval initially pending:",
        "PASS"
        if pending_pass
        else "FAIL",
    )


    print(
        "Initially not executed:",
        "PASS"
        if not_executed_pass
        else "FAIL",
    )


    print(
        "Execution blocked before approval:",
        "PASS"
        if initially_blocked_pass
        else "FAIL",
    )


    print(
        "Synthetic approval recorded:",
        "PASS"
        if approved_pass
        else "FAIL",
    )


    print(
        "Eligible after approval:",
        "PASS"
        if executable_after_approval_pass
        else "FAIL",
    )


    print(
        "Ready state recorded:",
        "PASS"
        if ready_pass
        else "FAIL",
    )


    print(
        "Internal audit history:",
        "PASS"
        if history_pass
        else "FAIL",
    )


    print(
        "External audit log created:",
        "PASS"
        if audit_file_pass
        else "FAIL",
    )


    overall = all(
        [
            created_pass,
            pending_pass,
            not_executed_pass,
            initially_blocked_pass,
            approved_pass,
            executable_after_approval_pass,
            ready_pass,
            history_pass,
            audit_file_pass,
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
        audit.log_path,
    )


if __name__ == "__main__":

    main()