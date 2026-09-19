from response.response_action import (
    ResponseAction,
)

from response.approval_workflow import (
    ApprovalWorkflow,
)

from response.safe_response_controller import (
    SafeResponseController,
)


def main():

    print()
    print("=" * 80)
    print(
        "SENTINEL-X SAFE RESPONSE CONTROLLER TEST"
    )
    print("=" * 80)


    workflow = (
        ApprovalWorkflow()
    )


    controller = (
        SafeResponseController(
            dry_run=True
        )
    )


    # ============================================================
    # ACTION 1
    # APPROVED + READY
    # ============================================================

    action = ResponseAction(

        incident_id=
            "INC-CONTROLLER-001",

        action_type=
            "QUARANTINE_FILE",

        target={

            "files": [

                {
                    "path":
                        r"C:\Temp\demo.exe",

                    "sha256":
                        "CONTROLLER_SHA256",
                },
            ],
        },

        reason=
            "Synthetic response routing test.",

        requested_by=
            "ResponseRecommendationAgent",

        risk_level=
            "CRITICAL",

        approval_required=
            True,

        policy_decision=
            "RECOMMEND_ONLY",
    )


    workflow.request_approval(
        action
    )


    workflow.approve(

        action=
            action,

        analyst=
            "SyntheticSOCAnalyst",

        comment=
            "Approved for dry-run routing test.",
    )


    workflow.mark_ready(
        action
    )


    result = (
        controller.route(
            action
        )
    )


    print()
    print(
        "Action ID:",
        action.action_id,
    )

    print(
        "Controller Status:",
        result[
            "status"
        ],
    )

    print(
        "Dry Run:",
        result[
            "dry_run"
        ],
    )

    print(
        "Executed:",
        result[
            "executed"
        ],
    )


    # ============================================================
    # VALIDATE SAFE ROUTING
    # ============================================================

    dry_run_pass = (
        result[
            "status"
        ]
        == "DRY_RUN"
    )


    not_executed_pass = (
        result[
            "executed"
        ]
        is False
    )


    precheck_pass = (
        result[
            "precheck"
        ][
            "passed"
        ]
        is True
    )


    # ============================================================
    # ACTION 2
    # NOT APPROVED
    # ============================================================

    pending_action = ResponseAction(

        incident_id=
            "INC-CONTROLLER-002",

        action_type=
            "BLOCK_NETWORK",

        target={

            "connections": [

                {
                    "remote_ip":
                        "203.0.113.70",

                    "remote_port":
                        443,
                },
            ],
        },

        reason=
            "Synthetic blocked response test.",

        requested_by=
            "ResponseRecommendationAgent",

        risk_level=
            "HIGH",

        approval_required=
            True,

        policy_decision=
            "RECOMMEND_ONLY",
    )


    pending_result = (
        controller.route(
            pending_action
        )
    )


    pending_block_pass = (

        pending_result[
            "success"
        ]
        is False

        and

        pending_result[
            "status"
        ]
        == "BLOCKED"

        and

        pending_result[
            "executed"
        ]
        is False
    )


    # ============================================================
    # ACTION 3
    # POLICY DENIED
    # ============================================================

    denied_action = ResponseAction(

        incident_id=
            "INC-CONTROLLER-003",

        action_type=
            "TERMINATE_PROCESS",

        target={

            "processes": [

                {
                    "pid":
                        12345,

                    "name":
                        "demo.exe",
                },
            ],
        },

        reason=
            "Synthetic denied policy test.",

        requested_by=
            "ResponseRecommendationAgent",

        risk_level=
            "HIGH",

        approval_required=
            True,

        policy_decision=
            "DENY",
    )


    denied_action.approve(
        actor=
            "SyntheticSOCAnalyst"
    )


    denied_action.mark_ready(
        actor=
            "SyntheticSOCAnalyst"
    )


    denied_result = (
        controller.route(
            denied_action
        )
    )


    denied_pass = (

        denied_result[
            "status"
        ]
        == "BLOCKED"

        and

        denied_result[
            "executed"
        ]
        is False
    )


    # ============================================================
    # ACTIVE MODE TEST
    #
    # Even dry_run=False must NOT execute.
    # ============================================================

    active_controller = (
        SafeResponseController(
            dry_run=False
        )
    )


    active_result = (
        active_controller.route(
            action
        )
    )


    active_disabled_pass = (

        active_result[
            "status"
        ]
        == "EXECUTION_DISABLED"

        and

        active_result[
            "executed"
        ]
        is False
    )


    # ============================================================
    # AUDIT VALIDATION
    # ============================================================

    audit_pass = (
        controller.audit_log.log_path.exists()
    )


    history_pass = any(

        item.get(
            "event"
        )
        == "DRY_RUN_ROUTED"

        for item in action.audit_history
    )


    # ============================================================
    # FINAL OUTPUT
    # ============================================================

    print()
    print("=" * 80)
    print(
        "FINAL SAFE RESPONSE CONTROLLER VALIDATION"
    )
    print("=" * 80)


    print(
        "Approved action passed precheck:",
        "PASS"
        if precheck_pass
        else "FAIL",
    )


    print(
        "Dry-run routing:",
        "PASS"
        if dry_run_pass
        else "FAIL",
    )


    print(
        "No real execution:",
        "PASS"
        if not_executed_pass
        else "FAIL",
    )


    print(
        "Pending action blocked:",
        "PASS"
        if pending_block_pass
        else "FAIL",
    )


    print(
        "Policy-denied action blocked:",
        "PASS"
        if denied_pass
        else "FAIL",
    )


    print(
        "Active execution disabled:",
        "PASS"
        if active_disabled_pass
        else "FAIL",
    )


    print(
        "Controller audit history:",
        "PASS"
        if history_pass
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
            precheck_pass,
            dry_run_pass,
            not_executed_pass,
            pending_block_pass,
            denied_pass,
            active_disabled_pass,
            history_pass,
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


if __name__ == "__main__":

    main()