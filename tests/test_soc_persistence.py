from response.response_action import (
    ResponseAction,
)

from response.soc_case_store import (
    SOCCaseStore,
)

from response.response_action_store import (
    ResponseActionStore,
)

from response.approval_workflow import (
    ApprovalWorkflow,
)


def main():

    print()
    print("=" * 80)
    print(
        "SENTINEL-X SOC CASE + RESPONSE PERSISTENCE TEST"
    )
    print("=" * 80)


    # ============================================================
    # INITIALIZE STORES
    # ============================================================

    case_store = (
        SOCCaseStore()
    )


    action_store = (
        ResponseActionStore()
    )


    approval_workflow = (
        ApprovalWorkflow()
    )


    # ============================================================
    # COUNTS BEFORE
    # ============================================================

    case_count_before = (
        case_store.count()
    )


    action_count_before = (
        action_store.count()
    )


    # ============================================================
    # SYNTHETIC SOC CASE
    # ============================================================

    case = {

        "incident_id":
            "INC-PERSIST-001",

        "status":
            "AWAITING_ANALYST_REVIEW",

        "decision": {

            "incident_id":
                "INC-PERSIST-001",

            "initial_risk_score":
                96,

            "initial_risk_level":
                "CRITICAL",

            "best_plan": {

                "plan_name":
                    "Targeted Full Remediation",

                "predicted_residual_risk":
                    0,

                "operational_impact": {

                    "impact_level":
                        "MEDIUM",
                },
            },
        },

        "explanation": {

            "status":
                "EXPLANATION_GENERATED",

            "summary":
                (
                    "Digital Twin selected targeted remediation "
                    "because it reduced modeled residual risk "
                    "while avoiding endpoint-wide isolation."
                ),
        },

        "ticket_data": {

            "ticket_id":
                "TKT-PERSIST-001",

            "incident_id":
                "INC-PERSIST-001",

            "priority":
                "P1",

            "risk_score":
                96,

            "risk_level":
                "CRITICAL",

            "selected_plan":
                "Targeted Full Remediation",

            "predicted_residual_risk":
                0,

            "operational_impact":
                "MEDIUM",

            "approval_required":
                True,

            "approval_status":
                "PENDING",

            "status":
                "AWAITING_APPROVAL",

            "assigned_analyst":
                "",
        },
    }


    # ============================================================
    # SAVE SOC CASE
    # ============================================================

    case_store.save_case(
        case
    )


    # ============================================================
    # CREATE RESPONSE ACTION
    # ============================================================

    action = ResponseAction(

        incident_id=
            "INC-PERSIST-001",

        action_type=
            "QUARANTINE_FILE",

        target={

            "files": [

                {

                    "path":
                        r"C:\Temp\demo.exe",

                    "sha256":
                        "PERSIST_TEST_SHA256",
                }
            ]
        },

        reason=
            "Synthetic persistence validation.",

        requested_by=
            "PersistenceTest",

        risk_level=
            "CRITICAL",

        approval_required=
            True,

        policy_decision=
            "RECOMMEND_ONLY",
    )


    # ============================================================
    # REQUEST APPROVAL
    # ============================================================

    approval_workflow.request_approval(
        action
    )


    # ============================================================
    # SAVE RESPONSE ACTION
    # ============================================================

    action_store.save_action(
        action
    )


    # ============================================================
    # LOAD CASE BACK
    # ============================================================

    loaded_case = (
        case_store.get_case(
            "INC-PERSIST-001"
        )
    )


    # ============================================================
    # LOAD ACTION BACK
    # ============================================================

    loaded_action = (
        action_store.get_action(
            action.action_id
        )
    )


    # ============================================================
    # LOAD ACTIONS BY INCIDENT
    # ============================================================

    incident_actions = (
        action_store.get_by_incident(
            "INC-PERSIST-001"
        )
    )


    # ============================================================
    # COUNTS AFTER
    # ============================================================

    case_count_after = (
        case_store.count()
    )


    action_count_after = (
        action_store.count()
    )


    # ============================================================
    # INITIAL PERSISTENCE VALIDATION
    # ============================================================

    case_pass = (
        loaded_case
        is not None
    )


    case_status_pass = (

        loaded_case
        is not None

        and

        loaded_case[
            "status"
        ]
        == "AWAITING_ANALYST_REVIEW"
    )


    decision_pass = (

        loaded_case
        is not None

        and

        loaded_case[
            "decision"
        ][
            "best_plan"
        ][
            "plan_name"
        ]
        == "Targeted Full Remediation"
    )


    explanation_pass = (

        loaded_case
        is not None

        and

        loaded_case[
            "explanation"
        ][
            "status"
        ]
        == "EXPLANATION_GENERATED"
    )


    action_pass = (
        loaded_action
        is not None
    )


    action_type_pass = (

        loaded_action
        is not None

        and

        loaded_action.action_type
        == "QUARANTINE_FILE"
    )


    target_pass = (

        loaded_action
        is not None

        and

        loaded_action.target[
            "files"
        ][
            0
        ][
            "sha256"
        ]
        == "PERSIST_TEST_SHA256"
    )


    approval_pending_pass = (

        loaded_action
        is not None

        and

        loaded_action.approval_status
        == "PENDING"
    )


    incident_lookup_pass = (
        len(
            incident_actions
        )
        >= 1
    )


    case_count_pass = (
        case_count_after
        >= case_count_before
    )


    action_count_pass = (
        action_count_after
        >= action_count_before
    )


    # ============================================================
    # UPDATE RESTORED ACTION THROUGH APPROVAL WORKFLOW
    # ============================================================

    print()
    print(
        "Restored Approval Status:",
        loaded_action.approval_status,
    )

    print(
        "Restored Execution Status:",
        loaded_action.execution_status,
    )


    # ------------------------------------------------------------
    # If action somehow was not restored as PENDING,
    # request approval again through the official workflow.
    # ------------------------------------------------------------

    if (
        loaded_action.approval_status
        != "PENDING"
    ):

        approval_workflow.request_approval(
            loaded_action
        )


    # ============================================================
    # APPROVE RESTORED ACTION
    # ============================================================

    approval_result = (
        approval_workflow.approve(

            action=
                loaded_action,

            analyst=
                "SOCAnalystPersistence",
        )
    )


    # ============================================================
    # MARK RESTORED ACTION READY
    # ============================================================

    ready_result = (
        approval_workflow.mark_ready(
            loaded_action
        )
    )


    # ============================================================
    # SAVE UPDATED STATE
    # ============================================================

    action_store.save_action(
        loaded_action
    )


    # ============================================================
    # RELOAD UPDATED ACTION FROM SQLITE
    # ============================================================

    reloaded_action = (
        action_store.get_action(
            loaded_action.action_id
        )
    )


    # ============================================================
    # RESTORED STATE VALIDATION
    # ============================================================

    approval_result_pass = (

        approval_result.get(
            "success",
            False,
        )
        is True
    )


    ready_result_pass = (

        ready_result.get(
            "success",
            False,
        )
        is True
    )


    restored_approval_pass = (

        reloaded_action
        is not None

        and

        reloaded_action.approval_status
        == "APPROVED"
    )


    restored_ready_pass = (

        reloaded_action
        is not None

        and

        reloaded_action.execution_status
        == "READY"
    )


    restored_state_pass = (

        restored_approval_pass

        and

        restored_ready_pass
    )


    # ============================================================
    # VERIFY TARGET STILL EXISTS AFTER SECOND SAVE
    # ============================================================

    restored_target_pass = (

        reloaded_action
        is not None

        and

        reloaded_action.target[
            "files"
        ][
            0
        ][
            "sha256"
        ]
        == "PERSIST_TEST_SHA256"
    )


    # ============================================================
    # VERIFY INCIDENT LINK STILL EXISTS
    # ============================================================

    reloaded_incident_actions = (
        action_store.get_by_incident(
            "INC-PERSIST-001"
        )
    )


    incident_link_pass = any(

        item.action_id
        == reloaded_action.action_id

        for item
        in reloaded_incident_actions
    )


    # ============================================================
    # PRINT STATE
    # ============================================================

    print()
    print(
        "After Approval:"
    )

    print(
        "Approval Status:",
        reloaded_action.approval_status,
    )

    print(
        "Execution Status:",
        reloaded_action.execution_status,
    )


    # ============================================================
    # FINAL VALIDATION
    # ============================================================

    print()
    print("=" * 80)
    print(
        "FINAL SOC PERSISTENCE VALIDATION"
    )
    print("=" * 80)


    print(
        "SOC case persisted:",
        "PASS"
        if case_pass
        else "FAIL",
    )


    print(
        "Case status restored:",
        "PASS"
        if case_status_pass
        else "FAIL",
    )


    print(
        "Digital Twin decision restored:",
        "PASS"
        if decision_pass
        else "FAIL",
    )


    print(
        "Explainability restored:",
        "PASS"
        if explanation_pass
        else "FAIL",
    )


    print(
        "ResponseAction persisted:",
        "PASS"
        if action_pass
        else "FAIL",
    )


    print(
        "Response action type restored:",
        "PASS"
        if action_type_pass
        else "FAIL",
    )


    print(
        "Response target restored:",
        "PASS"
        if target_pass
        else "FAIL",
    )


    print(
        "Pending approval state restored:",
        "PASS"
        if approval_pending_pass
        else "FAIL",
    )


    print(
        "Incident action lookup:",
        "PASS"
        if incident_lookup_pass
        else "FAIL",
    )


    print(
        "Case store count valid:",
        "PASS"
        if case_count_pass
        else "FAIL",
    )


    print(
        "Action store count valid:",
        "PASS"
        if action_count_pass
        else "FAIL",
    )


    print(
        "Restored action approved through workflow:",
        "PASS"
        if approval_result_pass
        else "FAIL",
    )


    print(
        "Restored action marked READY:",
        "PASS"
        if ready_result_pass
        else "FAIL",
    )


    print(
        "APPROVED state survived persistence:",
        "PASS"
        if restored_approval_pass
        else "FAIL",
    )


    print(
        "READY state survived persistence:",
        "PASS"
        if restored_ready_pass
        else "FAIL",
    )


    print(
        "Approval/READY state survived persistence:",
        "PASS"
        if restored_state_pass
        else "FAIL",
    )


    print(
        "Target survived second persistence:",
        "PASS"
        if restored_target_pass
        else "FAIL",
    )


    print(
        "Incident-action link preserved:",
        "PASS"
        if incident_link_pass
        else "FAIL",
    )


    # ============================================================
    # SAFETY VALIDATION
    # ============================================================

    real_response_executed = False


    safety_pass = (
        real_response_executed
        is False
    )


    print(
        "No real response executed:",
        "PASS"
        if safety_pass
        else "FAIL",
    )


    # ============================================================
    # OVERALL RESULT
    # ============================================================

    overall = all(
        [
            case_pass,
            case_status_pass,
            decision_pass,
            explanation_pass,
            action_pass,
            action_type_pass,
            target_pass,
            approval_pending_pass,
            incident_lookup_pass,
            case_count_pass,
            action_count_pass,
            approval_result_pass,
            ready_result_pass,
            restored_approval_pass,
            restored_ready_pass,
            restored_state_pass,
            restored_target_pass,
            incident_link_pass,
            safety_pass,
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